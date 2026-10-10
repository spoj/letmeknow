//! A `peer` stream: frames both ways. Files' `want_files` is answered here with `have`, by the serving rules; every other
//! frame goes to the node as it comes.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use anyhow::Result;
use iroh::EndpointId;
use lmk_proto::{Bytes, frame, peer::Frame};
use lmk_transport::{Conn, RecvStream, SendStream};
use n0_future::task::spawn;
use tokio::sync::{mpsc, oneshot};

use crate::{Event, Inner};

/// Takes the answer to a `want_files`; `None` for those sent unasked, whose answers start downloads.
type HaveReply = Option<oneshot::Sender<Vec<[u8; 32]>>>;

pub(crate) enum Input {
    Frame(Frame),
    Closed,
    Send(Frame),
    Want { group: Bytes, files: Vec<[u8; 32]>, reply: HaveReply },
}

struct Session {
    inner: Arc<Inner>,
    peer: EndpointId,
    send: SendStream,
    /// Our `want_files` awaiting their `have`, in order.
    wants: HashMap<Bytes, VecDeque<HaveReply>>,
}

/// Runs the connection's one peer stream; the connection closes with it.
pub(crate) async fn run(
    inner: Arc<Inner>,
    conn: Conn,
    send: SendStream,
    mut recv: RecvStream,
    input: mpsc::UnboundedSender<Input>,
    mut rx: mpsc::UnboundedReceiver<Input>,
) {
    let peer = conn.remote_id();
    inner.events.send(Event::Connected(peer)).ok();
    spawn(async move {
        while let Ok(frame) = frame::read_known(&mut recv).await {
            if input.send(Input::Frame(frame)).is_err() {
                return;
            }
        }
        input.send(Input::Closed).ok();
    });
    let mut session = Session { inner, peer, send, wants: HashMap::new() };
    let result = async {
        while let Some(input) = rx.recv().await {
            match input {
                Input::Frame(frame) => session.frame(frame).await?,
                Input::Closed => break,
                Input::Send(frame) => {
                    if let Some(frame) = session.inner.groups.admit(&session.peer, frame) {
                        frame::write(&mut session.send, &frame).await?;
                    }
                }
                Input::Want { group, files, reply } => {
                    session.wants.entry(group.clone()).or_default().push_back(reply);
                    let files = files.into_iter().map(Bytes::from).collect();
                    frame::write(&mut session.send, &Frame::WantFiles { group, files }).await?;
                }
            }
        }
        anyhow::Ok(())
    }
    .await;
    if let Err(e) = result {
        tracing::debug!("peer stream with {} ended: {e:#}", peer.fmt_short());
    }
    conn.close(b"peer stream ended");
}

impl Session {
    async fn frame(&mut self, frame: Frame) -> Result<()> {
        match frame {
            Frame::WantFiles { group, files } => {
                let mut have = Vec::new();
                if self.inner.groups.is_member(&group.0, &self.peer) {
                    let linked = self.inner.groups.files(&group.0);
                    for file in files {
                        let Ok(hash) = <[u8; 32]>::try_from(&file.0[..]) else { continue };
                        if linked.iter().any(|link| link.hash == hash) && self.inner.files.serve(&hash).await? {
                            have.push(file);
                        }
                    }
                }
                frame::write(&mut self.send, &Frame::Have { group, files: have }).await?;
            }
            Frame::Have { group, files } => self.on_have(group, files),
            frame => {
                self.inner.events.send(Event::Frame(self.peer, frame)).ok();
            }
        }
        Ok(())
    }

    fn on_have(&mut self, group: Bytes, files: Vec<Bytes>) {
        let Some(reply) = self.wants.get_mut(&group).and_then(VecDeque::pop_front) else { return };
        let hashes: Vec<[u8; 32]> = files.iter().filter_map(|f| f.0[..].try_into().ok()).collect();
        match reply {
            Some(reply) => {
                reply.send(hashes).ok();
            }
            None => {
                let links = self.inner.groups.files(&group.0);
                for link in links.iter().filter(|link| hashes.contains(&link.hash)) {
                    self.inner.offer(link, self.peer);
                }
            }
        }
    }
}

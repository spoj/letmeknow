//! A `peer` stream: frames both ways. Files' `want_files` is answered here with `have`, by the serving rules; every other
//! frame goes to the node as it comes.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use anyhow::Result;
use iroh::{
    EndpointId,
    endpoint::{Connection, RecvStream, SendStream},
};
use lmk_proto::{Bytes, frame, peer::Frame};
use n0_future::task::spawn;
use tokio::{io::AsyncReadExt, sync::{mpsc, oneshot}};
use crate::budget::{MAX_BODY, Packet, Permit};

#[derive(Debug)]
pub struct Receipt {
    _body: Permit,
    _decoded: Permit,
}

use crate::{Event, Inner};

/// Takes the answer to a `want_files`; `None` for those sent unasked, whose answers start downloads.
type HaveReply = Option<oneshot::Sender<Vec<[u8; 32]>>>;

pub(crate) enum Input {
    Frame(Frame, Receipt),
    Closed,
    Send(Packet),
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
    conn: Connection,
    send: SendStream,
    mut recv: RecvStream,
    input: mpsc::UnboundedSender<Input>,
    mut rx: mpsc::UnboundedReceiver<Input>,
) {
    let peer = conn.remote_id();
    inner.events.send(Event::Connected(peer)).ok();
    let reading = inner.clone();
    spawn(async move {
        let read = async {
            loop {
                let length = recv.read_u32().await? as usize;
                anyhow::ensure!(length <= MAX_BODY, "peer frame too large");
                let body_slot = reading.bodies.clone().acquire_many_owned((length + 65_536) as u32).await?;
                let mut body_permit = reading.incoming.acquire(peer, length + 65_536).await;
                let body = async {
                    let mut body = vec![0; length];
                    recv.read_exact(&mut body).await?;
                    let decoded = reading.incoming.acquire(peer, length * 3).await;
                    let frame = serde_json::from_slice::<Frame>(&body);
                    drop(body);
                    anyhow::Ok((frame, decoded))
                };
                let (frame, decoded) = n0_future::time::timeout(std::time::Duration::from_secs(10 + length as u64 / 32_768), body).await??;
                body_permit.release(length);
                drop(body_slot);
                if let Ok(frame) = frame {
                    input.send(Input::Frame(frame, Receipt { _body: body_permit, _decoded: decoded })).map_err(|_| anyhow::anyhow!("peer closed"))?;
                }
            }
            #[allow(unreachable_code)]
            anyhow::Ok(())
        }.await;
        if let Err(error) = read { tracing::debug!("reading peer: {error:#}"); }
        input.send(Input::Closed).ok();
    });
    let mut session = Session { inner, peer, send, wants: HashMap::new() };
    let result = async {
        while let Some(input) = rx.recv().await {
            match input {
                Input::Frame(frame, receipt) => session.frame(frame, receipt).await?,
                Input::Closed => break,
                Input::Send(Packet { frame, permit }) => {
                    if let Some(frame) = session.inner.groups.admit(&session.peer, frame) {
                        n0_future::time::timeout(std::time::Duration::from_secs(75), frame::write(&mut session.send, &frame)).await??;
                    }
                    drop(permit);
                }
                Input::Want { group, files, reply } => {
                    session.wants.entry(group.clone()).or_default().push_back(reply);
                    let files = files.into_iter().map(Bytes::from).collect();
                    if let Some(frame) = session.inner.groups.admit(&session.peer, Frame::WantFiles { group, files }) {
                        frame::write(&mut session.send, &frame).await?;
                    }
                }
            }
        }
        anyhow::Ok(())
    }
    .await;
    if let Err(e) = result {
        tracing::debug!("peer stream with {} ended: {e:#}", peer.fmt_short());
    }
    conn.close(0u32.into(), b"peer stream ended");
}

impl Session {
    async fn frame(&mut self, frame: Frame, receipt: Receipt) -> Result<()> {
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
                if let Some(frame) = self.inner.groups.admit(&self.peer, Frame::Have { group, files: have }) {
                    frame::write(&mut self.send, &frame).await?;
                }
            }
            Frame::Have { group, files } => self.on_have(group, files),
            frame => {
                self.inner.events.send(Event::Frame(self.peer, frame, receipt)).ok();
            }
        }
        Ok(())
    }

    fn on_have(&mut self, group: Bytes, files: Vec<Bytes>) {
        let Some(reply) = self.wants.get_mut(&group).and_then(VecDeque::pop_front) else { return };
        if !self.inner.groups.is_member(&group.0, &self.peer) { return; }
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

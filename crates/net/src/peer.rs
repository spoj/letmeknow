//! A `peer` stream: frames both ways.

use std::sync::Arc;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use lmk_proto::{frame, peer::Frame};
use n0_future::task::spawn;
use tokio::sync::mpsc;

use crate::{Event, Inner};

/// Runs the connection's one peer stream; the connection closes with it. The peer's frames are read one at a time, as
/// the node takes them: a peer that sends faster than that waits, and so does one that does not read what it is sent.
pub(crate) async fn run(inner: Arc<Inner>, conn: Connection, mut send: SendStream, mut recv: RecvStream, mut out: mpsc::UnboundedReceiver<Frame>) {
    let peer = conn.remote_id();
    let (read, mut frames) = mpsc::channel(1);
    spawn(async move {
        while let Ok(frame) = frame::read_known(&mut recv).await {
            if read.send(frame).await.is_err() {
                return;
            }
        }
    });
    let result = async {
        loop {
            tokio::select! {
                frame = frames.recv() => match frame {
                    Some(frame) => inner.events.send(Event::Frame(peer, frame)).await?,
                    None => break,
                },
                frame = out.recv() => match frame {
                    Some(frame) => {
                        if let Some(frame) = inner.groups.admit(&peer, frame) {
                            frame::write(&mut send, &frame).await?;
                        }
                    }
                    None => break,
                },
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

//! A `peer` stream: frames both ways.

use std::sync::Arc;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use lmk_proto::{frame, peer::Frame};
use n0_future::time::{Duration, timeout};
use tokio::sync::mpsc;

use crate::{Event, Inner};

/// How long a write to a peer may wait to move on. A peer that reads slowly, or through a relay that passes 1 MiB a
/// second, takes some of a frame much sooner; one that keeps its connection and reads nothing does not.
const WRITE: Duration = Duration::from_secs(120);

/// Runs the connection's one peer stream; the connection closes with it. The peer's frames are read one at a time, as
/// the node takes them: a peer that sends faster than that waits. One that reads nothing of what it is sent for `WRITE`
/// is closed, and what is queued for it goes; a frame larger than its reader takes is left out. A peer that serves no
/// group is read up to `MAX_ASK` a frame, and one larger closes the connection.
pub(crate) async fn run(inner: Arc<Inner>, conn: Connection, mut send: SendStream, mut recv: RecvStream, mut out: mpsc::UnboundedReceiver<Frame>) {
    let peer = conn.remote_id();
    let read = async {
        loop {
            let max = if inner.groups.serves(&peer) { frame::MAX_FRAME } else { frame::MAX_ASK };
            let Ok(frame) = frame::read_known(&mut recv, max).await else { break };
            inner.events.send(Event::Frame(peer, frame)).await?;
        }
        anyhow::Ok(())
    };
    let write = async {
        while let Some(frame) = out.recv().await {
            if let Some(frame) = inner.groups.admit(&peer, frame) {
                let bytes = frame::encode(&frame);
                if bytes.len() - 4 > frame::MAX_FRAME as usize {
                    continue;
                }
                let mut rest = bytes.as_slice();
                while !rest.is_empty() {
                    let n = timeout(WRITE, send.write(rest)).await??;
                    rest = &rest[n..];
                }
            }
        }
        anyhow::Ok(())
    };
    let result = tokio::select! {
        r = read => r,
        r = write => r,
    };
    if let Err(e) = result {
        tracing::debug!("peer stream with {} ended: {e:#}", peer.fmt_short());
    }
    conn.close(0u32.into(), b"peer stream ended");
}

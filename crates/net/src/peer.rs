//! A `peer` stream: frames both ways.

use std::sync::Arc;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use lmk_proto::{frame, peer::Frame};
use n0_future::time::{Duration, Instant, timeout};
use tokio::sync::mpsc;
use tokio_util::io::InspectReader;

use crate::{Event, Inner};

/// How long a write to a peer may wait to move on. A peer that reads slowly, or through a relay that passes 1 MiB a
/// second, takes some of a frame much sooner; one that keeps its connection and reads nothing does not.
const WRITE: Duration = Duration::from_secs(120);
/// How often the node is told that bytes keep coming from a peer: well within a request's `TIMEOUT`.
const ARRIVING: Duration = Duration::from_secs(1);

/// Runs the connection's one peer stream; the connection closes with it. The peer's frames are read one at a time, as
/// the node takes them: a peer that sends faster than that waits. As bytes come, the node is told so, every `ARRIVING`
/// at most and when it has room. One that reads nothing of what it is sent for `WRITE` is closed, and what is queued
/// for it goes; a frame larger than its reader takes is left out. A peer that is served no group, and that no join in
/// flight names, is read up to `MAX_ASK` a frame, and one larger closes the connection.
pub(crate) async fn run(inner: Arc<Inner>, conn: Connection, mut send: SendStream, recv: RecvStream, mut out: mpsc::UnboundedReceiver<Frame>) {
    let peer = conn.remote_id();
    let mut told = Instant::now();
    let mut recv = InspectReader::new(recv, |_: &[u8]| {
        if told.elapsed() >= ARRIVING && inner.events.try_send(Event::Arriving(peer)).is_ok() {
            told = Instant::now();
        }
    });
    let read = async {
        loop {
            let Ok(frame) = frame::read_known(&mut recv, || inner.groups.serves(&peer)).await else { break };
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

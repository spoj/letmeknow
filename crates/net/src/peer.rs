//! A `peer` stream: frames both ways.

use std::sync::Arc;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use lmk_proto::{frame, peer::Frame};
use n0_future::task::spawn;
use tokio::sync::mpsc;

use crate::{Event, Inner};

pub(crate) enum Input {
    Frame(Frame),
    Closed,
    Send(Frame),
}

/// Runs the connection's one peer stream; the connection closes with it.
pub(crate) async fn run(
    inner: Arc<Inner>,
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    input: mpsc::UnboundedSender<Input>,
    mut rx: mpsc::UnboundedReceiver<Input>,
    dialed: bool,
) {
    let peer = conn.remote_id();
    inner.events.send(Event::Connected(peer, dialed)).ok();
    spawn(async move {
        while let Ok(frame) = frame::read_known(&mut recv).await {
            if input.send(Input::Frame(frame)).is_err() {
                return;
            }
        }
        input.send(Input::Closed).ok();
    });
    let result = async {
        while let Some(input) = rx.recv().await {
            match input {
                Input::Frame(frame) => {
                    inner.events.send(Event::Frame(peer, frame)).ok();
                }
                Input::Closed => break,
                Input::Send(frame) => {
                    if let Some(frame) = inner.groups.admit(&peer, frame) {
                        frame::write(&mut send, &frame).await?;
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

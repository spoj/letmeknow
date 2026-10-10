//! What our protocols run over: connections between endpoints, named by their keys, on the `letmeknow/2` ALPN, each
//! carrying bidirectional streams. iroh carries them in production, and a simulator in its tests.

use std::{future::Future, pin::Pin, sync::Arc};

use anyhow::Result;
pub use iroh::{EndpointAddr, EndpointId};
use iroh::{Endpoint, endpoint};
use lmk_proto::frame::ALPN;
use tokio::io::{AsyncRead, AsyncWrite};

/// Sendable in the browser too, as the membership client's futures must be.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
pub type SendStream = Box<dyn AsyncWrite + Send + Unpin>;
pub type RecvStream = Box<dyn AsyncRead + Send + Unpin>;
pub type Conn = Arc<dyn Connection>;

pub trait Transport: Send + Sync {
    fn id(&self) -> EndpointId;
    fn connect(&self, addr: EndpointAddr) -> BoxFuture<Result<Conn>>;
}

pub trait Connection: Send + Sync {
    fn remote_id(&self) -> EndpointId;
    fn open_bi(&self) -> BoxFuture<Result<(SendStream, RecvStream)>>;
    fn accept_bi(&self) -> BoxFuture<Result<(SendStream, RecvStream)>>;
    fn close(&self, reason: &[u8]);
    /// Whether it closed, from either side or for want of a path.
    fn closed(&self) -> bool;
    /// Distinct among an endpoint's connections.
    fn stable_id(&self) -> usize;
}

pub struct Iroh(pub Endpoint);

impl Transport for Iroh {
    fn id(&self) -> EndpointId {
        self.0.id()
    }

    fn connect(&self, addr: EndpointAddr) -> BoxFuture<Result<Conn>> {
        let endpoint = self.0.clone();
        Box::pin(async move { Ok(Arc::new(IrohConnection(endpoint.connect(addr, ALPN).await?)) as Conn) })
    }
}

pub struct IrohConnection(pub endpoint::Connection);

impl Connection for IrohConnection {
    fn remote_id(&self) -> EndpointId {
        self.0.remote_id()
    }

    fn open_bi(&self) -> BoxFuture<Result<(SendStream, RecvStream)>> {
        let conn = self.0.clone();
        Box::pin(async move {
            let (send, recv) = conn.open_bi().await?;
            Ok((Box::new(send) as SendStream, Box::new(recv) as RecvStream))
        })
    }

    fn accept_bi(&self) -> BoxFuture<Result<(SendStream, RecvStream)>> {
        let conn = self.0.clone();
        Box::pin(async move {
            let (send, recv) = conn.accept_bi().await?;
            Ok((Box::new(send) as SendStream, Box::new(recv) as RecvStream))
        })
    }

    fn close(&self, reason: &[u8]) {
        self.0.close(0u32.into(), reason);
    }

    fn closed(&self) -> bool {
        self.0.close_reason().is_some()
    }

    fn stable_id(&self) -> usize {
        self.0.stable_id()
    }
}

use std::{collections::BTreeMap, io, sync::{Arc, Mutex, Weak}};

use iroh::EndpointId;
use lmk_proto::peer::Frame;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const ENDPOINT_BYTES: usize = 8 << 20;
pub const TOTAL_BYTES: usize = 32 << 20;
pub const MAX_BODY: usize = (ENDPOINT_BYTES - 65_536) / 4;

#[derive(Debug)]
pub struct Permit {
    peer: OwnedSemaphorePermit,
    total: OwnedSemaphorePermit,
}

impl Permit {
    pub(crate) fn release(&mut self, bytes: usize) {
        drop(self.peer.split(bytes).unwrap());
        drop(self.total.split(bytes).unwrap());
    }
}

pub struct Packet {
    pub frame: Frame,
    pub permit: Permit,
}

pub struct Budget {
    total: Arc<Semaphore>,
    peers: Mutex<BTreeMap<EndpointId, Weak<Semaphore>>>,
}

impl Default for Budget {
    fn default() -> Self {
        Self { total: Arc::new(Semaphore::new(TOTAL_BYTES)), peers: Mutex::default() }
    }
}

impl Budget {
    fn peer(&self, peer: EndpointId) -> Arc<Semaphore> {
        let mut peers = self.peers.lock().unwrap();
        peers.retain(|_, value| value.strong_count() != 0);
        if let Some(value) = peers.get(&peer).and_then(Weak::upgrade) { return value; }
        let value = Arc::new(Semaphore::new(ENDPOINT_BYTES));
        peers.insert(peer, Arc::downgrade(&value));
        value
    }

    pub(crate) async fn acquire(&self, peer: EndpointId, bytes: usize) -> Permit {
        let peer = self.peer(peer).acquire_many_owned(bytes as u32).await.unwrap();
        let total = self.total.clone().acquire_many_owned(bytes as u32).await.unwrap();
        Permit { peer, total }
    }

    pub fn prepare(&self, peer: EndpointId, frame: &Frame) -> Option<Permit> {
        let mut size = Size(0);
        serde_json::to_writer(&mut size, frame).expect("our frames serialize");
        if size.0 > MAX_BODY { return None; }
        let bytes = (size.0 * 4 + 65_536) as u32;
        let peer = self.peer(peer).try_acquire_many_owned(bytes).ok()?;
        let total = self.total.clone().try_acquire_many_owned(bytes).ok()?;
        Some(Permit { peer, total })
    }
}

struct Size(usize);
impl io::Write for Size {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.0 += bytes.len(); Ok(bytes.len()) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lmk_proto::Bytes;

    #[tokio::test]
    async fn ownership_survives_reconnection_and_release() {
        let budget = Budget::default();
        let peer = iroh::SecretKey::generate().public();
        let mut first = budget.acquire(peer, ENDPOINT_BYTES).await;
        let frame = Frame::Live { group: Bytes(vec![1; 16]), items: vec![Bytes(vec![2; 1024])] };
        assert!(budget.prepare(peer, &frame).is_none());
        first.release(ENDPOINT_BYTES / 2);
        let next = budget.prepare(peer, &frame).unwrap();
        drop(first);
        assert!(budget.total.available_permits() < TOTAL_BYTES);
        drop(next);
        assert_eq!(budget.total.available_permits(), TOTAL_BYTES);
    }
}

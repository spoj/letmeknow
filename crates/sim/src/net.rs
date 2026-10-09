//! The simulated network: endpoints named by their keys, connections between them whose streams keep their order and
//! deliver each write after a latency the seed draws, so that writes on different streams reorder; endpoints going
//! offline and crashing, partitions and heals, and connections dropped. A connection whose path is lost stalls, losing
//! what was in flight, and closes after an idle timeout, as QUIC's do.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use anyhow::{Result, bail};
use iroh::{EndpointAddr, EndpointId};
use lmk_transport::{BoxFuture, Conn, Connection, RecvStream, SendStream, Transport};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::time::{Instant, Sleep, sleep, sleep_until};

use crate::Rng;

/// Takes a connection an endpoint accepts.
pub type Accept = Arc<dyn Fn(Conn) + Send + Sync>;
/// Sees every frame written but those that open streams: sender, receiver, whether the stream is a `peer` one, and the
/// frame's JSON.
pub type Inspect = Arc<dyn Fn(EndpointId, EndpointId, bool, &[u8]) + Send + Sync>;

#[derive(Clone)]
pub struct Net(Arc<Mutex<State>>);

struct State {
    rng: Rng,
    endpoints: BTreeMap<EndpointId, Endpoint>,
    conns: BTreeMap<usize, ConnState>,
    pipes: BTreeMap<usize, Pipe>,
    next: usize,
    inspect: Option<Inspect>,
    trace: Sha256,
}

struct Endpoint {
    generation: u64,
    online: bool,
    side: u8,
    /// One way, to or from any other endpoint.
    latency: Duration,
    accept: Option<Accept>,
}

struct ConnState {
    ends: [EndpointId; 2],
    generations: [u64; 2],
    closed: bool,
    /// Its path is lost: it closes after an idle timeout.
    cut: bool,
    /// Streams each end has yet to accept, with when they reach it.
    incoming: [VecDeque<(Instant, usize, usize)>; 2],
    notify: Arc<Notify>,
    pipes: Vec<usize>,
}

/// One direction of a stream.
struct Pipe {
    from: EndpointId,
    to: EndpointId,
    conn: usize,
    queue: VecDeque<(Instant, Vec<u8>)>,
    offset: usize,
    last: Instant,
    fin: Option<Instant>,
    reset: bool,
    reader: Option<Waker>,
    /// Bytes written not yet split into frames, and whether the stream is a `peer` one, once its first frame says.
    unframed: Vec<u8>,
    peer: Option<bool>,
}

impl Net {
    pub fn new(seed: u64) -> Self {
        Net(Arc::new(Mutex::new(State {
            rng: Rng(seed ^ 0x6e65_7477_6f72_6b00),
            endpoints: BTreeMap::new(),
            conns: BTreeMap::new(),
            pipes: BTreeMap::new(),
            next: 0,
            inspect: None,
            trace: Sha256::new(),
        })))
    }

    pub fn inspect(&self, inspect: Inspect) {
        self.0.lock().unwrap().inspect = Some(inspect);
    }

    /// A hash of every write so far: when, between whom, and what.
    pub fn trace(&self) -> [u8; 32] {
        self.0.lock().unwrap().trace.clone().finalize().into()
    }

    /// An endpoint's transport, from now on the one its key answers on; a former one, as before a crash, is dead.
    pub fn bind(&self, id: EndpointId) -> SimTransport {
        let mut st = self.0.lock().unwrap();
        let latency = Duration::from_millis(5 + st.rng.below(100));
        let endpoint = st.endpoints.entry(id).or_insert(Endpoint { generation: 0, online: true, side: 0, latency, accept: None });
        endpoint.generation += 1;
        endpoint.accept = None;
        let generation = endpoint.generation;
        drop(st);
        self.lost();
        SimTransport { net: self.clone(), id, generation }
    }

    /// Where the transport bound last hands the connections peers open.
    pub fn listen(&self, id: EndpointId, accept: Accept) {
        self.0.lock().unwrap().endpoints.get_mut(&id).expect("bound").accept = Some(accept);
    }

    /// Kills the endpoint's transport, as a crash does.
    pub fn kill(&self, id: EndpointId) {
        if let Some(endpoint) = self.0.lock().unwrap().endpoints.get_mut(&id) {
            endpoint.generation += 1;
            endpoint.accept = None;
        }
        self.lost();
    }

    pub fn set_online(&self, id: EndpointId, online: bool) {
        self.0.lock().unwrap().endpoints.get_mut(&id).expect("bound").online = online;
        self.lost();
    }

    /// Puts each endpoint on a side; only endpoints on one side reach each other.
    pub fn partition(&self, sides: &BTreeMap<EndpointId, u8>) {
        for (id, endpoint) in &mut self.0.lock().unwrap().endpoints {
            endpoint.side = sides.get(id).copied().unwrap_or(0);
        }
        self.lost();
    }

    /// Drops a connection between two endpoints, if one is open.
    pub fn drop_connection(&self, a: EndpointId, b: EndpointId) {
        let mut st = self.0.lock().unwrap();
        let id = st.conns.iter().find(|(_, c)| !c.closed && (c.ends == [a, b] || c.ends == [b, a])).map(|(id, _)| *id);
        if let Some(id) = id {
            st.close(id);
        }
    }

    /// Cuts the connections whose ends no longer reach each other, which close after an idle timeout.
    fn lost(&self) {
        let mut st = self.0.lock().unwrap();
        let now = Instant::now();
        let lost: Vec<usize> = st.conns.iter().filter(|(_, c)| !c.closed && !c.cut && !st.alive(c)).map(|(id, _)| *id).collect();
        for id in lost {
            let timeout = Duration::from_millis(5_000 + st.rng.below(25_000));
            let conn = st.conns.get_mut(&id).unwrap();
            conn.cut = true;
            for pipe in conn.pipes.clone() {
                st.pipes.get_mut(&pipe).unwrap().queue.retain(|(at, _)| *at <= now);
            }
            let net = self.clone();
            tokio::spawn(async move {
                sleep(timeout).await;
                net.0.lock().unwrap().close(id);
            });
        }
    }

    /// Whether two endpoints reach each other now.
    pub fn path(&self, a: EndpointId, b: EndpointId) -> bool {
        self.0.lock().unwrap().path(a, b)
    }

    fn reaches(&self, from: EndpointId, generation: u64, to: EndpointId) -> bool {
        let st = self.0.lock().unwrap();
        st.current(from, generation) && st.endpoints.get(&to).is_some_and(|e| e.accept.is_some()) && st.path(from, to)
    }
}

impl State {
    fn current(&self, id: EndpointId, generation: u64) -> bool {
        self.endpoints.get(&id).is_some_and(|e| e.generation == generation)
    }

    fn path(&self, a: EndpointId, b: EndpointId) -> bool {
        let (Some(a), Some(b)) = (self.endpoints.get(&a), self.endpoints.get(&b)) else { return false };
        a.online && b.online && a.side == b.side
    }

    fn alive(&self, conn: &ConnState) -> bool {
        self.current(conn.ends[0], conn.generations[0]) && self.current(conn.ends[1], conn.generations[1]) && self.path(conn.ends[0], conn.ends[1])
    }

    fn latency(&mut self, a: EndpointId, b: EndpointId) -> Duration {
        let base = self.endpoints[&a].latency + self.endpoints[&b].latency;
        // Now and then a loss to recover from.
        let stall = if self.rng.below(50) == 0 { self.rng.below(2_000) } else { 0 };
        base + Duration::from_millis(self.rng.below(20) + stall)
    }

    fn close(&mut self, id: usize) {
        let Some(conn) = self.conns.get_mut(&id) else { return };
        if conn.closed {
            return;
        }
        conn.closed = true;
        conn.notify.notify_waiters();
        for pipe in conn.pipes.clone() {
            let pipe = self.pipes.get_mut(&pipe).unwrap();
            pipe.reset = true;
            if let Some(reader) = pipe.reader.take() {
                reader.wake();
            }
        }
    }

    fn pipe(&mut self, conn: usize, from: EndpointId, to: EndpointId, first: Instant) -> usize {
        let id = self.next;
        self.next += 1;
        let pipe = Pipe { from, to, conn, queue: VecDeque::new(), offset: 0, last: first, fin: None, reset: false, reader: None, unframed: Vec::new(), peer: None };
        self.pipes.insert(id, pipe);
        self.conns.get_mut(&conn).unwrap().pipes.push(id);
        id
    }

    /// Writes to a pipe: lost if its connection's path is, else delivered after a latency, in order. Returns the
    /// frames it completed but one that opens the stream, and whether the stream is a `peer` one.
    fn write(&mut self, id: usize, bytes: &[u8]) -> io::Result<(bool, Vec<Vec<u8>>)> {
        let pipe = &self.pipes[&id];
        let (conn, from, to) = (pipe.conn, pipe.from, pipe.to);
        if pipe.reset || pipe.fin.is_some() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let now = Instant::now();
        self.trace.update([&(id as u64).to_le_bytes()[..], &lmk_proto::clock::now().to_le_bytes(), bytes].concat());
        if self.conns[&conn].cut {
            return Ok((false, Vec::new()));
        }
        let at = (now + self.latency(from, to) + Duration::from_micros(bytes.len() as u64 / 10)).max(self.pipes[&id].last);
        let pipe = self.pipes.get_mut(&id).unwrap();
        pipe.last = at;
        pipe.queue.push_back((at, bytes.to_vec()));
        if let Some(reader) = pipe.reader.take() {
            reader.wake();
        }
        pipe.unframed.extend_from_slice(bytes);
        let mut frames = Vec::new();
        while pipe.unframed.len() >= 4 {
            let len = u32::from_be_bytes(pipe.unframed[..4].try_into().unwrap()) as usize;
            if pipe.unframed.len() < 4 + len {
                break;
            }
            let frame: Vec<u8> = pipe.unframed.drain(..4 + len).skip(4).collect();
            match pipe.peer {
                None if frame.starts_with(br#"{"stream":"#) => pipe.peer = Some(frame == br#"{"stream":"peer"}"#),
                None => {
                    pipe.peer = Some(false);
                    frames.push(frame);
                }
                Some(_) => frames.push(frame),
            }
        }
        Ok((pipe.peer == Some(true), frames))
    }
}

pub struct SimTransport {
    net: Net,
    id: EndpointId,
    generation: u64,
}

impl Transport for SimTransport {
    fn id(&self) -> EndpointId {
        self.id
    }

    fn connect(&self, addr: EndpointAddr) -> BoxFuture<Result<Conn>> {
        let (net, from, generation, to) = (self.net.clone(), self.id, self.generation, addr.id);
        Box::pin(async move {
            let (handshake, fail) = {
                let mut st = net.0.lock().unwrap();
                if !st.endpoints.contains_key(&to) {
                    bail!("no such endpoint");
                }
                (st.latency(from, to) * 2, Duration::from_millis(1_000 + st.rng.below(9_000)))
            };
            if !net.reaches(from, generation, to) {
                sleep(fail).await;
                bail!("{} is unreachable", to.fmt_short());
            }
            sleep(handshake).await;
            let mut st = net.0.lock().unwrap();
            if !(st.current(from, generation) && st.path(from, to)) {
                bail!("{} is unreachable", to.fmt_short());
            }
            let Some(accept) = st.endpoints[&to].accept.clone() else { bail!("{} is unreachable", to.fmt_short()) };
            let id = st.next;
            st.next += 1;
            let generations = [generation, st.endpoints[&to].generation];
            let notify = Arc::new(Notify::new());
            let conn = ConnState { ends: [from, to], generations, closed: false, cut: false, incoming: Default::default(), notify, pipes: Vec::new() };
            st.conns.insert(id, conn);
            drop(st);
            accept(Arc::new(SimConn { net: net.clone(), id, side: 1 }));
            Ok(Arc::new(SimConn { net, id, side: 0 }) as Conn)
        })
    }
}

/// One end of a connection.
struct SimConn {
    net: Net,
    id: usize,
    side: usize,
}

impl Connection for SimConn {
    fn remote_id(&self) -> EndpointId {
        self.net.0.lock().unwrap().conns[&self.id].ends[1 - self.side]
    }

    fn open_bi(&self) -> BoxFuture<Result<(SendStream, RecvStream)>> {
        let (net, id, side) = (self.net.clone(), self.id, self.side);
        Box::pin(async move {
            let mut st = net.0.lock().unwrap();
            let conn = &st.conns[&id];
            if conn.closed {
                bail!("the connection closed");
            }
            let [me, peer] = [conn.ends[side], conn.ends[1 - side]];
            let first = Instant::now() + st.latency(me, peer);
            let out = st.pipe(id, me, peer, first);
            let back = st.pipe(id, peer, me, Instant::now());
            let conn = st.conns.get_mut(&id).unwrap();
            conn.incoming[1 - side].push_back((first, out, back));
            conn.notify.notify_waiters();
            Ok(streams(&net, out, back))
        })
    }

    fn accept_bi(&self) -> BoxFuture<Result<(SendStream, RecvStream)>> {
        let (net, id, side) = (self.net.clone(), self.id, self.side);
        Box::pin(async move {
            loop {
                let (notify, wait) = {
                    let mut st = net.0.lock().unwrap();
                    let conn = st.conns.get_mut(&id).unwrap();
                    if conn.closed {
                        bail!("the connection closed");
                    }
                    let notify = conn.notify.clone();
                    match conn.incoming[side].front() {
                        Some(&(at, theirs, back)) if at <= Instant::now() => {
                            conn.incoming[side].pop_front();
                            return Ok(streams(&net, back, theirs));
                        }
                        Some(&(at, _, _)) => (notify, Some(at)),
                        None => (notify, None),
                    }
                };
                let notified = notify.notified();
                match wait {
                    Some(at) => tokio::select! { biased; _ = notified => {}, _ = sleep_until(at) => {} },
                    None => notified.await,
                }
            }
        })
    }

    fn close(&self, _: &[u8]) {
        self.net.0.lock().unwrap().close(self.id);
    }

    fn closed(&self) -> bool {
        self.net.0.lock().unwrap().conns[&self.id].closed
    }

    fn stable_id(&self) -> usize {
        self.id
    }
}

fn streams(net: &Net, send: usize, recv: usize) -> (SendStream, RecvStream) {
    (Box::new(Writer { net: net.clone(), pipe: send }), Box::new(Reader { net: net.clone(), pipe: recv, sleep: None }))
}

struct Writer {
    net: Net,
    pipe: usize,
}

impl AsyncWrite for Writer {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let (frames, inspect, ends) = {
            let mut st = self.net.0.lock().unwrap();
            let frames = st.write(self.pipe, buf);
            let pipe = &st.pipes[&self.pipe];
            (frames, st.inspect.clone(), (pipe.from, pipe.to))
        };
        let (peer, frames) = frames?;
        if let Some(inspect) = inspect {
            for frame in frames {
                inspect(ends.0, ends.1, peer, &frame);
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.finish();
        Poll::Ready(Ok(()))
    }
}

impl Writer {
    fn finish(&self) {
        let mut st = self.net.0.lock().unwrap();
        let pipe = st.pipes.get_mut(&self.pipe).unwrap();
        if pipe.fin.is_none() {
            pipe.fin = Some(pipe.last.max(Instant::now()));
            if let Some(reader) = pipe.reader.take() {
                reader.wake();
            }
        }
    }
}

/// Dropping a stream finishes it, as QUIC's do.
impl Drop for Writer {
    fn drop(&mut self) {
        self.finish();
    }
}

struct Reader {
    net: Net,
    pipe: usize,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl AsyncRead for Reader {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let now = Instant::now();
        let until = {
            let mut st = self.net.0.lock().unwrap();
            let pipe = st.pipes.get_mut(&self.pipe).unwrap();
            if pipe.reset {
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
            let until = match pipe.queue.front() {
                Some((at, bytes)) if *at <= now => {
                    let n = buf.remaining().min(bytes.len() - pipe.offset);
                    buf.put_slice(&bytes[pipe.offset..pipe.offset + n]);
                    pipe.offset += n;
                    if pipe.offset == bytes.len() {
                        pipe.queue.pop_front();
                        pipe.offset = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                Some((at, _)) => Some(*at),
                None => match pipe.fin {
                    Some(fin) if fin <= now => return Poll::Ready(Ok(())),
                    fin => fin,
                },
            };
            pipe.reader = Some(cx.waker().clone());
            let Some(until) = until else { return Poll::Pending };
            until
        };
        let sleep = self.sleep.get_or_insert_with(|| Box::pin(sleep_until(until)));
        sleep.as_mut().reset(until);
        if sleep.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

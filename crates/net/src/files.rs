//! Files over iroh-blobs: the only module that knows it. Links are plain BLAKE3 over the
//! ciphertext, so replacing iroh-blobs later keeps every link valid.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use bao_tree::{ChunkNum, ChunkRanges};
use iroh::{Endpoint, EndpointId};
use iroh_blobs::{
    BlobsProtocol, Hash,
    api::{Store, TempTag},
    protocol::GetRequest,
    provider::events::{AbortReason, ConnectMode, EventMask, EventSender, ObserveMode, ProviderMessage, RequestMode, ThrottleMode},
    store::{GcConfig, ProtectCb, ProtectOutcome},
};
use lmk_proto::links::FileLink;
use n0_future::{StreamExt, join_all, task::spawn, time::timeout};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, watch},
};

use crate::{
    Groups,
    seal::{Opener, SEALED, Sealer, sealed_len},
};

/// Pieces handed out to holders, in 1 KiB BLAKE3 chunks: 1 MiB, or 16 sealed chunks.
const PIECE: u64 = 1024;
/// How long a download with no holder left waits for another.
const HOLDER_WAIT: Duration = Duration::from_secs(30);

pub(crate) struct Files {
    store: Store,
    endpoint: Endpoint,
    downloads: Arc<Mutex<HashMap<[u8; 32], Download>>>,
    /// Files just added, kept from deletion until the next collection has seen them.
    added: Arc<Mutex<Vec<TempTag>>>,
}

struct Download {
    holders: mpsc::UnboundedSender<EndpointId>,
    done: watch::Receiver<Option<bool>>,
}

impl Files {
    /// Every `collect`, the store deletes the files no group links, unless they are on their way in.
    pub async fn new(
        endpoint: Endpoint,
        dir: Option<std::path::PathBuf>,
        groups: Arc<dyn Groups>,
        collect: Duration,
    ) -> Result<Self> {
        let downloads: Arc<Mutex<HashMap<[u8; 32], Download>>> = Arc::default();
        let added: Arc<Mutex<Vec<TempTag>>> = Arc::default();
        let (downloading, just_added) = (downloads.clone(), added.clone());
        let protect: ProtectCb = Arc::new(move |live: &mut HashSet<Hash>| {
            for group in groups.groups() {
                live.extend(groups.files(&group).iter().map(|file| Hash::from_bytes(file.hash)));
            }
            live.extend(downloading.lock().unwrap().keys().map(|hash| Hash::from_bytes(*hash)));
            live.extend(just_added.lock().unwrap().drain(..).map(|tag| tag.hash()));
            Box::pin(std::future::ready(ProtectOutcome::Continue))
        });
        let gc = GcConfig { interval: collect, add_protected: Some(protect) };
        let store = match dir {
            #[cfg(not(target_family = "wasm"))]
            Some(dir) => {
                let options = iroh_blobs::store::fs::options::Options { gc: Some(gc), ..iroh_blobs::store::fs::options::Options::new(&dir) };
                (*iroh_blobs::store::fs::FsStore::load_with_opts(dir.join("blobs.db"), options).await?).clone()
            }
            #[cfg(target_family = "wasm")]
            Some(_) => bail!("a browser keeps files in memory"),
            None => (*iroh_blobs::store::mem::MemStore::new_with_opts(iroh_blobs::store::mem::Options { gc_config: Some(gc) })).clone(),
        };
        Ok(Files { store, endpoint, downloads, added })
    }

    /// Serves complete files to current members only: checked per connection, per request, and
    /// per 16 KiB sent.
    pub fn protocol(&self, groups: Arc<dyn Groups>) -> BlobsProtocol {
        let mask = EventMask {
            connected: ConnectMode::Intercept,
            get: RequestMode::Intercept,
            get_many: RequestMode::Disabled,
            push: RequestMode::Disabled,
            observe: ObserveMode::Intercept,
            throttle: ThrottleMode::Intercept,
        };
        let (events, mut rx) = EventSender::channel(64, mask);
        spawn(async move {
            let mut peers = HashMap::new();
            let mut requests = HashMap::new();
            while let Some(message) = rx.recv().await {
                match message {
                    ProviderMessage::ClientConnected(msg) => {
                        let peer = msg.endpoint_id.filter(|peer| groups.groups().iter().any(|g| groups.is_member(g, peer)));
                        if let Some(peer) = peer {
                            peers.insert(msg.connection_id, peer);
                        }
                        msg.tx.send(peer.map(|_| ()).ok_or(AbortReason::Permission)).await.ok();
                    }
                    ProviderMessage::ConnectionClosed(msg) => {
                        peers.remove(&msg.connection_id);
                        requests.retain(|&(connection, _), _| connection != msg.connection_id);
                    }
                    ProviderMessage::GetRequestReceived(msg) => {
                        let hash = *msg.request.hash.as_bytes();
                        let found = peers.get(&msg.connection_id).and_then(|peer| {
                            let group = groups.groups().into_iter().find(|g| {
                                groups.is_member(g, peer) && groups.files(g).iter().any(|file| file.hash == hash)
                            })?;
                            Some((*peer, group))
                        });
                        let allowed = found.is_some();
                        if let Some(found) = found {
                            requests.insert((msg.connection_id, msg.request_id), found);
                        }
                        msg.tx.send(allowed.then_some(()).ok_or(AbortReason::Permission)).await.ok();
                    }
                    ProviderMessage::Throttle(msg) => {
                        let allowed = requests
                            .get(&(msg.connection_id, msg.request_id))
                            .is_some_and(|(peer, group)| groups.is_member(group, peer));
                        msg.tx.send(allowed.then_some(()).ok_or(AbortReason::Permission)).await.ok();
                    }
                    ProviderMessage::ObserveRequestReceived(msg) => {
                        msg.tx.send(Err(AbortReason::Permission)).await.ok();
                    }
                    _ => {}
                }
            }
        });
        BlobsProtocol::new(&self.store, Some(events))
    }

    /// Seals plaintext under a new key and holds the ciphertext.
    pub async fn add(&self, mut plain: impl AsyncRead + Unpin + Send + Sync + 'static) -> Result<FileLink> {
        let mut key = [0; 32];
        getrandom::fill(&mut key)?;
        let (sealed, mut rx) = mpsc::channel(4);
        let size = Arc::new(AtomicU64::new(0));
        let read = size.clone();
        spawn(async move {
            let mut sealer = Sealer::new(&key);
            let mut buf = vec![0; SEALED];
            loop {
                let item = match plain.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        read.fetch_add(n as u64, Ordering::Relaxed);
                        Ok(sealer.push(&buf[..n]).into())
                    }
                    Err(e) => Err(e),
                };
                let failed = item.is_err();
                if sealed.send(item).await.is_err() || failed {
                    return;
                }
            }
            sealed.send(Ok(sealer.finish().into())).await.ok();
        });
        let stream = n0_future::stream::poll_fn(move |cx| rx.poll_recv(cx));
        let tag = self.store.add_stream(stream).await.temp_tag().await?;
        let hash = *tag.hash().as_bytes();
        self.added.lock().unwrap().push(tag);
        Ok(FileLink { hash, size: size.load(Ordering::Relaxed), key })
    }

    pub async fn complete(&self, hash: &[u8; 32]) -> Result<bool> {
        Ok(self.bitfield(hash).await?.is_complete())
    }

    /// Verified ciphertext bytes held.
    pub async fn held(&self, hash: &[u8; 32]) -> Result<u64> {
        Ok(self.store.remote().local(Hash::from_bytes(*hash)).await?.local_bytes())
    }

    /// A held file's ciphertext, whole.
    pub async fn ciphertext(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        Ok(self.store.get_bytes(Hash::from_bytes(*hash)).await?.to_vec())
    }

    /// Holds a file's ciphertext, as `ciphertext` gave it.
    pub async fn hold(&self, ciphertext: Vec<u8>) -> Result<()> {
        let tag = self.store.add_bytes(ciphertext).temp_tag().await?;
        self.added.lock().unwrap().push(tag);
        Ok(())
    }

    pub async fn read(&self, link: &FileLink, out: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
        ensure!(self.complete(&link.hash).await?, "{} is not held", link.link());
        let mut reader = self.store.reader(Hash::from_bytes(link.hash));
        let mut opener = Opener::new(&link.key, sealed_len(link.size));
        let (mut buf, mut plain) = (vec![0; SEALED], Vec::new());
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            opener.push(&buf[..n], &mut plain)?;
            out.write_all(&plain).await?;
            plain.clear();
        }
        opener.finish(&mut plain)?;
        out.write_all(&plain).await?;
        Ok(())
    }

    /// Adds a holder to the file's download, starting one if none runs; `done` is called once it ends.
    pub fn offer(self: &Arc<Self>, link: &FileLink, holder: EndpointId, done: impl FnOnce(bool) + Send + 'static) {
        let mut downloads = self.downloads.lock().unwrap();
        if let Some(download) = downloads.get(&link.hash)
            && download.holders.send(holder).is_ok()
        {
            return;
        }
        let (holders, rx) = mpsc::unbounded_channel();
        holders.send(holder).unwrap();
        let (finished, done_rx) = watch::channel(None);
        downloads.insert(link.hash, Download { holders, done: done_rx });
        let (files, hash, sealed) = (self.clone(), link.hash, sealed_len(link.size));
        spawn(async move {
            let result = files.download(hash, sealed, rx).await;
            if let Err(e) = &result {
                tracing::debug!("download of {} stopped: {e:#}", Hash::from_bytes(hash));
            }
            files.downloads.lock().unwrap().remove(&hash);
            finished.send_replace(Some(result.is_ok()));
            done(result.is_ok());
        });
    }

    /// Waits for the running download of a file, if any, and says whether the file is held.
    pub async fn wait(&self, hash: &[u8; 32]) -> Result<bool> {
        let done = self.downloads.lock().unwrap().get(hash).map(|d| d.done.clone());
        if let Some(mut done) = done {
            done.wait_for(Option::is_some).await?;
        }
        self.complete(hash).await
    }

    /// Fetches missing pieces from every holder at once; a holder that fails is dropped, and its
    /// piece goes to the others, resuming from what was verified.
    async fn download(&self, hash: [u8; 32], sealed: u64, mut new: mpsc::UnboundedReceiver<EndpointId>) -> Result<()> {
        let mut holders: Vec<EndpointId> = Vec::new();
        loop {
            while let Ok(holder) = new.try_recv() {
                if !holders.contains(&holder) {
                    holders.push(holder);
                }
            }
            let pieces = self.missing(&hash, sealed).await?;
            if pieces.is_empty() {
                return Ok(());
            }
            if holders.is_empty() {
                match timeout(HOLDER_WAIT, new.recv()).await {
                    Ok(Some(holder)) => holders.push(holder),
                    _ => bail!("no holder left"),
                }
                continue;
            }
            let queue = Mutex::new(pieces);
            let results = join_all(holders.iter().map(|&holder| self.fetch(holder, &hash, &queue))).await;
            holders = holders
                .into_iter()
                .zip(results)
                .filter_map(|(holder, result)| match result {
                    Ok(()) => Some(holder),
                    Err(e) => {
                        tracing::debug!("holder {} failed: {e:#}", holder.fmt_short());
                        None
                    }
                })
                .collect();
        }
    }

    async fn fetch(&self, holder: EndpointId, hash: &[u8; 32], queue: &Mutex<Vec<ChunkRanges>>) -> Result<()> {
        let conn = self.endpoint.connect(holder, iroh_blobs::ALPN).await?;
        loop {
            let Some(piece) = queue.lock().unwrap().pop() else {
                return Ok(());
            };
            let request = GetRequest::blob_ranges(Hash::from_bytes(*hash), piece.clone());
            if let Err(e) = self.store.remote().execute_get(conn.clone(), request).complete().await {
                queue.lock().unwrap().push(piece);
                return Err(e.into());
            }
        }
    }

    async fn missing(&self, hash: &[u8; 32], sealed: u64) -> Result<Vec<ChunkRanges>> {
        let have = self.bitfield(hash).await?.ranges;
        let chunks = sealed.div_ceil(1024);
        let mut pieces: Vec<ChunkRanges> = (0..chunks)
            .step_by(PIECE as usize)
            .map(|start| &ChunkRanges::from(ChunkNum(start)..ChunkNum((start + PIECE).min(chunks))) - &have)
            .filter(|piece| !piece.is_empty())
            .collect();
        pieces.reverse();
        Ok(pieces)
    }

    async fn bitfield(&self, hash: &[u8; 32]) -> Result<iroh_blobs::api::proto::Bitfield> {
        self.store.observe(Hash::from_bytes(*hash)).stream().await?.next().await.context("the store answers observe")
    }
}

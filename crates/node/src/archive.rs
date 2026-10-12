use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use lmk_proto::{Bytes, head::Head};
use n0_future::boxed::BoxFuture;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];
pub type Batch = [u8; 16];
pub type Pins = Vec<(Vec<u8>, Option<Hash>)>;
const WIDTH: usize = 32;

pub trait Archive: Send + Sync {
    fn read(&self, hash: Hash) -> BoxFuture<Result<Vec<u8>>>;
    fn write(&self, batch: Batch, raw: bool, hash: Hash, children: Vec<Hash>, bytes: Vec<u8>) -> BoxFuture<Result<()>>;
    fn publish(&self, batch: Batch, pins: Pins) -> BoxFuture<Result<()>>;
    fn discard(&self, batch: Batch) -> BoxFuture<Result<()>>;
    fn recover(&self, pins: Pins) -> BoxFuture<Result<()>>;
    fn close(&self) -> BoxFuture<Result<()>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Root {
    pub hash: Hash,
    pub end: u64,
    pub height: u8,
    pub bytes: u64,
}

#[derive(Clone)]
pub(crate) struct Cold(pub Arc<dyn Archive>);

pub(crate) struct RawPage {
    pub after: u64,
    pub before: Hash,
    pub entries: Vec<Bytes>,
    pub head: Option<Head>,
}

pub(crate) struct Digests {
    pub after: u64,
    pub before: Hash,
    pub values: Vec<Hash>,
}

impl Cold {
    async fn block(&self, hash: Hash) -> Result<Vec<u8>> {
        let bytes = self.0.read(hash).await?;
        ensure!(Hash::from(Sha256::digest(&bytes)) == hash, "corrupt immutable archive block");
        Ok(bytes)
    }

    async fn branch(&self, batch: Batch, raw: bool, height: u8, children: Vec<Root>) -> Result<Root> {
        ensure!(children.len() <= WIDTH && height <= 4, "archive index capacity exhausted");
        let mut bytes = vec![0, height];
        for child in &children {
            bytes.extend_from_slice(&child.end.to_be_bytes());
            bytes.extend_from_slice(&child.hash);
            bytes.extend_from_slice(&child.bytes.to_be_bytes());
        }
        let hash = Sha256::digest(&bytes).into();
        let root = Root { hash, end: children.last().unwrap().end, height, bytes: bytes.len() as u64 + children.iter().map(|r| r.bytes).sum::<u64>() };
        self.0.write(batch, raw, hash, children.iter().map(|r| r.hash).collect(), bytes).await?;
        Ok(root)
    }

    async fn children(&self, root: Root) -> Result<Vec<Root>> {
        let bytes = self.block(root.hash).await?;
        ensure!(bytes.len() >= 50 && bytes[0] == 0 && bytes[1] == root.height && (bytes.len() - 2) % 48 == 0 && bytes.len() <= 2 + 48 * WIDTH, "invalid archive index");
        let children: Vec<_> = bytes[2..].chunks_exact(48).map(|b| Root {
            end: u64::from_be_bytes(b[..8].try_into().unwrap()), hash: b[8..40].try_into().unwrap(), height: root.height - 1,
            bytes: u64::from_be_bytes(b[40..48].try_into().unwrap()),
        }).collect();
        ensure!(children.last().unwrap().end == root.end && children.windows(2).all(|rs| rs[0].end < rs[1].end), "invalid archive index range");
        Ok(children)
    }

    async fn append(&self, batch: Batch, raw: bool, root: Option<Root>, leaf: Root) -> Result<Root> {
        let Some(mut root) = root else { return Ok(leaf) };
        ensure!(leaf.end > root.end, "archive append is not contiguous");
        let mut prefixes = Vec::new();
        while root.height > 0 {
            let mut children = self.children(root).await?;
            root = children.pop().unwrap();
            prefixes.push(children);
        }
        let mut added = vec![root, leaf];
        for children in prefixes.into_iter().rev() {
            let height = added[0].height + 1;
            let mut children: Vec<Root> = children.into_iter().chain(added).collect();
            let rest = if children.len() > WIDTH { Some(children.split_off(WIDTH)) } else { None };
            added = vec![self.branch(batch, raw, height, children).await?];
            if let Some(rest) = rest { added.push(self.branch(batch, raw, height, rest).await?); }
        }
        if added.len() == 1 { return Ok(added[0]); }
        self.branch(batch, raw, added[0].height + 1, added).await
    }

    async fn leaf(&self, mut root: Root, position: u64) -> Result<Vec<u8>> {
        ensure!(position > 0 && position <= root.end, "position outside archived prefix");
        while root.height > 0 {
            root = self.children(root).await?.into_iter().find(|r| position <= r.end).context("missing archive range")?;
        }
        self.block(root.hash).await
    }

    pub(crate) async fn append_digests(&self, batch: Batch, root: Option<Root>, after: u64, before: Hash, values: &[Hash]) -> Result<Root> {
        ensure!(!values.is_empty() && values.len() <= 1024 && root.map_or(0, |r| r.end) == after, "invalid digest append");
        let mut bytes = Vec::with_capacity(41 + values.len() * 32);
        bytes.push(1);
        bytes.extend_from_slice(&after.to_be_bytes());
        bytes.extend_from_slice(&before);
        for value in values { bytes.extend_from_slice(value); }
        let hash = Sha256::digest(&bytes).into();
        let leaf = Root { hash, end: after + values.len() as u64, height: 0, bytes: bytes.len() as u64 };
        self.0.write(batch, false, hash, Vec::new(), bytes).await?;
        self.append(batch, false, root, leaf).await
    }

    pub(crate) async fn append_raw(&self, batch: Batch, root: Option<Root>, page: &RawPage) -> Result<Root> {
        ensure!(!page.entries.is_empty() && page.entries.len() <= 1024 && root.map_or(0, |r| r.end) == page.after, "invalid raw append");
        let mut bytes = vec![2];
        bytes.extend_from_slice(&page.after.to_be_bytes());
        bytes.extend_from_slice(&page.before);
        let head = serde_json::to_vec(&page.head)?;
        bytes.extend_from_slice(&(head.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&head);
        for entry in &page.entries {
            bytes.extend_from_slice(&(entry.0.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&entry.0);
        }
        let hash = Sha256::digest(&bytes).into();
        let leaf = Root { hash, end: page.after + page.entries.len() as u64, height: 0, bytes: bytes.len() as u64 };
        self.0.write(batch, true, hash, Vec::new(), bytes).await?;
        self.append(batch, true, root, leaf).await
    }

    async fn leaf_digests(&self, root: Root, position: u64) -> Result<Digests> {
        let bytes = self.leaf(root, position).await?;
        ensure!(bytes.len() >= 73 && bytes[0] == 1 && (bytes.len() - 41) % 32 == 0, "invalid digest leaf");
        let after = u64::from_be_bytes(bytes[1..9].try_into()?);
        let values: Vec<Hash> = bytes[41..].chunks_exact(32).map(|v| v.try_into().unwrap()).collect();
        ensure!(after < position && position <= after + values.len() as u64 && values.len() <= 1024, "invalid digest leaf range");
        Ok(Digests { after, before: bytes[9..41].try_into()?, values })
    }

    pub(crate) async fn digests(&self, root: Root, after: u64, count: usize) -> Result<Digests> {
        ensure!(count > 0 && count <= 1024 && after + count as u64 <= root.end, "invalid digest range");
        let mut values = Vec::with_capacity(count);
        let mut before = None;
        while values.len() < count {
            let position = after + values.len() as u64 + 1;
            let page = self.leaf_digests(root, position).await?;
            let skip = (position - page.after - 1) as usize;
            before.get_or_insert_with(|| page.values[..skip].iter().fold(page.before, |h, d| lmk_proto::head::next_digest(&h, d)));
            values.extend(page.values.into_iter().skip(skip).take(count - values.len()));
        }
        Ok(Digests { after, before: before.unwrap(), values })
    }

    pub(crate) async fn hash_at(&self, root: Root, position: u64) -> Result<Hash> {
        let page = self.leaf_digests(root, position).await?;
        Ok(page.values[..(position - page.after) as usize].iter().fold(page.before, |h, d| lmk_proto::head::next_digest(&h, d)))
    }

    pub(crate) async fn raw(&self, root: Root, position: u64) -> Result<RawPage> {
        let bytes = self.leaf(root, position).await?;
        ensure!(bytes.len() >= 43 && bytes[0] == 2, "invalid raw leaf");
        let after = u64::from_be_bytes(bytes[1..9].try_into()?);
        let size = u16::from_be_bytes(bytes[41..43].try_into()?) as usize;
        let head = serde_json::from_slice(bytes.get(43..43 + size).context("truncated archive head")?)?;
        let mut rest = &bytes[43 + size..];
        let mut entries = Vec::new();
        while !rest.is_empty() {
            let size = u32::from_be_bytes(rest.get(..4).context("truncated entry size")?.try_into()?) as usize;
            let entry = rest.get(4..4 + size).context("truncated archive entry")?;
            entries.push(Bytes(entry.to_vec()));
            ensure!(entries.len() <= 1024, "raw leaf row limit");
            rest = &rest[4 + size..];
        }
        ensure!(after < position && position <= after + entries.len() as u64, "invalid raw leaf range");
        Ok(RawPage { after, before: bytes[9..41].try_into()?, entries, head })
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use native::Native;

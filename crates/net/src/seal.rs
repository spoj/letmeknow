//! STREAM sealing as in age: ChaCha20-Poly1305 over 65,520-byte plaintext chunks, so each sealed
//! chunk is 64 KiB; nonce = 11-byte big-endian chunk counter ‖ last-chunk flag.

use anyhow::{Result, anyhow, ensure};
use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit, Nonce, Tag};

pub const CHUNK: usize = 65_520;
const TAG: usize = 16;
pub const SEALED: usize = CHUNK + TAG;

pub fn sealed_len(plain_len: u64) -> u64 {
    plain_len + TAG as u64 * plain_len.div_ceil(CHUNK as u64).max(1)
}

fn nonce(i: u64, last: bool) -> Nonce {
    let mut n = [0; 12];
    n[3..11].copy_from_slice(&i.to_be_bytes());
    n[11] = last as u8;
    n.into()
}

/// Seals plaintext fed in pieces of any size; `push` returns sealed bytes as whole chunks fill.
pub struct Sealer {
    cipher: ChaCha20Poly1305,
    next: u64,
    buf: Vec<u8>,
}

impl Sealer {
    pub fn new(key: &[u8; 32]) -> Self {
        Sealer { cipher: ChaCha20Poly1305::new(&(*key).into()), next: 0, buf: Vec::with_capacity(SEALED) }
    }

    /// Holds back a full chunk until more data shows it is not the last.
    pub fn push(&mut self, mut data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        while !data.is_empty() {
            if self.buf.len() == CHUNK {
                out.extend(self.seal(false));
            }
            let take = (CHUNK - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        out
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.seal(true)
    }

    fn seal(&mut self, last: bool) -> Vec<u8> {
        let mut chunk = std::mem::replace(&mut self.buf, Vec::with_capacity(SEALED));
        let tag = self.cipher.encrypt_inout_detached(&nonce(self.next, last), &[], chunk.as_mut_slice().into()).unwrap();
        chunk.extend_from_slice(&tag);
        self.next += 1;
        chunk
    }
}

/// Opens a sealed stream fed in order, in pieces of any size. The sealed size comes from the link.
pub struct Opener {
    cipher: ChaCha20Poly1305,
    chunks: u64,
    next: u64,
    buf: Vec<u8>,
}

impl Opener {
    pub fn new(key: &[u8; 32], sealed_size: u64) -> Self {
        Opener {
            cipher: ChaCha20Poly1305::new(&(*key).into()),
            chunks: sealed_size.div_ceil(SEALED as u64),
            next: 0,
            buf: Vec::with_capacity(SEALED),
        }
    }

    pub fn push(&mut self, mut data: &[u8], out: &mut Vec<u8>) -> Result<()> {
        while !data.is_empty() {
            let take = (SEALED - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == SEALED {
                self.open(out)?;
            }
        }
        Ok(())
    }

    pub fn finish(mut self, out: &mut Vec<u8>) -> Result<()> {
        if self.next < self.chunks {
            self.open(out)?;
        }
        ensure!(self.next == self.chunks, "truncated: {} of {} chunks", self.next, self.chunks);
        Ok(())
    }

    fn open(&mut self, out: &mut Vec<u8>) -> Result<()> {
        let i = self.next;
        ensure!(i < self.chunks && self.buf.len() >= TAG, "data past the last chunk");
        let len = self.buf.len();
        let (text, tag) = self.buf.split_at_mut(len - TAG);
        let tag = Tag::try_from(&*tag).unwrap();
        self.cipher
            .decrypt_inout_detached(&nonce(i, i + 1 == self.chunks), &[], text.into(), &tag)
            .map_err(|_| anyhow!("chunk {i}: authentication failed"))?;
        out.extend_from_slice(text);
        self.next += 1;
        self.buf.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
        let mut sealer = Sealer::new(key);
        let mut out = sealer.push(plain);
        out.extend(sealer.finish());
        out
    }

    fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
        let mut plain = Vec::new();
        let mut opener = Opener::new(key, sealed.len() as u64);
        for piece in sealed.chunks(1000) {
            opener.push(piece, &mut plain)?;
        }
        opener.finish(&mut plain)?;
        Ok(plain)
    }

    #[test]
    fn round_trip_and_truncation() {
        let key = [7; 32];
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 5] {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let sealed = seal(&key, &plain);
            assert_eq!(sealed.len() as u64, sealed_len(len as u64));
            assert_eq!(open(&key, &sealed).unwrap(), plain);
            let mut sealer = Sealer::new(&key);
            let mut pieces: Vec<u8> = plain.chunks(777).flat_map(|p| sealer.push(p)).collect();
            pieces.extend(sealer.finish());
            assert_eq!(pieces, sealed);
            if sealed.len() > SEALED {
                assert!(open(&key, &sealed[..SEALED]).is_err(), "a cut stream lacks the last-chunk flag");
            }
        }
        assert_eq!(SEALED, 64 * 1024);
    }
}

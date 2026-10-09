//! An identity's key log: making entries, sealing them, and replaying the log; and the certificates its key signs for
//! sessions, checked against the log's newest key.

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signer, SigningKey};
use lmk_proto::Bytes;
use lmk_proto::group::{Credential, Service};
use lmk_proto::identity::{Body, CERTIFICATE_CONTEXT, Certified, ENTRY_CONTEXT, Envelope, id, key};
use sha2::{Digest, Sha256};

use crate::device::verify;

/// How long a certificate lasts, in milliseconds.
pub const DAY: u64 = 24 * 60 * 60 * 1000;

/// An identity's public key from its private one, a 32-byte Ed25519 seed.
pub fn public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

fn sign(seed: &[u8; 32], context: &[u8], body: Vec<u8>) -> Envelope {
    let sig = SigningKey::from_bytes(seed).sign(&[context, &body].concat()).to_bytes().to_vec();
    Envelope { body: Bytes(body), sig: Bytes(sig) }
}

/// A key log as replayed from its log.
#[derive(Clone, Debug)]
pub struct KeyLog {
    pub id: [u8; 32],
    pub name: String,
    pub membership: Service,
    /// Every key it took, oldest first.
    pub keys: Vec<[u8; 32]>,
    /// SHA-256 of the latest valid entry's body.
    latest: [u8; 32],
}

/// A new identity whose first key is `seed`'s: its id, and its first entry, sealed.
pub fn create(seed: &[u8; 32], name: &str, membership: Service) -> ([u8; 32], Vec<u8>) {
    let body = Body { prev: None, key: public(seed).into(), name: Some(name.into()), membership: Some(membership) };
    let body = serde_json::to_vec(&body).unwrap();
    let id = id(&body);
    (id, seal(&id, &sign(seed, ENTRY_CONTEXT, body)))
}

/// An entry as the service keeps it: a random nonce, then the sealed JSON envelope.
pub fn seal(id: &[u8], entry: &Envelope) -> Vec<u8> {
    let nonce = crate::random::<12>();
    let sealed = ChaCha20Poly1305::new(&Key::from(key(id)))
        .encrypt(&Nonce::from(nonce), serde_json::to_vec(entry).unwrap().as_slice())
        .unwrap();
    [nonce.as_slice(), &sealed].concat()
}

pub fn open(id: &[u8], sealed: &[u8]) -> Result<Envelope> {
    let (nonce, sealed) = sealed.split_at_checked(12).context("too short")?;
    let nonce: [u8; 12] = nonce.try_into()?;
    let plain = ChaCha20Poly1305::new(&Key::from(key(id)))
        .decrypt(&Nonce::from(nonce), sealed)
        .ok()
        .context("not sealed under this identity's key")?;
    Ok(serde_json::from_slice(&plain)?)
}

/// An entry's body, if `by` signed it.
fn signed_body(entry: &Envelope, by: &[u8]) -> Option<(Body, [u8; 32])> {
    let body: Body = serde_json::from_slice(&entry.body.0).ok()?;
    let key = body.key.0.as_slice().try_into().ok()?;
    verify(by, ENTRY_CONTEXT, &entry.body.0, &entry.sig.0).then_some((body, key))
}

impl KeyLog {
    /// Replays a key log, in order: the first valid entry whose body hashes to the id, then the first valid entry per
    /// `prev`.
    pub fn replay<'a>(id: &[u8; 32], entries: impl IntoIterator<Item = &'a [u8]>) -> Result<Self> {
        let mut entries = entries.into_iter();
        let mut log = entries.by_ref().find_map(|entry| Self::created(id, entry)).context("the log has no valid first entry")?;
        for entry in entries {
            log.apply(entry);
        }
        Ok(log)
    }

    fn created(id: &[u8; 32], sealed: &[u8]) -> Option<Self> {
        let entry = open(id, sealed).ok()?;
        let first: Body = serde_json::from_slice(&entry.body.0).ok()?;
        let (body, key) = signed_body(&entry, &first.key.0)?;
        if body.prev.is_some() || Sha256::digest(&entry.body.0)[..] != id[..] {
            return None;
        }
        Some(KeyLog { id: *id, name: body.name?, membership: body.membership?, keys: vec![key], latest: *id })
    }

    /// Applies the next entry of the log if the current key signed it and it extends the log; returns whether it did.
    pub fn apply(&mut self, sealed: &[u8]) -> bool {
        let Ok(entry) = open(&self.id, sealed) else {
            return false;
        };
        let Some((body, key)) = signed_body(&entry, self.current()) else {
            return false;
        };
        if body.prev.as_ref().map(|prev| prev.0.as_slice()) != Some(self.latest.as_slice()) {
            return false;
        }
        self.keys.push(key);
        self.latest = Sha256::digest(&entry.body.0).into();
        true
    }

    /// The identity's newest key.
    pub fn current(&self) -> &[u8; 32] {
        self.keys.last().expect("a log starts with a key")
    }

    /// The sealed entry by which the current key, `seed`'s, hands over to `next`.
    pub fn rotate(&self, seed: &[u8; 32], next: &[u8; 32]) -> Vec<u8> {
        let body = Body { prev: Some(self.latest.into()), key: (*next).into(), name: None, membership: None };
        seal(&self.id, &sign(seed, ENTRY_CONTEXT, serde_json::to_vec(&body).unwrap()))
    }
}

/// A certificate by the identity key `seed`.
pub fn certify(seed: &[u8; 32], certified: &Certified) -> Envelope {
    sign(seed, CERTIFICATE_CONTEXT, serde_json::to_vec(certified).unwrap())
}

/// What a certificate says, unchecked.
pub fn certified(certificate: &Envelope) -> Option<Certified> {
    serde_json::from_slice(&certificate.body.0).ok()
}

/// Checks a member's certificate against its identity's key log: it must name the member's key, name and identity, be
/// signed by the identity's newest key, and not have run out. Returns why not, if not.
pub fn check(certificate: Option<&Envelope>, credential: &Credential, log: &KeyLog, now: u64) -> Result<Certified, &'static str> {
    let certificate = certificate.ok_or("it has shown no certificate of its identity")?;
    let certified = certified(certificate).ok_or("its certificate does not parse")?;
    let identity = credential.identity.as_ref().ok_or("it speaks as no identity")?;
    if certified.identity.0 != log.id || identity.id.0 != log.id || certified.key != credential.key || certified.name != credential.name {
        return Err("its certificate is for another session");
    }
    if !verify(log.current(), CERTIFICATE_CONTEXT, &certificate.body.0, &certificate.sig.0) {
        return Err("its certificate is not by its identity's current key");
    }
    if certified.expires <= now {
        return Err("its certificate ran out");
    }
    Ok(certified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lmk_proto::group::IdentityRef;

    fn service() -> Service {
        Service::Folder("/tmp/lmk".into())
    }

    #[test]
    fn create_and_rotate() {
        let (first, second, third) = (crate::random(), crate::random(), crate::random());
        let (id, entry) = create(&first, "Matthew", service());
        let mut log = vec![b"junk".to_vec(), entry];
        let keys = KeyLog::replay(&id, log.iter().map(Vec::as_slice)).unwrap();
        assert_eq!((keys.name.as_str(), keys.current()), ("Matthew", &public(&first)));
        assert!(open(&[0; 32], &log[1]).is_err());
        log.push(keys.rotate(&first, &public(&second)));
        // A fork: the first entry that extends the log wins.
        log.push(keys.rotate(&first, &public(&third)));
        let keys = KeyLog::replay(&id, log.iter().map(Vec::as_slice)).unwrap();
        assert_eq!(keys.keys, [public(&first), public(&second)]);
        // An old key can sign nothing more.
        log.push(keys.rotate(&first, &public(&third)));
        let mut keys = KeyLog::replay(&id, log.iter().map(Vec::as_slice)).unwrap();
        assert_eq!(keys.current(), &public(&second));
        assert!(keys.apply(&keys.rotate(&second, &public(&third))));
        assert_eq!(keys.current(), &public(&third));
    }

    #[test]
    fn a_first_entry_must_hash_to_the_id() {
        let seed = crate::random();
        let (_, first) = create(&seed, "Matthew", service());
        let (other, _) = create(&seed, "Matthew", Service::Folder("/elsewhere".into()));
        assert!(KeyLog::replay(&other, [first.as_slice()]).is_err());
    }

    #[test]
    fn certificate_checks() {
        let (seed, next) = (crate::random(), crate::random());
        let (id, first) = create(&seed, "Matthew", service());
        let mut log = KeyLog::replay(&id, [first.as_slice()]).unwrap();
        let identity = IdentityRef { id: id.into(), membership: service() };
        let credential = Credential { name: "Builder".into(), key: Bytes(vec![1; 32]), identity: Some(identity) };
        let certified =
            Certified { identity: id.into(), key: credential.key.clone(), name: "Builder".into(), device: "laptop".into(), added_by: None, expires: 100 };
        let certificate = certify(&seed, &certified);
        assert_eq!(check(Some(&certificate), &credential, &log, 99), Ok(certified.clone()));
        assert!(check(Some(&certificate), &credential, &log, 100).is_err());
        assert!(check(None, &credential, &log, 99).is_err());
        let other = Credential { key: Bytes(vec![2; 32]), ..credential.clone() };
        assert!(check(Some(&certificate), &other, &log, 99).is_err());
        assert!(log.apply(&log.rotate(&seed, &public(&next))));
        assert!(check(Some(&certificate), &credential, &log, 99).is_err());
        assert!(check(Some(&certify(&next, &certified)), &credential, &log, 99).is_ok());
    }
}

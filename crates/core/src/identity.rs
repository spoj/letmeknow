//! An identity's key log: making entries, sealing them, and replaying the log into its current key and device list;
//! and checking a member's certificate against that list.

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signer, SigningKey};
use lmk_proto::Bytes;
use lmk_proto::group::{Credential, Service};
use lmk_proto::identity::{Body, ENTRY_CONTEXT, Envelope, Listed, certified, id, key};
use sha2::{Digest, Sha256};

use crate::device::verify;

/// A day, in milliseconds.
pub const DAY: u64 = 24 * 60 * 60 * 1000;

/// An Ed25519 public key from its private one, a 32-byte seed.
pub fn public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// A signature by `seed` over `bytes`.
pub fn sign(seed: &[u8; 32], bytes: &[u8]) -> Vec<u8> {
    SigningKey::from_bytes(seed).sign(bytes).to_bytes().to_vec()
}

fn envelope(seed: &[u8; 32], body: &Body) -> Envelope {
    let body = serde_json::to_vec(body).unwrap();
    Envelope { sig: Bytes(sign(seed, &[ENTRY_CONTEXT, &body].concat())), body: Bytes(body) }
}

/// A key log as replayed from its log.
#[derive(Clone, Debug)]
pub struct KeyLog {
    pub id: [u8; 32],
    pub name: String,
    pub membership: Service,
    /// Every key it took, oldest first.
    pub keys: Vec<[u8; 32]>,
    /// The current list of devices.
    pub devices: Vec<Listed>,
    /// The keys of the devices its first entry listed.
    first: Vec<Bytes>,
    /// The keys of the devices an earlier entry listed and the current one does not.
    dropped: Vec<Bytes>,
    /// SHA-256 of the latest valid entry's body.
    latest: [u8; 32],
}

/// How a member's certificate stands against its identity's key log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Its device is listed, by this name; `added`: not among the identity's first devices.
    Verified { device: String, added: bool },
    /// Its device was never listed, or the certificate does not check out: the key log may not show it yet.
    Unverified,
    /// An earlier entry listed its device and the current one does not.
    Dropped,
}

/// A new identity whose first key is `seed`'s and whose first device is `device`: its id, and its first entry, sealed.
pub fn create(seed: &[u8; 32], name: &str, membership: Service, device: Listed) -> ([u8; 32], Vec<u8>) {
    let body = Body { prev: None, key: public(seed).into(), devices: vec![device], name: Some(name.into()), membership: Some(membership) };
    let entry = envelope(seed, &body);
    let id = id(&entry.body.0);
    (id, seal(&id, &entry))
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
        let first = body.devices.iter().map(|device| device.key.clone()).collect();
        Some(KeyLog { id: *id, name: body.name?, membership: body.membership?, keys: vec![key], devices: body.devices, first, dropped: Vec::new(), latest: *id })
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
        let gone = self.devices.iter().filter(|held| !body.devices.iter().any(|device| device.key == held.key)).map(|held| held.key.clone());
        self.dropped.extend(gone.collect::<Vec<_>>());
        self.dropped.retain(|dropped| !body.devices.iter().any(|device| device.key == *dropped));
        self.devices = body.devices;
        self.keys.push(key);
        self.latest = Sha256::digest(&entry.body.0).into();
        true
    }

    /// The identity's newest key.
    pub fn current(&self) -> &[u8; 32] {
        self.keys.last().expect("a log starts with a key")
    }

    /// Whether an earlier entry listed the device with this key and the current one does not.
    pub fn dropped(&self, device: &[u8]) -> bool {
        self.dropped.iter().any(|dropped| dropped.0 == device)
    }

    /// The sealed entry by which the current key, `seed`'s, hands over to `next`, which may be the same, listing
    /// `devices`.
    pub fn next(&self, seed: &[u8; 32], next: &[u8; 32], devices: Vec<Listed>) -> Vec<u8> {
        let body = Body { prev: Some(self.latest.into()), key: (*next).into(), devices, name: None, membership: None };
        seal(&self.id, &envelope(seed, &body))
    }

    /// How a member's certificate stands: its device's key must have signed its session key and the identity's id.
    pub fn verify(&self, credential: &Credential) -> Verdict {
        let Some(certificate) = &credential.certificate else { return Verdict::Unverified };
        let signed = verify(&certificate.device.0, b"", &certified(&credential.key.0, &self.id), &certificate.sig.0);
        if certificate.identity.id.0 != self.id || !signed {
            return Verdict::Unverified;
        }
        match self.devices.iter().find(|device| device.key == certificate.device) {
            Some(device) => Verdict::Verified { device: device.name.clone(), added: !self.first.contains(&device.key) },
            None if self.dropped(&certificate.device.0) => Verdict::Dropped,
            None => Verdict::Unverified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lmk_proto::group::{Certificate, IdentityRef};

    fn service() -> Service {
        Service::Folder("/tmp/lmk".into())
    }

    fn listed(seed: &[u8; 32], name: &str) -> Listed {
        Listed { key: public(seed).into(), name: name.into() }
    }

    fn replay(id: &[u8; 32], log: &[Vec<u8>]) -> KeyLog {
        KeyLog::replay(id, log.iter().map(Vec::as_slice)).unwrap()
    }

    #[test]
    fn create_and_replace_the_key() {
        let (first, second, third) = (crate::random(), crate::random(), crate::random());
        let laptop = listed(&crate::random(), "laptop");
        let (id, entry) = create(&first, "Matthew", service(), laptop.clone());
        let mut log = vec![b"junk".to_vec(), entry];
        let keys = replay(&id, &log);
        assert_eq!((keys.name.as_str(), keys.current(), &keys.devices[..]), ("Matthew", &public(&first), &[laptop.clone()][..]));
        assert!(open(&[0; 32], &log[1]).is_err());
        log.push(keys.next(&first, &public(&second), vec![laptop.clone()]));
        // A fork: the first entry that extends the log wins.
        log.push(keys.next(&first, &public(&third), vec![laptop.clone()]));
        let keys = replay(&id, &log);
        assert_eq!(keys.keys, [public(&first), public(&second)]);
        // An old key can sign nothing more.
        log.push(keys.next(&first, &public(&third), vec![laptop.clone()]));
        let mut keys = replay(&id, &log);
        assert_eq!(keys.current(), &public(&second));
        assert!(keys.apply(&keys.next(&second, &public(&third), vec![laptop])));
        assert_eq!(keys.current(), &public(&third));
    }

    #[test]
    fn a_first_entry_must_hash_to_the_id() {
        let seed = crate::random();
        let laptop = listed(&crate::random(), "laptop");
        let (_, first) = create(&seed, "Matthew", service(), laptop.clone());
        let (other, _) = create(&seed, "Matthew", Service::Folder("/elsewhere".into()), laptop);
        assert!(KeyLog::replay(&other, [first.as_slice()]).is_err());
    }

    #[test]
    fn replay_drops_a_device_an_earlier_entry_listed_and_the_current_one_does_not() {
        let (key, next) = (crate::random(), crate::random());
        let (laptop, tablet, phone) = (listed(&crate::random(), "laptop"), listed(&crate::random(), "tablet"), listed(&crate::random(), "phone"));
        let (id, first) = create(&key, "Matthew", service(), laptop.clone());
        let mut log = vec![first];
        let keys = replay(&id, &log);
        log.push(keys.next(&key, &public(&key), vec![laptop.clone(), tablet.clone()]));
        let keys = replay(&id, &log);
        assert_eq!(keys.devices, [laptop.clone(), tablet.clone()]);
        assert!(!keys.dropped(&tablet.key.0) && !keys.dropped(&phone.key.0));
        log.push(keys.next(&key, &public(&next), vec![laptop.clone()]));
        let keys = replay(&id, &log);
        assert_eq!(keys.devices, vec![laptop.clone()]);
        assert!(keys.dropped(&tablet.key.0), "listed before, not now");
        assert!(!keys.dropped(&phone.key.0) && !keys.dropped(&laptop.key.0), "never listed, or listed now");
        // A rename restates the list: nothing is dropped.
        let renamed = Listed { name: "desk".into(), ..laptop.clone() };
        log.push(keys.next(&next, &public(&next), vec![renamed.clone(), phone.clone()]));
        let keys = replay(&id, &log);
        assert_eq!(keys.devices, [renamed, phone]);
        assert!(keys.dropped(&tablet.key.0) && !keys.dropped(&laptop.key.0));
    }

    #[test]
    fn a_certificate_is_verified_unverified_or_dropped() {
        let key = crate::random();
        let (laptop, tablet, phone): ([u8; 32], [u8; 32], [u8; 32]) = (crate::random(), crate::random(), crate::random());
        let (id, first) = create(&key, "Matthew", service(), listed(&laptop, "laptop"));
        let mut log = replay(&id, &[first]);
        let identity = IdentityRef { id: id.into(), membership: service() };
        let session = Bytes(vec![1; 32]);
        let of = |device: &[u8; 32]| Credential {
            name: "Builder".into(),
            key: session.clone(),
            certificate: Some(Certificate { identity: identity.clone(), device: public(device).into(), sig: Bytes(sign(device, &certified(&session.0, &id))) }.into()),
        };
        assert_eq!(log.verify(&of(&laptop)), Verdict::Verified { device: "laptop".into(), added: false });
        assert_eq!(log.verify(&of(&tablet)), Verdict::Unverified, "never listed");
        assert!(log.apply(&log.next(&key, &public(&key), vec![listed(&laptop, "laptop"), listed(&tablet, "tablet")])));
        assert_eq!(log.verify(&of(&tablet)), Verdict::Verified { device: "tablet".into(), added: true });
        assert!(log.apply(&log.next(&key, &public(&crate::random()), vec![listed(&laptop, "laptop")])));
        assert_eq!(log.verify(&of(&tablet)), Verdict::Dropped);
        assert_eq!(log.verify(&of(&phone)), Verdict::Unverified);
        let forged = Credential { key: Bytes(vec![2; 32]), ..of(&laptop) };
        assert_eq!(log.verify(&forged), Verdict::Unverified, "a signature over another session key");
        let none = Credential { certificate: None, ..of(&laptop) };
        assert_eq!(log.verify(&none), Verdict::Unverified);
    }
}

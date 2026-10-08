//! An identity's device list: making entries, sealing them, and replaying the log; and checking credentials against it.

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use lmk_proto::Bytes;
use lmk_proto::group::{Credential, Service};
use lmk_proto::identity::{Body, ENTRY_CONTEXT, Envelope, Op, id, key};
use sha2::{Digest, Sha256};

use crate::device::{Device, signed_by_device, verify};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub key: Bytes,
    pub name: String,
    /// The device that added it.
    pub by: Bytes,
}

/// A device list as replayed from its log.
#[derive(Clone, Debug)]
pub struct DeviceList {
    pub id: [u8; 32],
    pub name: String,
    pub membership: Service,
    pub devices: Vec<Listed>,
    removed: Vec<Bytes>,
    /// SHA-256 of the latest valid entry's body.
    latest: [u8; 32],
}

/// A new identity: its id, and its first entry, sealed.
pub fn create(device: &Device, name: &str, membership: Service) -> ([u8; 32], Vec<u8>) {
    let body = Body {
        prev: None,
        op: Op::Create,
        device: device.public().into(),
        device_name: device.name.clone(),
        by: device.public().into(),
        name: Some(name.into()),
        membership: Some(membership),
    };
    let body = serde_json::to_vec(&body).unwrap();
    let id = id(&body);
    (id, seal(&id, &envelope(device, body)))
}

fn envelope(by: &Device, body: Vec<u8>) -> Envelope {
    Envelope { sig: Bytes(by.sign(ENTRY_CONTEXT, &body)), body: Bytes(body) }
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

fn signed_body(entry: &Envelope) -> Option<Body> {
    let body: Body = serde_json::from_slice(&entry.body.0).ok()?;
    verify(&body.by.0, ENTRY_CONTEXT, &entry.body.0, &entry.sig.0).then_some(body)
}

impl DeviceList {
    /// Replays a device list's log, in order: the first valid `create`, then the first valid entry per `prev`.
    pub fn replay<'a>(id: &[u8; 32], entries: impl IntoIterator<Item = &'a [u8]>) -> Result<Self> {
        let mut entries = entries.into_iter();
        let mut list =
            entries.by_ref().find_map(|entry| Self::created(id, entry)).context("the log has no valid create entry")?;
        for entry in entries {
            list.apply(entry);
        }
        Ok(list)
    }

    fn created(id: &[u8; 32], sealed: &[u8]) -> Option<Self> {
        let entry = open(id, sealed).ok()?;
        let body = signed_body(&entry)?;
        let valid = body.op == Op::Create
            && body.prev.is_none()
            && body.by == body.device
            && Sha256::digest(&entry.body.0)[..] == id[..];
        if !valid {
            return None;
        }
        Some(DeviceList {
            id: *id,
            name: body.name?,
            membership: body.membership?,
            devices: vec![Listed { key: body.device.clone(), name: body.device_name, by: body.by }],
            removed: Vec::new(),
            latest: *id,
        })
    }

    /// Applies the next entry of the log if it validly extends the list; returns whether it did.
    pub fn apply(&mut self, sealed: &[u8]) -> bool {
        let Ok(entry) = open(&self.id, sealed) else {
            return false;
        };
        let Some(body) = signed_body(&entry) else {
            return false;
        };
        if body.prev.as_ref().map(|prev| prev.0.as_slice()) != Some(self.latest.as_slice()) || !self.has(&body.by.0) {
            return false;
        }
        match body.op {
            Op::Add if !self.has(&body.device.0) && !self.removed.contains(&body.device) => {
                self.devices.push(Listed { key: body.device, name: body.device_name, by: body.by })
            }
            Op::Remove if self.has(&body.device.0) => {
                self.devices.retain(|listed| listed.key != body.device);
                self.removed.push(body.device);
            }
            _ => return false,
        }
        self.latest = Sha256::digest(&entry.body.0).into();
        true
    }

    /// Whether the device is on the list at its latest entry.
    pub fn has(&self, device: &[u8]) -> bool {
        self.devices.iter().any(|listed| listed.key.0 == device)
    }

    /// Whether the device was on the list and was removed.
    pub fn removed(&self, device: &[u8]) -> bool {
        self.removed.iter().any(|removed| removed.0 == device)
    }

    /// The sealed entry by which `by` adds a device.
    pub fn add(&self, by: &Device, device: &[u8], device_name: &str) -> Vec<u8> {
        self.entry(by, Op::Add, device, device_name)
    }

    pub fn remove(&self, by: &Device, device: &[u8]) -> Vec<u8> {
        let name = self.devices.iter().find(|listed| listed.key.0 == device).map_or("", |listed| listed.name.as_str());
        self.entry(by, Op::Remove, device, name)
    }

    fn entry(&self, by: &Device, op: Op, device: &[u8], device_name: &str) -> Vec<u8> {
        let body = Body {
            prev: Some(self.latest.into()),
            op,
            device: device.into(),
            device_name: device_name.into(),
            by: by.public().into(),
            name: None,
            membership: None,
        };
        seal(&self.id, &envelope(by, serde_json::to_vec(&body).unwrap()))
    }
}

/// How a member's credential checks out. It marks the member; it never decides a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Its device signed its session key, and is on the device list of the identity it names.
    Verified,
    /// Its device signed its session key; it names no identity.
    NoIdentity,
    /// It names an identity whose list (as given) does not hold its device.
    NotListed,
    BadSignature,
}

/// Checks a credential against the device list of the identity it names, if the caller has it.
pub fn check(credential: &Credential, session_key: &[u8], list: Option<&DeviceList>) -> Verdict {
    if !signed_by_device(credential, session_key) {
        return Verdict::BadSignature;
    }
    let Some(identity) = &credential.identity else {
        return Verdict::NoIdentity;
    };
    match list {
        Some(list) if list.id[..] == identity.id.0[..] && list.has(&credential.device.0) => Verdict::Verified,
        _ => Verdict::NotListed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Service {
        Service::Folder("/tmp/lmk".into())
    }

    #[test]
    fn create_and_add() {
        let laptop = Device::new("laptop");
        let phone = Device::new("phone");
        let (id, first) = create(&laptop, "Matthew", service());
        let mut log = vec![first];
        let list = DeviceList::replay(&id, log.iter().map(Vec::as_slice)).unwrap();
        assert_eq!(list.name, "Matthew");
        assert!(list.has(&laptop.public()) && !list.has(&phone.public()));
        log.push(list.add(&laptop, &phone.public(), "phone"));
        let list = DeviceList::replay(&id, log.iter().map(Vec::as_slice)).unwrap();
        assert!(list.has(&phone.public()));
        assert_eq!(list.devices[1].by.0, laptop.public());
        let sealed = &log[1];
        assert!(!sealed.windows(5).any(|w| w == b"phone"));
        assert!(open(&[0; 32], sealed).is_err());
    }

    #[test]
    fn replay_with_a_fork_and_a_removed_device() {
        let laptop = Device::new("laptop");
        let phone = Device::new("phone");
        let tablet = Device::new("tablet");
        let stranger = Device::new("stranger");
        let (id, first) = create(&laptop, "Matthew", service());
        let mut log = vec![b"junk".to_vec(), first];
        let list = DeviceList::replay(&id, log.iter().map(Vec::as_slice)).unwrap();
        log.push(list.add(&laptop, &phone.public(), "phone"));
        // A fork: two entries extend the same entry; the first in log order wins.
        log.push(list.add(&laptop, &tablet.public(), "tablet"));
        let list = DeviceList::replay(&id, log.iter().map(Vec::as_slice)).unwrap();
        assert!(list.has(&phone.public()) && !list.has(&tablet.public()));
        // A device that is not on the list cannot sign.
        log.push(list.add(&stranger, &stranger.public(), "stranger"));
        // The phone removes the laptop; the laptop can then sign nothing, and is never added back.
        log.push(list.remove(&phone, &laptop.public()));
        let list = DeviceList::replay(&id, log.iter().map(Vec::as_slice)).unwrap();
        assert!(!list.has(&stranger.public()) && !list.has(&laptop.public()) && list.has(&phone.public()));
        assert!(list.removed(&laptop.public()) && !list.removed(&stranger.public()));
        log.push(list.add(&laptop, &tablet.public(), "tablet"));
        log.push(list.add(&phone, &laptop.public(), "laptop"));
        let mut replayed = DeviceList::replay(&id, log.iter().map(Vec::as_slice)).unwrap();
        assert_eq!(replayed.devices.len(), 1);
        // The phone can still extend it.
        assert!(replayed.apply(&replayed.add(&phone, &tablet.public(), "tablet")));
        assert!(replayed.has(&tablet.public()));
    }

    #[test]
    fn a_create_must_hash_to_the_id() {
        let laptop = Device::new("laptop");
        let (_, first) = create(&laptop, "Matthew", service());
        let (other, _) = create(&laptop, "Matthew", Service::Folder("/elsewhere".into()));
        assert!(DeviceList::replay(&other, [first.as_slice()]).is_err());
    }

    #[test]
    fn credential_checks() {
        let laptop = Device::new("laptop");
        let (id, first) = create(&laptop, "Matthew", service());
        let list = DeviceList::replay(&id, [first.as_slice()]).unwrap();
        let identity = lmk_proto::group::IdentityRef { id: id.into(), membership: service() };
        let credential = laptop.credential("Builder", b"session", Some(identity.clone()));
        assert_eq!(check(&credential, b"session", Some(&list)), Verdict::Verified);
        assert_eq!(check(&credential, b"session", None), Verdict::NotListed);
        assert_eq!(check(&credential, b"other", Some(&list)), Verdict::BadSignature);
        let phone = Device::new("phone");
        let claimed = phone.credential("Builder", b"session", Some(identity));
        assert_eq!(check(&claimed, b"session", Some(&list)), Verdict::NotListed);
        assert_eq!(check(&phone.credential("x", b"session", None), b"session", Some(&list)), Verdict::NoIdentity);
    }
}

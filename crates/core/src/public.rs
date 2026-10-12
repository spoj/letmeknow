//! A public log: making entries, sealing them, and replaying the log into its writers and name; and checking a member's
//! certificate against an identity's writers, its devices.

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use lmk_proto::Bytes;
use lmk_proto::group::{Credential, Service};
use lmk_proto::public::{Body, ENTRY_CONTEXT, Envelope, Listed, certified, id, key};
use sha2::{Digest, Sha256};

use crate::device::{public, sign, verify};

fn envelope(seed: &[u8; 32], body: &Body) -> Envelope {
    let body = serde_json::to_vec(body).unwrap();
    Envelope { sig: Bytes(sign(seed, &[ENTRY_CONTEXT, &body].concat())), by: Bytes(public(seed).to_vec()), body: Bytes(body) }
}

/// A public log as replayed from its log.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PublicLog {
    pub id: [u8; 32],
    pub name: String,
    pub membership: Service,
    /// The latest entry's writers.
    pub writers: Vec<Listed>,
    /// When the latest entry was appended, by its writer's clock, in milliseconds.
    pub at: u64,
    /// The keys of the writers an earlier entry listed and the latest does not.
    dropped: Vec<Bytes>,
    /// SHA-256 of the latest entry's body.
    latest: [u8; 32],
}

/// How a member's certificate stands against its identity's public log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Its device is a writer, by this name.
    Verified { device: String },
    /// Its device was never a writer, or the certificate does not check out: the log may not show it yet.
    Unverified,
    /// An earlier entry listed its device and the latest does not, or the log is closed.
    Dropped,
}

/// A new public log whose first writer is `writer`, `seed`'s: its id, and its first entry, sealed.
pub fn create(seed: &[u8; 32], name: &str, membership: Service, writer: Listed, at: u64) -> ([u8; 32], Vec<u8>) {
    let body = Body { prev: None, writers: vec![writer], name: name.into(), at, membership: Some(membership) };
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
        .context("not sealed under this log's key")?;
    Ok(serde_json::from_slice(&plain)?)
}

/// An entry's body, if one of `writers` signed it.
fn signed_body(entry: &Envelope, writers: &[Listed]) -> Option<Body> {
    let signed = writers.iter().any(|writer| writer.key == entry.by) && verify(&entry.by.0, ENTRY_CONTEXT, &entry.body.0, &entry.sig.0);
    signed.then(|| serde_json::from_slice(&entry.body.0).ok())?
}

impl PublicLog {
    /// Replays a public log, in order: the first valid entry whose body hashes to the id, then the first valid entry per
    /// `prev`.
    pub fn replay<'a>(id: &[u8; 32], entries: impl IntoIterator<Item = &'a [u8]>) -> Result<Self> {
        let mut entries = entries.into_iter();
        let mut log = entries.by_ref().find_map(|entry| Self::created(id, entry)).context("the log has no valid first entry")?;
        for entry in entries {
            log.apply(entry);
        }
        Ok(log)
    }

    /// The log its first entry starts, which hashes to the id and is signed by a writer it lists.
    pub fn created(id: &[u8; 32], sealed: &[u8]) -> Option<Self> {
        let entry = open(id, sealed).ok()?;
        let first: Body = serde_json::from_slice(&entry.body.0).ok()?;
        let body = signed_body(&entry, &first.writers)?;
        if body.prev.is_some() || Sha256::digest(&entry.body.0)[..] != id[..] {
            return None;
        }
        let membership = body.membership?;
        Some(PublicLog { id: *id, name: body.name, membership, writers: body.writers, at: body.at, dropped: Vec::new(), latest: *id })
    }

    /// Applies the next entry of the log if a writer of the latest signed it and it extends the log; returns whether it
    /// did.
    pub fn apply(&mut self, sealed: &[u8]) -> bool {
        let Ok(entry) = open(&self.id, sealed) else {
            return false;
        };
        let Some(body) = signed_body(&entry, &self.writers) else {
            return false;
        };
        if body.prev.as_ref().map(|prev| prev.0.as_slice()) != Some(self.latest.as_slice()) {
            return false;
        }
        let gone: Vec<Bytes> = self.writers.iter().filter(|held| !body.writers.iter().any(|w| w.key == held.key)).map(|held| held.key.clone()).collect();
        self.dropped.extend(gone);
        self.dropped.retain(|dropped| !body.writers.iter().any(|w| w.key == *dropped));
        (self.writers, self.name, self.at) = (body.writers, body.name, body.at);
        self.latest = Sha256::digest(&entry.body.0).into();
        true
    }

    /// Whether the closing entry, which lists no writers, ended the log.
    pub fn closed(&self) -> bool {
        self.writers.is_empty()
    }

    /// The sealed entry after the latest, by `seed`'s writer, listing `writers` and `name`, appended at `at`.
    pub fn next(&self, seed: &[u8; 32], writers: Vec<Listed>, name: &str, at: u64) -> Vec<u8> {
        let body = Body { prev: Some(self.latest.into()), writers, name: name.into(), at, membership: None };
        seal(&self.id, &envelope(seed, &body))
    }

    /// How a member's certificate stands: its device's key must have signed its session key and the identity's id.
    pub fn verify(&self, credential: &Credential) -> Verdict {
        let Some(certificate) = &credential.certificate else { return Verdict::Unverified };
        let signed = verify(&certificate.device.0, b"", &certified(&credential.key.0, &self.id), &certificate.sig.0);
        if certificate.identity.id.0 != self.id || !signed {
            return Verdict::Unverified;
        }
        match self.writers.iter().find(|device| device.key == certificate.device) {
            Some(device) => Verdict::Verified { device: device.name.clone() },
            None if self.closed() || self.dropped.contains(&certificate.device) => Verdict::Dropped,
            None => Verdict::Unverified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lmk_proto::group::{Certificate, IdentityRef};

    fn service() -> Service {
        crate::group::tests::service("https://lmk.example")
    }

    fn listed(seed: &[u8; 32], name: &str) -> Listed {
        Listed { key: public(seed).into(), name: name.into() }
    }

    fn replay(id: &[u8; 32], log: &[Vec<u8>]) -> PublicLog {
        PublicLog::replay(id, log.iter().map(Vec::as_slice)).unwrap()
    }

    #[test]
    fn an_entry_counts_only_if_a_writer_of_the_one_before_signed_it() {
        let (laptop, tablet, stranger) = (crate::random(), crate::random(), crate::random());
        let (id, first) = create(&laptop, "Matthew", service(), listed(&laptop, "laptop"), 1);
        let mut log = vec![b"junk".to_vec(), first];
        let latest = replay(&id, &log);
        assert_eq!((latest.name.as_str(), &latest.writers[..], latest.at), ("Matthew", &[listed(&laptop, "laptop")][..], 1));
        assert!(open(&[0; 32], &log[1]).is_err());
        // Neither the tablet, not listed yet, nor a stranger writes.
        log.push(latest.next(&tablet, vec![listed(&tablet, "tablet")], "Matthew", 2));
        log.push(latest.next(&stranger, vec![listed(&stranger, "stranger")], "Mallory", 2));
        assert_eq!(replay(&id, &log).writers, [listed(&laptop, "laptop")]);
        // The laptop lists the tablet; of two entries after the same one, the first counts.
        log.push(latest.next(&laptop, vec![listed(&laptop, "laptop"), listed(&tablet, "tablet")], "Matthew", 3));
        log.push(latest.next(&laptop, vec![listed(&laptop, "laptop")], "Fork", 3));
        let latest = replay(&id, &log);
        assert_eq!(latest.writers, [listed(&laptop, "laptop"), listed(&tablet, "tablet")]);
        // The tablet, now a writer, renames the identity and drops the laptop, which then writes no more.
        log.push(latest.next(&tablet, vec![listed(&tablet, "tablet")], "Matt", 4));
        let mut latest = replay(&id, &log);
        assert_eq!((latest.name.as_str(), &latest.writers[..], latest.at), ("Matt", &[listed(&tablet, "tablet")][..], 4));
        assert!(!latest.apply(&latest.next(&laptop, vec![listed(&laptop, "laptop")], "Matt", 5)));
    }

    #[test]
    fn after_the_closing_entry_no_entry_counts() {
        let laptop = crate::random();
        let (id, first) = create(&laptop, "Matthew", service(), listed(&laptop, "laptop"), 1);
        let mut log = replay(&id, &[first]);
        assert!(log.apply(&log.next(&laptop, Vec::new(), "Matthew", 2)));
        assert!(log.closed());
        assert!(!log.apply(&log.next(&laptop, vec![listed(&laptop, "laptop")], "Matthew", 3)));
    }

    #[test]
    fn a_first_entry_hashes_to_the_id_and_is_signed_by_a_writer_it_lists() {
        let (seed, other) = (crate::random(), crate::random());
        let (_, first) = create(&seed, "Matthew", service(), listed(&seed, "laptop"), 1);
        let (elsewhere, _) = create(&seed, "Matthew", crate::group::tests::service("https://elsewhere.example"), listed(&seed, "laptop"), 1);
        assert!(PublicLog::replay(&elsewhere, [first.as_slice()]).is_err());
        let (id, unlisted) = create(&other, "Matthew", service(), listed(&seed, "laptop"), 1);
        assert!(PublicLog::replay(&id, [unlisted.as_slice()]).is_err(), "signed by a key it does not list");
    }

    #[test]
    fn a_certificate_is_verified_unverified_or_dropped() {
        let (laptop, tablet, phone): ([u8; 32], [u8; 32], [u8; 32]) = (crate::random(), crate::random(), crate::random());
        let (id, first) = create(&laptop, "Matthew", service(), listed(&laptop, "laptop"), 1);
        let mut log = replay(&id, &[first]);
        let identity = IdentityRef { id: id.into(), membership: service() };
        let session = Bytes(vec![1; 32]);
        let of = |device: &[u8; 32]| Credential {
            name: "builder".into(),
            key: session.clone(),
            certificate: Some(Certificate { identity: identity.clone(), device: public(device).into(), sig: Bytes(sign(device, &certified(&session.0, &id))) }.into()),
        };
        assert_eq!(log.verify(&of(&laptop)), Verdict::Verified { device: "laptop".into() });
        assert_eq!(log.verify(&of(&tablet)), Verdict::Unverified, "never listed");
        assert!(log.apply(&log.next(&laptop, vec![listed(&laptop, "laptop"), listed(&tablet, "tablet")], "Matthew", 2)));
        assert_eq!(log.verify(&of(&tablet)), Verdict::Verified { device: "tablet".into() });
        assert!(log.apply(&log.next(&laptop, vec![listed(&laptop, "desk")], "Matthew", 3)));
        assert_eq!((log.verify(&of(&tablet)), log.verify(&of(&laptop))), (Verdict::Dropped, Verdict::Verified { device: "desk".into() }));
        assert_eq!(log.verify(&of(&phone)), Verdict::Unverified);
        let forged = Credential { key: Bytes(vec![2; 32]), ..of(&laptop) };
        assert_eq!(log.verify(&forged), Verdict::Unverified, "a signature over another session key");
        let none = Credential { certificate: None, ..of(&laptop) };
        assert_eq!(log.verify(&none), Verdict::Unverified);
        assert!(log.apply(&log.next(&laptop, Vec::new(), "Matthew", 4)));
        assert_eq!((log.verify(&of(&laptop)), log.verify(&of(&phone))), (Verdict::Dropped, Verdict::Dropped), "closed: every device");
    }
}

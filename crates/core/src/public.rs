//! Keys-only public directories and authorization of device-signed private session claims.

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::VerifyingKey;
use lmk_proto::Bytes;
use lmk_proto::group::{Credential, Service};
use lmk_proto::public::{Body, ENTRY_CONTEXT, Envelope, certified, id, key};
use sha2::{Digest, Sha256};

use crate::device::{public, sign, verify};

fn envelope(seed: &[u8; 32], body: &Body) -> Envelope {
    let body = serde_json::to_vec(body).unwrap();
    Envelope { sig: Bytes(sign(seed, &[ENTRY_CONTEXT, &body].concat())), by: Bytes(public(seed).to_vec()), body: Bytes(body) }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicLog {
    pub id: [u8; 32],
    pub membership: Service,
    pub writers: Vec<Bytes>,
    /// Every key the log ever dropped: none returns.
    dropped: Vec<Bytes>,
    latest: [u8; 32],
}

/// Authorization in the authenticated directory view held here, not proof of its freshness or a person's identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Authorized,
    Unverified,
    Dropped,
}

pub fn create(seed: &[u8; 32], membership: Service) -> ([u8; 32], Vec<u8>) {
    let body = Body { prev: None, writers: vec![public(seed).into()], membership: Some(membership) };
    let entry = envelope(seed, &body);
    let id = id(&entry.body.0);
    (id, seal(&id, &entry))
}

/// A random nonce followed by the sealed JSON envelope. Every identity-ID holder can open it.
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

fn signed_body(entry: &Envelope, writers: &[Bytes]) -> Option<Body> {
    if !writers.contains(&entry.by) || !verify(&entry.by.0, ENTRY_CONTEXT, &entry.body.0, &entry.sig.0) {
        return None;
    }
    let body: Body = serde_json::from_slice(&entry.body.0).ok()?;
    for writer in &body.writers {
        let key = VerifyingKey::from_bytes(writer.0.as_slice().try_into().ok()?).ok()?;
        if key.is_weak() {
            return None;
        }
    }
    Some(body)
}

/// Checks the signed claims only. Whether this device is a writer is a separate directory check.
pub fn verify_certificate(credential: &Credential) -> bool {
    let Some(c) = &credential.certificate else { return false };
    let (Ok(session), Ok(identity), Ok(device)) = (
        credential.key.0.as_slice().try_into(), c.identity.id.0.as_slice().try_into(), c.device.0.as_slice().try_into(),
    ) else { return false };
    verify(&c.device.0, b"", &certified(session, identity, device, &c.name, &c.device_name), &c.sig.0)
}

impl PublicLog {
    /// The first valid genesis and then the first valid successor per predecessor, in service order.
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
        let body = signed_body(&entry, &first.writers)?;
        if body.prev.is_some() || Sha256::digest(&entry.body.0)[..] != id[..] {
            return None;
        }
        Some(PublicLog { id: *id, membership: body.membership?, writers: body.writers, dropped: Vec::new(), latest: *id })
    }

    pub fn apply(&mut self, sealed: &[u8]) -> bool {
        let Ok(entry) = open(&self.id, sealed) else { return false };
        let Some(body) = signed_body(&entry, &self.writers) else { return false };
        let linked = body.prev.as_ref().map(|prev| prev.0.as_slice()) == Some(self.latest.as_slice());
        if !linked || body.membership.is_some() || body.writers.iter().any(|writer| self.dropped.contains(writer)) {
            return false;
        }
        self.dropped.extend(self.writers.iter().filter(|held| !body.writers.contains(held)).cloned());
        self.writers = body.writers;
        self.latest = Sha256::digest(&entry.body.0).into();
        true
    }

    pub fn closed(&self) -> bool {
        self.writers.is_empty()
    }

    pub fn is_dropped(&self, key: &Bytes) -> bool {
        self.dropped.contains(key)
    }

    pub fn next(&self, seed: &[u8; 32], mut writers: Vec<Bytes>) -> Vec<u8> {
        writers.sort();
        writers.dedup();
        let body = Body { prev: Some(self.latest.into()), writers, membership: None };
        seal(&self.id, &envelope(seed, &body))
    }

    pub fn verify(&self, credential: &Credential) -> Verdict {
        let Some(certificate) = &credential.certificate else { return Verdict::Unverified };
        if certificate.identity.id.0 != self.id || !verify_certificate(credential) {
            return Verdict::Unverified;
        }
        if self.writers.contains(&certificate.device) {
            Verdict::Authorized
        } else if self.closed() || self.is_dropped(&certificate.device) {
            Verdict::Dropped
        } else {
            Verdict::Unverified
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lmk_proto::group::{Certificate, IdentityRef};

    fn service() -> Service {
        crate::group::tests::service("lmk.example")
    }

    fn replay(id: &[u8; 32], log: &[Vec<u8>]) -> PublicLog {
        PublicLog::replay(id, log.iter().map(Vec::as_slice)).unwrap()
    }

    #[test]
    fn writer_succession_authority_and_permanent_closure() {
        let (a, b, stranger) = (crate::random(), crate::random(), crate::random());
        let (id, first) = create(&a, service());
        let mut log = replay(&id, &[b"junk".to_vec(), first.clone()]);
        let keys: Vec<Bytes> = vec![public(&a).into(), public(&b).into()];
        assert_eq!(log.writers, keys[..1]);
        assert!(open(&[0; 32], &first).is_err());
        assert!(!log.apply(&log.next(&b, keys.clone())));
        assert!(!log.apply(&log.next(&stranger, keys.clone())));
        let branch = log.next(&a, keys[..1].to_vec());
        assert!(log.apply(&log.next(&a, vec![keys[1].clone(), keys[0].clone(), keys[1].clone()])));
        assert!(!log.apply(&branch));
        let mut ordered = keys.clone();
        ordered.sort();
        assert_eq!(log.writers, ordered);
        let body = Body { prev: Some(log.latest.into()), writers: keys.clone(), membership: Some(service()) };
        assert!(!log.apply(&seal(&id, &envelope(&a, &body))), "a continuation cannot supply a service");
        for key in [Bytes(vec![1]), Bytes(vec![0; 32]), Bytes([vec![1], vec![0; 31]].concat())] {
            let bad = Body { writers: vec![key], membership: None, ..body.clone() };
            assert!(!log.apply(&seal(&id, &envelope(&a, &bad))), "malformed/weak writer");
        }
        assert!(log.apply(&log.next(&b, keys[1..].to_vec())));
        assert!(!log.apply(&log.next(&a, keys.clone())), "dropped writer");
        assert!(!log.apply(&log.next(&b, keys.clone())), "a dropped writer never returns");
        assert!(log.apply(&log.next(&b, vec![])));
        assert!(log.closed());
        assert!(!log.apply(&log.next(&b, keys)));
    }

    #[test]
    fn genesis_is_bound_to_its_bytes_service_writer_and_v2_domain() {
        let seed = crate::random();
        let (id, first) = create(&seed, service());
        let (elsewhere, _) = create(&seed, crate::group::tests::service("elsewhere.example"));
        assert!(PublicLog::replay(&elsewhere, [first.as_slice()]).is_err());
        let mut entry = open(&id, &first).unwrap();
        entry.sig = Bytes(sign(&seed, &[b"letmeknow public log v1\0", entry.body.0.as_slice()].concat()));
        assert!(PublicLog::replay(&id, [seal(&id, &entry).as_slice()]).is_err());
        let body = Body { prev: None, writers: vec![public(&crate::random()).into()], membership: Some(service()) };
        let entry = envelope(&seed, &body);
        let id = id_of(&entry.body.0);
        assert!(PublicLog::replay(&id, [seal(&id, &entry).as_slice()]).is_err());
    }

    #[test]
    fn private_claims_are_exactly_bound_and_authorization_remains_separate() {
        let seed = crate::random();
        let (id, first) = create(&seed, service());
        let mut log = replay(&id, &[first]);
        let key = public(&crate::random());
        let device = public(&seed);
        let of = |name: &str, device_name: &str| Credential {
            name: "handle".into(), key: key.into(),
            certificate: Some(Box::new(Certificate {
                identity: IdentityRef { id: id.into(), membership: service() }, device: device.into(),
                name: name.into(), device_name: device_name.into(),
                sig: Bytes(sign(&seed, &certified(&key, &id, &device, name, device_name))),
            })),
        };
        assert_ne!(certified(&key, &id, &device, "ab", "c"), certified(&key, &id, &device, "a", "bc"));
        for (name, label) in [("", ""), ("Ånn 🦊", "pöcket"), ("Ann", "laptop")] {
            let good = of(name, label);
            assert_eq!(log.verify(&good), Verdict::Authorized);
            for mutation in 0..10 {
                let mut bad = good.clone();
                let c = bad.certificate.as_mut().unwrap();
                match mutation {
                    0 => c.name.push('x'),
                    1 => c.device_name.push('x'),
                    2 => bad.key.0[0] ^= 1,
                    3 => c.device.0[0] ^= 1,
                    4 => c.identity.id.0[0] ^= 1,
                    5 => c.sig.0[0] ^= 1,
                    6 => c.device.0.pop().map(drop).unwrap(),
                    7 => c.identity.id.0.pop().map(drop).unwrap(),
                    8 => bad.key.0.pop().map(drop).unwrap(),
                    _ => c.sig = Bytes(sign(&seed, &[b"letmeknow certificate v1\0", key.as_slice(), id.as_slice()].concat())),
                }
                assert!(!verify_certificate(&bad), "mutation {mutation}");
                assert_eq!(log.verify(&bad), Verdict::Unverified);
            }
            let mut hint = good.clone();
            hint.certificate.as_mut().unwrap().identity.membership = crate::group::tests::service("hint.example");
            assert_eq!(log.verify(&hint), Verdict::Authorized, "route hint is not signed authority");
        }
        let other = crate::random();
        assert!(log.apply(&log.next(&seed, vec![public(&other).into()])));
        assert_eq!(log.verify(&of("Ann", "laptop")), Verdict::Dropped);
        assert!(!log.apply(&log.next(&other, vec![device.into()])), "a dropped device never returns");
        assert_eq!(log.verify(&of("Ann", "laptop")), Verdict::Dropped);
        assert!(log.apply(&log.next(&other, vec![public(&crate::random()).into()])), "a fresh key is the way back");
    }

    #[test]
    fn certificate_encoding_matches_literal_utf8_vector_and_rejects_wrong_length_signatures() {
        // RFC 8032 test key; the expected bytes do not use the production serializer.
        let seed = [0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60];
        let vector = b"letmeknow certificate v2\0\
            SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII\
            \xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\
            \x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a\
            \0\0\0\0\0\0\0\x06\xc3\x85\xf0\x9f\xa6\x8a\
            \0\0\0\0\0\0\0\x03e\xcc\x81";
        assert_eq!(certified(&[b'S'; 32], &[b'I'; 32], &public(&seed), "Å🦊", "e\u{301}"), vector);
        let mut credential = Credential {
            name: "handle".into(), key: [b'S'; 32].into(),
            certificate: Some(Box::new(Certificate {
                identity: IdentityRef { id: [b'I'; 32].into(), membership: service() },
                device: public(&seed).into(), name: "Å🦊".into(), device_name: "e\u{301}".into(),
                sig: Bytes(sign(&seed, vector)),
            })),
        };
        assert!(verify_certificate(&credential));
        for (offset, length) in [(121, 6_u64.to_le_bytes()), (135, 3_u64.to_le_bytes()),
            (121, 2_u64.to_be_bytes()), (135, 2_u64.to_be_bytes()),
            (121, 7_u64.to_be_bytes()), (135, 4_u64.to_be_bytes())] {
            let mut wrong = vector.to_vec();
            wrong[offset..offset + 8].copy_from_slice(&length);
            credential.certificate.as_mut().unwrap().sig = Bytes(sign(&seed, &wrong));
            assert!(!verify_certificate(&credential), "noncanonical length at {offset}: {length:?}");
        }
    }

    #[test]
    fn weak_key_forgeries_and_old_name_bearing_bodies_are_rejected() {
        let weak = [vec![1], vec![0; 31]].concat();
        let sig = [weak.as_slice(), &[0; 32]].concat();
        assert!(!verify(&weak, b"", b"anything", &sig));
        let old = serde_json::json!({"prev":null,"writers":[{"key":Bytes(weak),"name":"leak"}],"name":"leak","at":1734567890123_u64,"membership":service()});
        assert!(serde_json::from_value::<Body>(old).is_err());
    }

    use lmk_proto::public::id as id_of;
}

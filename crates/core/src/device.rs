//! The device key, kept in `device.json`, and the session credentials it signs.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use lmk_proto::Bytes;
use lmk_proto::group::{Credential, IdentityRef, SESSION_CONTEXT};
use openmls::prelude::SignatureScheme;
use openmls_basic_credential::SignatureKeyPair;
use serde::{Deserialize, Serialize};

/// `device.json`: `{"name", "key": <Ed25519 seed>, "identities": [<identity ref>]}`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    key: Bytes,
    /// The identities whose device lists this device is on.
    #[serde(default)]
    pub identities: Vec<IdentityRef>,
}

impl Device {
    pub fn new(name: &str) -> Self {
        Device { name: name.into(), key: crate::random::<32>().into(), identities: Vec::new() }
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.key.0.as_slice().try_into().expect("a device key is 32 bytes"))
    }

    pub fn public(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes()
    }

    /// An Ed25519 signature over `context` ‖ `bytes`.
    pub fn sign(&self, context: &[u8], bytes: &[u8]) -> Vec<u8> {
        self.signing_key().sign(&[context, bytes].concat()).to_bytes().to_vec()
    }

    /// The credential of a session whose MLS signature key is `session_key`.
    pub fn credential(&self, name: &str, session_key: &[u8], identity: Option<IdentityRef>) -> Credential {
        Credential {
            name: name.into(),
            device: self.public().into(),
            device_sig: Bytes(self.sign(SESSION_CONTEXT, session_key)),
            device_name: self.name.clone(),
            identity,
        }
    }

    /// The device key as an MLS signature key: a browser's one key is both its device and its session.
    pub fn signer(&self) -> SignatureKeyPair {
        SignatureKeyPair::from_raw(SignatureScheme::ED25519, self.key.0.clone(), self.public().to_vec())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        // Through a rename, so that a crash never leaves half a file and loses the key.
        let new = path.with_extension("new");
        options.open(&new)?.write_all(&serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(new, path)?;
        Ok(())
    }
}

/// Checks an Ed25519 signature by `key` over `context` ‖ `bytes`.
pub fn verify(key: &[u8], context: &[u8], bytes: &[u8], sig: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (<[u8; 32]>::try_from(key), Signature::from_slice(sig)) else {
        return false;
    };
    VerifyingKey::from_bytes(&key).is_ok_and(|key| key.verify(&[context, bytes].concat(), &sig).is_ok())
}

/// Whether the credential's device signed this session key.
pub fn signed_by_device(credential: &Credential, session_key: &[u8]) -> bool {
    verify(&credential.device.0, SESSION_CONTEXT, session_key, &credential.device_sig.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_signature() {
        let device = Device::new("laptop");
        let credential = device.credential("Builder", b"session key", None);
        assert!(signed_by_device(&credential, b"session key"));
        assert!(!signed_by_device(&credential, b"another key"));
        let other = Device::new("phone");
        let forged = Credential { device: other.public().into(), ..credential };
        assert!(!signed_by_device(&forged, b"session key"));
    }

    #[test]
    fn device_json_round_trip() {
        let dir = std::env::temp_dir().join(format!("lmk-core-device-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("device.json");
        let device = Device::new("laptop");
        device.save(&path).unwrap();
        let loaded = Device::load(&path).unwrap();
        assert_eq!(loaded.public(), device.public());
        assert_eq!(loaded.name, "laptop");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn device_as_session_signer() {
        use openmls_traits::signatures::Signer as _;
        let device = Device::new("browser");
        let signer = device.signer();
        let sig = signer.sign(b"bytes").unwrap();
        assert!(verify(&device.public(), b"", b"bytes", &sig));
    }
}

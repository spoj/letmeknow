//! The device key, kept in `device.json`: a device's MLS key in its identities' devices groups.

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use lmk_proto::Bytes;
use openmls::prelude::SignatureScheme;
use openmls_basic_credential::SignatureKeyPair;
use serde::{Deserialize, Serialize};

/// `device.json`: `{"name", "key": <Ed25519 seed>}`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    key: Bytes,
}

impl Device {
    pub fn new(name: &str) -> Self {
        Device { name: name.into(), key: crate::random::<32>().into() }
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.key.0.as_slice().try_into().expect("a device key is 32 bytes"))
    }

    pub fn public(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes()
    }

    /// The device key as an MLS signature key: the device's node's, and in a browser its one session's too.
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn device_as_signer() {
        use openmls_traits::signatures::Signer as _;
        let device = Device::new("browser");
        let sig = device.signer().sign(b"bytes").unwrap();
        assert!(verify(&device.public(), b"", b"bytes", &sig));
    }
}

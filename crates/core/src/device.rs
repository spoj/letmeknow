//! The device, kept in `device.json`: its name. Its key in each identity's devices group is that group's own.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use openmls::prelude::SignatureScheme;
use openmls_basic_credential::SignatureKeyPair;
use serde::{Deserialize, Serialize};

/// `device.json`: `{"name"}`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
}

impl Device {
    pub fn new(name: &str) -> Self {
        Device { name: name.into() }
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
        // Through a rename, so that a crash never leaves half a file.
        let new = path.with_extension("new");
        options.open(&new)?.write_all(&serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(new, path)?;
        Ok(())
    }
}

/// A device key, a 32-byte Ed25519 seed, as an MLS signature key.
pub fn signer(seed: &[u8; 32]) -> SignatureKeyPair {
    SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), crate::identity::public(seed).to_vec())
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
        Device::new("laptop").save(&path).unwrap();
        assert_eq!(Device::load(&path).unwrap().name, "laptop");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

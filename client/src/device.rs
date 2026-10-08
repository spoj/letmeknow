use anyhow::{Context, Result};
use letmeknow::proto::fingerprint;
use openmls::prelude::SignatureScheme;
use openmls_basic_credential::SignatureKeyPair;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// This letmeknow home as a device: a key that signs every session kept here, and the entities the device is in.
/// Sessions read it when they need it, so one that links the device is seen by all.
#[derive(Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    signer: SignatureKeyPair,
    #[serde(default)]
    pub entities: Vec<Membership>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Membership {
    pub id: String,
    pub name: String,
    /// Shared by the entity's devices; it locates and seals the entity's inbox.
    pub secret: String,
    /// The relay that keeps the entity's list.
    pub relay: String,
}

impl Device {
    pub fn load(home: &Path) -> Result<Self> {
        let path = file(home);
        if !path.exists() {
            let name = gethostname::gethostname().to_string_lossy().into_owned();
            let device = Self { name, signer: SignatureKeyPair::new(SignatureScheme::ED25519)?, entities: Vec::new() };
            device.save(home)?;
        }
        Ok(serde_json::from_slice(&std::fs::read(&path)?)?)
    }

    pub fn save(&self, home: &Path) -> Result<()> {
        crate::private_file(&file(home), &serde_json::to_vec(self)?)
    }

    pub fn id(&self) -> String {
        fingerprint(self.signer.public())
    }

    pub fn key(&self) -> &[u8] {
        self.signer.public()
    }

    pub fn signer(&self) -> &SignatureKeyPair {
        &self.signer
    }

    /// An entity this device is in, by id or name.
    pub fn entity(&self, name: &str) -> Result<&Membership> {
        self.entities.iter().find(|e| e.id == name || e.name == name).with_context(|| format!("this device is in no entity {name}"))
    }
}

fn file(home: &Path) -> PathBuf {
    home.join("device.json")
}

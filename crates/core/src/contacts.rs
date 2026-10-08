//! An identity's contacts: a Yjs map in its devices group, from identity id to how the identity knows them.

use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lmk_proto::Bytes;
use serde::{Deserialize, Serialize};
use yrs::encoding::serde::{from_any, to_any};
use yrs::updates::decoder::Decode;
use yrs::{Doc, Map, MapRef, Out, ReadTxn, StateVector, Transact, Update};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum How {
    /// It invited them, or scanned their code in person.
    Verified,
    /// A contact introduced them, and the introduction was accepted.
    Introduced,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub how: How,
    /// The introducer's identity id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<Bytes>,
    /// Milliseconds since the Unix epoch.
    pub at: u64,
}

/// The contacts doc. Sync `doc` like a doc's text: edits live, catch-up by diff, state linked in the Welcome.
pub struct Contacts {
    pub doc: Doc,
    map: MapRef,
}

impl Default for Contacts {
    fn default() -> Self {
        let doc = Doc::new();
        let map = doc.get_or_insert_map("contacts");
        Contacts { doc, map }
    }
}

fn key(id: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(id)
}

impl Contacts {
    /// From a saved state: a Yjs v1 update.
    pub fn load(state: &[u8]) -> Result<Self> {
        let contacts = Contacts::default();
        contacts.apply(state)?;
        Ok(contacts)
    }

    pub fn state(&self) -> Vec<u8> {
        self.doc.transact().encode_state_as_update_v1(&StateVector::default())
    }

    /// Applies an edit or a diff from another device.
    pub fn apply(&self, update: &[u8]) -> Result<()> {
        self.doc.transact_mut().apply_update(Update::decode_v1(update)?)?;
        Ok(())
    }

    /// Sets a contact; returns the edit to send to the identity's other devices.
    pub fn set(&self, id: &[u8], contact: &Contact) -> Vec<u8> {
        let mut txn = self.doc.transact_mut();
        self.map.insert(&mut txn, key(id), to_any(contact).unwrap());
        txn.encode_update_v1()
    }

    pub fn remove(&self, id: &[u8]) -> Vec<u8> {
        let mut txn = self.doc.transact_mut();
        self.map.remove(&mut txn, &key(id));
        txn.encode_update_v1()
    }

    /// The contact for an identity; none means unknown, known only by its own claim.
    pub fn get(&self, id: &[u8]) -> Option<Contact> {
        let txn = self.doc.transact();
        let Some(Out::Any(any)) = self.map.get(&txn, &key(id)) else {
            return None;
        };
        from_any(&any).ok()
    }

    /// The identity a contact name belongs to: a new identity using it gets a warning ("not your Bob").
    pub fn named(&self, name: &str) -> Option<Bytes> {
        self.all().into_iter().find(|(_, contact)| contact.name == name).map(|(id, _)| id)
    }

    pub fn all(&self) -> Vec<(Bytes, Contact)> {
        let txn = self.doc.transact();
        self.map
            .iter(&txn)
            .filter_map(|(id, value)| {
                let Out::Any(any) = value else { return None };
                Some((Bytes(URL_SAFE_NO_PAD.decode(id).ok()?), from_any(&any).ok()?))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_levels_and_sync() {
        let laptop = Contacts::default();
        let bob = Contact { name: "Bob (Acme)".into(), how: How::Verified, by: None, at: 1 };
        let carol = Contact { name: "Carol".into(), how: How::Introduced, by: Some(Bytes(vec![2; 32])), at: 2 };
        let edit = laptop.set(&[2; 32], &bob);
        laptop.set(&[3; 32], &carol);
        assert_eq!(laptop.get(&[2; 32]), Some(bob.clone()));
        assert_eq!(laptop.get(&[3; 32]).unwrap().how, How::Introduced);
        assert_eq!(laptop.get(&[4; 32]), None);
        assert_eq!(laptop.named("Bob (Acme)"), Some(Bytes(vec![2; 32])));

        let phone = Contacts::default();
        phone.apply(&edit).unwrap();
        assert_eq!(phone.get(&[2; 32]), Some(bob));
        assert_eq!(phone.get(&[3; 32]), None);
        let restored = Contacts::load(&laptop.state()).unwrap();
        assert_eq!(restored.all().len(), 2);
        phone.apply(&laptop.remove(&[2; 32])).unwrap();
        assert_eq!(phone.get(&[2; 32]), None);
    }
}

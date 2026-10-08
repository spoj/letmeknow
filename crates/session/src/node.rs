//! What the session needs from the parts built elsewhere: the group logic (lmk-core), peers (lmk-net) and the
//! membership service (lmk-membership). The session drives them; they tell it what arrives through `Inbound`.

use anyhow::Result;
use lmk_proto::Bytes;
use lmk_proto::group::{How, IdentityRef, Opening, Payload, Service, Settings};
use lmk_proto::links::{FileLink, Invite};
use lmk_proto::peer::{Admitted, InviteRequest};
use lmk_proto::{Answer, identity};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::cli::Request;

/// A group member, as the group logic knows it from its leaf and credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// The session key: the MLS signature key.
    pub key: Bytes,
    /// The iroh key its leaf names.
    pub iroh: Bytes,
    pub name: String,
    pub device: Bytes,
    pub device_name: String,
    pub identity: Option<Claim>,
    /// Who added it, by session key, and how; none for the group's creator.
    pub added: Option<(Bytes, How)>,
}

/// The identity a member speaks as, checked against its device list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub identity: IdentityRef,
    /// The identity's own name, from its device list: a claim.
    pub name: String,
    /// Why the check failed, if it did.
    pub error: Option<String>,
    /// For a device added to its identity lately: the name of the device that added it.
    pub added_by_device: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Known {
    Verified,
    Introduced,
}

/// This identity's name for another, and how it knows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub id: Bytes,
    pub name: String,
    pub how: Known,
    /// The introducer's identity id.
    pub by: Option<Bytes>,
}

/// What a commit changed, from this member's view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Joined { member: Member, by: Bytes, how: How },
    Left { member: Member, by: Bytes },
    /// This session was removed.
    Removed { by: Bytes },
    Settings { settings: Settings, by: Bytes },
    KeyUpdate,
}

/// The result of reading one log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applied {
    /// Not the first valid commit for this member's epoch.
    Skipped,
    Commit(Vec<Change>),
    /// This session's own pending commit, now merged.
    Own(Vec<Change>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Op {
    Add(Bytes),
    Remove(Bytes),
    Update,
    Settings(Settings),
}

pub struct Commit {
    pub entry: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
}

pub struct Opened {
    pub sender: Bytes,
    pub epoch: u64,
    pub payload: Payload,
}

pub struct DeviceList {
    pub name: String,
    /// Device keys and names.
    pub devices: Vec<(Bytes, String)>,
}

/// The group and identity logic: MLS state, device lists, contacts. No network: entries it makes are appended by the
/// session, and entries the logs hold are handed to it in order.
pub trait Core {
    /// This session's key.
    fn key(&self) -> Bytes;
    fn groups(&self) -> Vec<Bytes>;
    /// A new group, of which this session is the only member, speaking as `identity` (the device's first if none).
    fn create(&mut self, settings: Settings, identity: Option<&Bytes>) -> Result<Bytes>;
    fn key_package(&mut self, identity: Option<&Bytes>) -> Result<Bytes>;
    /// Who a key package would add.
    fn inspect(&self, key_package: &[u8]) -> Result<Member>;
    fn join(&mut self, welcome: &[u8]) -> Result<Bytes>;
    fn settings(&self, group: &[u8]) -> Result<Settings>;
    fn members(&self, group: &[u8]) -> Result<Vec<Member>>;
    /// Builds a commit on the current epoch and keeps it pending until `apply` meets it in the log.
    fn commit(&mut self, group: &[u8], op: Op) -> Result<Commit>;
    fn apply(&mut self, group: &[u8], entry: &[u8]) -> Result<Applied>;
    fn seal(&mut self, group: &[u8], payload: &Payload) -> Result<Vec<u8>>;
    fn open(&mut self, group: &[u8], ciphertext: &[u8]) -> Result<Opened>;
    fn forget(&mut self, group: &[u8]) -> Result<()>;

    /// This device's identities, and their names.
    fn identities(&self) -> Result<Vec<(IdentityRef, String)>>;
    /// A new identity with this device on it: the identity and its first device-list entry.
    fn identity_create(&mut self, name: &str, membership: Service) -> Result<(IdentityRef, Vec<u8>)>;
    /// The sealed entry that adds or removes a device, given the list's entries so far.
    fn identity_entry(&mut self, id: &[u8], add: Option<&str>, device: &[u8], log: &[Vec<u8>]) -> Result<Vec<u8>>;
    fn device_list(&self, id: &[u8], log: &[Vec<u8>]) -> Result<DeviceList>;
    /// This device's key and name.
    fn device(&self) -> (Bytes, String);
    fn contacts(&self) -> Result<Vec<Contact>>;
    fn set_contact(&mut self, contact: Contact) -> Result<()>;
    /// Groups open to this device's identities, from its devices groups.
    fn openings(&self) -> Result<Vec<Opening>>;
}

/// A membership service client, for both kinds of service. Answers that refuse are errors.
#[allow(async_fn_in_trait)]
pub trait Log {
    async fn append(&self, service: &Service, log: &[u8], entry: &[u8]) -> Result<u64>;
    async fn read(&self, service: &Service, log: &[u8], after: u64) -> Result<Vec<Vec<u8>>>;
    /// New entries of the log arrive as `Inbound::Entry`.
    fn follow(&self, service: &Service, log: &[u8]);
}

/// Who took a message: the iroh keys of the members that hold it, and those that refused it, with their reasons.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Delivery {
    pub held: Vec<Bytes>,
    pub refused: Vec<(Bytes, String)>,
}

/// The other members, over iroh.
#[allow(async_fn_in_trait)]
pub trait Peers {
    /// This session's iroh key and relay.
    fn address(&self) -> (Bytes, String);
    /// Sends a ciphertext to the members online; returns once one holds it, or none can.
    async fn send(&self, group: &[u8], ciphertext: &[u8]) -> Delivery;
    /// Pushes a commit the log has taken to the members online.
    fn commit(&self, group: &[u8], entry: &[u8]);
    /// The iroh keys of the group's members connected now.
    fn online(&self, group: &[u8]) -> Vec<Bytes>;
    async fn redeem(&self, invite: &Invite, request: &InviteRequest) -> Result<Answer<Admitted>>;
    async fn ask_to_join(&self, opening: &Opening, key_package: &[u8]) -> Result<Answer<Admitted>>;
    /// Seals and holds a file for a group.
    fn add_file(&self, group: &[u8], bytes: &[u8]) -> Result<FileLink>;
    /// A held file's plaintext.
    fn file(&self, link: &FileLink) -> Result<Option<Vec<u8>>>;
    /// Asks the group's members for a file; `Inbound::File` follows when it arrives.
    fn want(&self, group: &[u8], link: &FileLink);
    /// Waits until another member holds a file, or a timeout; returns the holders' iroh keys.
    async fn spread(&self, group: &[u8], link: &FileLink) -> Vec<Bytes>;
}

/// What reaches the session process.
pub enum Inbound {
    Request(Request, oneshot::Sender<serde_json::Value>),
    /// A log entry, from the service or a peer, at its position.
    Entry { log: Bytes, position: u64, entry: Vec<u8> },
    Message { group: Bytes, ciphertext: Vec<u8> },
    /// A member took, or refused, a message this session sent.
    Held { group: Bytes, id: [u8; 32], by: Bytes },
    Refused { group: Bytes, id: [u8; 32], by: Bytes, reason: String },
    File { hash: [u8; 32] },
    Invite { request: InviteRequest, reply: oneshot::Sender<Answer<Admitted>> },
    Join { group: Bytes, key_package: Bytes, reply: oneshot::Sender<Answer<Admitted>> },
    /// A peer's doc snapshot differs; answer with a `diff` message against its state vector.
    DocSv { group: Bytes, sv: Vec<u8> },
    Snapshot { group: Bytes, reply: oneshot::Sender<[u8; 32]> },
    FileChanged(Bytes),
}

/// The log id of an identity's device list.
pub fn device_log(id: &[u8]) -> Bytes {
    Bytes(identity::address(id).to_vec())
}

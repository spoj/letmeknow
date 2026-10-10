//! The devices kind, built in: an identity's devices group, whose members are its devices, each with its own device key
//! there. Its state is the identity, its private keys, its contacts and the groups open to it, kept in step through the
//! group's held messages, in log order, and handed to a new device as any kind's state. At a loss of its own it stops:
//! it takes no later message, appends nothing to the key log and hands out no state, until it takes a state past the
//! loss. A device certifies its sessions
//! with its device key, and keeps the identity's key log in step with the group: its list of devices follows the
//! group's members, and its key is replaced when a device leaves, and monthly.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use lmk_core::contacts::Contact;
use lmk_core::device::Device;
use lmk_core::identity::{self, DAY, KeyLog, public};
use lmk_core::provider::Provider;
use lmk_proto::Bytes;
use lmk_proto::group::{Certificate, DEVICES, IdentityRef, Opening, PROTOCOL, Service, Settings, UPDATE};
use lmk_proto::identity::{Listed, certified};
use lmk_proto::links::Invite;
use n0_future::task::spawn;
use n0_future::time::{Duration, sleep};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{Event, Item, Member, Node, hex, now};

/// How long an identity keeps a key before a device replaces it, in milliseconds.
const ROTATE: u64 = 30 * DAY;
/// How many half seconds a new device waits for its identity's state.
const STATE_WAIT: u32 = 60;
/// How often a device runs its duties in each of its devices groups, besides as their logs move.
const DUTY_CHECK: Duration = Duration::from_secs(10 * 60);

/// A devices group's state, as the group's log stands at `position`.
#[derive(Clone, Serialize, Deserialize)]
struct Book {
    identity: IdentityRef,
    name: String,
    position: u64,
    /// The identity's private keys, each with when it was made, in milliseconds, and the devices group's epoch then.
    keys: Vec<(Bytes, u64, u64)>,
    contacts: Vec<(Bytes, Contact)>,
    openings: Vec<Opening>,
    /// Fields a newer letmeknow added, kept when this device hands the state on.
    #[serde(flatten)]
    rest: Map<String, Value>,
}

impl Book {
    /// The private key whose public key is `key`, and when it was made.
    fn seed(&self, key: &[u8; 32]) -> Option<([u8; 32], u64)> {
        self.keys.iter().find_map(|(seed, at, _)| {
            let seed: [u8; 32] = seed.0.as_slice().try_into().ok()?;
            (public(&seed) == *key).then_some((seed, *at))
        })
    }

    /// Takes the keys of another state that this one lacks.
    fn take_keys(&mut self, keys: Vec<(Bytes, u64, u64)>) {
        for key in keys {
            if !self.keys.iter().any(|(seed, ..)| *seed == key.0) {
                self.keys.push(key);
            }
        }
    }
}

/// What this device keeps of a devices group: its state, once it has one.
#[derive(Default, Serialize, Deserialize)]
struct Record {
    book: Option<Book>,
    /// The position of a message this device lost, where its state stopped.
    stopped: Option<u64>,
    /// When this device made or joined the group, which orders its identities.
    since: u64,
}

/// A held message of a devices group.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Entry {
    /// A new key of the identity, made in the group's epoch `epoch`.
    Key { key: Bytes, at: u64, epoch: u64 },
    Contact { identity: Bytes, contact: Contact },
    /// A group open to the identity, replacing the opening of the same group.
    Opening { opening: Opening },
}

/// A device that lacks its identity's current key asks the devices online for the group's state: the key it lacks, the
/// devices it asked, by iroh key, those of them that have not answered, and whether it reported the key lost.
struct Asked {
    key: [u8; 32],
    asked: Vec<Bytes>,
    waiting: Vec<Bytes>,
    reported: bool,
}

/// Keeps the device, as when it is renamed: its `device.json`, or a browser's record.
pub type Save = Arc<dyn Fn(&Device) -> Result<()> + Send + Sync>;

/// The devices kind, on a device's node.
pub struct Devices<P> {
    node: Node<P>,
    device: Device,
    save: Save,
    /// Held while a record is read and written back.
    lock: Arc<Mutex<()>>,
    /// Held while a pass of the duties runs.
    passing: Arc<tokio::sync::Mutex<()>>,
    /// By devices group.
    asked: Arc<Mutex<HashMap<Vec<u8>, Asked>>>,
}

impl<P> Clone for Devices<P> {
    fn clone(&self) -> Self {
        Devices {
            node: self.node.clone(),
            device: self.device.clone(),
            save: self.save.clone(),
            lock: self.lock.clone(),
            passing: self.passing.clone(),
            asked: self.asked.clone(),
        }
    }
}

fn record_key(gid: &[u8]) -> String {
    format!("devices/{}", hex(gid))
}

impl<P: Provider + Send + 'static> Devices<P> {
    /// The devices kind on `node`, kept by `save`; it runs its duties in each devices group now, then every while.
    pub fn new(node: Node<P>, device: Device, save: Save) -> Self {
        let devices = Devices { node, device, save, lock: Arc::default(), passing: Arc::default(), asked: Arc::default() };
        let checking = devices.clone();
        spawn(async move {
            loop {
                for (gid, _) in checking.books() {
                    if let Err(error) = checking.duties(&gid.0).await {
                        tracing::warn!("the duties of a devices group: {error:#}");
                    }
                }
                sleep(DUTY_CHECK).await;
            }
        });
        devices
    }

    fn record(&self, gid: &[u8]) -> Record {
        let record = self.node.record(&record_key(gid)).ok().flatten();
        record.and_then(|record| serde_json::from_slice(&record).ok()).unwrap_or_default()
    }

    fn save(&self, gid: &[u8], record: &Record) -> Result<()> {
        self.node.put_record(&record_key(gid), &serde_json::to_vec(record)?)
    }

    /// The devices groups with their state, oldest first.
    fn books(&self) -> Vec<(Bytes, Book)> {
        let mut records: Vec<(Bytes, Record)> = self
            .node
            .groups()
            .into_iter()
            .filter(|gid| self.node.settings(&gid.0).is_ok_and(|s| s.kind == DEVICES))
            .map(|gid| {
                let record = self.record(&gid.0);
                (gid, record)
            })
            .collect();
        records.sort_by_key(|(_, record)| record.since);
        records.into_iter().filter_map(|(gid, record)| Some((gid, record.book?))).collect()
    }

    fn book(&self, identity: &[u8]) -> Result<(Bytes, Book)> {
        self.books().into_iter().find(|(_, book)| book.identity.id.0 == identity).context("this device is not on that identity")
    }

    /// This device's name.
    pub fn name(&self) -> Option<String> {
        self.node.device_name()
    }

    /// This device's identities, with their names.
    pub fn identities(&self) -> Vec<(IdentityRef, String)> {
        self.books().into_iter().map(|(_, book)| (book.identity, book.name)).collect()
    }

    /// The contacts of this device's identities.
    pub fn contacts(&self) -> Vec<(Bytes, Contact)> {
        self.books().into_iter().flat_map(|(_, book)| book.contacts).collect()
    }

    /// The groups open to this device's identities.
    pub fn openings(&self) -> Vec<Opening> {
        self.books().into_iter().flat_map(|(_, book)| book.openings).collect()
    }

    /// An identity's devices: their keys and names.
    pub fn devices(&self, identity: &[u8]) -> Result<Vec<(Bytes, String)>> {
        let (gid, _) = self.book(identity)?;
        Ok(self.node.members(&gid.0)?.into_iter().map(|m| (m.key, m.name)).collect())
    }

    /// This device's key on an identity.
    pub fn key(&self, identity: &[u8]) -> Result<Bytes> {
        Ok(self.node.key_in(&self.book(identity)?.0.0))
    }

    /// Starts an identity, with this device its first, and its devices group.
    pub async fn create(&self, name: &str, membership: Service) -> Result<IdentityRef> {
        let settings = Settings { protocol: PROTOCOL, kind: DEVICES.into(), name: name.into(), open: Vec::new(), carry: 7, update: UPDATE, membership: membership.clone(), rest: Default::default() };
        let gid = self.node.create(settings, None)?;
        let seed = lmk_core::random::<32>();
        let device = Listed { key: self.node.key_in(&gid.0), name: self.device_name() };
        let (id, entry) = identity::create(&seed, name, membership.clone(), device);
        let identity = IdentityRef { id: id.into(), membership };
        if let Err(error) = self.node.append_identity(&identity, &entry).await {
            self.node.leave(&gid.0).await?;
            return Err(error);
        }
        let book = Book {
            identity: identity.clone(),
            name: name.into(),
            position: 0,
            keys: vec![(Bytes(seed.to_vec()), now(), self.node.epoch(&gid.0)?)],
            contacts: Vec::new(),
            openings: Vec::new(),
            rest: Map::new(),
        };
        self.save(&gid.0, &Record { book: Some(book), since: now(), stopped: None })?;
        self.node.follow_log(&gid.0, Some(0))?;
        Ok(identity)
    }

    fn device_name(&self) -> String {
        self.node.device_name().unwrap_or_default()
    }

    /// A device link: whoever opens it becomes a device of the identity.
    pub async fn invite(&self, identity: &[u8]) -> Result<String> {
        let (gid, _) = self.book(identity)?;
        Ok(self.node.invite(&gid.0, None, None).await?.link())
    }

    /// Joins an identity through a device link, with a new device key, and waits a while for its state.
    pub async fn join(&self, link: &Invite) -> Result<()> {
        ensure!(link.device, "not a device link");
        let (gid, _) = self.node.join(link, None).await?;
        ensure!(self.node.settings(&gid.0)?.kind == DEVICES, "the link led to a group, not an identity");
        let lock = self.lock.lock().unwrap();
        let mut record = self.record(&gid.0);
        record.since = now();
        self.save(&gid.0, &record)?;
        if record.book.is_none() {
            self.node.follow_log(&gid.0, None)?;
        }
        drop(lock);
        for _ in 0..STATE_WAIT {
            if self.record(&gid.0).book.is_some() {
                break;
            }
            sleep(Duration::from_millis(500)).await;
        }
        Ok(())
    }

    /// Sets a contact of this device's first identity.
    pub async fn set_contact(&self, id: &[u8], contact: Contact) -> Result<()> {
        let (gid, _) = self.books().into_iter().next().context("this device is on no identity")?;
        self.enter(&gid.0, Entry::Contact { identity: Bytes(id.to_vec()), contact }).await
    }

    /// Records a group open to an identity, keeping the fields a newer letmeknow added to its record, unless it is
    /// recorded so already.
    pub async fn set_opening(&self, identity: &[u8], mut opening: Opening) -> Result<()> {
        let (gid, book) = self.book(identity)?;
        if let Some(held) = book.openings.iter().find(|held| held.group == opening.group) {
            for (field, value) in &held.rest {
                opening.rest.entry(field.clone()).or_insert_with(|| value.clone());
            }
        }
        if book.openings.contains(&opening) {
            return Ok(());
        }
        self.enter(&gid.0, Entry::Opening { opening }).await
    }

    /// Takes a device off an identity, then brings the identity's key log in step: a new key, and a list without it.
    pub async fn remove(&self, identity: &[u8], device: &[u8]) -> Result<()> {
        let (gid, _) = self.book(identity)?;
        ensure!(device != self.node.key_in(&gid.0).0, "to take this device off its identity, leave it");
        self.node.remove(&gid.0, device).await?;
        self.duties(&gid.0).await
    }

    /// Takes this device off an identity: it asks the other devices to remove it, or, the identity's only device, ends
    /// the identity. Returns whether it ended.
    pub async fn leave(&self, identity: &[u8]) -> Result<bool> {
        let (gid, _) = self.book(identity)?;
        let ended = self.node.leave(&gid.0).await?.is_none();
        let _lock = self.lock.lock().unwrap();
        self.node.delete_record(&record_key(&gid.0))?;
        Ok(ended)
    }

    /// Renames this device: its record, and its credential in its devices groups, whose key logs then list it so.
    pub async fn rename(&self, name: &str) -> Result<()> {
        let mut device = self.device.clone();
        device.name = name.into();
        (self.save)(&device)?;
        self.node.rename_device(name).await?;
        for (gid, _) in self.books() {
            self.duties(&gid.0).await?;
        }
        Ok(())
    }

    /// Sends a held message of the group, and waits until its entry counts.
    async fn enter(&self, gid: &[u8], entry: Entry) -> Result<()> {
        self.node.send_counted(gid, &serde_json::to_value(entry)?).await.map(drop)
    }

    /// Runs the duties of a devices group in the background.
    fn due(&self, gid: &[u8]) {
        let (devices, gid) = (self.clone(), gid.to_vec());
        spawn(async move {
            if let Err(error) = devices.duties(&gid).await {
                tracing::warn!("the duties of a devices group: {error:#}");
            }
        });
    }

    /// The duties of a devices group, as its log and the identity's key log stand, each read afresh from its service:
    /// the key log first, since a device's Add is in the group's log before any entry lists it. Devices the key log took
    /// off leave the group. A device that holds the identity's current key appends, chained to the key log's last entry,
    /// one restating the list of devices when it differs from the group's members, with a new key when a device left;
    /// and one with a new key when the current one is a month old. One that lacks the key asks for it.
    pub async fn duties(&self, gid: &[u8]) -> Result<()> {
        let _passing = self.passing.lock().await;
        let Some(book) = self.record(gid).book else { return Ok(()) };
        let log = self.node.read_key_log(&book.identity).await?;
        self.node.read_group(gid).await?;
        let members = self.node.members(gid)?;
        let dropped: Vec<&Member> = members.iter().filter(|m| log.dropped(&m.key.0)).collect();
        if !dropped.is_empty() {
            for member in dropped {
                self.node.remove(gid, &member.key.0).await?;
            }
            return Ok(());
        }
        let Some(book) = self.record(gid).book.filter(|_| self.record(gid).stopped.is_none()) else { return Ok(()) };
        let Some((seed, at)) = book.seed(log.current()) else { return self.missing(gid, &log) };
        self.asked.lock().unwrap().remove(gid);
        let mut listed: Vec<Listed> = members.into_iter().map(|m| Listed { key: m.key, name: m.name }).collect();
        listed.sort();
        let mut current = log.devices.clone();
        current.sort();
        let left = current.iter().any(|device| !listed.iter().any(|member| member.key == device.key));
        let due = at + ROTATE <= now();
        if listed == current && !due {
            return Ok(());
        }
        let next = if left || due { self.new_key(gid, &book, &log).await? } else { *log.current() };
        // The design appends an entry naming a new key only once another device's summary holds its key message, or at
        // once when no other device is listed. Until the peer protocol brings summaries, it does once the message's entry
        // counts, as `new_key` returns.
        self.node.append_identity(&book.identity, &log.next(&seed, &next, listed)).await?;
        Ok(())
    }

    /// A key the key log has not taken, made in the group's current epoch, so that no device removed before it holds
    /// it: one this device or another made already, or else a new one, sent to the group first.
    async fn new_key(&self, gid: &[u8], book: &Book, log: &KeyLog) -> Result<[u8; 32]> {
        let epoch = self.node.epoch(gid)?;
        let made = book.keys.iter().filter(|(_, _, made)| *made == epoch).filter_map(|(seed, ..)| Some(public(seed.0.as_slice().try_into().ok()?)));
        if let Some(key) = made.into_iter().find(|key| !log.keys.contains(key)) {
            return Ok(key);
        }
        let seed = lmk_core::random::<32>();
        self.enter(gid, Entry::Key { key: Bytes(seed.to_vec()), at: now(), epoch }).await?;
        Ok(public(&seed))
    }

    /// This device lacks the key the key log names: it asks each device online for the group's state, which carries the
    /// keys; once, after its first pass for that key, every device it asked answered without it, or it asked none, it
    /// reports the key lost or taken.
    fn missing(&self, gid: &[u8], log: &KeyLog) -> Result<()> {
        let online: Vec<Bytes> = self.node.online(gid)?.into_iter().map(|m| m.iroh).collect();
        let mut all = self.asked.lock().unwrap();
        let first = all.get(gid).is_none_or(|asked| asked.key != *log.current());
        if first {
            all.insert(gid.to_vec(), Asked { key: *log.current(), asked: Vec::new(), waiting: Vec::new(), reported: false });
        }
        let asked = all.get_mut(gid).unwrap();
        let new: Vec<Bytes> = online.into_iter().filter(|peer| !asked.asked.contains(peer)).collect();
        for peer in new {
            self.node.ask_state(gid, &peer.0)?;
            asked.asked.push(peer.clone());
            asked.waiting.push(peer);
        }
        if !first && asked.waiting.is_empty() && !asked.reported {
            asked.reported = true;
            let text = "this device does not hold its identity's current key, and no device online has it: it was lost, or someone \
                        took the identity over; start a new identity";
            self.node.warn(gid, text.into());
        }
        Ok(())
    }

    /// A certificate that the session with MLS key `key` is one of this device's, speaking as the identity: by this
    /// device's key on it.
    pub fn certify(&self, identity: &[u8], key: &[u8]) -> Result<Certificate> {
        let (gid, book) = self.book(identity)?;
        let sig = self.node.sign(&gid.0, &certified(key, identity))?;
        Ok(Certificate { identity: book.identity, device: self.node.key_in(&gid.0), sig: Bytes(sig) })
    }

    /// The identity a devices group is of, once this device has its state.
    pub fn identity(&self, gid: &[u8]) -> Option<IdentityRef> {
        Some(self.record(gid).book?.identity)
    }

    /// Takes the events of devices groups, but for their members joining and leaving and warnings; returns every other
    /// event. Its duties run as the group or the identity's key log moves.
    pub fn on(&self, event: Event) -> Option<Event> {
        if let Event::Keys { identity } = &event {
            if let Ok((gid, _)) = self.book(&identity.0) {
                self.due(&gid.0);
            }
            return Some(event);
        }
        let Some(gid) = event.group().cloned() else { return Some(event) };
        let ours = self.node.settings(&gid.0).is_ok_and(|s| s.kind == DEVICES) || self.node.record(&record_key(&gid.0)).ok().flatten().is_some();
        if !ours {
            return Some(event);
        }
        let taken = match event {
            Event::State { data, from, .. } => self.take_state(&gid.0, &from, &data),
            Event::Logged { .. } => self.logged(&gid.0),
            Event::Snapshot { reply, .. } => {
                let record = self.record(&gid.0);
                let book = record.book.filter(|_| record.stopped.is_none()).map(|book| serde_json::to_vec(&book).expect("JSON"));
                reply.send(book).ok();
                Ok(())
            }
            Event::Removed { .. } => {
                self.asked.lock().unwrap().remove(&gid.0);
                self.node.delete_record(&record_key(&gid.0))
            }
            Event::Joined { .. } | Event::Left { .. } => {
                self.due(&gid.0);
                return Some(event);
            }
            Event::Warning { .. } => return Some(event),
            Event::Settings { .. } => {
                self.due(&gid.0);
                Ok(())
            }
            _ => Ok(()),
        };
        taken.err().map(|error| Event::Warning { group: Some(gid), text: format!("{error:#}") })
    }

    /// Takes a state another device handed this one, unless it is older than its own, or than the loss it stopped at;
    /// the keys it carries this device takes whatever its age.
    fn take_state(&self, gid: &[u8], from: &Member, data: &[u8]) -> Result<()> {
        let mut handed: Book = serde_json::from_slice(data)?;
        {
            let _lock = self.lock.lock().unwrap();
            let mut record = self.record(gid);
            let stopped = record.stopped.is_some_and(|lost| handed.position < lost);
            match &mut record.book {
                Some(held) if held.position > handed.position || stopped => held.take_keys(handed.keys),
                held => {
                    record.stopped = None;
                    if let Some(held) = held.take() {
                        handed.take_keys(held.keys);
                    }
                    let position = handed.position;
                    record.book = Some(handed);
                    self.node.follow_log(gid, Some(position))?;
                }
            }
            self.save(gid, &record)?;
        }
        if let Some(asked) = self.asked.lock().unwrap().get_mut(gid) {
            asked.waiting.retain(|peer| *peer != from.iroh);
        }
        self.due(gid);
        Ok(())
    }

    /// Applies the group's held messages taken since the state, up to a loss of this device's own, where it stops and
    /// asks for a state.
    fn logged(&self, gid: &[u8]) -> Result<()> {
        let _lock = self.lock.lock().unwrap();
        let mut record = self.record(gid);
        let Some(book) = record.book.as_mut().filter(|_| record.stopped.is_none()) else { return Ok(()) };
        let me = self.node.key_in(gid);
        for item in self.node.entries(gid, book.position)? {
            let entry = match item {
                Item::Lost(lost) if lost.member.key == me => {
                    record.stopped = Some(lost.position);
                    break;
                }
                Item::Lost(lost) => {
                    book.position = lost.position;
                    continue;
                }
                Item::Entry(entry) => entry,
            };
            book.position = entry.position;
            match serde_json::from_value(entry.payload) {
                Ok(Entry::Key { key, at, epoch }) => book.take_keys(vec![(key, at, epoch)]),
                Ok(Entry::Contact { identity, contact }) => {
                    book.contacts.retain(|(id, _)| *id != identity);
                    book.contacts.push((identity, contact));
                }
                Ok(Entry::Opening { opening }) => {
                    book.openings.retain(|held| held.group != opening.group);
                    book.openings.push(opening);
                }
                Err(error) => tracing::debug!("skipped an entry of a devices group: {error:#}"),
            }
        }
        let position = book.position;
        self.save(gid, &record)?;
        self.node.follow_log(gid, Some(position))?;
        let Some(lost) = record.stopped else { return Ok(()) };
        let text = format!("this device lost the message at position {lost} of its identity's devices group: it waits for a device's state past it");
        self.node.warn(gid, text);
        self.node.follow_log(gid, None)
    }
}

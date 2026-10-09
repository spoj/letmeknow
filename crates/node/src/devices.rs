//! The devices kind, built in: an identity's devices group, whose members are its devices. Its state is the identity,
//! its private keys, its contacts and the groups open to it, kept in step through the group's kind log and handed to a
//! new device as any kind's state. A device certifies its sessions with the identity's newest key, and replaces the key
//! when a device leaves and monthly.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use lmk_core::contacts::Contact;
use lmk_core::device::Device;
use lmk_core::identity::{self, DAY, public};
use lmk_core::provider::Provider;
use lmk_proto::Bytes;
use lmk_proto::group::{DEVICES, IdentityRef, Opening, PROTOCOL, Service, Settings};
use lmk_proto::identity::{Certified, Envelope};
use lmk_proto::links::Invite;
use n0_future::task::spawn;
use n0_future::time::{Duration, sleep};
use serde::{Deserialize, Serialize};

use crate::{Event, Node, hex, now};

/// How long an identity keeps a key before a device replaces it, in milliseconds.
const ROTATE: u64 = 30 * DAY;
/// How often a device checks whether a key is due to be replaced.
const ROTATE_CHECK: Duration = Duration::from_secs(60 * 60);

/// A devices group's state, as the kind's log stands at `position`.
#[derive(Clone, Serialize, Deserialize)]
struct Book {
    identity: IdentityRef,
    name: String,
    position: u64,
    /// The epoch of the last entry taken.
    epoch: u64,
    /// The identity's private keys, with when each was made, in milliseconds.
    keys: Vec<(Bytes, u64)>,
    contacts: Vec<(Bytes, Contact)>,
    openings: Vec<Opening>,
}

impl Book {
    /// The private key whose public key is `key`.
    fn seed(&self, key: &[u8; 32]) -> Option<([u8; 32], u64)> {
        self.keys.iter().find_map(|(seed, at)| {
            let seed: [u8; 32] = seed.0.as_slice().try_into().ok()?;
            (public(&seed) == *key).then_some((seed, *at))
        })
    }
}

/// What this device keeps of a devices group: its state, once it has one, and its own place in it.
#[derive(Default, Serialize, Deserialize)]
struct Record {
    book: Option<Book>,
    /// The name of the device that added this one.
    added_by: Option<String>,
    /// When this device made or joined the group, which orders its identities.
    since: u64,
}

/// An entry of a devices group's log.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Entry {
    /// A new key of the identity.
    Key { key: Bytes, at: u64 },
    Contact { identity: Bytes, contact: Contact },
    /// A group open to the identity, replacing the opening of the same group.
    Opening { opening: Opening },
}

/// The devices kind, on a device's node.
pub struct Devices<P> {
    node: Node<P>,
    device: Device,
    /// Held while a record is read and written back.
    lock: Arc<Mutex<()>>,
}

impl<P> Clone for Devices<P> {
    fn clone(&self) -> Self {
        Devices { node: self.node.clone(), device: self.device.clone(), lock: self.lock.clone() }
    }
}

fn record_key(gid: &[u8]) -> String {
    format!("devices/{}", hex(gid))
}

impl<P: Provider + Send + 'static> Devices<P> {
    /// The devices kind on `node`, whose key is `device`'s; it replaces each identity's key once it is a month old.
    pub fn new(node: Node<P>, device: Device) -> Self {
        let devices = Devices { node, device, lock: Arc::default() };
        let rotating = devices.clone();
        spawn(async move {
            loop {
                for (gid, _) in rotating.books() {
                    if let Err(error) = rotating.rotate_if_due(&gid.0).await {
                        tracing::warn!("replacing an identity's key: {error:#}");
                    }
                }
                sleep(ROTATE_CHECK).await;
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

    /// Each identity's newest public key, as the key log held shows it.
    pub fn keys(&self) -> Vec<(Bytes, Bytes)> {
        let held = self.books().into_iter().filter_map(|(_, book)| Some((book.identity.id.clone(), self.node.held_key_log(&book.identity.id.0)?)));
        held.map(|(id, log)| (id, Bytes(log.current().to_vec()))).collect()
    }

    /// An identity's devices: their keys and names.
    pub fn devices(&self, identity: &[u8]) -> Result<Vec<(Bytes, String)>> {
        let (gid, _) = self.book(identity)?;
        Ok(self.node.members(&gid.0)?.into_iter().map(|m| (m.key, m.name)).collect())
    }

    /// Starts an identity, with this device its first, and its devices group.
    pub async fn create(&self, name: &str, membership: Service) -> Result<IdentityRef> {
        let seed = lmk_core::random::<32>();
        let (id, entry) = identity::create(&seed, name, membership.clone());
        let identity = IdentityRef { id: id.into(), membership: membership.clone() };
        self.node.append_identity(&identity, &entry).await?;
        let settings = Settings { protocol: PROTOCOL, kind: DEVICES.into(), name: name.into(), open: Vec::new(), keep: 90, membership, log: None };
        let gid = self.node.create(settings, None)?;
        let epoch = self.node.epoch(&gid.0)?;
        let book = Book {
            identity: identity.clone(),
            name: name.into(),
            position: 0,
            epoch,
            keys: vec![(Bytes(seed.to_vec()), now())],
            contacts: Vec::new(),
            openings: Vec::new(),
        };
        self.save(&gid.0, &Record { book: Some(book), added_by: None, since: now() })?;
        self.node.follow_log(&gid.0, Some((0, epoch)))?;
        Ok(identity)
    }

    /// A device link: whoever opens it becomes a device of the identity.
    pub fn invite(&self, identity: &[u8]) -> Result<String> {
        let (gid, _) = self.book(identity)?;
        Ok(Invite { device: true, ..self.node.invite(&gid.0, None, None)? }.link())
    }

    /// Joins an identity through a device link; its state follows.
    pub async fn join(&self, link: &Invite) -> Result<()> {
        ensure!(link.device, "not a device link");
        let gid = self.node.join(link, None).await?;
        ensure!(self.node.settings(&gid.0)?.kind == DEVICES, "the link led to a group, not an identity");
        let added_by = self.node.members(&gid.0)?.into_iter().find(|m| m.iroh.0 == link.key).map(|m| m.name);
        let _lock = self.lock.lock().unwrap();
        let mut record = self.record(&gid.0);
        (record.added_by, record.since) = (added_by, now());
        self.save(&gid.0, &record)?;
        if record.book.is_none() {
            self.node.follow_log(&gid.0, None)?;
        }
        Ok(())
    }

    /// Sets a contact of this device's first identity.
    pub async fn set_contact(&self, id: &[u8], contact: Contact) -> Result<()> {
        let (gid, _) = self.books().into_iter().next().context("this device is on no identity")?;
        let entry = Entry::Contact { identity: Bytes(id.to_vec()), contact };
        self.node.append(&gid.0, &serde_json::to_value(entry)?).await.map(drop)
    }

    /// Records a group open to an identity, unless it is recorded so already.
    pub async fn set_opening(&self, identity: &[u8], opening: Opening) -> Result<()> {
        let (gid, book) = self.book(identity)?;
        if book.openings.contains(&opening) {
            return Ok(());
        }
        self.node.append(&gid.0, &serde_json::to_value(Entry::Opening { opening })?).await.map(drop)
    }

    /// Takes a device off an identity, and replaces the identity's key, which it held.
    pub async fn remove(&self, identity: &[u8], device: &[u8]) -> Result<()> {
        ensure!(device != self.device.public(), "a device is taken off its identity by another of its devices");
        let (gid, _) = self.book(identity)?;
        self.node.remove(&gid.0, device).await?;
        self.rotate(&gid.0).await
    }

    async fn rotate_if_due(&self, gid: &[u8]) -> Result<()> {
        let Some(book) = self.record(gid).book else { return Ok(()) };
        let log = self.node.key_log(&book.identity).await?;
        match book.seed(log.current()) {
            Some((_, at)) if at + ROTATE <= now() => self.rotate(gid).await,
            _ => Ok(()),
        }
    }

    /// Replaces the identity's key: the new one goes to its devices first, then into its key log, by the current one.
    async fn rotate(&self, gid: &[u8]) -> Result<()> {
        let book = self.record(gid).book.context("this device has no state of the identity yet")?;
        let log = self.node.read_key_log(&book.identity).await?;
        let (current, _) = book.seed(log.current()).context("this device does not hold the identity's current key")?;
        let next = lmk_core::random::<32>();
        self.node.append(gid, &serde_json::to_value(Entry::Key { key: Bytes(next.to_vec()), at: now() })?).await?;
        self.node.append_identity(&book.identity, &log.rotate(&current, &public(&next))).await.map(drop)
    }

    /// A certificate, for a day, by the identity's newest key, that the session with MLS key `key` and name `name` is
    /// one of this device's.
    pub async fn certify(&self, identity: &[u8], key: Bytes, name: String) -> Result<Envelope> {
        let (gid, book) = self.book(identity)?;
        let log = self.node.key_log(&book.identity).await?;
        let (seed, _) = book.seed(log.current()).context("this device does not hold its identity's current key yet")?;
        let added_by = self.record(&gid.0).added_by;
        let certified = Certified { identity: book.identity.id, key, name, device: self.device.name.clone(), added_by, expires: now() + DAY };
        Ok(identity::certify(&seed, &certified))
    }

    /// Takes the events of devices groups; returns every other event.
    pub fn on(&self, event: Event) -> Option<Event> {
        let gid = event.group()?.clone();
        let ours = self.node.settings(&gid.0).is_ok_and(|s| s.kind == DEVICES) || self.node.record(&record_key(&gid.0)).ok().flatten().is_some();
        if !ours {
            return Some(event);
        }
        let taken = match event {
            Event::State { data, .. } => self.take_state(&gid.0, &data),
            Event::Logged { .. } => self.logged(&gid.0),
            Event::Snapshot { reply, .. } => {
                let book = self.record(&gid.0).book.map(|book| serde_json::to_vec(&book).expect("JSON"));
                reply.send(book).ok();
                Ok(())
            }
            Event::Removed { .. } => self.node.delete_record(&record_key(&gid.0)),
            Event::Warning { .. } => return Some(event),
            _ => Ok(()),
        };
        taken.err().map(|error| Event::Warning { group: Some(gid), text: format!("{error:#}") })
    }

    /// Takes a state another device handed this one, unless it is older than its own.
    fn take_state(&self, gid: &[u8], data: &[u8]) -> Result<()> {
        let book: Book = serde_json::from_slice(data)?;
        let _lock = self.lock.lock().unwrap();
        let mut record = self.record(gid);
        if record.book.as_ref().is_some_and(|held| held.position > book.position) {
            return Ok(());
        }
        let (position, epoch) = (book.position, book.epoch);
        record.book = Some(book);
        self.save(gid, &record)?;
        self.node.follow_log(gid, Some((position, epoch)))
    }

    /// Applies the entries of the log taken since the state.
    fn logged(&self, gid: &[u8]) -> Result<()> {
        let _lock = self.lock.lock().unwrap();
        let mut record = self.record(gid);
        let Some(book) = &mut record.book else { return Ok(()) };
        let mut rotated = None;
        for entry in self.node.entries(gid, book.position)? {
            (book.position, book.epoch) = (entry.position, entry.epoch);
            match serde_json::from_value(entry.payload) {
                Ok(Entry::Key { key, at }) => {
                    if !book.keys.iter().any(|(held, _)| *held == key) {
                        rotated = key.0.as_slice().try_into().ok().map(|seed| public(&seed));
                        book.keys.push((key, at));
                    }
                }
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
        let (identity, position, epoch) = (book.identity.clone(), book.position, book.epoch);
        self.save(gid, &record)?;
        self.node.follow_log(gid, Some((position, epoch)))?;
        // The device that made a key enters it in the key log once its devices have it: read the log until it shows.
        if let Some(key) = rotated {
            let node = self.node.clone();
            spawn(async move {
                for _ in 0..10 {
                    if node.read_key_log(&identity).await.is_ok_and(|log| *log.current() == key) {
                        return;
                    }
                    sleep(Duration::from_secs(2)).await;
                }
            });
        }
        Ok(())
    }
}

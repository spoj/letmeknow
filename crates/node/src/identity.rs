//! The identity kind, built in: an identity's group, whose members are its devices, each with its own device key
//! there, and whose settings carry the id of the identity's public log. A device certifies its sessions with its device
//! key, and keeps the keys-only directory in step with the group, restating it twice a year for retention.
//! Names are signed from committed private state, never published in the directory.
//! Its held messages are adds, invites into groups for one device's sessions, which that device keeps until it takes
//! them or they expire; its live ones tell which sessions each device runs, and the groups they are in.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use lmk_core::device::Device;
use lmk_core::provider::Provider;
use lmk_proto::Bytes;
use lmk_proto::group::{Certificate, IDENTITY, IdentityRef, PROTOCOL, Service, Settings, UPDATE};
use lmk_proto::links::Invite;
use lmk_proto::public::certified;
use n0_future::task::spawn;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Event, Item, Node, hex, now};

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;

const NO_IDENTITY: &str = "this device is on no identity";

/// How long an add's invite is valid, in milliseconds: a week, for a browser opened now and then.
pub const ADD_VALID: u64 = 7 * 24 * 60 * 60 * 1000;

/// An invite into a group for a session of one of the identity's devices, held in the identity group.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename = "add")]
pub struct Add {
    /// The device: its key on the identity.
    pub device: Bytes,
    /// The session's handle; empty for the session that acts for the device, as a browser's.
    pub session: String,
    pub group: Bytes,
    pub kind: String,
    pub name: String,
    pub link: String,
    /// When the link expires, in milliseconds.
    pub expires: u64,
}

/// What a device tells its identity's other devices, live: the handles of its sessions that run, and the groups they are
/// in. A device of 0.14 tells no groups.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename = "presence")]
pub struct Presence {
    pub sessions: Vec<String>,
    #[serde(default)]
    pub groups: Vec<SessionGroup>,
}

/// A group one of a device's sessions is in, as that session shows it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionGroup {
    /// The session's handle; none for a browser's, its device's only session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    pub group: Bytes,
    pub name: String,
    /// Its kind and its other members, as they show to the session; empty where a session of 0.14 wrote them.
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub members: Vec<String>,
}

/// An add for this device, which its identity group keeps until it is taken: its position there, and the name of the
/// device that sent it.
pub struct Pending {
    pub position: u64,
    pub by: String,
    pub add: Add,
}

/// Keeps the device, as when it is renamed: its `device.json`, or a browser's record.
pub type Save = Arc<dyn Fn(&Device) -> Result<()> + Send + Sync>;

/// The identity kind, on a device's node.
pub struct Identity<P> {
    node: Node<P>,
    device: Device,
    save: Save,
    shared: Arc<Shared>,
}

#[derive(Default)]
struct Shared {
    /// Held while a pass of the duties runs.
    passing: tokio::sync::Mutex<()>,
    /// This device's sessions that run and their groups, as the session acting for it last found them.
    presence: Mutex<Presence>,
    /// What the other devices last told of theirs: by device key.
    heard: Mutex<HashMap<Bytes, Presence>>,
    /// The positions of the adds taken, until the log is let go of past them.
    taken: Mutex<BTreeSet<u64>>,
}

impl<P> Clone for Identity<P> {
    fn clone(&self) -> Self {
        Identity { node: self.node.clone(), device: self.device.clone(), save: self.save.clone(), shared: self.shared.clone() }
    }
}

impl<P: Provider + Send + 'static> Identity<P> {
    /// The identity kind on `node`, kept by `save`. Its duties run as each identity group's do (`Event::Duties`).
    pub fn new(node: Node<P>, device: Device, save: Save) -> Self {
        Identity { node, device, save, shared: Arc::default() }
    }

    /// The identity group of this device's identity, once it made or joined one, until it leaves it.
    fn group(&self) -> Option<Bytes> {
        self.node.groups().into_iter().find(|gid| self.node.settings(&gid.0).is_ok_and(|s| s.kind == IDENTITY) && !self.node.leaving(&gid.0))
    }

    /// The identity group, and the identity it is of.
    fn own(&self) -> Result<(Bytes, IdentityRef)> {
        let gid = self.group().context(NO_IDENTITY)?;
        let identity = self.identity_of(&gid.0).context("an identity group without a public log")?;
        Ok((gid, identity))
    }

    /// This device's name.
    pub fn name(&self) -> Option<String> {
        self.node.device_name()
    }

    /// This device's identity, with its name.
    pub fn identity(&self) -> Option<(IdentityRef, String)> {
        let (gid, identity) = self.own().ok()?;
        Some((identity, self.node.settings(&gid.0).ok()?.name))
    }

    /// The identity's devices: their keys and names.
    pub fn devices(&self) -> Result<Vec<(Bytes, String)>> {
        let gid = self.group().context(NO_IDENTITY)?;
        Ok(self.node.members(&gid.0)?.into_iter().map(|m| (m.key, m.name)).collect())
    }

    /// This device's key on its identity.
    pub fn key(&self) -> Result<Bytes> {
        Ok(self.node.key_in(&self.group().context(NO_IDENTITY)?.0))
    }

    /// Starts an identity, with this device its first, and its identity group.
    pub async fn create(&self, name: &str, membership: Service) -> Result<IdentityRef> {
        ensure!(self.group().is_none(), "this device is on an identity already: leave it first");
        let settings =
            Settings { protocol: PROTOCOL, kind: IDENTITY.into(), name: name.into(), carry: 7, update: UPDATE, membership, public: None, rest: Default::default() };
        let identity = self.node.create_identity(settings).await?;
        self.node.follow_log(&self.group().context(NO_IDENTITY)?.0, Some(0))?;
        Ok(identity)
    }

    /// A device link: whoever opens it becomes a device of the identity.
    pub async fn invite(&self) -> Result<String> {
        let gid = self.group().context(NO_IDENTITY)?;
        Ok(self.node.invite(&gid.0, None, crate::INVITE_VALID).await?.link())
    }

    /// Joins an identity through a device link, with a new device key. The identity's public log lists the device once a
    /// device it lists runs its duties.
    pub async fn join(&self, link: &Invite) -> Result<()> {
        ensure!(link.device, "not a device link");
        ensure!(self.group().is_none(), "this device is on an identity already: leave it first");
        let (gid, _) = self.node.join(link, None).await?;
        ensure!(self.node.settings(&gid.0)?.kind == IDENTITY, "the link led to a group, not an identity");
        self.node.follow_log(&gid.0, Some(0))
    }

    /// Hands an add to the device it names: a held message in the identity group.
    pub async fn deliver(&self, add: &Add) -> Result<()> {
        let gid = self.group().context(NO_IDENTITY)?;
        self.node.send(&gid.0, &serde_json::to_value(add)?).await?;
        Ok(())
    }

    /// The adds for this device that the identity group keeps, in log order, but those taken or expired; lets go of the
    /// log up to the first of them.
    pub fn adds(&self) -> Result<Vec<Pending>> {
        let Some(gid) = self.group() else { return Ok(Vec::new()) };
        let me = self.node.key_in(&gid.0);
        let (mut pending, mut passed) = (Vec::new(), None);
        {
            let taken = self.shared.taken.lock().unwrap();
            for item in self.node.entries(&gid.0, 0)? {
                let position = item.position();
                let add = match item {
                    Item::Entry(entry) => serde_json::from_value::<Add>(entry.payload)
                        .ok()
                        .filter(|add| add.device == me && now() < add.expires && !taken.contains(&position))
                        .map(|add| Pending { position, by: entry.from.name, add }),
                    Item::Lost(_) => None,
                };
                match add {
                    Some(add) => pending.push(add),
                    None if pending.is_empty() => passed = Some(position),
                    None => {}
                }
            }
        }
        if let Some(passed) = passed {
            self.node.follow_log(&gid.0, Some(passed))?;
        }
        Ok(pending)
    }

    /// Lets go of an add that was taken.
    pub fn take(&self, position: u64) -> Result<()> {
        self.shared.taken.lock().unwrap().insert(position);
        self.adds().map(drop)
    }

    /// Sets which of this device's sessions run and their groups, as the session acting for it found them; the identity's
    /// other devices online hear of a change.
    pub fn set_presence(&self, presence: Presence) {
        let mut own = self.shared.presence.lock().unwrap();
        if *own == presence {
            return;
        }
        *own = presence;
        drop(own);
        if let Some(gid) = self.group() {
            self.tell(&gid.0, None);
        }
    }

    /// The sessions a device runs and their groups, as last heard; this device's as last found.
    pub fn presence_of(&self, device: &Bytes) -> Presence {
        if self.key().is_ok_and(|me| me == *device) {
            return self.shared.presence.lock().unwrap().clone();
        }
        self.shared.heard.lock().unwrap().get(device).cloned().unwrap_or_default()
    }

    /// Tells the other devices online, or the one with key `to`, which of this device's sessions run, in which groups.
    fn tell(&self, gid: &[u8], to: Option<&Bytes>) {
        let presence = serde_json::to_value(&*self.shared.presence.lock().unwrap()).expect("JSON");
        let to = to.map(|key| hex(&Sha256::digest(&key.0)[..8]));
        if let Err(error) = self.node.send_live(gid, &presence, to.as_deref()) {
            tracing::debug!("telling which sessions run: {error:#}");
        }
    }

    /// Takes a device off the identity, then lists the identity's devices without it.
    pub async fn remove(&self, device: &[u8]) -> Result<()> {
        let gid = self.group().context(NO_IDENTITY)?;
        ensure!(device != self.node.key_in(&gid.0).0, "to take this device off its identity, leave it");
        self.node.remove(&gid.0, device).await?;
        self.duties(&gid.0).await
    }

    /// Takes this device off its identity. Listed on the identity's public log, it first lists the other devices, or as
    /// the only one closes the log, again while another device's publication moves the directory on meanwhile; then it
    /// asks the others to remove it, or, the only device, ends the identity. Returns whether it ended.
    pub async fn leave(&self) -> Result<bool> {
        let (gid, identity) = self.own()?;
        let me = self.node.key_in(&gid.0);
        loop {
            let predecessor = self.node.read_public(&identity).await?;
            if !predecessor.writers.contains(&me) {
                break;
            }
            self.node.inner.caught_up(&gid.0).await?;
            let others = self.node.members(&gid.0)?.into_iter().filter(|m| m.key != me).map(|m| m.key).collect();
            match self.node.publish(&gid.0, &predecessor, others).await {
                Err(error) if error.is::<crate::Advanced>() => continue,
                published => _ = published?,
            }
            break;
        }
        Ok(self.node.leave(&gid.0).await?.is_none())
    }

    /// Renames the identity in its private settings; sessions refresh their signed claims after catching up.
    pub async fn rename(&self, name: &str) -> Result<()> {
        let gid = self.group().context(NO_IDENTITY)?;
        self.node.change_settings(&gid.0, |settings| Settings { name: name.into(), ..settings }).await?;
        self.duties(&gid.0).await
    }

    /// Renames this device's record and its credential in its private identity group.
    pub async fn rename_device(&self, name: &str) -> Result<()> {
        let mut device = self.device.clone();
        device.name = name.into();
        (self.save)(&device)?;
        self.node.rename_device(name).await?;
        match self.group() {
            Some(gid) => self.duties(&gid.0).await,
            None => Ok(()),
        }
    }

    /// Runs the duties of an identity group in the background.
    fn due(&self, gid: &[u8]) {
        let (devices, gid) = (self.clone(), gid.to_vec());
        spawn(async move {
            if let Err(error) = devices.duties(&gid).await
                && devices.node.groups().iter().any(|group| group.0 == gid)
            {
                devices.node.inner.warn(Some(&gid), format!("the duties of an identity group: {error:#}"));
            }
        });
    }

    /// Derive the roster after reading its public predecessor and applying the private log, not merely receiving it;
    /// again while another device's publication moves the directory on meanwhile.
    pub async fn duties(&self, gid: &[u8]) -> Result<()> {
        let _passing = self.shared.passing.lock().await;
        let Some(identity) = self.identity_of(gid) else { return Ok(()) };
        loop {
            let latest = self.node.read_public(&identity).await?;
            self.node.inner.caught_up(gid).await?;
            let me = self.node.key_in(gid);
            if !latest.writers.contains(&me) {
                return Ok(());
            }
            let writers = self.node.members(gid)?.into_iter().map(|m| m.key).collect();
            match self.node.publish(gid, &latest, writers).await {
                Err(error) if error.is::<crate::Advanced>() => continue,
                published => return published.map(drop),
            }
        }
    }

    /// A certificate that the session with MLS key `key` is one of this device's, speaking as the identity: by this
    /// device's key on it.
    pub fn certify(&self, key: &[u8]) -> Result<Certificate> {
        let gid = self.group().context(NO_IDENTITY)?;
        let st = self.node.inner.lock();
        let g = st.group(&gid.0)?;
        let settings = g.mls.settings();
        let identity = IdentityRef { id: settings.public.context("an identity without a directory")?, membership: settings.membership };
        let (seed, session) = st.device_keys.get(&gid.0).context("not this device's identity")?;
        let own = g.mls.members().into_iter().find(|m| m.key == session.key()).context("not a member")?;
        let device_name = own.credential.context("not a letmeknow credential")?.name;
        let device = lmk_core::device::public(seed);
        let sig = lmk_core::device::sign(seed, &certified(key.try_into()?, identity.id.0.as_slice().try_into()?, &device, &settings.name, &device_name));
        Ok(Certificate { identity, device: device.into(), name: settings.name, device_name, sig: Bytes(sig) })
    }

    /// The identity whose identity group `gid` is.
    pub fn identity_of(&self, gid: &[u8]) -> Option<IdentityRef> {
        let settings = self.node.settings(gid).ok().filter(|settings| settings.kind == IDENTITY)?;
        Some(IdentityRef { id: settings.public?, membership: settings.membership })
    }

    /// Takes the events of identity groups, but for their members joining and leaving, adds kept (`Logged`) and
    /// warnings; returns every other event. Its duties run as the group's do, and as the identity's public log moves. A
    /// device that comes online hears which sessions this one runs.
    pub fn on(&self, event: Event) -> Option<Event> {
        if let Event::Public { identity } = &event {
            if let Ok((gid, own)) = self.own()
                && own.id == *identity
            {
                self.due(&gid.0);
            }
            return Some(event);
        }
        if let Event::Removed { kind, .. } = &event {
            return (kind != IDENTITY).then_some(event);
        }
        let Some(gid) = event.group().cloned() else { return Some(event) };
        if self.identity_of(&gid.0).is_none() {
            return Some(event);
        }
        match event {
            Event::Snapshot { reply, .. } => _ = reply.send(None),
            Event::Duties { .. } => self.due(&gid.0),
            Event::Synced { member, .. } => self.tell(&gid.0, Some(&member.key)),
            Event::Live { sender, payload, .. } => {
                if let Ok(presence) = serde_json::from_value(payload) {
                    self.shared.heard.lock().unwrap().insert(sender.key, presence);
                }
            }
            Event::Joined { .. } | Event::Left { .. } | Event::Settings { .. } | Event::Heard { .. } | Event::Logged { .. } | Event::Warning { .. } => return Some(event),
            _ => {}
        }
        None
    }
}

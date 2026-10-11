//! The devices kind, built in: an identity's devices group, whose members are its devices, each with its own device key
//! there, and whose settings carry the id of the identity's public log. A device certifies its sessions with its device
//! key, and keeps the public log in step with the group: a device the latest entry lists appends the next whenever the
//! group's members, their names or the group's name differ from it, and the latest again once it is half a year old.

use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use lmk_core::device::Device;
use lmk_core::provider::Provider;
use lmk_proto::Bytes;
use lmk_proto::group::{Certificate, DEVICES, IdentityRef, PROTOCOL, Service, Settings, UPDATE};
use lmk_proto::links::Invite;
use lmk_proto::public::{Listed, certified};
use n0_future::task::spawn;

use crate::{Event, Node, now};

/// How old the latest entry of an identity's public log grows before a device appends it again, in milliseconds.
const RESTATE: u64 = 182 * 24 * 60 * 60 * 1000;

const NO_IDENTITY: &str = "this device is on no identity";

/// Keeps the device, as when it is renamed: its `device.json`, or a browser's record.
pub type Save = Arc<dyn Fn(&Device) -> Result<()> + Send + Sync>;

/// The devices kind, on a device's node.
pub struct Devices<P> {
    node: Node<P>,
    device: Device,
    save: Save,
    /// Held while a pass of the duties runs.
    passing: Arc<tokio::sync::Mutex<()>>,
}

impl<P> Clone for Devices<P> {
    fn clone(&self) -> Self {
        Devices { node: self.node.clone(), device: self.device.clone(), save: self.save.clone(), passing: self.passing.clone() }
    }
}

impl<P: Provider + Send + 'static> Devices<P> {
    /// The devices kind on `node`, kept by `save`. Its duties run as each devices group's do (`Event::Duties`).
    pub fn new(node: Node<P>, device: Device, save: Save) -> Self {
        Devices { node, device, save, passing: Arc::default() }
    }

    /// The devices group of this device's identity, once it made or joined one, until it leaves it.
    fn group(&self) -> Option<Bytes> {
        self.node.groups().into_iter().find(|gid| self.node.settings(&gid.0).is_ok_and(|s| s.kind == DEVICES) && !self.node.leaving(&gid.0))
    }

    /// The devices group, and the identity it is of.
    fn own(&self) -> Result<(Bytes, IdentityRef)> {
        let gid = self.group().context(NO_IDENTITY)?;
        let identity = self.identity_of(&gid.0).context("a devices group without a public log")?;
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

    /// Starts an identity, with this device its first, and its devices group.
    pub async fn create(&self, name: &str, membership: Service) -> Result<IdentityRef> {
        ensure!(self.group().is_none(), "this device is on an identity already: leave it first");
        let settings =
            Settings { protocol: PROTOCOL, kind: DEVICES.into(), name: name.into(), carry: 7, update: UPDATE, membership, public: None, rest: Default::default() };
        self.node.create_identity(settings).await
    }

    /// A device link: whoever opens it becomes a device of the identity.
    pub async fn invite(&self) -> Result<String> {
        let gid = self.group().context(NO_IDENTITY)?;
        Ok(self.node.invite(&gid.0, None).await?.link())
    }

    /// Joins an identity through a device link, with a new device key. The identity's public log lists the device once a
    /// device it lists runs its duties.
    pub async fn join(&self, link: &Invite) -> Result<()> {
        ensure!(link.device, "not a device link");
        ensure!(self.group().is_none(), "this device is on an identity already: leave it first");
        let (gid, _) = self.node.join(link, None).await?;
        ensure!(self.node.settings(&gid.0)?.kind == DEVICES, "the link led to a group, not an identity");
        Ok(())
    }

    /// Takes a device off the identity, then lists the identity's devices without it.
    pub async fn remove(&self, device: &[u8]) -> Result<()> {
        let gid = self.group().context(NO_IDENTITY)?;
        ensure!(device != self.node.key_in(&gid.0).0, "to take this device off its identity, leave it");
        self.node.remove(&gid.0, device).await?;
        self.duties(&gid.0).await
    }

    /// Takes this device off its identity. Listed on the identity's public log, it first lists the other devices, or as
    /// the only one closes the log; then it asks the others to remove it, or, the only device, ends the identity. Returns
    /// whether it ended.
    pub async fn leave(&self) -> Result<bool> {
        let (gid, identity) = self.own()?;
        let me = self.node.key_in(&gid.0);
        if self.node.read_public(&identity).await?.writers.iter().any(|writer| writer.key == me) {
            let others = self.node.members(&gid.0)?.into_iter().filter(|m| m.key != me).map(|m| Listed { key: m.key, name: m.name }).collect();
            self.node.publish(&gid.0, others, &self.node.settings(&gid.0)?.name).await?;
        }
        Ok(self.node.leave(&gid.0).await?.is_none())
    }

    /// Renames this device: its record, and its credential in its devices group, whose public log then lists it so.
    pub async fn rename(&self, name: &str) -> Result<()> {
        let mut device = self.device.clone();
        device.name = name.into();
        (self.save)(&device)?;
        self.node.rename_device(name).await?;
        match self.group() {
            Some(gid) => self.duties(&gid.0).await,
            None => Ok(()),
        }
    }

    /// Runs the duties of a devices group in the background.
    fn due(&self, gid: &[u8]) {
        let (devices, gid) = (self.clone(), gid.to_vec());
        spawn(async move {
            if let Err(error) = devices.duties(&gid).await {
                tracing::debug!("the duties of a devices group: {error:#}");
            }
        });
    }

    /// The duties of a devices group, as it and the identity's public log stand, each read afresh: a device the latest
    /// entry lists appends the next, listing the group's members by their names under the group's name, when that
    /// differs from the latest, and the latest again once it is `RESTATE` old.
    pub async fn duties(&self, gid: &[u8]) -> Result<()> {
        let _passing = self.passing.lock().await;
        let Some(identity) = self.identity_of(gid) else { return Ok(()) };
        let latest = self.node.read_public(&identity).await?;
        self.node.read_group(gid).await?;
        let me = self.node.key_in(gid);
        if !latest.writers.iter().any(|writer| writer.key == me) {
            return Ok(());
        }
        let mut writers: Vec<Listed> = self.node.members(gid)?.into_iter().map(|m| Listed { key: m.key, name: m.name }).collect();
        writers.sort();
        let mut listed = latest.writers.clone();
        listed.sort();
        let name = self.node.settings(gid)?.name;
        if writers != listed || name != latest.name || latest.at + RESTATE <= now() {
            self.node.publish(gid, writers, &name).await?;
        }
        Ok(())
    }

    /// A certificate that the session with MLS key `key` is one of this device's, speaking as the identity: by this
    /// device's key on it.
    pub fn certify(&self, key: &[u8]) -> Result<Certificate> {
        let (gid, identity) = self.own()?;
        let sig = self.node.sign(&gid.0, &certified(key, &identity.id.0))?;
        Ok(Certificate { identity, device: self.node.key_in(&gid.0), sig: Bytes(sig) })
    }

    /// The identity whose devices group `gid` is.
    pub fn identity_of(&self, gid: &[u8]) -> Option<IdentityRef> {
        let settings = self.node.settings(gid).ok().filter(|settings| settings.kind == DEVICES)?;
        Some(IdentityRef { id: settings.public?, membership: settings.membership })
    }

    /// Takes the events of devices groups, but for their members joining and leaving and warnings; returns every other
    /// event. Its duties run as the group's do, and as the identity's public log moves.
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
            return (kind != DEVICES).then_some(event);
        }
        let Some(gid) = event.group().cloned() else { return Some(event) };
        if self.identity_of(&gid.0).is_none() {
            return Some(event);
        }
        match event {
            Event::Snapshot { reply, .. } => _ = reply.send(None),
            Event::Duties { .. } => self.due(&gid.0),
            Event::Joined { .. } | Event::Left { .. } | Event::Warning { .. } => return Some(event),
            _ => {}
        }
        None
    }
}

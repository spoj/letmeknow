//! Test doubles for the group logic, the peers and the membership service: one in-memory world that several sessions
//! share. Commits are JSON naming the epoch they build on, so the log's first valid commit per epoch wins as in MLS.

use anyhow::{Context, Result, bail, ensure};
use lmk_proto::Answer;
use lmk_proto::Bytes;
use lmk_proto::group::{How, IdentityRef, Opening, Payload, Service, Settings};
use lmk_proto::links::{FileLink, Invite};
use lmk_proto::peer::{Admitted, InviteRequest};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

use crate::node::{Applied, Change, Commit, Contact, Core, Delivery, DeviceList, Inbound, Log, Member, Op, Opened, Peers};

#[derive(Default)]
pub struct World {
    pub nodes: HashMap<Bytes, Node>,
    logs: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    followers: HashMap<Vec<u8>, Vec<mpsc::UnboundedSender<Inbound>>>,
    files: HashMap<[u8; 32], Vec<u8>>,
    holders: HashMap<[u8; 32], HashSet<Bytes>>,
    /// Members that refuse every message, with the reason.
    pub refuse: HashMap<Bytes, String>,
    /// While set, files reach no one until `release_files`.
    pub hold_files: bool,
    wanted: Vec<(Bytes, [u8; 32])>,
}

/// One session, by its iroh key.
pub struct Node {
    pub me: Member,
    pub inbound: mpsc::UnboundedSender<Inbound>,
    pub online: bool,
    groups: HashMap<Vec<u8>, Group>,
    pending: HashMap<Vec<u8>, Vec<u8>>,
    pub identities: Vec<(IdentityRef, String)>,
    pub contacts: Vec<Contact>,
    pub openings: Vec<Opening>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Group {
    settings: Settings,
    members: Vec<Member>,
    epoch: u64,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    group: Vec<u8>,
    epoch: u64,
    by: Bytes,
    op: Op,
    nonce: u64,
}

#[derive(Serialize, Deserialize)]
struct Welcome {
    group: Vec<u8>,
    state: Group,
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    sender: Bytes,
    epoch: u64,
    payload: Payload,
    nonce: u64,
}

pub type Shared = Arc<Mutex<World>>;

impl World {
    /// Adds a session to the world; returns its parts.
    pub fn join(world: &Shared, me: Member, inbound: mpsc::UnboundedSender<Inbound>) -> (FakeCore, FakePeers, FakeLog) {
        let iroh = me.iroh.clone();
        let node = Node {
            me,
            inbound: inbound.clone(),
            online: true,
            groups: HashMap::new(),
            pending: HashMap::new(),
            identities: Vec::new(),
            contacts: Vec::new(),
            openings: Vec::new(),
        };
        world.lock().unwrap().nodes.insert(iroh.clone(), node);
        (FakeCore(world.clone(), iroh.clone()), FakePeers(world.clone(), iroh), FakeLog(world.clone(), inbound))
    }

    /// Lets every file that was asked for reach whoever asked.
    pub fn release_files(world: &Shared) {
        let mut world = world.lock().unwrap();
        world.hold_files = false;
        for (iroh, hash) in std::mem::take(&mut world.wanted) {
            world.holders.entry(hash).or_default().insert(iroh.clone());
            let _ = world.nodes[&iroh].inbound.send(Inbound::File { hash });
        }
    }

    fn members_online(&self, group: &[u8], me: &Bytes) -> Vec<Bytes> {
        self.nodes
            .iter()
            .filter(|(iroh, node)| *iroh != me && node.online && node.groups.contains_key(group))
            .map(|(iroh, _)| iroh.clone())
            .collect()
    }
}

fn nonce() -> u64 {
    rand::random()
}

pub struct FakeCore(Shared, Bytes);

impl FakeCore {
    fn with<T>(&self, f: impl FnOnce(&mut Node) -> T) -> T {
        f(self.0.lock().unwrap().nodes.get_mut(&self.1).unwrap())
    }

    fn group(&self, group: &[u8]) -> Result<Group> {
        self.with(|node| node.groups.get(group).cloned()).context("not in that group")
    }
}

impl Core for FakeCore {
    fn key(&self) -> Bytes {
        self.with(|node| node.me.key.clone())
    }

    fn groups(&self) -> Vec<Bytes> {
        let mut groups: Vec<Bytes> = self.with(|node| node.groups.keys().map(|g| Bytes(g.clone())).collect());
        groups.sort();
        groups
    }

    fn create(&mut self, settings: Settings, _: Option<&Bytes>) -> Result<Bytes> {
        let gid = rand::random::<[u8; 16]>().to_vec();
        self.with(|node| node.groups.insert(gid.clone(), Group { settings, members: vec![node.me.clone()], epoch: 0 }));
        Ok(Bytes(gid))
    }

    fn key_package(&mut self, _: Option<&Bytes>) -> Result<Bytes> {
        Ok(Bytes(serde_json::to_vec(&self.with(|node| node.me.clone()))?))
    }

    fn inspect(&self, key_package: &[u8]) -> Result<Member> {
        Ok(serde_json::from_slice(key_package)?)
    }

    fn join(&mut self, welcome: &[u8]) -> Result<Bytes> {
        let welcome: Welcome = serde_json::from_slice(welcome)?;
        self.with(|node| node.groups.insert(welcome.group.clone(), welcome.state));
        Ok(Bytes(welcome.group))
    }

    fn settings(&self, group: &[u8]) -> Result<Settings> {
        Ok(self.group(group)?.settings)
    }

    fn members(&self, group: &[u8]) -> Result<Vec<Member>> {
        Ok(self.group(group)?.members)
    }

    fn commit(&mut self, group: &[u8], op: Op) -> Result<Commit> {
        let state = self.group(group)?;
        let by = self.key();
        let entry = serde_json::to_vec(&Entry { group: group.to_vec(), epoch: state.epoch, by: by.clone(), op: op.clone(), nonce: nonce() })?;
        let welcome = match op {
            Op::Add(key_package) => {
                let mut state = state.clone();
                let mut member: Member = serde_json::from_slice(&key_package.0)?;
                member.added = Some((by, How::Invite));
                state.members.push(member);
                state.epoch += 1;
                Some(serde_json::to_vec(&Welcome { group: group.to_vec(), state })?)
            }
            _ => None,
        };
        self.with(|node| node.pending.insert(group.to_vec(), entry.clone()));
        Ok(Commit { entry, welcome })
    }

    fn apply(&mut self, group: &[u8], bytes: &[u8]) -> Result<Applied> {
        let entry: Entry = serde_json::from_slice(bytes)?;
        let mut state = self.group(group)?;
        if entry.epoch != state.epoch || !state.members.iter().any(|m| m.key == entry.by) {
            return Ok(Applied::Skipped);
        }
        state.epoch += 1;
        let me = self.key();
        let changes = match entry.op {
            Op::Add(key_package) => {
                let mut member: Member = serde_json::from_slice(&key_package.0)?;
                member.added = Some((entry.by.clone(), How::Invite));
                state.members.push(member.clone());
                vec![Change::Joined { member, by: entry.by.clone(), how: How::Invite }]
            }
            Op::Remove(key) => {
                let at = state.members.iter().position(|m| m.key == key).context("no such member")?;
                let member = state.members.remove(at);
                match key == me {
                    true => vec![Change::Removed { by: entry.by.clone() }],
                    false => vec![Change::Left { member, by: entry.by.clone() }],
                }
            }
            Op::Update => vec![Change::KeyUpdate],
            Op::Settings(settings) => {
                state.settings = settings.clone();
                vec![Change::Settings { settings, by: entry.by.clone() }]
            }
        };
        let own = self.with(|node| {
            node.groups.insert(group.to_vec(), state);
            node.pending.remove(group).is_some_and(|pending| pending == bytes)
        });
        Ok(if own { Applied::Own(changes) } else { Applied::Commit(changes) })
    }

    fn seal(&mut self, group: &[u8], payload: &Payload) -> Result<Vec<u8>> {
        let epoch = self.group(group)?.epoch;
        Ok(serde_json::to_vec(&Sealed { sender: self.key(), epoch, payload: payload.clone(), nonce: nonce() })?)
    }

    fn open(&mut self, group: &[u8], ciphertext: &[u8]) -> Result<Opened> {
        self.group(group)?;
        let sealed: Sealed = serde_json::from_slice(ciphertext)?;
        Ok(Opened { sender: sealed.sender, epoch: sealed.epoch, payload: sealed.payload })
    }

    fn forget(&mut self, group: &[u8]) -> Result<()> {
        self.with(|node| node.groups.remove(group));
        Ok(())
    }

    fn identities(&self) -> Result<Vec<(IdentityRef, String)>> {
        Ok(self.with(|node| node.identities.clone()))
    }

    fn identity_create(&mut self, name: &str, membership: Service) -> Result<(IdentityRef, Vec<u8>)> {
        let identity = IdentityRef { id: Bytes(rand::random::<[u8; 32]>().to_vec()), membership };
        self.with(|node| node.identities.push((identity.clone(), name.to_owned())));
        let (device, device_name) = self.device();
        Ok((identity, serde_json::to_vec(&(name, Some(device_name), device))?))
    }

    fn identity_entry(&mut self, _: &[u8], add: Option<&str>, device: &[u8], _: &[Vec<u8>]) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&("", add, Bytes(device.to_vec())))?)
    }

    fn device_list(&self, _: &[u8], log: &[Vec<u8>]) -> Result<DeviceList> {
        let mut list = DeviceList { name: String::new(), devices: Vec::new() };
        for entry in log {
            let (name, add, device): (String, Option<String>, Bytes) = serde_json::from_slice(entry)?;
            if list.name.is_empty() {
                list.name = name;
            }
            match add {
                Some(device_name) => list.devices.push((device, device_name)),
                None => list.devices.retain(|(d, _)| *d != device),
            }
        }
        Ok(list)
    }

    fn device(&self) -> (Bytes, String) {
        self.with(|node| (node.me.device.clone(), node.me.device_name.clone()))
    }

    fn contacts(&self) -> Result<Vec<Contact>> {
        Ok(self.with(|node| node.contacts.clone()))
    }

    fn set_contact(&mut self, contact: Contact) -> Result<()> {
        self.with(|node| {
            node.contacts.retain(|c| c.id != contact.id);
            node.contacts.push(contact);
        });
        Ok(())
    }

    fn openings(&self) -> Result<Vec<Opening>> {
        Ok(self.with(|node| node.openings.clone()))
    }
}

pub struct FakeLog(Shared, mpsc::UnboundedSender<Inbound>);

impl Log for FakeLog {
    async fn append(&self, _: &Service, log: &[u8], entry: &[u8]) -> Result<u64> {
        let mut world = self.0.lock().unwrap();
        let entries = world.logs.entry(log.to_vec()).or_default();
        entries.push(entry.to_vec());
        let position = entries.len() as u64;
        for follower in world.followers.get(log).into_iter().flatten() {
            let _ = follower.send(Inbound::Entry { log: Bytes(log.to_vec()), position, entry: entry.to_vec() });
        }
        Ok(position)
    }

    async fn read(&self, _: &Service, log: &[u8], after: u64) -> Result<Vec<Vec<u8>>> {
        let world = self.0.lock().unwrap();
        Ok(world.logs.get(log).map(|entries| entries[after as usize..].to_vec()).unwrap_or_default())
    }

    fn follow(&self, _: &Service, log: &[u8]) {
        self.0.lock().unwrap().followers.entry(log.to_vec()).or_default().push(self.1.clone());
    }
}

pub struct FakePeers(Shared, Bytes);

impl Peers for FakePeers {
    fn address(&self) -> (Bytes, String) {
        (self.1.clone(), crate::RELAY.into())
    }

    async fn send(&self, group: &[u8], ciphertext: &[u8]) -> Delivery {
        let world = self.0.lock().unwrap();
        let mut delivery = Delivery::default();
        for iroh in world.members_online(group, &self.1) {
            match world.refuse.get(&iroh) {
                Some(reason) => delivery.refused.push((iroh, reason.clone())),
                None => {
                    let message = Inbound::Message { group: Bytes(group.to_vec()), ciphertext: ciphertext.to_vec() };
                    let _ = world.nodes[&iroh].inbound.send(message);
                    delivery.held.push(iroh);
                }
            }
        }
        delivery
    }

    fn commit(&self, _: &[u8], _: &[u8]) {}

    fn online(&self, group: &[u8]) -> Vec<Bytes> {
        self.0.lock().unwrap().members_online(group, &self.1)
    }

    async fn redeem(&self, invite: &Invite, request: &InviteRequest) -> Result<Answer<Admitted>> {
        let (reply, answer) = oneshot::channel();
        let inviter = self.0.lock().unwrap().nodes.get(&Bytes(invite.key.to_vec())).context("no such inviter")?.inbound.clone();
        inviter.send(Inbound::Invite { request: request.clone(), reply })?;
        Ok(answer.await?)
    }

    async fn ask_to_join(&self, opening: &Opening, key_package: &[u8]) -> Result<Answer<Admitted>> {
        let (reply, answer) = oneshot::channel();
        let member = {
            let world = self.0.lock().unwrap();
            let online = opening.members.iter().find(|iroh| world.nodes.get(*iroh).is_some_and(|n| n.online));
            world.nodes[online.context("no member online")?].inbound.clone()
        };
        member.send(Inbound::Join { group: opening.group.clone(), key_package: Bytes(key_package.to_vec()), reply })?;
        Ok(answer.await?)
    }

    fn add_file(&self, _: &[u8], bytes: &[u8]) -> Result<FileLink> {
        let mut world = self.0.lock().unwrap();
        let hash: [u8; 32] = rand::random();
        world.files.insert(hash, bytes.to_vec());
        world.holders.entry(hash).or_default().insert(self.1.clone());
        Ok(FileLink { hash, size: bytes.len() as u64, key: [7; 32] })
    }

    fn file(&self, link: &FileLink) -> Result<Option<Vec<u8>>> {
        let world = self.0.lock().unwrap();
        ensure!(link.key == [7; 32], "wrong key");
        let held = world.holders.get(&link.hash).is_some_and(|h| h.contains(&self.1));
        Ok(held.then(|| world.files[&link.hash].clone()))
    }

    fn want(&self, _: &[u8], link: &FileLink) {
        let mut world = self.0.lock().unwrap();
        world.wanted.push((self.1.clone(), link.hash));
        if !world.hold_files {
            drop(world);
            World::release_files(&self.0);
        }
    }

    async fn spread(&self, group: &[u8], link: &FileLink) -> Vec<Bytes> {
        let mut world = self.0.lock().unwrap();
        if world.hold_files {
            return Vec::new();
        }
        let online = world.members_online(group, &self.1);
        world.holders.entry(link.hash).or_default().extend(online.iter().cloned());
        online
    }
}

/// A member as a fake session presents itself.
pub fn member(name: &str, identity: Option<IdentityRef>, identity_name: &str) -> Member {
    let key = Bytes(rand::random::<[u8; 32]>().to_vec());
    let claim = identity.map(|identity| crate::node::Claim { identity, name: identity_name.into(), error: None, added_by_device: None });
    Member {
        iroh: Bytes(rand::random::<[u8; 32]>().to_vec()),
        key,
        name: name.into(),
        device: Bytes(rand::random::<[u8; 32]>().to_vec()),
        device_name: format!("{name}'s laptop"),
        identity: claim,
        added: None,
    }
}

pub fn set_online(world: &Shared, member: &Member, online: bool) -> Result<()> {
    match world.lock().unwrap().nodes.get_mut(&member.iroh) {
        Some(node) => node.online = online,
        None => bail!("no such node"),
    }
    Ok(())
}

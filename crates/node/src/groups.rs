//! What the peers need from the group logic (`Groups`), what an inviter decides (`Admit`), and taking in a message.

use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::VerifyingKey;
use iroh::EndpointId;
use lmk_core::group::{self as core, Change, Removed, Unheld, key_package_credential, key_package_leaf};
use lmk_core::identity::{DeviceList, Verdict, check};
use lmk_core::invite::Target;
use lmk_core::provider::Provider;
use lmk_membership::Chain;
use lmk_net::{Admit, Groups, Taken};
use lmk_proto::group::{CHAT, ContactsUpdate, Control, How, Reason, Refusal, Service, type_of};
use lmk_proto::head::{self, Head};
use lmk_proto::links::FileLink;
use lmk_proto::peer::{Admitted, Frame, Hello, InviteRequest, KindFrame, List};
use lmk_proto::{Answer, Bytes};
use n0_future::boxed::BoxFuture;
use n0_future::time::timeout;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::{
    Event, Inner, Item, MAX_MESSAGE, Message, SNAPSHOT_WAIT, State, Work, ciphertext_key, doc_key, endpoint_id, entry_key,
    get, message_key, now, put, yjs,
};

/// A head that needs no signature: the empty log's.
fn empty(log: &[u8]) -> Head {
    Head { log: log.into(), length: 0, hash: head::start(log).into(), time: 0, sig: Bytes::default() }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Takes in a ciphertext from a peer: held, waiting for a commit, or given up.
    pub(crate) fn take(&self, st: &mut State<P>, gid: &[u8], ciphertext: &[u8]) -> Taken {
        let id: [u8; 32] = Sha256::digest(ciphertext).into();
        let Ok(g) = st.group_mut(gid) else { return Taken::Refused };
        if g.rec.items.iter().any(|item| item.id.0 == id) {
            return Taken::Held;
        }
        if g.rec.given_up.iter().any(|(_, given)| given.0 == id) {
            return Taken::Refused;
        }
        let Ok(epoch) = core::epoch_of(ciphertext) else { return Taken::Refused };
        let opened = if ciphertext.len() > MAX_MESSAGE {
            Err(Reason::Size)
        } else if epoch > g.mls.epoch() {
            if !g.future.iter().any(|waiting| waiting == ciphertext) {
                g.future.push(ciphertext.to_vec());
            }
            self.work.send(Work::Read(gid.to_vec())).ok();
            return Taken::Waiting;
        } else {
            self.open(st, gid, ciphertext, id, epoch).map_err(|error| {
                tracing::debug!("a message did not open: {error:#}");
                if error.is::<Unheld>() {
                    Reason::Old
                } else if error.is::<Removed>() {
                    Reason::Removed
                } else {
                    Reason::Unreadable
                }
            })
        };
        match opened {
            Ok(()) => Taken::Held,
            Err(reason) => {
                self.give_up(st, gid, epoch, id, reason);
                self.save(st, gid);
                Taken::Refused
            }
        }
    }

    fn save(&self, st: &State<P>, gid: &[u8]) {
        if let Err(error) = st.save(gid) {
            self.warn(Some(gid), format!("{error:#}"));
        }
    }

    /// Records a message as given up, and reports it unless it is from before this session joined or as old as one
    /// it held and dropped after `keep`. The first given up since the last report has the next one sent in a moment.
    fn give_up(&self, st: &mut State<P>, gid: &[u8], epoch: u64, id: [u8; 32], reason: Reason) {
        let g = st.groups.get_mut(gid).unwrap();
        g.rec.given_up.push((epoch, Bytes(id.to_vec())));
        if epoch >= g.mls.joined() && epoch > g.rec.expired {
            if g.rec.unreported.is_empty() {
                self.work.send(Work::Report(gid.to_vec())).ok();
            }
            g.rec.unreported.push(Refusal { id: Bytes(id.to_vec()), reason });
        }
    }

    fn open(&self, st: &mut State<P>, gid: &[u8], ciphertext: &[u8], id: [u8; 32], epoch: u64) -> Result<()> {
        let g = st.groups.get_mut(gid).unwrap();
        let opened = g.mls.open(&st.provider, ciphertext, now())?;
        let sender = g.mls.members().into_iter().find(|m| m.key == opened.key).unwrap_or(core::Member {
            index: opened.index,
            key: opened.key.clone(),
            credential: Some(opened.sender.clone()),
            leaf: None,
        });
        let sender = st.member(gid, &sender).context("the sender has no letmeknow credential")?;
        let group = Bytes(gid.to_vec());
        let payload = opened.payload;
        if Control::TYPES.contains(&type_of(&payload)) {
            match serde_json::from_value(payload.clone())? {
                Control::Leave => {
                    if opened.current.is_some() {
                        self.work.send(Work::Remove { group: gid.to_vec(), key: opened.key.clone() }).ok();
                    }
                    hold(st, gid, Message { id: Bytes(id.to_vec()), group, epoch, at: now(), sender, payload }, ciphertext)?;
                }
                Control::Introduce { identity, name, how, to } => {
                    let me = Bytes(Sha256::digest(st.session.key())[..8].to_vec());
                    if to.is_empty() || to.contains(&me) {
                        self.events.send(Event::Introduced { group, by: sender, identity, name, how }).ok();
                    }
                }
                Control::Refused { messages } => {
                    let held = Message { id: Bytes(id.to_vec()), group: group.clone(), epoch, at: now(), sender: sender.clone(), payload };
                    hold(st, gid, held, ciphertext)?;
                    let peer = endpoint_id(&sender.iroh.0);
                    let mut own = Vec::new();
                    for refusal in messages {
                        let Ok(sent) = <[u8; 32]>::try_from(&refusal.id.0[..]) else { continue };
                        if let (Some(waiter), Some(peer)) = (st.waiters.get(&sent), peer) {
                            waiter.send((peer, Some(refusal.reason))).ok();
                        } else if get::<Message>(&st.provider, &message_key(&sent))?.is_some_and(|m| m.sender.key.0 == st.session.key()) {
                            own.push(refusal);
                        }
                    }
                    if !own.is_empty() {
                        self.events.send(Event::Refused { group, by: sender, messages: own }).ok();
                    }
                }
            }
        } else if st.devices(gid) {
            let (ContactsUpdate::Edit { update } | ContactsUpdate::Diff { update }) = serde_json::from_value(payload)?;
            let state = yjs::apply(&st.contacts_state(gid)?, &update.0)?;
            st.provider.put(&doc_key(gid), &state)?;
        } else if opened.held {
            let message = Message { id: Bytes(id.to_vec()), group, epoch, at: now(), sender, payload };
            hold(st, gid, message.clone(), ciphertext)?;
            self.events.send(Event::Message(message)).ok();
        } else {
            self.events.send(Event::Live { group, sender, payload }).ok();
        }
        Ok(())
    }

    /// Answers an invite stream's request.
    async fn redeemed(self: &Arc<Self>, request: InviteRequest) -> Result<Admitted> {
        let (secret, key_package, now) = (request.secret.0, request.key_package.0, now());
        let (joiner, bound) = {
            let st = self.state.lock().unwrap();
            let (joiner, _) = key_package_credential(&st.provider, &key_package)?;
            (joiner, st.invites.bound(&secret, now).is_some())
        };
        let list = match (bound, &joiner.identity) {
            (true, Some(identity)) => self.list(identity).await.ok(),
            _ => None,
        };
        let redeemed = {
            let mut st = self.state.lock().unwrap();
            let st = &mut *st;
            st.invites.redeem(&st.provider, &secret, &key_package, list.as_ref(), now)?
        };
        match redeemed.target {
            Target::Group(gid) => self.admit(&gid, key_package, How::Invite, redeemed.label).await,
            Target::Device(id) => {
                let identity = {
                    let st = self.state.lock().unwrap();
                    st.device.identities.iter().find(|identity| identity.id.0 == id).cloned()
                };
                let identity = identity.context("this device left the identity")?;
                let list = self.list(&identity).await?;
                let entry = list.add(
                    &self.state.lock().unwrap().device,
                    &redeemed.joiner.device.0,
                    &redeemed.joiner.device_name,
                );
                self.logs.client(&identity.membership)?.append(&lmk_proto::identity::address(&id), &entry).await?;
                self.list(&identity).await?;
                let gid = self.state.lock().unwrap().devices_group(&id).context("no devices group")?;
                self.admit(&gid, key_package, How::Invite, None).await
            }
        }
    }

    /// Answers a request to join a group open to the joiner's identity.
    async fn open_join(self: &Arc<Self>, gid: &[u8], key_package: Vec<u8>) -> Result<Admitted> {
        let (joiner, key, open) = {
            let st = self.state.lock().unwrap();
            let (joiner, key) = key_package_credential(&st.provider, &key_package)?;
            (joiner, key, st.group(gid)?.mls.settings().open)
        };
        let identity = joiner.identity.clone().filter(|identity| open.iter().any(|named| named.id == identity.id));
        let identity = identity.context("it speaks as no identity the group is open to")?;
        let list = self.list(&identity).await?;
        ensure!(
            check(&joiner, &key, Some(&list)) == Verdict::Verified,
            "its device is not on its identity's device list"
        );
        self.admit(gid, key_package, How::Open, None).await
    }

    /// Commits the Add, and answers with the Welcome and the state of the group's kind, or of its contacts, as a file.
    /// A joiner whose session does not support the group's kind is refused.
    async fn admit(
        self: &Arc<Self>,
        gid: &[u8],
        key_package: Vec<u8>,
        how: How,
        label: Option<String>,
    ) -> Result<Admitted> {
        {
            let mut st = self.state.lock().unwrap();
            let kind = st.group(gid)?.mls.settings().kind;
            let leaf = key_package_leaf(&st.provider, &key_package)?;
            ensure!(leaf.kinds.contains(&kind), "its session does not support {kind} groups");
            if let Some(label) = label {
                let (_, key) = key_package_credential(&st.provider, &key_package)?;
                st.labels.insert(key, label);
            }
        }
        let add = Change { add: vec![key_package], how: Some(how), ..Change::default() };
        let (welcome, position) = self.commit(gid, |_| Ok(add.clone())).await?;
        let (state, before) = {
            let st = self.state.lock().unwrap();
            let g = st.group(gid)?;
            let before = g.rec.items.iter().filter(|item| item.epoch < g.mls.epoch()).map(|item| item.id.clone()).collect();
            let state = match (st.devices(gid), g.mls.settings().kind == CHAT) {
                (true, _) => Ok(st.contacts_state(gid)?),
                (false, true) => Err(None),
                (false, false) => {
                    let (reply, state) = oneshot::channel();
                    self.events.send(Event::Snapshot { group: Bytes(gid.to_vec()), reply }).ok();
                    Err(Some(state))
                }
            };
            (state, before)
        };
        let state = match state {
            Ok(state) => Some(state),
            Err(None) => None,
            Err(Some(asked)) => timeout(SNAPSHOT_WAIT, asked).await.ok().and_then(Result::ok).flatten(),
        };
        let doc = match state {
            Some(state) => Some(self.state_file(gid, state).await?),
            None => None,
        };
        Ok(Admitted { welcome: Bytes(welcome.context("an add makes a Welcome")?), position, doc, before })
    }

    fn answer(&self, group: Option<&[u8]>, admitted: Result<Admitted>) -> Answer<Admitted> {
        match admitted {
            Ok(admitted) => Answer::Ok(admitted),
            Err(error) => {
                self.warn(group, format!("refused a join: {error:#}"));
                Answer::Refused { refused: format!("{error:#}") }
            }
        }
    }
}

impl<P: Provider + Send + 'static> Groups for Inner<P> {
    fn groups(&self) -> Vec<Vec<u8>> {
        self.state.lock().unwrap().groups.keys().cloned().collect()
    }

    fn is_member(&self, group: &[u8], peer: &EndpointId) -> bool {
        let st = self.state.lock().unwrap();
        st.groups.get(group).is_some_and(|g| {
            g.mls.members().iter().any(|m| m.leaf.as_ref().is_some_and(|leaf| leaf.key.0 == peer.as_bytes()))
        })
    }

    fn hello(&self, group: &[u8]) -> Hello {
        let st = self.state.lock().unwrap();
        let Some(g) = st.groups.get(group) else {
            return Hello { group: group.into(), epoch: 0, head: empty(group), floor: 0, joined: 0, log: None, all: true };
        };
        let (epoch, joined) = (g.mls.epoch(), g.mls.joined());
        let head = g.rec.chain.as_ref().map_or_else(|| empty(group), |chain| chain.head.clone());
        let floor = joined.max(epoch.saturating_sub(self.window.epochs as u64));
        let log = g.rec.log.as_ref().and_then(|log| Some(log.chain.as_ref()?.head.clone()));
        Hello { group: group.into(), epoch, head, floor, joined, log, all: true }
    }

    fn verify_head(&self, group: &[u8], head: &Head) -> bool {
        if *head == empty(group) || head.length == 0 && head.hash.0 == head::start(group) {
            return true;
        }
        let st = self.state.lock().unwrap();
        let Some(g) = st.groups.get(group) else {
            return false;
        };
        match g.mls.settings().membership {
            Service::Serve { key, .. } => {
                let key: Option<[u8; 32]> = key.0.try_into().ok();
                key.and_then(|key| VerifyingKey::from_bytes(&key).ok()).is_some_and(|key| head.verify(&key))
            }
            Service::Folder(_) => true,
        }
    }

    fn chain(&self, group: &[u8], position: u64) -> Option<[u8; 32]> {
        let st = self.state.lock().unwrap();
        st.groups.get(group)?.rec.chain.as_ref()?.hash_at(position)
    }

    fn entries(&self, group: &[u8], after: u64) -> Vec<Bytes> {
        let st = self.state.lock().unwrap();
        let Some(g) = st.groups.get(group) else {
            return Vec::new();
        };
        (after + 1..=g.rec.logged)
            .filter_map(|position| st.provider.get(&entry_key(group, position)).ok()?.map(Bytes))
            .collect()
    }

    fn apply(&self, group: &[u8], entries: Vec<Bytes>, head: Head) -> Result<()> {
        let (after, chain) = {
            let st = self.state.lock().unwrap();
            let g = st.group(group)?;
            let mut chain: Chain = g.rec.chain.clone().context("no chain of the group's log yet")?;
            let after = chain.length();
            chain.extend(after, &entries, &head)?;
            self.logs.client(&g.mls.settings().membership)?.set_chain(chain.clone());
            (after, chain)
        };
        self.logged(group, after, entries, Some(chain))
    }

    fn items(&self, group: &[u8], from: u64) -> Vec<(u64, [u8; 32])> {
        let st = self.state.lock().unwrap();
        let Some(g) = st.groups.get(group) else {
            return Vec::new();
        };
        let held = g.rec.items.iter().map(|item| (item.epoch, &item.id));
        let given_up = g.rec.given_up.iter().map(|(epoch, id)| (*epoch, id));
        held.chain(given_up)
            .filter(|(epoch, _)| *epoch >= from)
            .filter_map(|(epoch, id)| Some((epoch, id.0.as_slice().try_into().ok()?)))
            .collect()
    }

    fn message(&self, group: &[u8], id: &[u8; 32]) -> Option<Vec<u8>> {
        let st = self.state.lock().unwrap();
        st.groups.get(group)?.rec.items.iter().any(|item| item.id.0 == id).then_some(())?;
        st.provider.get(&ciphertext_key(id)).ok()?
    }

    fn receive(&self, group: &[u8], ciphertext: &[u8]) -> Taken {
        let mut st = self.state.lock().unwrap();
        self.take(&mut st, group, ciphertext)
    }

    fn below(&self, group: &[u8], items: Vec<(u64, [u8; 32])>) {
        let floor = self.hello(group).floor;
        let mut st = self.state.lock().unwrap();
        let Ok(g) = st.group(group) else { return };
        let known = |id: &[u8; 32]| g.rec.items.iter().any(|item| item.id.0 == id) || g.rec.given_up.iter().any(|(_, given)| given.0 == id);
        let lacked: Vec<_> = items.into_iter().filter(|(epoch, id)| *epoch < floor && !known(id)).collect();
        for (epoch, id) in lacked {
            self.give_up(&mut st, group, epoch, id, Reason::Old);
        }
        self.save(&st, group);
    }

    fn frame(&self, peer: EndpointId, frame: KindFrame) {
        let gid = frame.group.0.clone();
        let mut st = self.state.lock().unwrap();
        if !st.devices(&gid) {
            let from = st.by_iroh(&gid, &peer);
            self.events.send(Event::Frame { group: frame.group.clone(), from, frame: frame.value() }).ok();
            return;
        }
        if let Err(error) = self.contacts_frame(&mut st, peer, frame) {
            tracing::debug!("a contacts frame from {}: {error:#}", peer.fmt_short());
        }
    }

    fn state(&self, group: &[u8], peer: EndpointId, link: Option<String>) {
        match link {
            Some(link) => self.work.send(Work::State { group: group.to_vec(), link, by: peer }).ok(),
            None => self.work.send(Work::StateWanted { group: group.to_vec(), by: peer }).ok(),
        };
    }

    fn log_head(&self, peer: EndpointId, group: &[u8], head: Head) {
        self.judge_log_head(peer, group, head);
    }

    fn files(&self, group: &[u8]) -> Vec<FileLink> {
        let st = self.state.lock().unwrap();
        let Some(g) = st.groups.get(group) else {
            return Vec::new();
        };
        g.rec.held(g.mls.settings().keep)
    }

    fn lists(&self, groups: &[Vec<u8>]) -> Vec<List> {
        let st = self.state.lock().unwrap();
        let mut ids: Vec<Bytes> = groups.iter().flat_map(|gid| st.identities(gid)).map(|identity| identity.id).collect();
        ids.sort();
        ids.dedup();
        // A folder signs no heads; its sessions read it directly.
        let signed = ids.iter().filter_map(|id| st.lists.get(&id.0)).filter(|known| matches!(known.list.membership, Service::Serve { .. }));
        signed.map(|known| List { identity: Bytes(known.list.id.to_vec()), entries: known.entries.clone(), head: known.head.clone() }).collect()
    }

    fn list(&self, peer: EndpointId, list: List) {
        if let Err(error) = self.presented(peer, list) {
            tracing::debug!("a device list from {}: {error:#}", peer.fmt_short());
        }
    }
}

/// Stores a held message and its ciphertext.
fn hold<P: Provider>(st: &mut State<P>, gid: &[u8], message: Message, ciphertext: &[u8]) -> Result<()> {
    let id = message.id.0.clone();
    st.group_mut(gid)?.rec.items.push(Item { epoch: message.epoch, id: message.id.clone(), at: message.at });
    st.provider.put(&ciphertext_key(&id), ciphertext)?;
    put(&st.provider, &message_key(&id), &message)?;
    st.save(gid)
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// A devices group's contacts, compared as a doc's text was: a member whose snapshot differs gets this session's
    /// state vector (`doc_sv`), and answers it with a `diff` of what this session lacks.
    fn contacts_frame(&self, st: &mut State<P>, peer: EndpointId, frame: KindFrame) -> Result<()> {
        let (gid, state) = (frame.group.0.clone(), st.contacts_state(&frame.group.0)?);
        let field = |name: &str| serde_json::from_value::<Bytes>(frame.body.get(name).cloned().unwrap_or(Value::Null));
        match frame.name.as_str() {
            "doc" if field("snapshot")?.0 != yjs::snapshot(&state)? => {
                let reply = json!({ "doc_sv": { "sv": Bytes(yjs::state_vector(&state)?) } });
                self.net().frame(peer, Frame::Kind(KindFrame::new(frame.group, reply)?));
            }
            "doc_sv" => {
                let diff = serde_json::to_value(ContactsUpdate::Diff { update: Bytes(yjs::diff(&state, &field("sv")?.0)?) })?;
                let g = st.groups.get_mut(&gid).context("not in that group")?;
                let ciphertext = g.mls.seal(&st.provider, &st.session, &diff, false)?.1;
                self.net().send_to(peer, &gid, ciphertext);
            }
            _ => {}
        }
        Ok(())
    }

    /// Checks a device list a peer presented, and holds it if it is newer than the one held.
    fn presented(&self, peer: EndpointId, presented: List) -> Result<()> {
        let id: [u8; 32] = presented.identity.0.as_slice().try_into().context("an identity id is 32 bytes")?;
        let mut st = self.state.lock().unwrap();
        let ours = st.groups.keys().any(|gid| st.identities(gid).iter().any(|identity| identity.id.0 == id));
        ensure!(ours, "an identity none of our groups' members speaks as");
        let log = lmk_proto::identity::address(&id);
        let List { entries, head, .. } = presented;
        let hash = entries.iter().fold(head::start(&log), |hash, entry| head::next(&hash, &entry.0));
        ensure!(head.log.0 == log && head.length == entries.len() as u64 && head.hash.0 == hash, "its head does not cover its entries");
        let list = DeviceList::replay(&id, entries.iter().map(|entry| entry.0.as_slice()))?;
        let Service::Serve { key, .. } = &list.membership else { bail!("a device list in a folder") };
        let key = VerifyingKey::from_bytes(key.0.as_slice().try_into().context("a service key is 32 bytes")?)?;
        ensure!(head.verify(&key), "a head its service did not sign");
        let at = head.time;
        self.take_list(&mut st, list, entries, head, at, &peer.fmt_short().to_string());
        Ok(())
    }
}

pub(crate) struct Admitter<P>(pub Arc<Inner<P>>);

impl<P: Provider + Send + 'static> Admit for Admitter<P> {
    fn invite(&self, _: EndpointId, request: InviteRequest) -> BoxFuture<Answer<Admitted>> {
        let inner = self.0.clone();
        Box::pin(async move {
            let admitted = inner.redeemed(request).await;
            inner.answer(None, admitted)
        })
    }

    fn join(&self, _: EndpointId, group: Vec<u8>, key_package: Vec<u8>) -> BoxFuture<Answer<Admitted>> {
        let inner = self.0.clone();
        Box::pin(async move {
            let admitted = inner.open_join(&group, key_package).await;
            inner.answer(Some(&group), admitted)
        })
    }
}

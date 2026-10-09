//! What the peers need from the group logic (`Groups`), what an inviter decides (`Admit`), and taking in a message.

use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::VerifyingKey;
use iroh::EndpointId;
use lmk_core::group::{self as core, Change, key_package_credential, key_package_leaf};
use lmk_core::identity::{KeyLog, certified, check};
use lmk_core::provider::Provider;
use lmk_membership::Chain;
use lmk_net::{Admit, Groups, Taken};
use lmk_proto::group::{CHAT, Control, Credential, How, Service, type_of};
use lmk_proto::head::{self, Head};
use lmk_proto::identity::Envelope;
use lmk_proto::links::FileLink;
use lmk_proto::peer::{Admitted, Hello, InviteRequest, Keys, KindFrame};
use lmk_proto::{Answer, Bytes};
use n0_future::boxed::BoxFuture;
use n0_future::time::timeout;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::{
    Event, Inner, Item, MAX_MESSAGE, Message, SNAPSHOT_WAIT, State, Work, ciphertext_key, entry_key, message_key, now, put,
};

/// A head that needs no signature: the empty log's.
fn empty(log: &[u8]) -> Head {
    Head { log: log.into(), length: 0, hash: head::start(log).into(), time: 0, sig: Bytes::default() }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Takes in a ciphertext from a peer: what became of it is told to the peer.
    pub(crate) fn take(&self, st: &mut State<P>, gid: &[u8], ciphertext: &[u8]) -> Taken {
        self.open(st, gid, ciphertext).unwrap_or_else(|error| Taken::Refused(format!("{error:#}")))
    }

    fn open(&self, st: &mut State<P>, gid: &[u8], ciphertext: &[u8]) -> Result<Taken> {
        let id: [u8; 32] = Sha256::digest(ciphertext).into();
        let g = st.group_mut(gid)?;
        if g.rec.items.iter().any(|item| item.id.0 == id) {
            return Ok(Taken::Held);
        }
        ensure!(!g.rec.given_up.iter().any(|(_, given)| given.0 == id), "given up");
        let epoch = core::epoch_of(ciphertext)?;
        if ciphertext.len() > MAX_MESSAGE {
            g.rec.given_up.push((epoch, Bytes(id.to_vec())));
            st.save(gid)?;
            bail!("larger than 1 MiB");
        }
        if epoch > g.mls.epoch() {
            if !g.future.iter().any(|waiting| waiting == ciphertext) {
                g.future.push(ciphertext.to_vec());
            }
            self.work.send(Work::Read(gid.to_vec())).ok();
            return Ok(Taken::Waiting);
        }
        let g = st.groups.get_mut(gid).unwrap();
        let opened = match g.mls.open(&st.provider, ciphertext, now()) {
            Ok(opened) => opened,
            Err(error) => {
                g.rec.given_up.push((epoch, Bytes(id.to_vec())));
                st.save(gid)?;
                return Err(error);
            }
        };
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
            }
        } else if opened.held {
            let message = Message { id: Bytes(id.to_vec()), group, epoch, at: now(), sender, payload };
            hold(st, gid, message.clone(), ciphertext)?;
            self.events.send(Event::Message(message)).ok();
        } else {
            self.events.send(Event::Live { group, sender, payload }).ok();
        }
        Ok(Taken::Held)
    }

    /// Answers an invite stream's request.
    async fn redeemed(self: &Arc<Self>, request: InviteRequest) -> Result<Admitted> {
        let (secret, key_package, now) = (request.secret.0, request.key_package.0, now());
        let (joiner, bound) = {
            let st = self.state.lock().unwrap();
            (key_package_credential(&st.provider, &key_package)?, st.invites.bound(&secret, now).is_some())
        };
        let log = match (bound, &joiner.identity) {
            (true, Some(identity)) => self.read_keys(identity).await.ok(),
            _ => None,
        };
        let redeemed = {
            let mut st = self.state.lock().unwrap();
            let st = &mut *st;
            st.invites.redeem(&st.provider, &secret, &key_package, request.certificate.as_ref(), log.as_ref(), now)?
        };
        if let Some(certificate) = request.certificate {
            self.certified(&joiner, certificate);
        }
        self.admit(&redeemed.group, key_package, How::Invite, redeemed.label).await
    }

    /// Answers a request to join a group open to the joiner's identity.
    async fn open_join(self: &Arc<Self>, gid: &[u8], key_package: Vec<u8>, certificate: Envelope) -> Result<Admitted> {
        let (joiner, open) = {
            let st = self.state.lock().unwrap();
            (key_package_credential(&st.provider, &key_package)?, st.group(gid)?.mls.settings().open)
        };
        let identity = joiner.identity.clone().filter(|identity| open.iter().any(|named| named.id == identity.id));
        let identity = identity.context("it speaks as no identity the group is open to")?;
        let log = self.read_keys(&identity).await?;
        if let Err(error) = check(Some(&certificate), &joiner, &log, now()) {
            anyhow::bail!("{error}");
        }
        self.certified(&joiner, certificate);
        self.admit(gid, key_package, How::Open, None).await
    }

    /// Holds a joiner's certificate.
    fn certified(&self, joiner: &Credential, certificate: Envelope) {
        if let Some(identity) = &joiner.identity {
            self.state.lock().unwrap().certificates.insert((joiner.key.0.clone(), identity.id.0.clone()), certificate);
        }
    }

    /// Commits the Add, and answers with the Welcome and the state of the group's kind, as a file.
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
                let joiner = key_package_credential(&st.provider, &key_package)?;
                st.labels.insert(joiner.key.0, label);
            }
        }
        let add = Change { add: vec![key_package], how: Some(how), ..Change::default() };
        let (welcome, position) = self.commit(gid, |_| Ok(add.clone())).await?;
        let (state, before) = {
            let st = self.state.lock().unwrap();
            let g = st.group(gid)?;
            let before = g.rec.items.iter().filter(|item| item.epoch < g.mls.epoch()).map(|item| item.id.clone()).collect();
            let state = (g.mls.settings().kind != CHAT).then(|| {
                let (reply, state) = oneshot::channel();
                self.events.send(Event::Snapshot { group: Bytes(gid.to_vec()), reply }).ok();
                state
            });
            (state, before)
        };
        let state = match state {
            Some(asked) => timeout(SNAPSHOT_WAIT, asked).await.ok().and_then(Result::ok).flatten(),
            None => None,
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
            return Hello { group: group.into(), epoch: 0, head: empty(group), floor: 0, joined: 0, log: None };
        };
        let (epoch, joined) = (g.mls.epoch(), g.mls.joined());
        let head = g.rec.chain.as_ref().map_or_else(|| empty(group), |chain| chain.head.clone());
        let floor = joined.max(epoch.saturating_sub(self.window.epochs as u64));
        let log = g.rec.log.as_ref().and_then(|log| Some(log.chain.as_ref()?.head.clone()));
        Hello { group: group.into(), epoch, head, floor, joined, log }
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

    fn frame(&self, peer: EndpointId, frame: KindFrame) {
        let from = self.state.lock().unwrap().by_iroh(&frame.group.0, &peer);
        self.events.send(Event::Frame { group: frame.group.clone(), from, frame: frame.value() }).ok();
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

    fn keys(&self, groups: &[Vec<u8>]) -> Vec<Keys> {
        let st = self.state.lock().unwrap();
        let mut ids: Vec<Bytes> = groups.iter().flat_map(|gid| st.identities(gid)).map(|identity| identity.id).collect();
        ids.sort();
        ids.dedup();
        // A folder signs no heads; its sessions read it directly.
        let signed = ids.iter().filter_map(|id| st.keys.get(&id.0)).filter(|known| matches!(known.log.membership, Service::Serve { .. }));
        signed.map(|known| Keys { identity: Bytes(known.log.id.to_vec()), entries: known.entries.clone(), head: known.head.clone() }).collect()
    }

    fn key_log(&self, peer: EndpointId, keys: Keys) {
        if let Err(error) = self.presented(peer, keys) {
            tracing::debug!("a key log from {}: {error:#}", peer.fmt_short());
        }
    }

    fn certificates(&self, groups: &[Vec<u8>]) -> Vec<Envelope> {
        let st = self.state.lock().unwrap();
        let mut certificates: Vec<Envelope> = Vec::new();
        for member in groups.iter().filter_map(|gid| st.groups.get(gid)).flat_map(|g| g.mls.members()) {
            let Some(credential) = &member.credential else { continue };
            let Some(identity) = &credential.identity else { continue };
            if let Some(certificate) = st.certificate(credential, &identity.id.0)
                && !certificates.contains(certificate)
            {
                certificates.push(certificate.clone());
            }
        }
        certificates
    }

    fn certificate(&self, _: EndpointId, certificate: Envelope) {
        let Some(certified) = certified(&certificate) else { return };
        let mut st = self.state.lock().unwrap();
        let member = st.groups.values().flat_map(|g| g.mls.members()).find_map(|m| m.credential.filter(|c| c.key == certified.key));
        let Some(credential) = member.filter(|c| c.identity.as_ref().is_some_and(|i| i.id == certified.identity)) else { return };
        let key = (certified.key.0.clone(), certified.identity.0.clone());
        let log = st.keys.get(&certified.identity.0).map(|known| &known.log);
        let valid = |c: &Envelope| log.is_some_and(|log| check(Some(c), &credential, log, now()).is_ok());
        // A valid certificate beats one that is not, and else the later one wins.
        let newer = st.certificates.get(&key).is_none_or(|held| match (valid(&certificate), valid(held)) {
            (true, false) => true,
            (false, true) => false,
            _ => certified.expires > lmk_core::identity::certified(held).map_or(0, |held| held.expires),
        });
        if newer {
            st.certificates.insert(key, certificate);
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
    /// Checks a key log a peer presented, and holds it if it is newer than the one held.
    fn presented(&self, peer: EndpointId, presented: Keys) -> Result<()> {
        let id: [u8; 32] = presented.identity.0.as_slice().try_into().context("an identity id is 32 bytes")?;
        let mut st = self.state.lock().unwrap();
        let ours = st.groups.keys().any(|gid| st.identities(gid).iter().any(|identity| identity.id.0 == id));
        ensure!(ours, "an identity none of our groups' members speaks as");
        let log = lmk_proto::identity::address(&id);
        let Keys { entries, head, .. } = presented;
        let hash = entries.iter().fold(head::start(&log), |hash, entry| head::next(&hash, &entry.0));
        ensure!(head.log.0 == log && head.length == entries.len() as u64 && head.hash.0 == hash, "its head does not cover its entries");
        let log = KeyLog::replay(&id, entries.iter().map(|entry| entry.0.as_slice()))?;
        let Service::Serve { key, .. } = &log.membership else { bail!("a key log in a folder") };
        let key = VerifyingKey::from_bytes(key.0.as_slice().try_into().context("a service key is 32 bytes")?)?;
        ensure!(head.verify(&key), "a head its service did not sign");
        let at = head.time;
        self.take_keys(&mut st, log, entries, head, at, &peer.fmt_short().to_string());
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

    fn join(&self, _: EndpointId, group: Vec<u8>, key_package: Vec<u8>, certificate: Envelope) -> BoxFuture<Answer<Admitted>> {
        let inner = self.0.clone();
        Box::pin(async move {
            let admitted = inner.open_join(&group, key_package, certificate).await;
            inner.answer(Some(&group), admitted)
        })
    }
}

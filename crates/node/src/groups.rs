//! What the peers need from the group logic (`Groups`), whom a member admits (`Admit`), and taking in a message.

use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::VerifyingKey;
use iroh::EndpointId;
use lmk_core::group::{self as core, Change, Removed, Unheld, key_package_credential, key_package_leaf};
use lmk_core::identity::{certified, check};
use lmk_core::provider::Provider;
use lmk_net::{Admit, Groups, Taken};
use lmk_proto::group::{CHAT, Control, Credential, How, Reason, Refusal, Service, type_of};
use lmk_proto::head::Head;
use lmk_proto::identity::Envelope;
use lmk_proto::links::FileLink;
use lmk_proto::peer::{Admitted, Hello, Join};
use lmk_proto::{Answer, Bytes};
use n0_future::boxed::BoxFuture;
use n0_future::time::timeout;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::logs::empty;
use crate::{
    Event, Inner, Item, MAX_MESSAGE, Message, Rule, SNAPSHOT_WAIT, State, Work, ciphertext_key, endpoint_id, get,
    message_key, now, put,
};

/// The answer to a secret no rule admits by: whether it is unknown, used or expired is not told.
const UNKNOWN: &str = "unknown, used or expired invite";

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
                self.given_up(st, gid);
                Taken::Refused
            }
        }
    }

    /// Saves what was given up, which may leave the kind's log behind.
    fn given_up(&self, st: &mut State<P>, gid: &[u8]) {
        if let Err(error) = st.save(gid).and_then(|()| self.kind_advance(st, gid)) {
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
                Control::Invite { hash, expires, label, to } => {
                    let held = Message { id: Bytes(id.to_vec()), group, epoch, at: now(), sender, payload };
                    hold(st, gid, held, ciphertext)?;
                    let by = Bytes(opened.key.clone());
                    st.group_mut(gid)?.rec.invites.push(Rule { hash, expires, label, to, by });
                    st.save(gid)?;
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
        } else if opened.held {
            let message = Message { id: Bytes(id.to_vec()), group, epoch, at: now(), sender, payload };
            hold(st, gid, message.clone(), ciphertext)?;
            self.events.send(Event::Message(message)).ok();
            self.kind_advance(st, gid)?;
        } else {
            self.events.send(Event::Live { group, sender, payload }).ok();
        }
        Ok(())
    }

    /// Answers a joiner's request: it brings an invite's secret, or speaks as an identity the group is open to.
    async fn admit_join(self: &Arc<Self>, join: Join) -> Result<Admitted> {
        let Join { secret, group, key_package, certificate } = join;
        let joiner = key_package_credential(&self.state.lock().unwrap().provider, &key_package.0)?;
        let (gid, how, invite, to) = match (secret, group) {
            (Some(secret), _) => {
                let hash = Bytes(Sha256::digest(&secret.0).to_vec());
                let st = self.state.lock().unwrap();
                let found = st.groups.iter().find_map(|(gid, g)| Some((gid.clone(), g.rec.invites.iter().find(|rule| rule.hash == hash)?.clone())));
                let (gid, rule) = found.context(UNKNOWN)?;
                ensure!(now() < rule.expires && !st.group(&gid)?.mls.used(&hash.0), UNKNOWN);
                (gid, How::Invite, Some(hash), rule.to)
            }
            (None, Some(gid)) => {
                let open = self.state.lock().unwrap().group(&gid.0)?.mls.settings().open;
                let identity = joiner.identity.as_ref().filter(|identity| open.iter().any(|named| named.id == identity.id));
                (gid.0, How::Open, None, Some(identity.context("it speaks as no identity the group is open to")?.id.clone()))
            }
            (None, None) => bail!("a request names an invite's secret or a group"),
        };
        if let Some(to) = to {
            let identity = joiner.identity.clone().filter(|identity| identity.id == to).context("this invite is for another identity")?;
            let log = self.read_keys(&identity).await?;
            if let Err(error) = check(certificate.as_ref(), &joiner, &log, now()) {
                bail!("{error}");
            }
        }
        if let Some(certificate) = certificate {
            self.certified(&joiner, certificate);
        }
        self.admit(&gid, key_package.0, how, invite).await
    }

    /// Holds a joiner's certificate.
    fn certified(&self, joiner: &Credential, certificate: Envelope) {
        if let Some(identity) = &joiner.identity {
            self.state.lock().unwrap().certificates.insert((joiner.key.0.clone(), identity.id.0.clone()), certificate);
        }
    }

    /// Commits the Add, naming the invite the joiner came in by, which no earlier commit may have used, and answers with
    /// the Welcome and the state of the group's kind, as a file. A joiner whose session does not support the group's kind
    /// is refused.
    async fn admit(self: &Arc<Self>, gid: &[u8], key_package: Vec<u8>, how: How, invite: Option<Bytes>) -> Result<Admitted> {
        {
            let st = self.state.lock().unwrap();
            let kind = st.group(gid)?.mls.settings().kind;
            let leaf = key_package_leaf(&st.provider, &key_package)?;
            ensure!(leaf.kinds.contains(&kind), "its session does not support {kind} groups");
        }
        let add = Change { add: vec![key_package], how: Some(how), invite: invite.clone(), ..Change::default() };
        let (welcome, position) = self
            .commit(gid, |g| {
                ensure!(invite.as_ref().is_none_or(|invite| !g.used(&invite.0)), UNKNOWN);
                Ok(add.clone())
            })
            .await?;
        let (state, before, logs) = {
            let st = self.state.lock().unwrap();
            let g = st.group(gid)?;
            let before = g.rec.items.iter().filter(|item| item.epoch < g.mls.epoch()).map(|item| item.id.clone()).collect();
            let state = (g.mls.settings().kind != CHAT).then(|| {
                let (reply, state) = oneshot::channel();
                self.events.send(Event::Snapshot { group: Bytes(gid.to_vec()), reply }).ok();
                state
            });
            (state, before, g.rec.kind_logs.clone())
        };
        let state = match state {
            Some(asked) => timeout(SNAPSHOT_WAIT, asked).await.ok().and_then(Result::ok).flatten(),
            None => None,
        };
        let doc = match state {
            Some(state) => Some(self.state_file(gid, state).await?),
            None => None,
        };
        let certificates = lmk_net::Groups::certificates(&**self, &[gid.to_vec()]);
        Ok(Admitted { welcome: Bytes(welcome.context("an add makes a Welcome")?), position, doc, before, certificates, logs })
    }

}

impl<P: Provider + Send + 'static> Groups for Inner<P> {
    fn groups(&self) -> Vec<Vec<u8>> {
        self.state.lock().unwrap().groups.keys().cloned().collect()
    }

    fn in_leaf(&self, group: &[u8], peer: &EndpointId) -> bool {
        self.state.lock().unwrap().in_leaf(group, peer).is_some()
    }

    fn is_member(&self, group: &[u8], peer: &EndpointId) -> bool {
        self.state.lock().unwrap().serves(group, peer)
    }

    fn hello(&self, group: &[u8]) -> Hello {
        let st = self.state.lock().unwrap();
        let Some(g) = st.groups.get(group) else {
            return Hello { group: group.into(), epoch: 0, floor: 0, joined: 0 };
        };
        let (epoch, joined) = (g.mls.epoch(), g.mls.joined());
        let floor = joined.max(epoch.saturating_sub(self.window.epochs as u64));
        Hello { group: group.into(), epoch, floor, joined }
    }

    fn logs(&self, group: &[u8]) -> Vec<Vec<u8>> {
        let st = self.state.lock().unwrap();
        let Some(g) = st.groups.get(group) else { return Vec::new() };
        let kind = g.rec.kind_logs.iter().map(|log| log.id.0.clone());
        let identities = st.identities(group).into_iter().map(|identity| lmk_proto::identity::address(&identity.id.0).to_vec());
        let mut logs: Vec<Vec<u8>> = [group.to_vec()].into_iter().chain(kind).chain(identities).filter(|id| st.logs.contains_key(id)).collect();
        logs.sort();
        logs.dedup();
        logs
    }

    fn head(&self, log: &[u8]) -> Head {
        self.state.lock().unwrap().logs.get(log).map_or_else(|| empty(log), |l| l.head(log))
    }

    fn verify_head(&self, log: &[u8], head: &Head) -> bool {
        if head.length == 0 && head.hash == empty(log).hash {
            return true;
        }
        let st = self.state.lock().unwrap();
        match st.logs.get(log).map(|l| &l.service) {
            Some(Service::Serve { key, .. }) => {
                let key: Option<[u8; 32]> = key.0.clone().try_into().ok();
                key.and_then(|key| VerifyingKey::from_bytes(&key).ok()).is_some_and(|key| head.verify(&key))
            }
            Some(Service::Folder(_)) => true,
            None => false,
        }
    }

    fn chain(&self, log: &[u8], position: u64) -> Option<[u8; 32]> {
        self.state.lock().unwrap().logs.get(log)?.chain.as_ref()?.hash_at(position)
    }

    fn entries(&self, log: &[u8], after: u64) -> Vec<Bytes> {
        self.state.lock().unwrap().entries(log, after)
    }

    fn apply(&self, log: &[u8], entries: Vec<Bytes>, head: Head) -> Result<()> {
        self.take_entries(log, entries, head)
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
        self.given_up(&mut st, group);
    }

    fn state(&self, group: &[u8], peer: EndpointId, link: Option<String>) {
        match link {
            Some(link) => self.work.send(Work::State { group: group.to_vec(), link, by: peer }).ok(),
            None => self.work.send(Work::StateWanted { group: group.to_vec(), by: peer }).ok(),
        };
    }

    fn files(&self, group: &[u8]) -> Vec<FileLink> {
        let st = self.state.lock().unwrap();
        let Some(g) = st.groups.get(group) else {
            return Vec::new();
        };
        g.rec.held(g.mls.settings().keep)
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

    fn certificate(&self, peer: EndpointId, certificate: Envelope) {
        let mut st = self.state.lock().unwrap();
        let gids: Vec<Vec<u8>> = st.groups.keys().cloned().collect();
        let served = |st: &State<P>| gids.iter().filter(|gid| st.serves(gid, &peer)).cloned().collect::<Vec<_>>();
        let before = served(&st);
        take_certificate(&mut st, certificate);
        for gid in served(&st).into_iter().filter(|gid| !before.contains(gid)) {
            self.net().changed(&gid);
        }
    }
}

/// Holds a certificate a peer showed, even of a session not yet a member here, as one whose Add is still on its way.
/// A valid certificate beats one that is not, and else the later one wins.
pub(crate) fn take_certificate<P: Provider>(st: &mut State<P>, certificate: Envelope) {
    let Some(certified) = certified(&certificate) else { return };
    let members = st.groups.values().flat_map(|g| g.mls.members());
    let credential = members.filter_map(|m| m.credential).find(|c| c.key == certified.key && c.identity.as_ref().is_some_and(|i| i.id == certified.identity));
    let log = st.keys.get(&certified.identity.0);
    let valid = |c: &Envelope| matches!((&credential, log), (Some(credential), Some(log)) if check(Some(c), credential, log, now()).is_ok());
    let key = (certified.key.0.clone(), certified.identity.0.clone());
    let fresh = valid(&certificate);
    let newer = st.certificates.get(&key).is_none_or(|held| match (fresh, valid(held)) {
        (true, false) => true,
        (false, true) => false,
        _ => certified.expires > lmk_core::identity::certified(held).map_or(0, |held| held.expires),
    });
    if newer {
        st.certificates.insert(key, certificate);
    } else if credential.is_some() && !fresh {
        st.ahead.insert(key, certificate);
    }
}

/// Stores a held message and its ciphertext.
fn hold<P: Provider>(st: &mut State<P>, gid: &[u8], message: Message, ciphertext: &[u8]) -> Result<()> {
    let id = message.id.0.clone();
    st.group_mut(gid)?.rec.items.push(Item { epoch: message.epoch, id: message.id.clone(), at: message.at, position: None });
    st.provider.put(&ciphertext_key(&id), ciphertext)?;
    put(&st.provider, &message_key(&id), &message)?;
    st.save(gid)
}

pub(crate) struct Admitter<P>(pub Arc<Inner<P>>);

impl<P: Provider + Send + 'static> Admit for Admitter<P> {
    fn join(&self, _: EndpointId, join: Join) -> BoxFuture<Answer<Admitted>> {
        let inner = self.0.clone();
        Box::pin(async move {
            match inner.admit_join(join).await {
                Ok(admitted) => Answer::Ok(admitted),
                Err(error) => {
                    inner.warn(None, format!("refused a join: {error:#}"));
                    Answer::Refused { refused: format!("{error:#}") }
                }
            }
        })
    }
}

//! Admission, both sides: a joiner asks the members an invite link names, keeping its KeyPackage until one admits it; a
//! member answers by the invite's rule, checked again as the Add is built, or with the logged Welcome to a joiner it
//! added before whose answer was lost.

use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use iroh::{EndpointId, RelayUrl};
use lmk_core::group::{Change, Group, key_package_credential, key_package_leaf, key_package_reference};
use lmk_core::public::Verdict;
use lmk_core::provider::Provider;
use lmk_net::Admit;
use lmk_proto::epoch::{Checkpoint, StateLink, Transition};
use lmk_proto::group::{CHAT, Certificate, Control, Credential, IDENTITY, How};
use lmk_proto::links::{Address, Invite, RELAY};
use lmk_proto::peer::{Admitted, Join};
use lmk_proto::{Answer, Bytes};
use n0_future::boxed::BoxFuture;
use n0_future::task::spawn;
use n0_future::{FuturesUnordered, StreamExt};
use n0_future::time::{Duration, Instant, sleep_until, timeout};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::logs::NOT_FOLLOWED;
use crate::{Event, G, Inner, MEMBER_WAIT, Member, Node, Rec, Rule, SNAPSHOT_WAIT, State, device_key_key, endpoint_id, get, now, put};

/// How many members besides the inviter a link names, of those online that hold the invite's message.
const LINK_MEMBERS: usize = 3;
/// How long a joiner waits to reach each member it asks, all at once, and then for each one's answer.
const DIAL_WAIT: Duration = Duration::from_secs(30);
const JOIN_WAIT: Duration = Duration::from_secs(30);
/// How long the inviter, whom a link names first, has to be reached before the other members it names are asked: so the
/// inviter admits whom it invited when it is online.
const INVITER_FIRST: Duration = Duration::from_secs(3);

/// A joiner's KeyPackage, whose private keys openmls keeps, and the device key it is made with for an identity group.
#[derive(Serialize, Deserialize)]
struct Joining {
    key_package: Bytes,
    device: Option<Bytes>,
}

impl<P: Provider + Send + 'static> Node<P> {
    /// An invite into a group, valid for `valid` milliseconds, for anyone or `to` an identity, or one of its devices:
    /// shared with the members as a held message, and a link that names this session and up to three members online
    /// that hold it.
    pub async fn invite(&self, gid: &[u8], to: Option<Bytes>, valid: u64) -> Result<Invite> {
        let secret: [u8; 16] = lmk_core::random();
        let hash = Bytes(Sha256::digest(secret).to_vec());
        let expires = now() + valid;
        let device = {
            let mut st = self.inner.lock();
            let by = Bytes(st.me(gid).to_vec());
            let g = st.group_mut(gid)?;
            g.rec.invites.push(Rule { hash: hash.clone(), expires, to: to.clone(), by });
            st.save(gid)?;
            st.group(gid)?.mls.settings().kind == IDENTITY
        };
        let rule = serde_json::to_value(Control::Invite { hash, expires, to })?;
        let position = self.send(gid, &rule).await?.position;
        // The members online whose summaries hold the invite's message admit by it too: a member asked before its push
        // arrived would refuse the joiner.
        let online = self.online(gid)?;
        let holding = || -> Result<Vec<Member>> {
            let heard = self.heard(gid)?;
            let holds = |m: &Member| position.is_some_and(|p| heard.iter().any(|h| h.member.key == m.key && h.held.contains(p)));
            Ok(online.iter().filter(|m| holds(m)).cloned().collect())
        };
        if position.is_some() {
            let all = async {
                loop {
                    let heard = self.inner.heard.notified();
                    if holding()?.len() == online.len() {
                        return anyhow::Ok(());
                    }
                    heard.await;
                }
            };
            timeout(MEMBER_WAIT, all).await.unwrap_or(Ok(()))?;
        }
        let holders = holding()?;
        let st = self.inner.lock();
        let mut members = vec![address(*self.inner.net().id().as_bytes(), self.inner.relay.as_str())];
        for member in holders.iter().take(LINK_MEMBERS) {
            let Some(leaf) = endpoint_id(&member.iroh.0).and_then(|peer| st.in_leaf(gid, &peer)?.leaf) else { continue };
            members.push(address(*endpoint_id(&leaf.key.0).context("an iroh key")?.as_bytes(), &leaf.relay));
        }
        Ok(Invite { device, secret, members })
    }

    /// Joins through an invite link, speaking as `identity`: asks the members it names in turn, as each is reached. A
    /// device link joins with a new device key. Returns the group, and the iroh key of the member that admitted this
    /// session.
    pub async fn join(&self, link: &Invite, identity: Option<Certificate>) -> Result<(Bytes, [u8; 32])> {
        let ours: RelayUrl = RELAY.parse()?;
        let members = link
            .members
            .iter()
            .map(|member| Ok((EndpointId::from_bytes(&member.key)?, member.relay.as_ref().map_or(Ok(ours.clone()), |relay| relay.parse())?)))
            .collect::<Result<Vec<_>>>()?;
        let (secret, devices) = (Bytes(link.secret.to_vec()), link.device);
        // Refusals after an uncertain attempt do not erase the original package or its private keys.
        let joining = [b"node/joining/".as_slice(), &Sha256::digest(&secret.0)].concat();
        let (join, device_key) = {
            let mut st = self.inner.lock();
            st.speak(identity);
            let kept = match get::<Joining>(&st.provider, &joining)? {
                Some(kept) => {
                    ensure!(kept.device.is_some() == devices, "invite kind changed; original joining keys were preserved");
                    kept
                }
                None => {
                    let device_key = devices.then(|| st.device_key()).transpose()?;
                    let session = device_key.as_ref().map_or(&st.session, |(_, session)| session);
                    let kept = Joining { key_package: Bytes(session.key_package(&st.provider)?), device: device_key.map(|(seed, _)| Bytes(seed.to_vec())) };
                    put(&st.provider, &joining, &kept)?;
                    kept
                }
            };
            let device_key = kept.device.map(|seed| seed.0.try_into()).transpose().ok().context("a device key is 32 bytes")?;
            (Join { secret, key_package: kept.key_package }, device_key)
        };
        self.inner.durable().await?;
        // Each dial is a task of its own, so it goes on, and times out, while a member reached earlier is asked.
        let inviter_first = Instant::now() + INVITER_FIRST;
        let mut dials: FuturesUnordered<_> = members
            .into_iter()
            .enumerate()
            .map(|(i, (peer, relay))| {
                let net = self.inner.net().clone();
                spawn(async move {
                    let dialed = timeout(DIAL_WAIT, net.dial(peer, relay.clone())).await;
                    if i > 0 {
                        sleep_until(inviter_first).await;
                    }
                    (peer, relay, dialed)
                })
            })
            .collect();
        let mut refusal = anyhow::anyhow!("no member the invite names is online");
        while let Some(dialed) = dials.next().await {
            let (peer, relay, dialed) = dialed?;
            if !matches!(dialed, Ok(Ok(()))) {
                tracing::debug!("{} is not online", peer.fmt_short());
                continue;
            }
            match timeout(JOIN_WAIT, self.inner.net().join(peer, relay, join.clone())).await {
                Ok(Ok(Answer::Ok(admitted))) => {
                    let package = key_package_reference(&self.inner.lock().provider, &join.key_package.0)?;
                    let gid = self.inner.welcomed(admitted, peer, device_key, package, &joining).await?;
                    self.inner.durable().await?;
                    return Ok((gid, *peer.as_bytes()));
                }
                Ok(Ok(Answer::Refused { refused })) => {
                    refusal = anyhow::anyhow!("refused: {refused}");
                }
                Ok(Err(error)) => {
                    tracing::debug!("asking {} to admit this session: {error:#}", peer.fmt_short());
                }
                Err(_) => {
                    tracing::debug!("{} did not answer", peer.fmt_short());
                }
            }
        }
        Err(refusal)
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Joins a group from the Welcome a member at `by` sent: an identity group with the device key `device_key`, and only
    /// then, as a link's kind is not authenticated.
    async fn welcomed(self: &Arc<Self>, admitted: Admitted, by: EndpointId, device_key: Option<[u8; 32]>, package: [u8; 32], joining: &[u8]) -> Result<Bytes> {
        let gid = {
            let mut st = self.lock();
            st.provider.savepoint()?;
            let installed = (|| {
                let mls = Group::join(&st.provider, &admitted.welcome.0, &package)?;
                let checkpoint = &admitted.checkpoint;
                ensure!(checkpoint.package == package && checkpoint.verify(&admitted.welcome.0), "invalid admission checkpoint");
                ensure!(checkpoint.transition.group.as_slice() == mls.id(), "checkpoint names another group");
                let members = mls.members();
                ensure!(members.iter().any(|member| member.key == checkpoint.signer
                    && member.leaf.as_ref().is_some_and(|leaf| leaf.key.0 == by.as_bytes())), "attester is not the invite channel's MLS member");
                ensure!(members.iter().any(|member| member.index == mls.own_index() && member.key == checkpoint.added_key), "checkpoint names another admitted key");
                ensure!(!st.groups.contains_key(mls.id()), "this session is in that group already");
                ensure!((mls.settings().kind == IDENTITY) == device_key.is_some(), "the link was altered: another group kind");
                ensure!(self.kinds.contains(&mls.settings().kind), "unsupported group kind");
                let source = &checkpoint.transition.source;
                if source.epoch == 0 {
                    ensure!(*source == lmk_proto::epoch::Anchor::genesis(&checkpoint.transition.group, source.service, source.log_ref), "invalid checkpoint genesis");
                }
                let anchor = checkpoint.transition.successor()?;
                let service = mls.settings().membership;
                let key = crate::logs::authority(&service)?;
                let id = lmk_proto::head::reference(&key, &mls.capability(&st.provider)?);
                ensure!((anchor.epoch, anchor.service, anchor.log_ref) == (mls.epoch(), key, id), "admission destination mismatch");
                let gid = mls.id().to_vec();
                let rec = Rec { active: Bytes(id.to_vec()), position: anchor.base, start: anchor.base, expired: anchor.base,
                    updated: now(), shown: anchor.base, ..Rec::default() };
                let readers = members.into_iter().filter_map(|member| member.leaf.map(|leaf| leaf.key)).collect();
                let log = crate::logs::Log::new(crate::logs::Of::Group { group: Bytes(gid.clone()), anchor }, service, id, readers);
                let predecessor = if st.logs.contains_key(source.log_ref.as_slice()) { None } else {
                    let service = lmk_proto::group::Service::Serve { key: Bytes(source.service.to_vec()), relay: String::new(), addrs: Vec::new(), rest: Default::default() };
                    let mut old = crate::logs::Log::new(crate::logs::Of::Group { group: Bytes(gid.clone()), anchor: source.clone() }, service, source.log_ref, Vec::new());
                    old.raw = false;
                    old.cut = Some(checkpoint.transition.cut);
                    old.closed = Some(now());
                    old.transition = Some(checkpoint.transition.clone());
                    Some(old)
                };
                let mut usage: crate::logs::Usage = get(&st.provider, b"node/archive-usage")?.unwrap_or_default();
                for source in std::iter::once(&log).chain(predecessor.iter()) { usage.evidence += serde_json::to_vec(source)?.len() as u64 + 4096; }
                ensure!(usage.evidence <= crate::logs::EVIDENCE_LIMIT, "admission metadata quota exhausted");
                put(&st.provider, b"node/archive-usage", &usage)?;
                put(&st.provider, &crate::rec_key(&gid), &rec)?;
                put(&st.provider, &crate::logs::log_key(&id), &log)?;
                let mut gids: Vec<Bytes> = st.groups.keys().map(|gid| Bytes(gid.clone())).collect();
                gids.push(Bytes(gid.clone()));
                put(&st.provider, b"node/groups", &gids)?;
                let mut logs: Vec<Bytes> = st.logs.keys().map(|id| Bytes(id.clone())).collect();
                logs.push(Bytes(id.to_vec()));
                if let Some(old) = &predecessor {
                    logs.push(Bytes(old.log_ref.to_vec()));
                    put(&st.provider, &crate::logs::log_key(&old.log_ref), old)?;
                }
                put(&st.provider, b"node/logs", &logs)?;
                put(&st.provider, &[b"node/checkpoint/".as_slice(), &gid].concat(), checkpoint)?;
                let session = device_key.map(|seed| {
                    put(&st.provider, &device_key_key(&gid), &Bytes(seed.to_vec()))?;
                    Ok::<_, anyhow::Error>((seed, st.keyed(seed)?))
                }).transpose()?;
                st.provider.delete(joining)?;
                Ok::<_, anyhow::Error>((gid, mls, rec, id, log, predecessor, session))
            })();
            let (gid, mls, rec, id, log, predecessor, session) = match installed {
                Ok(value) => {
                    if let Err(error) = st.provider.release() { tracing::error!("admission release failed: {error:#}"); std::process::abort(); }
                    value
                }
                Err(error) => {
                    if let Err(rollback) = st.provider.rollback_to() { tracing::error!("admission rollback failed: {rollback:#}"); std::process::abort(); }
                    return Err(error);
                }
            };
            st.logs.insert(id.to_vec(), log);
            if let Some(old) = predecessor { st.logs.insert(old.log_ref.to_vec(), old); }
            st.groups.insert(gid.clone(), G::new(mls, rec, Default::default()));
            if let Some(session) = session { st.device_keys.insert(gid.clone(), session); }
            st.gate = true;
            gid
        };
        self.durable().await?;
        self.refresh_all().await;
        self.dial_all();
        let id = self.lock().group(&gid)?.rec.active.0.clone();
        self.follow(&id);
        if let Some(link) = admitted.doc { self.state_from(&gid, link, by); }
        Ok(Bytes(gid))
    }
}

/// A member to dial, as an invite link names it.
fn address(key: [u8; 32], relay: &str) -> Address {
    let ours = RELAY.parse::<RelayUrl>().ok();
    Address { key, relay: (relay.parse::<RelayUrl>().ok() != ours).then(|| relay.to_string()) }
}

/// The answer to a secret no rule admits by: whether it is unknown, used or expired is not told.
const UNKNOWN: &str = "unknown, used or expired invite";
const INVITER_LEFT: &str = "its inviter left the group";
const FOR_ANOTHER: &str = "this invite is for another identity, or another device";
const MEMBER_ALREADY: &str = "this session is a member already";

/// Whether `g`, as it stands, admits a joiner by an invite: checked when its request comes, and each time the commit
/// that adds it is built. An invite dies when its inviter leaves the group.
fn admits(g: &G, joiner: &Credential, rule: &Rule) -> Result<()> {
    let members = g.mls.members();
    ensure!(now() < rule.expires && !g.mls.used(&rule.hash.0), UNKNOWN);
    ensure!(members.iter().any(|m| m.key == rule.by.0) && !g.left(&rule.by.0), INVITER_LEFT);
    ensure!(members.iter().all(|member| member.key != joiner.key.0), MEMBER_ALREADY);
    Ok(())
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Answers a joiner's request, which brings an invite's secret.
    async fn admit_join(self: &Arc<Self>, join: Join) -> Result<Admitted> {
        let Join { secret, key_package } = join;
        let joiner = key_package_credential(&self.lock().provider, &key_package.0)?;
        let hash = Bytes(Sha256::digest(&secret.0).to_vec());
        let package = key_package_reference(&self.lock().provider, &key_package.0)?;
        let cached = self.lock().logged_welcome(&hash, &package)?;
        if let Some((gid, cached)) = cached {
            return self.admitted(&gid, cached).await;
        }
        let found = self.lock().groups.iter().find_map(|(gid, g)| Some((gid.clone(), g.rec.invites.iter().find(|rule| rule.hash == hash)?.clone())));
        let (gid, rule) = found.context(UNKNOWN)?;
        self.caught_up(&gid).await?;
        let cached = self.lock().logged_welcome(&hash, &package)?;
        if let Some((gid, cached)) = cached { return self.admitted(&gid, cached).await; }
        admits(self.lock().group(&gid)?, &joiner, &rule)?;
        // Its identity's public log, read afresh, must list the device that certified it.
        if let Some(to) = &rule.to {
            let certificate = joiner.certificate.as_ref().filter(|c| c.identity.id == *to || c.device == *to).context(FOR_ANOTHER)?;
            match self.read_public(&certificate.identity).await?.verify(&joiner) {
                Verdict::Verified { .. } => {}
                Verdict::Unverified => bail!("its device is not on its identity's list"),
                Verdict::Dropped => bail!("its device was taken off its identity"),
            }
        }
        self.admit(&gid, key_package.0, &joiner, rule).await
    }

    /// Commits the Add, naming the invite the joiner came in by, and answers with the Welcome and the state of the group's
    /// kind, as a file. Each build of the commit checks the joiner's rule again. A joiner whose session does not support
    /// the group's kind is refused.
    async fn admit(self: &Arc<Self>, gid: &[u8], key_package: Vec<u8>, joiner: &Credential, rule: Rule) -> Result<Admitted> {
        {
            let st = self.lock();
            let kind = st.group(gid)?.mls.settings().kind;
            let leaf = key_package_leaf(&st.provider, &key_package)?;
            ensure!(leaf.kinds.contains(&kind), "its session does not support {kind} groups");
        }
        let package = key_package_reference(&self.lock().provider, &key_package)?;
        let add = Change { add: vec![key_package], how: Some(How::Invite), invite: Some(rule.hash.clone()), ..Change::default() };
        self.commit(gid, |_, g| {
            admits(g, joiner, &rule)?;
            Ok(Some(add.clone()))
        }).await?.context("an Add has effect")?;
        let (_, cached) = self.lock().logged_welcome(&rule.hash, &package)?.context("accepted Add cache missing")?;
        self.admitted(gid, cached).await
    }

    async fn admitted(self: &Arc<Self>, gid: &[u8], mut cached: Admitted) -> Result<Admitted> {
        let (anchor, position, state) = {
            let st = self.lock();
            let g = st.group(gid)?;
            let state = (g.mls.settings().kind != CHAT).then(|| {
                let (reply, state) = oneshot::channel();
                self.events.send(Event::Snapshot { group: Bytes(gid.to_vec()), reply }).ok();
                state
            });
            (st.active(gid)?.anchor()?.clone(), g.rec.position, state)
        };
        let state = match state {
            Some(asked) => timeout(SNAPSHOT_WAIT, asked).await.ok().and_then(Result::ok).flatten(),
            None => None,
        };
        if let Some(state) = state {
            let prefix = self.state_hash(&anchor, position).await?;
            let link = self.state_file(gid, state).await?;
            let st = self.lock();
            if st.active(gid)?.anchor()? == &anchor && st.group(gid)?.rec.position == position {
                cached.doc = Some(StateLink { link, anchor, position, prefix });
            }
        }
        self.durable().await?;
        Ok(cached)
    }
}

#[derive(Serialize, Deserialize)]
struct Acceptance {
    welcome: Bytes,
    transition: Transition,
}

#[derive(Serialize, Deserialize)]
struct Recovery {
    invite: Bytes,
    package: [u8; 32],
    added_key: [u8; 32],
    leaf: Bytes,
    root: [u8; 32],
    epoch: u64,
    signer: [u8; 32],
    signature: Bytes,
}

fn recovery_key(gid: &[u8], package: &[u8]) -> Vec<u8> {
    [b"node/recovery/".as_slice(), gid, package].concat()
}

fn acceptance_key(root: &[u8; 32]) -> Vec<u8> {
    [b"node/acceptance/".as_slice(), root].concat()
}

impl<P: Provider> State<P> {
    pub(crate) fn cache_admissions(&mut self, gid: &[u8], transition: &Transition, welcome: &[u8]) -> Result<()> {
        let epoch = transition.successor()?.epoch;
        let adds: Vec<_> = self.group(gid)?.mls.added().iter().filter(|added| added.epoch == epoch && added.invite.is_some()).cloned().collect();
        if adds.is_empty() { return Ok(()); }
        let root = transition.hash();
        put(&self.provider, &acceptance_key(&root), &Acceptance { welcome: Bytes(welcome.to_vec()), transition: transition.clone() })?;
        for added in adds {
            let leaf = self.group(gid)?.mls.leaf_bytes(&added.member.key.0)?.context("added leaf missing")?;
            let mut checkpoint = Checkpoint { transition: transition.clone(), package: added.key_package_ref,
                added_key: added.member.key.0.as_slice().try_into()?, signer: self.me(gid).try_into()?, signature: Bytes::default() };
            checkpoint.signature = Bytes(self.session_of(gid).sign(&checkpoint.signed(welcome))?);
            let cache = Recovery { invite: added.invite.unwrap(), package: checkpoint.package, added_key: checkpoint.added_key,
                leaf: Bytes(leaf), root, epoch, signer: checkpoint.signer, signature: checkpoint.signature };
            put(&self.provider, &recovery_key(gid, &cache.package), &cache)?;
            self.group_mut(gid)?.rec.admissions.push(Bytes(cache.package.to_vec()));
        }
        Ok(())
    }

    pub(crate) fn prune_admissions(&mut self, gid: &[u8]) -> Result<()> {
        let mut keep = Vec::new();
        let (mut live, mut pruned) = (std::collections::BTreeSet::new(), std::collections::BTreeSet::new());
        for package in &self.group(gid)?.rec.admissions {
            let cache: Recovery = get(&self.provider, &recovery_key(gid, &package.0))?.context("missing recovery cache")?;
            if self.group(gid)?.mls.leaf_bytes(&cache.added_key)?.as_deref() == Some(cache.leaf.0.as_slice()) {
                keep.push(package.clone());
                live.insert(cache.root);
            } else {
                pruned.insert(cache.root);
                self.provider.delete(&recovery_key(gid, &package.0))?;
            }
        }
        for root in pruned.difference(&live) { self.provider.delete(&acceptance_key(root))?; }
        self.group_mut(gid)?.rec.admissions = keep;
        Ok(())
    }

    pub(crate) fn admission_floor(&self, gid: &[u8]) -> Result<Option<u64>> {
        let mut floor: Option<u64> = None;
        for package in &self.group(gid)?.rec.admissions {
            let cache: Recovery = get(&self.provider, &recovery_key(gid, &package.0))?.context("missing recovery cache")?;
            floor = Some(floor.map_or(cache.epoch, |floor| floor.min(cache.epoch)));
        }
        Ok(floor)
    }

    fn logged_welcome(&self, invite: &Bytes, package: &[u8; 32]) -> Result<Option<(Vec<u8>, Admitted)>> {
        for (gid, g) in &self.groups {
            if self.conflicting(gid) { continue; }
            let Some(cache) = get::<Recovery>(&self.provider, &recovery_key(gid, package))? else { continue };
            if cache.invite != *invite || g.mls.leaf_bytes(&cache.added_key)?.as_deref() != Some(cache.leaf.0.as_slice()) { continue; }
            let accepted: Acceptance = get(&self.provider, &acceptance_key(&cache.root))?.context("missing accepted Welcome")?;
            let checkpoint = Checkpoint { transition: accepted.transition, package: cache.package, added_key: cache.added_key,
                signer: cache.signer, signature: cache.signature };
            return Ok(Some((gid.clone(), Admitted { welcome: accepted.welcome, checkpoint, doc: None })));
        }
        Ok(None)
    }
}

pub(crate) struct Admitter<P>(pub Arc<Inner<P>>);

impl<P: Provider + Send + 'static> Admit for Admitter<P> {
    fn join(&self, _: EndpointId, join: Join) -> BoxFuture<Answer<Admitted>> {
        let inner = self.0.clone();
        Box::pin(async move {
            match inner.admit_join(join).await {
                Ok(admitted) => Answer::Ok(admitted),
                Err(error) => {
                    let refused = format!("{error:#}");
                    // A joiner asks every member a link names, so routine refusals are many and no one's concern.
                    if [UNKNOWN, INVITER_LEFT, FOR_ANOTHER, NOT_FOLLOWED, MEMBER_ALREADY].contains(&refused.as_str()) {
                        tracing::debug!("refused a join: {refused}");
                    } else {
                        inner.warn(None, format!("refused a join: {refused}"));
                    }
                    Answer::Refused { refused }
                }
            }
        })
    }
}

//! Admission, both sides: a joiner asks the members an invite link names, keeping its KeyPackage until one admits it; a
//! member answers by the invite's rule, checked again as the Add is built, with the commit entry that added the joiner,
//! or with the one it kept to a joiner it added before whose answer was lost.

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use iroh::{EndpointId, RelayUrl};
use lmk_core::group::{Change, Group, key_package_credential, key_package_leaf, key_package_reference, open_link, seal_link};
use lmk_core::public::Verdict;
use lmk_core::provider::Provider;
use lmk_net::Admit;
use lmk_proto::group::{CHAT, Certificate, Control, Credential, IDENTITY, How, Service};
use lmk_proto::links::Invite;
use lmk_proto::peer::{Admitted, Join};
use lmk_proto::{Answer, Bytes};
use n0_future::boxed::BoxFuture;
use n0_future::task::spawn;
use n0_future::{FuturesUnordered, StreamExt};
use n0_future::time::{Duration, Instant, sleep, sleep_until, timeout};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::logs::NOT_FOLLOWED;
use crate::reading::{admitted_key, commit_key};
use crate::{G, Inner, MEMBER_WAIT, Member, Node, Rec, Rule, State, device_key_key, endpoint_id, get, now, put};

/// How many members besides the inviter a link names, of those online that hold the invite's message.
const LINK_MEMBERS: usize = 3;
/// How long a joiner waits to reach each member it names.
const DIAL_WAIT: Duration = Duration::from_secs(30);
/// How long a joiner waits for each member's answer.
const JOIN_WAIT: Duration = Duration::from_secs(30);
/// How long a joiner asks the members it names: one that gave no answer is asked again until this has passed. A member
/// busy past `JOIN_WAIT` still answers with the Add it kept.
const JOIN_LIMIT: Duration = Duration::from_secs(300);
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
        let id = self.send(gid, &rule, None)?;
        let seq = self.inner.lock().record(gid, &id.0)?.context("the invite's message")?.header.seq;
        // The members online whose summaries hold the invite's message admit by it too: a member asked before its push
        // arrived would refuse the joiner.
        let online = self.online(gid)?;
        let holding = || -> Result<Vec<Member>> {
            let holders = self.inner.lock().holders_of(gid, seq)?;
            Ok(online.iter().filter(|m| holders.contains(&m.key)).cloned().collect())
        };
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
        let holders = holding()?;
        let st = self.inner.lock();
        let Service::Serve { domain, .. } = st.group(gid)?.mls.settings().membership else { bail!("unsupported membership service") };
        let mut members = vec![*self.inner.net().id().as_bytes()];
        members.extend(holders.iter().take(LINK_MEMBERS).filter_map(|member| endpoint_id(&member.iroh.0)).map(|peer| *peer.as_bytes()));
        Ok(Invite { device, secret, domain, members })
    }

    /// Joins through an invite link, speaking as `identity`: asks the members it names in turn, as each is reached. A
    /// device link joins with a new device key. Returns the group, and the iroh key of the member that admitted this
    /// session.
    pub async fn join(&self, link: &Invite, identity: Option<Certificate>) -> Result<(Bytes, [u8; 32])> {
        let service: Vec<RelayUrl> = match (self.inner.resolve)(link.domain.clone()).await {
            Ok(directory) => vec![directory.relay.parse()?],
            Err(error) => {
                self.inner.warn(None, format!("joining without the directory of {}: {error:#}", link.domain));
                Vec::new()
            }
        };
        // Each member is dialed at the relay it last said it was on, and at the link's service.
        let hint = |peer: EndpointId| -> Vec<RelayUrl> { self.inner.lock().hint_of(&peer).into_iter().chain(service.clone()).chain(self.inner.chosen.clone()).collect() };
        let members = link.members.iter().map(|member| Ok(EndpointId::from_bytes(member)?)).collect::<Result<Vec<_>>>()?;
        let (secret, devices) = (Bytes(link.secret.to_vec()), link.device);
        // The KeyPackage, its private keys and its device key are kept until this session joins or every member it asks
        // refuses it: a member that added it asked again answers with the commit entry it kept.
        let joining = [b"node/joining/".as_slice(), &Sha256::digest(&secret.0)].concat();
        let (join, device_key) = {
            let mut st = self.inner.lock();
            st.speak(identity);
            // One kept for the link read as the other kind, as altered, is not this join's: the Welcome is checked against
            // the kind this join asks for.
            let kept = match get::<Joining>(&st.provider, &joining)? {
                Some(kept) if kept.device.is_some() == devices => kept,
                _ => {
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
        // Each dial is a task of its own, so it goes on, and times out, while a member reached earlier is asked.
        let inviter_first = Instant::now() + INVITER_FIRST;
        let mut dials: FuturesUnordered<_> = members
            .into_iter()
            .enumerate()
            .map(|(i, peer)| {
                let net = self.inner.net().clone();
                let (hint, own) = (hint(peer), self.inner.relays.clone());
                spawn(async move {
                    // A dial that fails at once, as one from a node that has just started can, is tried again until the wait
                    // is up.
                    let dialed = timeout(DIAL_WAIT, async {
                        while let Err(error) = net.dial(peer, hint.clone(), Box::pin(std::future::ready(own.clone()))).await {
                            tracing::debug!("dialing {}: {error:#}", peer.fmt_short());
                            sleep(Duration::from_secs(1)).await;
                        }
                    })
                    .await;
                    if i > 0 {
                        sleep_until(inviter_first).await;
                    }
                    (peer, dialed)
                })
            })
            .collect();
        let mut refusal = anyhow::anyhow!("no member the invite names is online");
        let mut refused_by_all = true;
        // Members that gave no answer wait until the members reached meanwhile are asked, then are asked again, while
        // JOIN_LIMIT has not passed.
        let until = Instant::now() + JOIN_LIMIT;
        let mut silent = VecDeque::new();
        loop {
            let peer = match dials.next().await {
                Some(dialed) => {
                    let (peer, dialed) = dialed?;
                    if dialed.is_err() {
                        tracing::debug!("{} is not online", peer.fmt_short());
                        refused_by_all = false;
                        continue;
                    }
                    peer
                }
                None => match silent.pop_front() {
                    Some(peer) if Instant::now() < until => peer,
                    _ => break,
                },
            };
            let answer = timeout(JOIN_WAIT, self.inner.net().join(peer, hint(peer), Box::pin(std::future::ready(self.inner.relays.clone())), join.clone())).await;
            match answer {
                Ok(Ok(Answer::Ok(admitted))) => {
                    let gid = self.inner.welcomed(admitted, &join.key_package.0, peer, device_key).await?;
                    self.inner.lock().provider.delete(&joining)?;
                    return Ok((gid, *peer.as_bytes()));
                }
                Ok(Ok(Answer::Refused { refused })) => refusal = anyhow::anyhow!("refused: {refused}"),
                // The connection may have been replaced by one the member dialed meanwhile; asking again is safe, as a
                // member that added this session answers with the Add it kept. The ask may have added it.
                Ok(Err(error)) => {
                    refused_by_all = false;
                    tracing::debug!("asking {} to admit this session: {error:#}", peer.fmt_short());
                    sleep(Duration::from_secs(1)).await;
                    silent.push_back(peer);
                }
                Err(_) => {
                    refused_by_all = false;
                    tracing::debug!("{} did not answer", peer.fmt_short());
                    silent.push_back(peer);
                }
            }
        }
        if refused_by_all {
            self.inner.lock().provider.delete(&joining)?;
        }
        Err(refusal)
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Joins a group from the Add's answer, a member at `by` sent for this session's KeyPackage: an identity group with the
    /// device key `device_key`, and only then, as a link's kind is not authenticated.
    async fn welcomed(self: &Arc<Self>, admitted: Admitted, key_package: &[u8], by: EndpointId, device_key: Option<[u8; 32]>) -> Result<Bytes> {
        let (gid, doc) = {
            let mut st = self.lock();
            let st = &mut *st;
            let mls = Group::join(&st.provider, &admitted.commit.0, &admitted.welcome.0, &admitted.sig.0, &key_package_reference(&st.provider, key_package)?)?;
            ensure!(!st.groups.contains_key(mls.id()), "this session is in that group already");
            if (mls.settings().kind == IDENTITY) != device_key.is_some() {
                mls.delete(&st.provider)?;
                bail!("the link was altered: it admits to a group of another kind than it says");
            }
            // Opened now: the state key is the one of the epoch the Welcome starts in, which a later commit moves past.
            // A state that does not open is asked for from `by` once the log is read, as a missing one is.
            let doc = match admitted.doc {
                Some(sealed) => match mls.state_secret(&st.provider) {
                    Ok(key) => open_link(&key, &sealed.0).ok(),
                    Err(error) => {
                        mls.delete(&st.provider)?;
                        return Err(error);
                    }
                },
                None => None,
            };
            let hands_state = !matches!(mls.settings().kind.as_str(), CHAT | IDENTITY);
            let wanted = (doc.is_none() && hands_state).then(|| (*by.as_bytes(), mls.epoch()));
            let gid = st.add_group(mls, Rec { wanted, ..Rec::default() })?;
            if let Some(seed) = device_key {
                put(&st.provider, &device_key_key(&gid), &Bytes(seed.to_vec()))?;
                let session = st.keyed(seed)?;
                st.device_keys.insert(gid.clone(), (seed, session));
            }
            (gid, doc)
        };
        // The members' public logs first, which the gate needs to take their summaries, before the log's commits apply.
        self.refresh_all().await;
        if let Err(error) = self.read_group(&gid).await {
            self.warn(Some(&gid), format!("reading the group's log: {error:#}"));
        }
        match doc {
            Some(link) => self.state_from(&gid, link, by),
            None => self.lock().ask_state(&gid)?,
        }
        Ok(Bytes(gid))
    }
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
    ensure!(members.iter().any(|m| m.key == rule.by.0) && g.left(&rule.by.0).is_none(), INVITER_LEFT);
    ensure!(members.iter().all(|member| member.key != joiner.key.0), MEMBER_ALREADY);
    Ok(())
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Answers a joiner's request, which brings an invite's secret.
    async fn admit_join(self: &Arc<Self>, join: Join) -> Result<Admitted> {
        let Join { secret, key_package } = join;
        let joiner = key_package_credential(&self.lock().provider, &key_package.0)?;
        let hash = Bytes(Sha256::digest(&secret.0).to_vec());
        let found = self.lock().groups.iter().find_map(|(gid, g)| Some((gid.clone(), g.rec.invites.iter().find(|rule| rule.hash == hash)?.clone())));
        let (gid, rule) = found.context(UNKNOWN)?;
        // A joiner the log shows added, whose answer was lost, asks again with the same KeyPackage.
        self.caught_up(&gid).await?;
        let logged = self.lock().logged_commit(&gid, &key_package.0)?;
        if let Some(epoch) = logged {
            return self.admitted(&gid, epoch).await;
        }
        self.remove_lapsed(&gid, &joiner.key.0).await?;
        admits(self.lock().group(&gid)?, &joiner, &rule)?;
        // Its identity's public log, read afresh, must list the device that certified it.
        if let Some(to) = &rule.to {
            let certificate = joiner.certificate.as_ref().filter(|c| c.identity.id == *to || c.device == *to).context(FOR_ANOTHER)?;
            match self.read_public(&certificate.identity).await?.verify(&joiner) {
                Verdict::Authorized => {}
                Verdict::Unverified => bail!("its device is not on its identity's list"),
                Verdict::Dropped => bail!("its device was taken off its identity"),
            }
        }
        match self.admit(&gid, key_package.0.clone(), &joiner, rule).await {
            // Another ask with this KeyPackage, as the joiner's again after one failed in transit, may have added it meanwhile.
            Err(error) => {
                let logged = self.lock().logged_commit(&gid, &key_package.0)?;
                match logged {
                    Some(epoch) => self.admitted(&gid, epoch).await,
                    None => Err(error),
                }
            }
            admitted => admitted,
        }
    }

    /// Removes the member whose key a joiner brings, in a commit of its own, if the log of the epoch it is in was let go: a
    /// member that was out past the retention, and not yet removed by the hourly check, must go before its key is added.
    async fn remove_lapsed(self: &Arc<Self>, gid: &[u8], key: &[u8]) -> Result<()> {
        let epoch = {
            let st = self.lock();
            let g = st.group(gid)?;
            let at = g.rec.members.iter().find(|(member, _)| member.0 == key).map(|(_, at)| *at);
            at.and_then(|at| g.rec.epochs.iter().find(|epoch| epoch.epoch == at).cloned())
        };
        let Some(epoch) = epoch else { return Ok(()) };
        if !self.let_go(vec![(epoch.service.clone(), epoch.capability)]).await.contains(&epoch.reference()?) {
            return Ok(());
        }
        let remove = |_: &State<P>, g: &G| Ok(g.mls.members().into_iter().find(|m| m.key == key).map(|m| Change { remove: vec![m.index], ..Change::default() }));
        self.commit(gid, remove).await?;
        Ok(())
    }

    /// Commits the Add, naming the invite the joiner came in by, and answers with its commit entry and the state of the
    /// group's kind, as a file. Each build of the commit checks the joiner's rule again. A joiner whose session does not support
    /// the group's kind is refused.
    async fn admit(self: &Arc<Self>, gid: &[u8], key_package: Vec<u8>, joiner: &Credential, rule: Rule) -> Result<Admitted> {
        {
            let st = self.lock();
            let kind = st.group(gid)?.mls.settings().kind;
            let leaf = key_package_leaf(&st.provider, &key_package)?;
            ensure!(leaf.kinds.contains(&kind), "its session does not support {kind} groups");
        }
        let add = Change { add: vec![key_package], how: Some(How::Invite), invite: Some(rule.hash.clone()), ..Change::default() };
        let epoch = self
            .commit(gid, |_, g| {
                admits(g, joiner, &rule)?;
                Ok(Some(add.clone()))
            })
            .await?
            .context("an Add has effect")?;
        self.admitted(gid, epoch).await
    }

    /// The answer to a joiner an Add moved into `epoch`: the Add's kept answer, and the state of the group's kind, sealed
    /// under the epoch's state key. The joiner is added, by an entry in the log: refusing it now would strand it, and it
    /// asks members for the state later.
    async fn admitted(self: &Arc<Self>, gid: &[u8], epoch: u64) -> Result<Admitted> {
        let (mut admitted, key) = {
            let st = self.lock();
            (
                get::<Admitted>(&st.provider, &commit_key(gid, epoch))?.context("an Add's answer is kept")?,
                st.provider.get(&admitted_key(gid, epoch))?.context("an Add's state key is kept")?,
            )
        };
        admitted.doc = self.state_link(gid).await.map(|link| seal_link(&key, &link)).transpose()?.map(Bytes);
        Ok(admitted)
    }
}

impl<P: Provider> State<P> {
    /// The epoch the Add of the joiner with this KeyPackage moved from, if its leaf has not updated since and this session
    /// made that Add, which keeps its answer.
    fn logged_commit(&self, gid: &[u8], key_package: &[u8]) -> Result<Option<u64>> {
        let g = self.group(gid)?;
        if !g.mls.unchanged(&self.provider, key_package)? {
            return Ok(None);
        }
        let reference = key_package_reference(&self.provider, key_package)?;
        let Some(added) = g.mls.added().iter().rev().find(|added| added.key_package_ref == reference) else { return Ok(None) };
        let epoch = added.epoch - 1;
        Ok(self.provider.get(&admitted_key(gid, epoch))?.is_some().then_some(epoch))
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

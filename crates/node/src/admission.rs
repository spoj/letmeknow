//! Admission, both sides: a joiner asks the members an invite link names, or the members of a group open to its
//! identity, keeping its KeyPackage until one admits it; a member answers by the invite's rule, checked again as the
//! Add is built, or with the logged Welcome to a joiner it added before whose answer was lost.

use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use iroh::{EndpointId, RelayUrl};
use lmk_core::group::{Change, Group, key_package_credential, key_package_leaf};
use lmk_core::identity::Verdict;
use lmk_core::provider::Provider;
use lmk_net::Admit;
use lmk_proto::entry::Entry;
use lmk_proto::group::{CHAT, Certificate, Control, Credential, DEVICES, How, Opening};
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
use crate::reading::Judged;
use crate::{Event, G, INVITE_VALID, Inner, MEMBER_WAIT, Member, Node, Rec, Rule, SNAPSHOT_WAIT, State, device_key_key, endpoint_id, get, now, put};

/// How many members besides the inviter a link names, of those online that hold the invite's message.
const LINK_MEMBERS: usize = 3;
/// How long a joiner waits to reach each member it asks, all at once, and then for each one's answer.
const DIAL_WAIT: Duration = Duration::from_secs(30);
const JOIN_WAIT: Duration = Duration::from_secs(30);
/// How long the inviter, whom a link names first, has to be reached before the other members it names are asked: so the
/// inviter admits whom it invited when it is online.
const INVITER_FIRST: Duration = Duration::from_secs(3);

/// A joiner's KeyPackage, whose private keys openmls keeps, and the device key it is made with for a devices group.
#[derive(Serialize, Deserialize)]
struct Joining {
    key_package: Bytes,
    device: Option<Bytes>,
}

impl<P: Provider + Send + 'static> Node<P> {
    /// An invite into a group, `--for` a contact name or `--to` an identity: shared with the members as a held
    /// message, and a link that names this session and up to three members online that hold it.
    pub async fn invite(&self, gid: &[u8], label: Option<String>, to: Option<Bytes>) -> Result<Invite> {
        let secret: [u8; 16] = lmk_core::random();
        let hash = Bytes(Sha256::digest(secret).to_vec());
        let expires = now() + INVITE_VALID;
        let device = {
            let mut st = self.inner.lock();
            let by = Bytes(st.me(gid).to_vec());
            let g = st.group_mut(gid)?;
            g.rec.invites.push(Rule { hash: hash.clone(), expires, label: label.clone(), to: to.clone(), by });
            st.save(gid)?;
            st.group(gid)?.mls.settings().kind == DEVICES
        };
        let rule = serde_json::to_value(Control::Invite { hash, expires, label, to })?;
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

    /// Joins through an invite link, speaking as `identity`: asks the members it names in turn. A device link joins
    /// with a new device key. Returns the group, and the iroh key of the member that admitted this session.
    pub async fn join(&self, link: &Invite, identity: Option<Certificate>) -> Result<(Bytes, [u8; 32])> {
        let ours: RelayUrl = RELAY.parse()?;
        let members = link
            .members
            .iter()
            .map(|member| Ok((EndpointId::from_bytes(&member.key)?, member.relay.as_ref().map_or(Ok(ours.clone()), |relay| relay.parse())?)))
            .collect::<Result<Vec<_>>>()?;
        self.ask(members, Some(Bytes(link.secret.to_vec())), None, identity, link.device).await
    }

    /// Asks the members of an open group to admit this session in turn, speaking as the identity `identity` certifies.
    pub async fn join_open(&self, opening: &Opening, identity: Certificate) -> Result<Bytes> {
        ensure!(self.inner.kinds.contains(&opening.kind), "this session does not support {} groups", opening.kind);
        let members = opening.members.iter().filter_map(|key| endpoint_id(&key.0)).map(|peer| (peer, self.inner.relay.clone())).collect();
        Ok(self.ask(members, None, Some(opening.group.clone()), Some(identity), false).await?.0)
    }

    /// Asks members in turn, as each is reached, to admit this session, by an invite's secret or a group open to
    /// `identity`.
    async fn ask(
        &self,
        members: Vec<(EndpointId, RelayUrl)>,
        secret: Option<Bytes>,
        group: Option<Bytes>,
        identity: Option<Certificate>,
        devices: bool,
    ) -> Result<(Bytes, [u8; 32])> {
        // The KeyPackage, its private keys and its device key are kept until this session joins or every member it asks
        // refuses it: a member that added it asks again answers with the Welcome its log holds.
        let target = secret.as_ref().map_or_else(|| group.clone().unwrap_or_default().0, |secret| Sha256::digest(&secret.0).to_vec());
        let joining = [b"node/joining/".as_slice(), &target].concat();
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
            (Join { secret, group, key_package: kept.key_package }, device_key)
        };
        // Each dial is a task of its own, so it goes on, and times out, while a member reached earlier is asked.
        let inviter_first = Instant::now() + if join.secret.is_some() { INVITER_FIRST } else { Duration::ZERO };
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
        let mut refused_by_all = true;
        while let Some(dialed) = dials.next().await {
            let (peer, relay, dialed) = dialed?;
            if !matches!(dialed, Ok(Ok(()))) {
                tracing::debug!("{} is not online", peer.fmt_short());
                refused_by_all = false;
                continue;
            }
            match timeout(JOIN_WAIT, self.inner.net().join(peer, relay, join.clone())).await {
                Ok(Ok(Answer::Ok(admitted))) => {
                    let gid = self.inner.welcomed(admitted, peer, device_key).await?;
                    self.inner.lock().provider.delete(&joining)?;
                    return Ok((gid, *peer.as_bytes()));
                }
                Ok(Ok(Answer::Refused { refused })) => refusal = anyhow::anyhow!("refused: {refused}"),
                Ok(Err(error)) => {
                    refused_by_all = false;
                    tracing::debug!("asking {} to admit this session: {error:#}", peer.fmt_short());
                }
                Err(_) => {
                    refused_by_all = false;
                    tracing::debug!("{} did not answer", peer.fmt_short());
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
    /// Joins a group from the Welcome a member at `by` sent: a devices group with the device key `device_key`, and only
    /// then, as a link's kind is not authenticated.
    async fn welcomed(self: &Arc<Self>, admitted: Admitted, by: EndpointId, device_key: Option<[u8; 32]>) -> Result<Bytes> {
        let gid = {
            let mut st = self.lock();
            let st = &mut *st;
            let mls = Group::join(&st.provider, &admitted.welcome.0)?;
            ensure!(!st.groups.contains_key(mls.id()), "this session is in that group already");
            if (mls.settings().kind == DEVICES) != device_key.is_some() {
                mls.delete(&st.provider)?;
                bail!("the link was altered: it admits to a group of another kind than it says");
            }
            let rec = Rec { position: admitted.position, start: admitted.position, expired: admitted.position, ..Rec::default() };
            let gid = st.add_group(mls, rec)?;
            if let Some(seed) = device_key {
                put(&st.provider, &device_key_key(&gid), &Bytes(seed.to_vec()))?;
                let session = st.keyed(seed)?;
                st.device_keys.insert(gid.clone(), (seed, session));
            }
            if admitted.doc.is_some() {
                st.groups.get_mut(&gid).unwrap().asked = now();
            }
            gid
        };
        // The members' key logs first, which the gate needs to take their summaries, before the log's commits apply.
        self.refresh_all().await;
        self.dial_all();
        if let Err(error) = self.read(&gid).await {
            self.warn(Some(&gid), format!("reading the group's log: {error:#}"));
        }
        self.follow(&gid);
        if let Some(link) = admitted.doc {
            self.state_from(&gid, link, by);
        }
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
const NOT_OPEN: &str = "it speaks as no identity the group is open to";
const INVITER_LEFT: &str = "its inviter left the group";
const FOR_ANOTHER: &str = "this invite is for another identity";

/// Whether `g`, as it stands, admits a joiner by an invite, or else by an opening: checked when its request comes, and
/// each time the commit that adds it is built. An invite dies when its inviter leaves the group.
fn admits(g: &G, joiner: &Credential, invite: &Option<Rule>) -> Result<()> {
    let members = g.mls.members();
    match invite {
        Some(rule) => {
            ensure!(now() < rule.expires && !g.mls.used(&rule.hash.0), UNKNOWN);
            ensure!(members.iter().any(|m| m.key == rule.by.0) && !g.left(&rule.by.0), INVITER_LEFT);
        }
        None => ensure!(joiner.identity().is_some_and(|identity| g.mls.settings().open.iter().any(|named| named.id == identity.id)), NOT_OPEN),
    }
    ensure!(members.iter().all(|member| member.key != joiner.key.0), "this session is a member already");
    Ok(())
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Answers a joiner's request: it brings an invite's secret, or speaks as an identity the group is open to.
    async fn admit_join(self: &Arc<Self>, join: Join) -> Result<Admitted> {
        let Join { secret, group, key_package } = join;
        let joiner = key_package_credential(&self.lock().provider, &key_package.0)?;
        let (gid, how, invite, to) = match (secret, group) {
            (Some(secret), _) => {
                let hash = Bytes(Sha256::digest(&secret.0).to_vec());
                let st = self.lock();
                let found = st.groups.iter().find_map(|(gid, g)| Some((gid.clone(), g.rec.invites.iter().find(|rule| rule.hash == hash)?.clone())));
                let (gid, rule) = found.context(UNKNOWN)?;
                let to = rule.to.clone();
                (gid, How::Invite, Some(rule), to)
            }
            (None, Some(gid)) => (gid.0, How::Open, None, Some(joiner.identity().context(NOT_OPEN)?.id.clone())),
            (None, None) => bail!("a request names an invite's secret or a group"),
        };
        // A joiner the log shows added, whose answer was lost, asks again with the same KeyPackage.
        self.caught_up(&gid).await?;
        let logged = self.lock().logged_welcome(&gid, &joiner, &key_package.0)?;
        if let Some((welcome, position)) = logged {
            return self.admitted(&gid, welcome, position).await;
        }
        admits(self.lock().group(&gid)?, &joiner, &invite)?;
        // Its identity's key log, read afresh, must list the device that certified it.
        if let Some(to) = to {
            let identity = joiner.identity().filter(|identity| identity.id == to).context(FOR_ANOTHER)?;
            match self.read_keys(identity).await?.verify(&joiner) {
                Verdict::Verified { .. } => {}
                Verdict::Unverified => bail!("its device is not on its identity's list"),
                Verdict::Dropped => bail!("its device was taken off its identity"),
            }
        }
        self.admit(&gid, key_package.0, &joiner, how, invite).await
    }

    /// Commits the Add, naming the invite the joiner came in by, and answers with the Welcome and the state of the group's
    /// kind, as a file. Each build of the commit checks the joiner's rule again. A joiner whose session does not support
    /// the group's kind is refused.
    async fn admit(self: &Arc<Self>, gid: &[u8], key_package: Vec<u8>, joiner: &Credential, how: How, invite: Option<Rule>) -> Result<Admitted> {
        {
            let st = self.lock();
            let kind = st.group(gid)?.mls.settings().kind;
            let leaf = key_package_leaf(&st.provider, &key_package)?;
            ensure!(leaf.kinds.contains(&kind), "its session does not support {kind} groups");
        }
        let add = Change { add: vec![key_package], how: Some(how), invite: invite.as_ref().map(|rule| rule.hash.clone()), ..Change::default() };
        let (welcome, position) = self
            .commit(gid, |_, g| {
                admits(g, joiner, &invite)?;
                Ok(Some(add.clone()))
            })
            .await?
            .context("an Add has effect")?;
        self.admitted(gid, welcome.context("an add makes a Welcome")?, position).await
    }

    /// The answer to a joiner added at `position`: the Welcome, and the state of the group's kind, as a file.
    async fn admitted(self: &Arc<Self>, gid: &[u8], welcome: Vec<u8>, position: u64) -> Result<Admitted> {
        let state = {
            let st = self.lock();
            let g = st.group(gid)?;
            (g.mls.settings().kind != CHAT).then(|| {
                let (reply, state) = oneshot::channel();
                self.events.send(Event::Snapshot { group: Bytes(gid.to_vec()), reply }).ok();
                state
            })
        };
        let state = match state {
            Some(asked) => timeout(SNAPSHOT_WAIT, asked).await.ok().and_then(Result::ok).flatten(),
            None => None,
        };
        // The joiner is added, by an entry in the log: refusing it now would strand it, and it asks members for the state
        // later.
        let doc = match state {
            Some(state) => match self.state_file(gid, state).await {
                Ok(link) => Some(link),
                Err(error) => {
                    self.warn(Some(gid), format!("admitting a member without the group's state: {error:#}"));
                    None
                }
            },
            None => None,
        };
        if let Err(error) = self.durable().await {
            self.warn(None, format!("saving this session's state: {error:#}"));
        }
        Ok(Admitted { welcome: Bytes(welcome), position, doc })
    }
}

impl<P: Provider> State<P> {
    /// The Welcome and position of the commit entry that added the joiner with this KeyPackage, if the joiner is a member
    /// whose leaf has not updated since.
    fn logged_welcome(&self, gid: &[u8], joiner: &Credential, key_package: &[u8]) -> Result<Option<(Vec<u8>, u64)>> {
        let g = self.group(gid)?;
        if !g.mls.unchanged(&self.provider, key_package)? {
            return Ok(None);
        }
        let Some(added) = g.mls.added().iter().rev().find(|added| added.member.key == joiner.key) else { return Ok(None) };
        for position in (g.rec.expired + 1..=g.rec.position).rev() {
            let Some(pos) = self.pos(gid, position)? else { continue };
            if matches!(pos.judged, Judged::Commit { .. }) && pos.epoch + 1 == added.epoch {
                let entry = self.provider.get(&crate::logs::entry_key(gid, position))?.context("a stored entry is missing")?;
                let Entry::Commit { welcome: Some(welcome), .. } = Entry::parse(&entry)? else { return Ok(None) };
                return Ok(Some((welcome, position)));
            }
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
                    if [UNKNOWN, NOT_OPEN, INVITER_LEFT, FOR_ANOTHER, NOT_FOLLOWED].contains(&refused.as_str()) {
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

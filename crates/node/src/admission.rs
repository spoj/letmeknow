//! Admission, both sides: a joiner asks the members an invite link names, keeping its KeyPackage until one admits it
//! into the group, of the service, that the link names; a member answers by the rule of the invite the link names, by
//! its group, its inviter's membership and the hash of its secret, checked again as the Add is built, with the commit
//! entry that added the joiner, or with the one it kept to a joiner it added before whose answer was lost. A joiner whose
//! device is neither admitted nor an admin gets in only by an admin's invite, which an admin answers: a member that is no
//! admin brings in no other device, not even through an admin its link names.

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use iroh::{EndpointId, RelayUrl};
use lmk_core::group::{Change, Group, Invited, delete_key_package, key_package_leaf, key_package_reference};
use lmk_net::Admit;
use lmk_proto::directory::relay_url;
use lmk_proto::group::{Control, Leaf, PROTOCOL, Service, Settings, Subgroup, UPDATE};
use lmk_proto::links::Invite;
use lmk_proto::peer::{Admitted, Join, SubgroupAsk};
use lmk_proto::clock::corrected;
use lmk_proto::{Answer, Bytes};
use n0_future::boxed::BoxFuture;
use n0_future::task::spawn;
use n0_future::{FuturesUnordered, StreamExt};
use n0_future::time::{Duration, Instant, sleep, sleep_until, timeout};
use sha2::{Digest, Sha256};

use crate::reading::commit_key;
use crate::{G, Inner, MEMBER_WAIT, Member, Node, Rec, Rule, State, endpoint_id, get, put};

/// How many members besides the inviter a link names, of those connected to it that hold the invite's message.
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
/// Maximum auto-joined subgroups kept per parent group.
const MAX_SUBGROUPS_PER_PARENT: usize = 64;
/// Maximum subgroup offers accepted per inviter per minute.
const MAX_SUBGROUP_OFFERS_PER_MIN: usize = 8;
/// How long a subgroup creator waits for a co-member's offer stream to finish.
const SUBGROUP_OFFER_WAIT: Duration = Duration::from_secs(45);
/// Receiver's bounded wait for pre-join parent refresh and subgroup join, strictly inside `SUBGROUP_OFFER_WAIT`.
const SUBGROUP_REFRESH_WAIT: Duration = Duration::from_secs(5);
const SUBGROUP_JOIN_WAIT: Duration = Duration::from_secs(30);
/// How long a subgroup's single-use targeted invite stays valid, in milliseconds.
const SUBGROUP_INVITE_VALID: u64 = 60_000;

/// Result of creating a subgroup of a parent group and inviting co-members to auto-join.
#[derive(Clone, Debug)]
pub struct SubgroupResult {
    pub group: Bytes,
    pub joined: Vec<Bytes>,
    pub failed: Vec<(Bytes, String)>,
}

impl Node {
    /// An invite into a group, valid for `valid` milliseconds: shared with the members as a held message, unless it is
    /// for one member (`to`), and a link that names the group, this session's membership, which made it, and the members
    /// to ask: this session and, when shared, up to three members connected to it that hold it, admins first.
    pub async fn invite(&self, gid: &[u8], valid: u64, to: Option<&[u8]>) -> Result<Invite> {
        let secret: [u8; 16] = lmk_core::random();
        let by = self.key();
        let expires = corrected() + valid;
        let to = to.map(|key| Bytes(key.to_vec()));
        let (hash, joined) = {
            let mut st = self.inner.lock();
            let g = st.group_mut(gid)?;
            let joined = g.mls.joined(&by.0).context("a member of its group")?;
            let hash = Invited::new(by.clone(), joined, &secret).hash(gid);
            g.rec.invites.push(Rule { hash: hash.clone(), expires, by: by.clone(), joined, to: to.clone() });
            st.save(gid)?;
            (hash, joined)
        };
        let mut holders = match to {
            Some(_) => {
                self.inner.caught_up(gid).await?;
                Vec::new()
            }
            None => {
                let rule = serde_json::to_value(Control::Invite { hash, expires })?;
                let id = self.send(gid, &rule, None).await?;
                let seq = self.inner.lock().record(gid, &id.0)?.context("the invite's message")?.header.seq;
                // The members connected whose summaries hold the invite's message admit by it too: a member asked before its
                // push arrived would refuse the joiner.
                let connected = self.connected(gid)?;
                let holding = || -> Result<Vec<Member>> {
                    let holders = self.inner.lock().holders_of(gid, seq)?;
                    Ok(connected.iter().filter(|m| holders.contains(&m.key)).cloned().collect())
                };
                let all = async {
                    loop {
                        let heard = self.inner.heard.notified();
                        if holding()?.len() == connected.len() {
                            return anyhow::Ok(());
                        }
                        heard.await;
                    }
                };
                timeout(MEMBER_WAIT, all).await.unwrap_or(Ok(()))?;
                holding()?
            }
        };
        let st = self.inner.lock();
        let g = st.group(gid)?;
        let Service::Serve { domain, key, .. } = g.mls.settings().membership else { bail!("unsupported membership service") };
        holders.sort_by_key(|member| !g.mls.admin(&member.key.0));
        let mut members = vec![(*self.inner.net().id().as_bytes(), self.inner.home.clone())];
        members.extend(holders.iter().filter_map(|member| Some((*endpoint_id(&member.iroh.0)?.as_bytes(), member.home.clone()))).take(LINK_MEMBERS));
        Ok(Invite { secret, domain, key: key.0.as_slice().try_into()?, group: gid.try_into()?, by: by.0.as_slice().try_into()?, joined, members })
    }

    /// Joins through an invite link: asks the members it names in turn, as each is reached, and reads their frames whole
    /// meanwhile, as an admitter's first hello, which comes before the Welcome, holds every intro of the group. With
    /// `leave`, this session's leave of the group (`Group::leave`) as it left it by itself, by which a member removes its
    /// membership first if it is a member still. Returns the group, and the iroh key of the member that admitted this
    /// session.
    pub async fn join(&self, link: &Invite, leave: Option<Bytes>) -> Result<(Bytes, [u8; 32])> {
        self.inner.join_link(link, leave, None, JOIN_LIMIT).await
    }

    /// Creates a subgroup of `parent` locked to `[self, ...peers]` and invites each peer over `Stream::Subgroup` so
    /// their daemon auto-joins via normal admission. Fails and removes the empty subgroup if no peer joins.
    pub async fn subgroup(&self, parent: &[u8], peers: &[Bytes], carry: u32, membership: Service) -> Result<SubgroupResult> {
        ensure!(!peers.is_empty(), "a subgroup needs at least one other member");
        self.inner.refresh(parent, false).await?;
        let me = self.key();
        let targets: Vec<(Bytes, EndpointId, Vec<RelayUrl>)> = {
            let st = self.inner.lock();
            let g = st.group(parent)?;
            ensure!(g.mls.settings().subgroup.is_none(), "cannot create a subgroup of a subgroup");
            ensure!(g.mls.active() && !g.rec.leaving, "parent group is no longer active");
            let parent_members = g.mls.members();
            let mut seen = std::collections::BTreeSet::new();
            let mut targets = Vec::with_capacity(peers.len());
            for peer in peers {
                ensure!(*peer != me, "cannot include yourself in subgroup peers");
                ensure!(seen.insert(peer.clone()), "duplicate peer in subgroup");
                let member = parent_members
                    .iter()
                    .find(|m| m.key == peer.0)
                    .with_context(|| format!("{} is not a member of the parent group", crate::fp(&peer.0)))?;
                let endpoint = endpoint_id(&member.leaf.key.0).context("invalid peer iroh key")?;
                let relay: RelayUrl = relay_url(&member.leaf.home).parse()?;
                targets.push((peer.clone(), endpoint, vec![relay]));
            }
            targets
        };
        let mut members: Vec<Bytes> = std::iter::once(me.clone()).chain(peers.iter().cloned()).collect();
        members.sort();
        let settings = Settings {
            protocol: PROTOCOL,
            carry,
            update: UPDATE,
            membership,
            admins: vec![],
            admitted: vec![],
            subgroup: Some(Subgroup { parent: Bytes(parent.to_vec()), members }),
        };
        let sub_gid = self.create(settings)?;
        let mut offers = FuturesUnordered::new();
        let mut failed = Vec::new();
        for (peer_key, endpoint, relays) in targets {
            match self.invite(&sub_gid.0, SUBGROUP_INVITE_VALID, Some(&peer_key.0)).await {
                Ok(invite) => {
                    let net = self.inner.net().clone();
                    let ask = SubgroupAsk { parent: Bytes(parent.to_vec()), link: invite.link() };
                    offers.push(async move {
                        let res = timeout(SUBGROUP_OFFER_WAIT, net.subgroup(endpoint, relays, ask)).await;
                        (peer_key, res)
                    });
                }
                Err(error) => failed.push((peer_key, format!("{error:#}"))),
            }
        }
        while let Some((peer_key, res)) = offers.next().await {
            match res {
                Ok(Ok(Answer::Ok(()))) => {}
                Ok(Ok(Answer::Refused { refused })) => failed.push((peer_key, refused)),
                Ok(Err(error)) => failed.push((peer_key, format!("peer unreachable or does not support subgroups (<= 0.26.3): {error:#}"))),
                Err(_) => failed.push((peer_key, "timed out waiting for peer to join subgroup".into())),
            }
        }
        // Compute actual joined peers from MLS state so a peer admitted right at the offer timeout is never treated as absent.
        let joined: Vec<Bytes> = {
            let st = self.inner.lock();
            st.groups
                .get(&sub_gid.0)
                .map(|g| g.mls.members().into_iter().filter(|m| m.key != me.0).map(|m| Bytes(m.key)).collect())
                .unwrap_or_default()
        };
        failed.retain(|(k, _)| !joined.contains(k));
        if joined.is_empty() {
            if let Err(error) = self.leave(&sub_gid.0) {
                tracing::debug!("cleaning up empty subgroup: {error:#}");
            }
            let reasons: Vec<String> = failed.iter().map(|(k, r)| format!("{}: {r}", crate::fp(&k.0))).collect();
            bail!("no peer joined subgroup ({})", reasons.join("; "));
        }
        Ok(SubgroupResult { group: sub_gid, joined, failed })
    }
}

impl Inner {
    async fn join_link(self: &Arc<Self>, link: &Invite, leave: Option<Bytes>, expected_parent: Option<&[u8]>, limit: Duration) -> Result<(Bytes, [u8; 32])> {
        // Each member is dialed at the relay of its own service.
        let member = |(key, home): &([u8; 32], String)| -> Result<(EndpointId, Vec<RelayUrl>)> { Ok((EndpointId::from_bytes(key)?, vec![relay_url(home).parse()?])) };
        let members = link.members.iter().map(member).collect::<Result<Vec<_>>>()?;
        let secret = Bytes(link.secret.to_vec());
        // The KeyPackage, whose private keys openmls keeps, is kept until this session joins or every member it asks
        // refuses it: a member that added it asked again answers with the commit entry it kept.
        let joining = [b"node/joining/".as_slice(), &Sha256::digest(&secret.0)].concat();
        let join = {
            let mut st = self.lock();
            ensure!(!st.groups.contains_key(link.group.as_slice()), "this session is in that group already");
            let key_package = match get::<Bytes>(&st.provider, &joining)? {
                Some(kept) => kept,
                None => {
                    let key_package = Bytes(st.session.key_package(&st.provider)?);
                    put(&st.provider, &joining, &key_package)?;
                    key_package
                }
            };
            st.joins.push(link.clone());
            Join { group: Bytes(link.group.to_vec()), by: Bytes(link.by.to_vec()), joined: link.joined, secret, key_package, leave }
        };
        // Each dial is a task of its own, so it goes on, and times out, while a member reached earlier is asked.
        let inviter_first = Instant::now() + INVITER_FIRST;
        let mut dials: FuturesUnordered<_> = members
            .into_iter()
            .enumerate()
            .map(|(i, (peer, relays))| {
                let net = self.net().clone();
                spawn(async move {
                    // A dial that fails at once, as one from a node that has just started can, is tried again until the wait
                    // is up.
                    let dialed = timeout(DIAL_WAIT, async {
                        while let Err(error) = net.dial(peer, relays.clone()).await {
                            tracing::debug!("dialing {}: {error:#}", peer.fmt_short());
                            sleep(Duration::from_secs(1)).await;
                        }
                    })
                    .await;
                    if i > 0 {
                        sleep_until(inviter_first).await;
                    }
                    (peer, relays, dialed)
                })
            })
            .collect();
        let mut refusal = anyhow::anyhow!("no member the invite names is online");
        let mut refused_by_all = true;
        // Members that gave no answer wait until the members reached meanwhile are asked, then are asked again, while
        // `limit` has not passed.
        let until = Instant::now() + limit;
        let mut silent = VecDeque::new();
        loop {
            let (peer, relays) = match dials.next().await {
                Some(dialed) => {
                    let (peer, relays, dialed) = dialed?;
                    if dialed.is_err() {
                        tracing::debug!("{} is not online", peer.fmt_short());
                        refused_by_all = false;
                        continue;
                    }
                    (peer, relays)
                }
                None => match silent.pop_front() {
                    Some(member) if Instant::now() < until => member,
                    _ => break,
                },
            };
            let answer = timeout(JOIN_WAIT, self.net().join(peer, relays.clone(), join.clone())).await;
            match answer {
                Ok(Ok(Answer::Ok(admitted))) => match self.welcomed(admitted, &join.key_package.0, link, expected_parent).await {
                    Ok(gid) => {
                        let mut st = self.lock();
                        st.joins.retain(|other| other != link);
                        st.provider.delete(&joining)?;
                        return Ok((gid, *peer.as_bytes()));
                    }
                    Err(error) => refusal = anyhow::anyhow!("refused: {error:#}"),
                },
                Ok(Ok(Answer::Refused { refused })) => refusal = anyhow::anyhow!("refused: {refused}"),
                // The connection may have been replaced by one the member dialed meanwhile; asking again is safe, as a
                // member that added this session answers with the Add it kept. The ask may have added it.
                Ok(Err(error)) => {
                    refused_by_all = false;
                    tracing::debug!("asking {} to admit this session: {error:#}", peer.fmt_short());
                    sleep(Duration::from_secs(1)).await;
                    silent.push_back((peer, relays));
                }
                Err(_) => {
                    refused_by_all = false;
                    tracing::debug!("{} did not answer", peer.fmt_short());
                    silent.push_back((peer, relays));
                }
            }
        }
        let mut st = self.lock();
        st.joins.retain(|other| other != link);
        if refused_by_all {
            delete_key_package(&st.provider, &join.key_package.0)?;
            st.provider.delete(&joining)?;
            st.scrub = true;
        }
        Err(refusal)
    }

    /// Joins the group a link names from the Add's answer a member sent for this session's KeyPackage.
    async fn welcomed(self: &Arc<Self>, admitted: Admitted, key_package: &[u8], link: &Invite, expected_parent: Option<&[u8]>) -> Result<Bytes> {
        let gid = {
            let mut st = self.lock();
            let st = &mut *st;
            let admission = lmk_core::group::Admission { welcome: admitted.welcome.0, cut: admitted.cut, sig: admitted.sig.0 };
            let package = key_package_reference(&st.provider, key_package)?;
            let mls = Group::join(&st.provider, &admitted.commit.0, &admission, &package, &link.group, &link.domain, &link.key)?;
            let sub = mls.settings().subgroup;
            if expected_parent.is_some() || sub.is_some() {
                let valid = (|| -> Result<()> {
                    let sub = sub.context("Welcome is not for a subgroup")?;
                    if let Some(expected_parent) = expected_parent {
                        ensure!(sub.parent.0 == expected_parent, "subgroup parent does not match offer");
                    }
                    ensure!(sub.members.iter().any(|k| k.0 == st.me()), "this session is not among subgroup members");
                    let parent_g = st.groups.get(&sub.parent.0).context("not a member of the subgroup's parent group")?;
                    ensure!(parent_g.mls.settings().subgroup.is_none(), "cannot join a subgroup of a subgroup");
                    ensure!(parent_g.mls.active() && !parent_g.rec.leaving, "parent group is no longer active");
                    let count = st
                        .groups
                        .values()
                        .filter(|g| g.mls.settings().subgroup.as_ref().is_some_and(|s| s.parent == sub.parent))
                        .count();
                    ensure!(count < MAX_SUBGROUPS_PER_PARENT, "too many subgroups for this parent group");
                    let parent_members = parent_g.mls.members();
                    ensure!(
                        sub.members.iter().all(|k| parent_members.iter().any(|m| m.key == k.0)),
                        "subgroup names a member outside the parent group"
                    );
                    Ok(())
                })();
                if let Err(error) = valid {
                    let _ = mls.delete(&st.provider);
                    return Err(error);
                }
            }
            // Its Add had no update path: its first update, due at once, merges its leaf into the tree (`merge`).
            st.add_group(mls, Rec { stirred: true, created: crate::now(), ..Rec::default() })?
        };
        if let Err(error) = self.read_group(&gid).await {
            self.warn(Some(&gid), format!("reading the group's log: {error:#}"));
        }
        // Its duties commit the update later if this one fails.
        if let Err(error) = self.merge(&gid).await {
            tracing::debug!("merging this session's leaf: {error:#}");
        }
        Ok(Bytes(gid))
    }

    async fn accept_subgroup(self: &Arc<Self>, peer: EndpointId, ask: SubgroupAsk) -> Result<()> {
        let invite = Invite::parse(&ask.link)?;
        {
            let st = self.lock();
            let parent_g = st.groups.get(&ask.parent.0).context("not a member of that parent group")?;
            ensure!(parent_g.mls.settings().subgroup.is_none(), "cannot create a subgroup of a subgroup");
            ensure!(parent_g.mls.active() && !parent_g.rec.leaving, "parent group is no longer active");
            let inviter = st.in_leaf(&ask.parent.0, &peer).context("sender is not a member of the parent group")?;
            ensure!(inviter.key == invite.by, "invite maker does not match sender");
            ensure!(parent_g.left(&inviter.key).is_none(), "sender left the parent group");
            let (parent_domain, parent_key) = match parent_g.mls.settings().membership {
                Service::Serve { domain, key, .. } => (domain, key),
                Service::Newer(_) => bail!("unsupported membership service"),
            };
            ensure!(
                invite.domain == parent_domain && invite.key == parent_key.0.as_slice(),
                "subgroup invite must use the parent group's membership service"
            );
            ensure!(
                invite.members.len() == 1
                    && invite.members[0].0 == *peer.as_bytes()
                    && invite.members[0].1 == inviter.leaf.home,
                "subgroup invite must route only through the inviter"
            );
            ensure!(!st.groups.contains_key(invite.group.as_slice()), "already in that subgroup");
            let count = st
                .groups
                .values()
                .filter(|g| g.mls.settings().subgroup.as_ref().is_some_and(|s| s.parent == ask.parent))
                .count();
            ensure!(count < MAX_SUBGROUPS_PER_PARENT, "too many subgroups for this parent group");
            let t = crate::now();
            let mut offers = self.subgroup_offers.lock().unwrap();
            let times = offers.entry(inviter.key.clone()).or_default();
            while times.front().is_some_and(|&at| t.saturating_sub(at) >= 60_000) {
                times.pop_front();
            }
            ensure!(times.len() < MAX_SUBGROUP_OFFERS_PER_MIN, "too many subgroup offers; slow down");
            times.push_back(t);
        }
        if let Err(error) = timeout(SUBGROUP_REFRESH_WAIT, self.refresh(&ask.parent.0, false)).await {
            tracing::debug!("parent refresh before subgroup join timed out: {error:#}");
        }
        self.join_link(&invite, None, Some(&ask.parent.0), SUBGROUP_JOIN_WAIT).await?;
        Ok(())
    }
}

/// The answer to a secret no rule admits by: whether it is unknown, used or expired is not told.
const UNKNOWN: &str = "unknown, used or expired invite";
const INVITER_LEFT: &str = "its inviter left the group";
const MEMBER_ALREADY: &str = "this session is a member already";
const FOR_ANOTHER: &str = "this invite is for another member";
const NOT_ADMITTED: &str = "the joining session's device is neither admitted nor an admin, so only an admin admits it, by an admin's invite: an admin invites it, or admits its device (`admitted add`)";

/// Whether `g`, as it stands, admits a joiner, by its key and leaf data, by an invite, as the member with key `me`:
/// checked when its request comes, and each time the commit that adds it is built. An invite dies when its inviter
/// leaves the group.
fn admits(g: &G, me: &[u8], (joiner, leaf): &(Vec<u8>, Leaf), rule: &Rule) -> Result<()> {
    let members = g.mls.members();
    ensure!(corrected() < rule.expires && !g.mls.used(&rule.hash.0), UNKNOWN);
    ensure!(g.mls.joined(&rule.by.0) == Some(rule.joined) && g.left(&rule.by.0).is_none(), INVITER_LEFT);
    ensure!(rule.to.as_ref().is_none_or(|to| to.0 == *joiner), FOR_ANOTHER);
    ensure!(members.iter().all(|member| member.key != *joiner), MEMBER_ALREADY);
    ensure!(g.mls.admits(leaf) || (g.mls.admin(me) && g.mls.admin(&rule.by.0)), NOT_ADMITTED);
    Ok(())
}

impl Inner {
    /// Answers a joiner's request by the rule of the invite it names: in its group, of its inviter's membership, with the
    /// hash its secret gives. A joiner whose key is a member, and which brings that membership's leave, is removed by it
    /// first, in a commit of its own, built only while that membership stands: a commit may not add a key it removes.
    async fn admit_join(self: &Arc<Self>, join: Join) -> Result<Admitted> {
        let Join { group, by, joined, secret, key_package, leave } = join;
        let gid = group.0;
        let invited = Invited::new(by, joined, &secret.0);
        let hash = invited.hash(&gid);
        let found = self.lock().groups.get(&gid).and_then(|g| g.rec.invites.iter().find(|rule| rule.by == invited.by && rule.joined == joined && rule.hash == hash).cloned());
        let rule = found.context(UNKNOWN)?;
        let joiner = key_package_leaf(&self.lock().provider, &key_package.0)?;
        // A joiner the log shows added, whose answer was lost, asks again with the same KeyPackage: it is answered at once
        // if this session applied the Add, else once it caught up.
        let logged = self.lock().logged_commit(&gid, &key_package.0)?;
        if let Some(epoch) = logged {
            return self.admitted(&gid, epoch);
        }
        self.caught_up(&gid).await?;
        let logged = self.lock().logged_commit(&gid, &key_package.0)?;
        if let Some(epoch) = logged {
            return self.admitted(&gid, epoch);
        }
        if let Some(sig) = &leave {
            let remove = |_: &State, g: &G| {
                let left = g.mls.left(&joiner.0, &sig.0);
                Ok(g.mls.members().into_iter().find(|m| m.key == joiner.0 && left).map(|m| Change { remove: vec![m.index], left: vec![sig.clone()], ..Change::default() }))
            };
            self.commit(&gid, remove).await?;
        }
        {
            let st = self.lock();
            admits(st.group(&gid)?, st.me(), &joiner, &rule)?;
        }
        match self.admit(&gid, key_package.0.clone(), &joiner, rule, invited).await {
            // Another ask with this KeyPackage, as the joiner's again after one failed in transit, may have added it meanwhile.
            Err(error) => {
                let logged = self.lock().logged_commit(&gid, &key_package.0)?;
                match logged {
                    Some(epoch) => self.admitted(&gid, epoch),
                    None => Err(error),
                }
            }
            admitted => admitted,
        }
    }

    /// Commits the Add, carrying the invite the joiner came in by, and answers with its commit entry. Each build of the
    /// commit checks the joiner's rule again.
    async fn admit(self: &Arc<Self>, gid: &[u8], key_package: Vec<u8>, joiner: &(Vec<u8>, Leaf), rule: Rule, invited: Invited) -> Result<Admitted> {
        let add = Change { add: vec![key_package], invite: Some(invited), ..Change::default() };
        let epoch = self
            .commit(gid, |st, g| {
                admits(g, st.me(), joiner, &rule)?;
                Ok(Some(add.clone()))
            })
            .await?
            .context("an Add has effect")?;
        self.admitted(gid, epoch)
    }

    /// The answer to a joiner an Add moved from `epoch`, which the Add's committer keeps.
    fn admitted(&self, gid: &[u8], epoch: u64) -> Result<Admitted> {
        get::<Admitted>(&self.lock().provider, &commit_key(gid, epoch))?.context("an Add's answer is kept")
    }
}

impl State {
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
        Ok(self.provider.get(&commit_key(gid, epoch))?.is_some().then_some(epoch))
    }
}


pub(crate) struct Admitter(pub Arc<Inner>);

impl Admit for Admitter {
    fn join(&self, _: EndpointId, join: Join) -> BoxFuture<Answer<Admitted>> {
        let inner = self.0.clone();
        Box::pin(async move {
            match inner.admit_join(join).await {
                Ok(admitted) => Answer::Ok(admitted),
                Err(error) => {
                    let refused = format!("{error:#}");
                    // A joiner asks every member a link names, so routine refusals are many and no one's concern.
                    if [UNKNOWN, INVITER_LEFT, MEMBER_ALREADY, FOR_ANOTHER, NOT_ADMITTED].contains(&refused.as_str()) {
                        tracing::debug!("refused a join: {refused}");
                    } else {
                        inner.warn(None, format!("refused a join: {refused}"));
                    }
                    Answer::Refused { refused }
                }
            }
        })
    }

    fn subgroup(&self, peer: EndpointId, ask: SubgroupAsk) -> BoxFuture<Answer<()>> {
        let inner = self.0.clone();
        Box::pin(async move {
            match inner.accept_subgroup(peer, ask).await {
                Ok(()) => Answer::Ok(()),
                Err(error) => {
                    let refused = format!("{error:#}");
                    tracing::debug!("refused a subgroup offer: {refused}");
                    Answer::Refused { refused }
                }
            }
        })
    }
}

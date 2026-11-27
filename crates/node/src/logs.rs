//! The logs this session follows: each group's log of its current epoch, of its commits and held messages' entries, and
//! the earlier epochs' logs it still reads. A capability names each at its membership service, which keeps it under the
//! reference `head::reference` derives from it, the log's id here. Each is read from its service, chained, held entry by
//! entry, shown to peers by its newest signed head and caught up from them, and handed to its group once held. A
//! session asks a service about its logs on pinned sends, as it commits, and when a normal send's in-memory verification
//! of the current log is missing or older than `REFRESH_TTL`: online members bring it the rest.

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use lmk_core::provider::SqliteProvider;
use lmk_membership::client::{Post, ServeClient};
use lmk_membership::{Contradiction, Expired, Frontier, Refused, Unsupported, WrongDirectory};
use lmk_net::peers::WAIT;
use lmk_proto::Bytes;
use lmk_proto::group::Service;
use lmk_proto::head::{self, Head};
use lmk_proto::membership::STALE;
use lmk_proto::clock::corrected;
use n0_future::time::{Duration, Instant, timeout};
use serde::{Deserialize, Serialize};

use crate::{Inner, SendError, State, Work, get, hex, put};

pub(crate) const NOT_FOLLOWED: &str = "this session does not follow that log";

/// How long a send waits for the service: chat works while it is down.
const SEND_WAIT: Duration = Duration::from_secs(5);
/// How long an in-memory service verification of a group's current log stays reusable for ordinary sends.
pub(crate) const REFRESH_TTL: Duration = Duration::from_secs(5 * 60);

/// How strictly `refresh` checks a group's current log against its membership service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Check {
    /// Ordinary send: reuse a direct service observation of the current log within `REFRESH_TTL` while not stale,
    /// lapsed, or behind locally held entries; fail open within `STALE` if unreachable.
    Cached,
    /// Rare membership check (e.g. subgroup setup): always ask `/heads`, fail open within `STALE` if unreachable.
    BestEffort,
    /// Pinned send (`--only` / `dm`): always ask `/heads` and fail closed (`SendError::Unverified`) if unreachable.
    Strict,
}

/// The log cleared by `refresh`, and whether clearance came from a direct service check in this call (vs. cache hit or
/// fail-open).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cleared {
    pub log: Vec<u8>,
    pub direct: bool,
}

/// One membership client per service, sharing the session's post; only the home's service sets the clock.
pub(crate) struct Clients {
    post: Post,
    home: String,
    clients: Mutex<HashMap<String, ServeClient>>,
}

impl Clients {
    pub fn new(post: Post, home: String) -> Self {
        Clients { post, home, clients: Mutex::default() }
    }

    pub fn client(&self, service: &Service) -> Result<ServeClient> {
        let name = serde_json::to_string(service)?;
        let mut clients = self.clients.lock().unwrap();
        if let Some(client) = clients.get(&name) {
            return Ok(client.clone());
        }
        let own = matches!(service, Service::Serve { domain, .. } if *domain == self.home);
        let client = ServeClient::for_service(self.post.clone(), service, own)?;
        clients.insert(name, client.clone());
        Ok(client)
    }
}

/// The key a membership service signs its heads with.
pub(crate) fn authority(service: &Service) -> Result<[u8; 32]> {
    let Service::Serve { key, .. } = service else { anyhow::bail!("unsupported membership service") };
    key.0.as_slice().try_into().context("a service key is 32 bytes")
}

/// What this session holds of a log of one of its groups' epochs.
#[derive(Serialize, Deserialize)]
pub(crate) struct Log {
    /// The group's id.
    pub group: Bytes,
    pub service: Service,
    /// The newest head held, which covers every entry held; none before the first.
    pub head: Option<Head>,
    /// When it was last read from its service, or the time of the newest head a peer's entries ended at, in
    /// milliseconds.
    pub at: u64,
    /// When this session began to follow it, in milliseconds.
    pub since: u64,
    /// When the service first answered that it let the log go, or this session took it as let go, and the length held
    /// then.
    pub lapsed: Option<(u64, u64)>,
    /// Monotonic time captured just before the most recent direct service observation confirming this log's frontier.
    /// In-memory only: a restarted session always starts cold.
    #[serde(skip)]
    pub verified: Option<Instant>,
    /// Valid signed heads observed from `/heads` ahead of our locally stored frontier, keyed by length with the
    /// monotonic instant each was recorded. Retained until entries verify consistency through each checkpoint.
    #[serde(skip)]
    pub seen_heads: BTreeMap<u64, (Head, Instant)>,
    /// Whether a signed contradiction was observed on this log in this process; blocks cache reuse.
    #[serde(skip)]
    pub contradicted: bool,
}

impl Log {
    pub fn new(group: Bytes, service: Service) -> Self {
        Log {
            group,
            service,
            head: None,
            at: 0,
            since: corrected(),
            lapsed: None,
            verified: None,
            seen_heads: BTreeMap::new(),
            contradicted: false,
        }
    }

    /// Whether this session has observed any signed head ahead of its locally stored entries for this log.
    pub fn behind_seen(&self) -> bool {
        self.seen_heads.keys().next_back().is_some_and(|&len| self.length() < len)
    }

    /// Whether a direct service observation of this log is still within `REFRESH_TTL` at `now` and free of adverse
    /// state (lapsed, contradicted, or behind a newer signed head).
    pub fn fresh(&self, now: Instant) -> bool {
        !self.contradicted
            && !self.behind_seen()
            && self.lapsed.is_none()
            && self.verified.is_some_and(|at| now.checked_duration_since(at).is_some_and(|age| age < REFRESH_TTL))
    }

    /// The entries held, positions 1 to this.
    pub fn length(&self) -> u64 {
        self.head.as_ref().map_or(0, |head| head.length)
    }

    /// Whether this session has not seen the log alive for `STALE`: past that, the service may have forgotten that it
    /// let the log go, so only new entries show it alive, and it is never appended to.
    pub fn stale(&self) -> bool {
        corrected() > self.at.max(self.since) + STALE
    }

    /// When the log turns stale unless this session sees it alive first, in milliseconds by this session's own clock, which
    /// its timers run on: `at` and `since` are by its service's.
    pub fn stale_at(&self) -> u64 {
        crate::now() + (self.at.max(self.since) + STALE).saturating_sub(corrected())
    }

    /// How far the log is authenticated, for the membership client.
    pub(crate) fn frontier(&self, id: &[u8]) -> Result<Frontier> {
        let (service, id) = (authority(&self.service)?, id.try_into()?);
        match &self.head {
            Some(head) => Frontier::from_head(service, id, head.clone()),
            None => Ok(Frontier::empty(service, id)),
        }
    }
}

pub(crate) fn log_key(id: &[u8]) -> Vec<u8> {
    [b"node/log/".as_slice(), id].concat()
}

/// An entry, after the chain's hash through it.
pub(crate) fn entry_key(id: &[u8], position: u64) -> Vec<u8> {
    [b"node/entry/".as_slice(), id, b"/", &position.to_be_bytes()].concat()
}

impl State {
    /// Loads the logs this session follows.
    pub(crate) fn load_logs(provider: &SqliteProvider) -> Result<BTreeMap<Vec<u8>, Log>> {
        let ids = get::<Vec<Bytes>>(provider, b"node/logs")?.unwrap_or_default();
        ids.into_iter().map(|id| Ok((id.0.clone(), get(provider, &log_key(&id.0))?.context("a log without its record")?))).collect()
    }

    pub(crate) fn log(&self, id: &[u8]) -> Result<&Log> {
        self.logs.get(id).context(NOT_FOLLOWED)
    }

    pub(crate) fn save_log(&self, id: &[u8]) -> Result<()> {
        put(&self.provider, &log_key(id), self.log(id)?)
    }

    /// Records that a log was read from its service as of `at`, if this session still follows it.
    pub(crate) fn read_as_of(&mut self, id: &[u8], at: u64) -> Result<()> {
        let Some(log) = self.logs.get_mut(id) else { return Ok(()) };
        log.at = log.at.max(at);
        self.save_log(id)
    }

    /// Records an in-memory monotonic timestamp of a direct service observation confirming `id`, unless `id` is lapsed,
    /// contradicted, or behind a newer signed head.
    pub(crate) fn mark_verified(&mut self, id: &[u8], asked: Instant) {
        if let Some(log) = self.logs.get_mut(id)
            && !log.contradicted
            && !log.behind_seen()
            && log.lapsed.is_none()
        {
            log.verified = Some(log.verified.map_or(asked, |prev| prev.max(asked)));
        }
    }

    fn save_logs(&self) -> Result<()> {
        let ids: Vec<Bytes> = self.logs.keys().map(|id| Bytes(id.clone())).collect();
        put(&self.provider, b"node/logs", &ids)
    }

    pub(crate) fn add_log(&mut self, id: &[u8], log: Log) -> Result<()> {
        self.logs.insert(id.to_vec(), log);
        self.save_log(id)?;
        self.save_logs()
    }

    pub(crate) fn drop_log(&mut self, id: &[u8]) -> Result<()> {
        let Some(log) = self.logs.remove(id) else { return Ok(()) };
        for position in 1..=log.length() {
            self.provider.delete(&entry_key(id, position))?;
        }
        self.provider.delete(&log_key(id))?;
        self.save_logs()
    }

    /// The entry held at a position of a log.
    pub(crate) fn entry(&self, id: &[u8], position: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.provider.get(&entry_key(id, position))?.map(|held| held[32..].to_vec()))
    }

    /// The log's chain hash through a position this session holds.
    pub(crate) fn hash_at(&self, id: &[u8], position: u64) -> Result<Option<[u8; 32]>> {
        if position == 0 {
            return Ok(Some(head::start(&authority(&self.log(id)?.service)?, id.try_into()?)));
        }
        Ok(self.provider.get(&entry_key(id, position))?.map(|held| held[..32].try_into().unwrap()))
    }

    /// The entries held after position `after`.
    pub(crate) fn entries(&self, id: &[u8], after: u64) -> Vec<Bytes> {
        (after + 1..).map_while(|position| self.entry(id, position).ok()?.map(Bytes)).collect()
    }

    /// The capability that names a log at its service, from the MLS state of the epoch the log is of, while the group is
    /// in it.
    pub(crate) fn capability(&self, id: &[u8]) -> Result<[u8; 32]> {
        let g = self.group(&self.log(id)?.group.0)?;
        ensure!(g.rec.log.0 == id, "the group has moved on from that log");
        g.mls.capability(&self.provider)
    }

    /// Starts the log of a group's current epoch, after position `base`, as the group's current log.
    pub(crate) fn next_log(&mut self, gid: &[u8], base: u64) -> Result<Vec<u8>> {
        let g = self.group(gid)?;
        let service = g.mls.settings().membership;
        let id = head::reference(&authority(&service)?, &g.mls.capability(&self.provider)?).to_vec();
        self.add_log(&id, Log::new(Bytes(gid.to_vec()), service))?;
        let rec = &mut self.group_mut(gid)?.rec;
        (rec.log, rec.base) = (Bytes(id.clone()), base);
        self.save(gid)?;
        Ok(id)
    }

    /// The last position of a group whose entry this session holds.
    pub(crate) fn held_to(&self, gid: &[u8]) -> Result<u64> {
        let rec = &self.group(gid)?.rec;
        Ok(rec.base + self.log(&rec.log.0)?.length())
    }

    /// The entry held at a position of a group's current log.
    pub(crate) fn group_entry(&self, gid: &[u8], position: u64) -> Result<Option<Vec<u8>>> {
        let rec = &self.group(gid)?.rec;
        self.entry(&rec.log.0, position - rec.base)
    }

    /// The logs of a group, its current one last.
    pub(crate) fn group_logs(&self, gid: &[u8]) -> Vec<Vec<u8>> {
        let current = self.groups.get(gid).map(|g| g.rec.log.0.clone());
        let of = |id: &Vec<u8>, log: &Log| log.group.0 == gid && Some(id) != current.as_ref();
        let mut logs: Vec<Vec<u8>> = self.logs.iter().filter(|(id, log)| of(id, log)).map(|(id, _)| id.clone()).collect();
        logs.extend(current);
        logs
    }

    /// Drops a group's earlier logs read longer than `before`.
    pub(crate) fn drop_earlier(&mut self, gid: &[u8], before: u64) -> Result<()> {
        let mut logs = self.group_logs(gid);
        logs.pop();
        for id in logs {
            if self.log(&id)?.at < before {
                self.drop_log(&id)?;
            }
        }
        Ok(())
    }

}

impl Inner {
    /// Checks the group's current log against its membership service according to `check` and returns the id of the
    /// log cleared for sending.
    ///
    /// For `Check::Cached`, reuses an in-memory service verification within `REFRESH_TTL` while the log is neither
    /// stale nor lapsed; if locally held commits have not been applied yet, waits via `caught_up`. For
    /// `Check::BestEffort` and `Check::Strict`, always queries `/heads`; `Check::Strict` fails closed with
    /// `SendError::Unverified` if the service does not answer, while non-strict modes fail open within `STALE` only
    /// when the log is not known lapsed and has no unapplied held commits.
    pub(crate) async fn refresh(self: &Arc<Self>, gid: &[u8], check: Check) -> Result<Cleared> {
        loop {
            let (id, service, capability, cache_hit, at_head) = {
                let st = self.lock();
                let id = st.group(gid)?.rec.log.0.clone();
                let log = st.log(&id)?;
                let cache_hit = check == Check::Cached && log.fresh(Instant::now()) && !log.stale();
                (id.clone(), log.service.clone(), st.capability(&id)?, cache_hit, st.at_head(gid))
            };
            if cache_hit {
                if at_head {
                    return Ok(Cleared { log: id, direct: false });
                }
                self.caught_up(gid).await.map_err(|e| if e.is::<Expired>() { SendError::LetGo.into() } else { e })?;
                continue;
            }
            let asked = Instant::now();
            let answer = match timeout(SEND_WAIT, async { self.clients.client(&service)?.heads(&[capability]).await }).await {
                Ok(Ok(mut answers)) => answers.remove(0),
                failed => {
                    let error = match failed {
                        Ok(Err(error)) => {
                            self.report(&error);
                            Some(error)
                        }
                        _ => None,
                    };
                    if check == Check::Strict {
                        let message = match error {
                            Some(error) => format!("membership service did not answer: {error:#}"),
                            None => "membership service did not answer".into(),
                        };
                        return Err(SendError::Unverified(message).into());
                    }
                    let (moved, lapsed, stale, contradicted, behind) = {
                        let st = self.lock();
                        let cur = st.group(gid)?.rec.log.0.clone();
                        let log = st.log(&cur)?;
                        (cur != id, log.lapsed.is_some(), log.stale(), log.contradicted, !st.at_head(gid) || log.behind_seen())
                    };
                    if moved {
                        continue;
                    }
                    if lapsed {
                        return Err(SendError::LetGo.into());
                    }
                    if stale || contradicted {
                        return match error {
                            Some(error) => Err(error),
                            None => Err(anyhow::anyhow!("the membership service did not answer")),
                        };
                    }
                    if behind {
                        self.caught_up(gid).await.map_err(|e| if e.is::<Expired>() { SendError::LetGo.into() } else { e })?;
                        continue;
                    }
                    return Ok(Cleared { log: id, direct: false });
                }
            };
            enum Outcome {
                Cleared(Cleared),
                CatchUp,
                Retry,
            }
            let outcome = {
                let mut st = self.lock();
                if st.group(gid)?.rec.log.0 != id {
                    Outcome::Retry
                } else {
                    let stale = st.log(&id)?.stale();
                    let lapsed = st.log(&id)?.lapsed.is_some();
                    let held = st.log(&id)?.length();
                    match answer {
                        Ok(head) => {
                            let hash_at = if head.length < held { st.hash_at(&id, head.length)? } else { None };
                            if let Err(error) = st.log(&id)?.frontier(&id)?.check(&head, hash_at) {
                                if let Some(contradiction) = error.downcast_ref::<Contradiction>() {
                                    self.contradicted(&mut st, &id, contradiction, "this session");
                                }
                                return Err(error);
                            }
                            if let Some((seen, _)) = st.log(&id)?.seen_heads.get(&head.length)
                                && seen.hash != head.hash
                            {
                                let contradiction = Contradiction { ours: seen.clone(), theirs: head };
                                self.contradicted(&mut st, &id, &contradiction, "this session");
                                return Err(contradiction.into());
                            }
                            // Any longer checkpoint already recorded before this request began proves rollback;
                            // an overlapping shorter response merely raced with an append, but if it is ahead of
                            // `held` we still retain it as a checkpoint before catching up.
                            if let Some(seen) = st
                                .log(&id)?
                                .seen_heads
                                .range((Bound::Excluded(head.length), Bound::Unbounded))
                                .find_map(|(_, (h, obs))| (asked >= *obs).then_some(h.clone()))
                            {
                                let contradiction = Contradiction { ours: seen, theirs: head };
                                self.contradicted(&mut st, &id, &contradiction, "this session");
                                return Err(contradiction.into());
                            }
                            let has_longer = st
                                .log(&id)?
                                .seen_heads
                                .range((Bound::Excluded(head.length), Bound::Unbounded))
                                .next()
                                .is_some();
                            if head.length > held {
                                let observed = Instant::now();
                                let log = st.logs.get_mut(&id).unwrap();
                                log.seen_heads.entry(head.length).or_insert((head, observed));
                                log.verified = None;
                                Outcome::CatchUp
                            } else if has_longer {
                                Outcome::CatchUp
                            } else if head.length == held {
                                if lapsed {
                                    return Err(SendError::LetGo.into());
                                }
                                if stale {
                                    self.lapse(&mut st, &id)?;
                                    return Err(SendError::LetGo.into());
                                }
                                st.read_as_of(&id, head.time)?;
                                st.mark_verified(&id, asked);
                                if st.at_head(gid) && !st.log(&id)?.behind_seen() {
                                    Outcome::Cleared(Cleared { log: id, direct: true })
                                } else {
                                    Outcome::CatchUp
                                }
                            } else if !stale && !lapsed {
                                Outcome::CatchUp
                            } else {
                                if !lapsed {
                                    self.lapse(&mut st, &id)?;
                                }
                                return Err(SendError::LetGo.into());
                            }
                        }
                        Err(_) => {
                            self.lapse(&mut st, &id)?;
                            return Err(SendError::LetGo.into());
                        }
                    }
                }
            };
            match outcome {
                Outcome::Cleared(cleared) => return Ok(cleared),
                Outcome::Retry => continue,
                Outcome::CatchUp => {
                    self.caught_up(gid).await.map_err(|e| if e.is::<Expired>() { SendError::LetGo.into() } else { e })?;
                    let cleared = {
                        let st = self.lock();
                        let cur = st.group(gid)?.rec.log.0.clone();
                        let log = st.log(&cur)?;
                        (st.at_head(gid)
                            && !log.stale()
                            && log.lapsed.is_none()
                            && !log.behind_seen()
                            && !log.contradicted
                            && log.verified.is_some_and(|at| at >= asked))
                        .then_some(Cleared { log: cur, direct: true })
                    };
                    if let Some(cleared) = cleared {
                        return Ok(cleared);
                    }
                }
            }
        }
    }

    /// Warns once of what the service answered that it is not the group's, or runs another minor. Other failures are
    /// retried at the next send or open.
    pub(crate) fn report(&self, error: &anyhow::Error) {
        if (error.is::<WrongDirectory>() || error.is::<Unsupported>()) && self.warned.lock().unwrap().insert(error.to_string()) {
            self.warn(None, error.to_string());
        }
        tracing::debug!("asking the membership service: {error:#}");
    }

    /// Reads a log from its service, through its end, while its group is in its epoch.
    pub(crate) async fn read(&self, id: &[u8]) -> Result<()> {
        loop {
            let (capability, service, frontier) = {
                let st = self.lock();
                let Ok(capability) = st.capability(id) else { return Ok(()) };
                let log = st.log(id)?;
                (capability, log.service.clone(), log.frontier(id)?)
            };
            let asked = Instant::now();
            let page = match self.clients.client(&service)?.read(&capability, &frontier).await {
                Ok(page) => page,
                Err(error) => {
                    if let Some(contradiction) = error.downcast_ref::<Contradiction>() {
                        self.contradicted(&mut self.lock(), id, contradiction, "this session");
                    }
                    if matches!(error.downcast_ref::<Refused>(), Some(Refused(code)) if code == "policy")
                        && self.lock().log(id).is_ok_and(Log::stale)
                    {
                        let expired = Expired(id.try_into()?);
                        return self.lapse(&mut self.lock(), id).and(Err(expired.into()));
                    }
                    if error.is::<Expired>() {
                        self.lapse(&mut self.lock(), id)?;
                    }
                    return Err(error);
                }
            };
            let more = !page.entries.is_empty();
            let mut st = self.lock();
            let was_stale = st.log(id).is_ok_and(Log::stale);
            if !more && was_stale {
                let expired = Expired(id.try_into()?);
                self.lapse(&mut st, id)?;
                return Err(expired.into());
            }
            if !more
                && let Some((seen, _)) = st.logs.get(id).and_then(|log| log.seen_heads.get(&page.head.length))
                && seen.hash != page.head.hash
            {
                let contradiction = Contradiction { ours: seen.clone(), theirs: page.head };
                self.contradicted(&mut st, id, &contradiction, "this session");
                return Err(contradiction.into());
            }
            if !more {
                let above = (Bound::Excluded(page.head.length), Bound::Unbounded);
                if let Some(seen) = st
                    .logs
                    .get(id)
                    .and_then(|log| log.seen_heads.range(above).find_map(|(_, (h, obs))| (asked >= *obs).then_some(h.clone())))
                {
                    let contradiction = Contradiction { ours: seen, theirs: page.head };
                    self.contradicted(&mut st, id, &contradiction, "this session");
                    return Err(contradiction.into());
                }
                if st.logs.get(id).is_some_and(|log| log.seen_heads.range(above).next().is_some()) {
                    // This empty read started before every longer checkpoint was recorded; retry for the newer entries.
                    continue;
                }
            }
            let (end, head_time, head_hash) = (page.head.length, page.head.time, page.head.hash);
            self.take_entries(&mut st, id, page.after, page.entries, page.head)?;
            let exact_match = !was_stale
                && st.log(id).is_ok_and(|log| log.length() == end)
                && st.hash_at(id, end)? == Some(head_hash);
            if exact_match {
                st.read_as_of(id, head_time)?;
            }
            if !more {
                let current_matching = exact_match
                    && st.logs.get(id).is_some_and(|log| {
                        st.groups.get(&log.group.0).is_some_and(|g| g.rec.log.0 == id)
                            && !log.stale()
                            && log.lapsed.is_none()
                            && !log.contradicted
                            && !log.behind_seen()
                    });
                if current_matching {
                    st.mark_verified(id, asked);
                }
                return Ok(());
            }
        }
    }

    /// Holds entries of a log that follow position `after` and end at `head`, a head its service signed, from the
    /// service or a peer: the new ones, if they chain on to this session's copy; a head that contradicts it is
    /// reported. Hands the new ones to the group, while it is the group's current log.
    pub(crate) fn take_entries(&self, st: &mut State, id: &[u8], after: u64, entries: Vec<Bytes>, head: Head) -> Result<()> {
        let length = st.log(id)?.length();
        if after > length {
            return Ok(());
        }
        let mut hashes = vec![st.hash_at(id, after)?.context("a held entry is missing")?];
        for entry in &entries {
            hashes.push(head::next(hashes.last().unwrap(), &entry.0));
        }
        if after + entries.len() as u64 != head.length || *hashes.last().unwrap() != head.hash {
            tracing::debug!("entries that do not end at their head");
            return Ok(());
        }
        let overlap = head.length.min(length);
        if st.hash_at(id, overlap)? != Some(hashes[(overlap - after) as usize]) {
            let ours = st.log(id)?.head.clone().context("a held entry without its head")?;
            self.contradicted(st, id, &Contradiction { ours, theirs: head }, "this session");
            return Ok(());
        }
        // Verify every retained checkpoint covered by `head` before writing entries or advancing the group.
        let checkpoints: Vec<(u64, Head)> = st
            .log(id)?
            .seen_heads
            .range(..=head.length)
            .map(|(&pos, (h, _))| (pos, h.clone()))
            .collect();
        for (pos, seen) in &checkpoints {
            let hash = if *pos <= length {
                st.hash_at(id, *pos)?
            } else {
                Some(hashes[(*pos - after) as usize])
            };
            if hash != Some(seen.hash) {
                let contradiction = Contradiction { ours: seen.clone(), theirs: head };
                self.contradicted(st, id, &contradiction, "this session");
                return Err(contradiction.into());
            }
        }
        let fresh = head.length > length;
        for position in length + 1..=head.length {
            let index = (position - after) as usize;
            st.provider.put(&entry_key(id, position), &[hashes[index].as_slice(), &entries[index - 1].0].concat())?;
        }
        let log = st.logs.get_mut(id).unwrap();
        log.seen_heads.retain(|&pos, _| pos > head.length);
        if head.length >= length {
            log.at = log.at.max(head.time);
        }
        if fresh {
            log.head = Some(head);
        }
        st.save_log(id)?;
        let group = st.log(id)?.group.0.clone();
        if fresh && st.groups.get(&group).is_some_and(|g| g.rec.log.0 == id) {
            self.advance(st, &group)?;
        }
        Ok(())
    }

    /// The service let a log go, as it answered. A group's current log that stays gone for `WAIT`, with no entry of it
    /// brought meanwhile, is left once it is found gone again, as it is read again then: the commit that moves the group
    /// on is in it, and no member can read it.
    fn lapse(&self, st: &mut State, id: &[u8]) -> Result<()> {
        let now = crate::now();
        let log = st.logs.get_mut(id).context(NOT_FOLLOWED)?;
        log.verified = None;
        let length = log.length();
        let since = match log.lapsed {
            Some((since, held)) if held == length => since,
            _ => {
                log.lapsed = Some((now, length));
                now
            }
        };
        let group = log.group.0.clone();
        st.save_log(id)?;
        if !st.groups.get(&group).is_some_and(|g| g.rec.log.0 == id) {
            return Ok(());
        }
        if now >= since + WAIT {
            self.work.send(Work::Gone(group)).ok();
        } else if since == now {
            self.work.send(Work::Duties(group)).ok();
        }
        Ok(())
    }
}

impl Inner {
    /// Reports a log that its service showed differently, here and at `there`, unless it reported those two heads of it
    /// already. Also invalidates in-memory refresh verification on `log`.
    pub(crate) fn contradicted(&self, st: &mut State, log: &[u8], contradiction: &Contradiction, there: &str) {
        if let Some(entry) = st.logs.get_mut(log) {
            entry.contradicted = true;
            entry.verified = None;
        }
        let Contradiction { ours, theirs } = contradiction;
        let mut heads = [(ours.length, ours.hash.to_vec()), (theirs.length, theirs.hash.to_vec())];
        heads.sort();
        if !self.contradictions.lock().unwrap().insert((log.to_vec(), heads)) {
            return;
        }
        let text = format!(
            "the membership service showed {there} another version of the group's log: length {} with hash {} here, length {} with hash {} there",
            ours.length,
            hex(&ours.hash),
            theirs.length,
            hex(&theirs.hash)
        );
        self.warn(st.logs.get(log).map(|l| l.group.0.as_slice()), text);
    }
}

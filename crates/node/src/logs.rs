//! The logs this session follows: each group's log of its current epoch, of its commits and held messages' entries, and
//! the earlier epochs' logs it still reads. A capability names each at its membership service, which keeps it under the
//! reference `head::reference` derives from it, the log's id here. Each is read from its service, chained, held entry by
//! entry, shown to peers by its newest signed head and caught up from them, and handed to its group once held. A
//! session asks a service about its logs only before it sends and as it commits: online members bring it the rest.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use lmk_core::provider::SqliteProvider;
use lmk_membership::client::{Post, ServeClient};
use lmk_membership::{Contradiction, Expired, Frontier, Refused, Unsupported, WrongDirectory};
use lmk_net::peers::WAIT;
use lmk_proto::Bytes;
use lmk_proto::group::Service;
use lmk_proto::head::{self, Head};
use lmk_proto::membership::{Expiry, STALE};
use lmk_proto::clock::corrected;
use n0_future::time::{Duration, timeout};
use serde::{Deserialize, Serialize};

use crate::{Epoch, Inner, SendError, State, Work, get, hex, put};

pub(crate) const NOT_FOLLOWED: &str = "this session does not follow that log";

/// How long a send waits for the service: chat works while it is down.
const SEND_WAIT: Duration = Duration::from_secs(5);

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
}

impl Log {
    pub fn new(group: Bytes, service: Service) -> Self {
        Log { group, service, head: None, at: 0, since: corrected(), lapsed: None }
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

impl Epoch {
    /// The reference of the epoch's log at its service.
    pub(crate) fn reference(&self) -> Result<[u8; 32]> {
        Ok(head::reference(&authority(&self.service)?, &self.capability))
    }

    /// Whether this session knows its log let go.
    pub(crate) fn gone(&self) -> bool {
        self.expired.is_some() || self.forgotten
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

    /// Takes expiries of logs of the group's earlier epochs, asked of their services or told by a neighbour, and the
    /// references of logs `forgotten`, that their services answered this session's own ask with a head of length 0
    /// (`let_go`): each expiry its service signed, and each forgotten log, of an epoch a member is in, leaves the
    /// members in that epoch behind, or the member whose claim it is.
    pub(crate) fn take_expiries(&mut self, gid: &[u8], expiries: &[Expiry], forgotten: &[[u8; 32]]) -> Result<bool> {
        let g = self.group_mut(gid)?;
        let key = VerifyingKey::from_bytes(&authority(&g.mls.settings().membership)?)?;
        let mut taken = false;
        for epoch in g.rec.epochs.iter_mut().filter(|epoch| epoch.expired.is_none()) {
            let reference = epoch.reference()?;
            if let Some(expiry) = expiries.iter().find(|expiry| expiry.log_ref == reference && expiry.verify(&key)) {
                (epoch.expired, taken) = (Some(expiry.clone()), true);
            } else if forgotten.contains(&reference) {
                (epoch.forgotten, taken) = (true, true);
            }
        }
        if taken {
            self.save(gid)?;
        }
        Ok(taken)
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
    /// Before a send: asks the service about the group's current log, and if it moved, or this session holds a commit of
    /// it that it has not applied, as while it waits for what the last one kept, waits until this session caught up with
    /// it, through each epoch a commit moves it to. Fails when the log counts as let go. Within `STALE`, a service that
    /// does not answer within `SEND_WAIT` holds nothing back: chat goes on while it is down.
    pub(crate) async fn refresh(self: &Arc<Self>, gid: &[u8]) -> Result<()> {
        let (id, service, capability, held) = {
            let st = self.lock();
            let id = st.group(gid)?.rec.log.0.clone();
            (id.clone(), st.log(&id)?.service.clone(), st.capability(&id)?, st.log(&id)?.length())
        };
        let current_stale = |st: &State| st.group(gid).and_then(|g| st.log(&g.rec.log.0)).is_ok_and(Log::stale);
        let answer = match timeout(SEND_WAIT, async { self.clients.client(&service)?.heads(&[capability]).await }).await {
            Ok(Ok(mut answers)) => answers.remove(0),
            Ok(Err(error)) => {
                self.report(&error);
                if current_stale(&self.lock()) {
                    return Err(error);
                }
                return Ok(());
            }
            Err(_) => {
                if current_stale(&self.lock()) {
                    anyhow::bail!("the membership service did not answer");
                }
                return Ok(());
            }
        };
        let stale = self.lock().log(&id).is_ok_and(Log::stale);
        match answer {
            Ok(head) if head.length == held && !stale => {
                self.lock().read_as_of(&id, head.time)?;
                if self.lock().at_head(gid) { Ok(()) } else { self.caught_up(gid).await }
            }
            Ok(head) if !stale || head.length > held => {
                self.caught_up(gid).await.map_err(|e| if e.is::<Expired>() { SendError::LetGo.into() } else { e })
            }
            _ => self.lapse(&mut self.lock(), &id).and(Err(SendError::LetGo.into())),
        }
    }

    /// Asks the services whether the logs the group's members are behind in were let go, but those known to be, so that
    /// the commit this session builds next removes those members (`due`).
    pub(crate) async fn ask_behind(self: &Arc<Self>, gid: &[u8]) -> Result<()> {
        let asked: Vec<Epoch> = {
            let st = self.lock();
            let g = st.group(gid)?;
            g.rec.epochs.iter().filter(|e| e.epoch < g.mls.epoch() && !e.gone()).cloned().collect()
        };
        if asked.is_empty() {
            return Ok(());
        }
        let (expiries, forgotten) = self.let_go(asked.iter().map(|epoch| (epoch.service.clone(), epoch.capability)).collect()).await;
        self.lock().take_expiries(gid, &expiries, &forgotten).map(drop)
    }

    /// Of the logs among `logs`, each a service and a capability of an epoch behind the group's current one, those their
    /// services let go: the expiries of those they answer so, and the references of those they answer with a head of
    /// length 0. Such a log held the commit that ended its epoch, so it holds nothing once its service forgot it,
    /// `EXPIRED_DAYS` after it let it go.
    pub(crate) async fn let_go(&self, logs: Vec<(Service, [u8; 32])>) -> (Vec<Expiry>, Vec<[u8; 32]>) {
        let mut services: Vec<(Service, Vec<[u8; 32]>)> = Vec::new();
        for (service, capability) in logs {
            match services.iter_mut().find(|(s, _)| *s == service) {
                Some((_, capabilities)) => capabilities.push(capability),
                None => services.push((service, vec![capability])),
            }
        }
        let (mut expiries, mut forgotten) = (Vec::new(), Vec::new());
        for (service, capabilities) in services {
            let answers = match self.clients.client(&service) {
                Ok(client) => client.heads(&capabilities).await,
                Err(error) => Err(error),
            };
            match answers {
                Ok(answers) => {
                    for answer in answers {
                        match answer {
                            Ok(head) if head.length == 0 => forgotten.push(head.log_ref),
                            Ok(_) => {}
                            Err(expiry) => expiries.push(expiry),
                        }
                    }
                }
                Err(error) => self.report(&error),
            }
        }
        (expiries, forgotten)
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
            let page = match self.clients.client(&service)?.read(&capability, &frontier).await {
                Ok(page) => page,
                Err(error) => {
                    if let Some(contradiction) = error.downcast_ref::<Contradiction>() {
                        self.contradicted(&self.lock(), id, contradiction, "this session");
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
            if !more && self.lock().log(id).is_ok_and(Log::stale) {
                let expired = Expired(id.try_into()?);
                return self.lapse(&mut self.lock(), id).and(Err(expired.into()));
            }
            let end = page.head.length;
            let mut st = self.lock();
            self.take_entries(&mut st, id, page.after, page.entries, page.head)?;
            if st.log(id).is_ok_and(|log| log.length() >= end) {
                st.read_as_of(id, corrected())?;
            }
            if !more {
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
        let fresh = head.length > length;
        for position in length + 1..=head.length {
            let index = (position - after) as usize;
            st.provider.put(&entry_key(id, position), &[hashes[index].as_slice(), &entries[index - 1].0].concat())?;
        }
        let log = st.logs.get_mut(id).unwrap();
        log.at = log.at.max(head.time);
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
    /// already.
    pub(crate) fn contradicted(&self, st: &State, log: &[u8], contradiction: &Contradiction, there: &str) {
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

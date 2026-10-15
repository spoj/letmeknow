//! Every log this session follows, alike: the log of a group's current epoch, of its commits and held messages'
//! entries, and the public logs of the identities its groups' members speak as. A capability names each at its
//! membership service, which keeps it under the reference `head::reference` derives from it, the log's id here. Each is
//! read from its service, chained, held entry by entry, shown to peers by its newest signed head and caught up from
//! them; what its entries mean is its log type's (`Of`), to which `Inner::check` hands them once held.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use lmk_core::provider::Provider;
use lmk_core::public::{PublicLog, Verdict};
use lmk_membership::client::{Post, ServeClient};
use lmk_membership::{Contradiction, Frontier, Unsupported, VerifiedPage, WrongDirectory};
use lmk_proto::Bytes;
use lmk_proto::group::{IdentityRef, Service};
use lmk_proto::head::{self, Head};
use lmk_proto::membership::Known;
use lmk_proto::clock::now;
use n0_future::time::{Duration, sleep, timeout};
use serde::{Deserialize, Serialize};

use crate::{Event, Inner, MEMBER_WAIT, State, Work, get, hex, put};

pub(crate) const NOT_FOLLOWED: &str = "this session does not follow that log";

/// How often, at most, a session asks its services for the heads of the logs it follows: a random time between three
/// quarters of it and all of it.
const POLL: Duration = Duration::from_secs(2 * 60);

/// The logs asked of one service, each with the length held.
type Asked = (Service, Vec<(Vec<u8>, Known)>);

/// One membership client per service, sharing the session's post.
pub(crate) struct Clients {
    post: Post,
    clients: Mutex<HashMap<String, ServeClient>>,
}

impl Clients {
    pub fn new(post: Post) -> Self {
        Clients { post, clients: Mutex::default() }
    }

    pub fn client(&self, service: &Service) -> Result<ServeClient> {
        let name = serde_json::to_string(service)?;
        let mut clients = self.clients.lock().unwrap();
        if let Some(client) = clients.get(&name) {
            return Ok(client.clone());
        }
        let client = ServeClient::for_service(self.post.clone(), service)?;
        clients.insert(name, client.clone());
        Ok(client)
    }
}

/// The key a membership service signs its heads with.
pub(crate) fn authority(service: &Service) -> Result<[u8; 32]> {
    let Service::Serve { key, .. } = service else { anyhow::bail!("unsupported membership service") };
    key.0.as_slice().try_into().context("a service key is 32 bytes")
}

/// What a log is, which decides what its entries mean.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Of {
    /// A group's log of an epoch, by the group's id.
    Group(Bytes),
    /// A public log, by its id: an identity's, by the identity's.
    Public(Bytes),
}

/// What this session holds of a log.
#[derive(Serialize, Deserialize)]
pub(crate) struct Log {
    pub of: Of,
    pub service: Service,
    /// The newest head held, which covers every entry held; none before the first.
    pub head: Option<Head>,
    /// When it was last read from its service, or the time of the newest head a peer's entries ended at, in
    /// milliseconds.
    pub at: u64,
}

impl Log {
    pub fn new(of: Of, service: Service) -> Self {
        Log { of, service, head: None, at: 0 }
    }

    /// The entries held, positions 1 to this.
    pub fn length(&self) -> u64 {
        self.head.as_ref().map_or(0, |head| head.length)
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

impl<P: Provider> State<P> {
    /// Loads the logs this session follows.
    pub(crate) fn load_logs(provider: &P) -> Result<BTreeMap<Vec<u8>, Log>> {
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
        log.at = at;
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

    /// The capability that names a log at its service: a public log's address, or a group's from the MLS state of the
    /// epoch the log is of, while the group is in it.
    pub(crate) fn capability(&self, id: &[u8]) -> Result<[u8; 32]> {
        match &self.log(id)?.of {
            Of::Public(public) => Ok(lmk_proto::public::address(&public.0)),
            Of::Group(group) => {
                let g = self.group(&group.0)?;
                ensure!(g.rec.log.0 == id, "the group has moved on from that log");
                g.mls.capability(&self.provider)
            }
        }
    }

    /// Starts the log of a group's current epoch, after position `base`, as the group's current log.
    pub(crate) fn next_log(&mut self, gid: &[u8], base: u64) -> Result<Vec<u8>> {
        let g = self.group(gid)?;
        let service = g.mls.settings().membership;
        let id = head::reference(&authority(&service)?, &g.mls.capability(&self.provider)?).to_vec();
        self.add_log(&id, Log::new(Of::Group(Bytes(gid.to_vec())), service))?;
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
        let of = |id: &Vec<u8>, log: &Log| matches!(&log.of, Of::Group(group) if group.0 == gid) && Some(id) != current.as_ref();
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

    /// The public log of an identity this session follows.
    pub(crate) fn public_log(&self, identity: &[u8]) -> Option<Vec<u8>> {
        self.logs.iter().find_map(|(id, log)| matches!(&log.of, Of::Public(of) if of.0 == identity).then(|| id.clone()))
    }

    /// The logs this session follows at their services: its public logs, and each group's current log.
    pub(crate) fn followed(&self) -> Vec<(Vec<u8>, Service, Known)> {
        let mut followed = Vec::new();
        for (id, log) in &self.logs {
            let current = match &log.of {
                Of::Public(_) => true,
                Of::Group(group) => self.groups.get(&group.0).is_some_and(|g| g.rec.log.0 == *id),
            };
            if let (true, Ok(capability)) = (current, self.capability(id)) {
                followed.push((id.clone(), log.service.clone(), Known(capability, log.length())));
            }
        }
        followed
    }

    /// The groups a log concerns.
    pub(crate) fn groups_of(&self, id: &[u8]) -> Vec<Vec<u8>> {
        match self.logs.get(id).map(|log| &log.of) {
            Some(Of::Group(group)) => vec![group.0.clone()],
            Some(Of::Public(public)) => {
                let of = |gid: &Vec<u8>| {
                    self.identities(gid).iter().any(|i| i.id == *public) || self.groups[gid].mls.settings().public.as_ref() == Some(public)
                };
                self.groups.keys().filter(|gid| of(gid)).cloned().collect()
            }
            None => Vec::new(),
        }
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Asks each service for the heads of the logs this session follows, and reads those that moved. A log the answer
    /// leaves out is unchanged as of the request, which counts as a read of it.
    pub(crate) async fn ask_heads(self: &Arc<Self>) {
        let followed = self.lock().followed();
        let mut services: Vec<Asked> = Vec::new();
        for (id, service, known) in followed {
            match services.iter_mut().find(|(s, _)| *s == service) {
                Some((_, logs)) => logs.push((id, known)),
                None => services.push((service, vec![(id, known)])),
            }
        }
        for (service, logs) in services {
            let sent = now();
            let known: Vec<Known> = logs.iter().map(|(_, known)| *known).collect();
            let moved = match self.clients.client(&service) {
                Ok(client) => client.heads(&known).await,
                Err(error) => Err(error),
            };
            let moved = match moved {
                Ok(moved) => moved,
                Err(error) => {
                    self.report(&error);
                    continue;
                }
            };
            for (id, _) in logs {
                if moved.iter().any(|head| head.log_ref[..] == id[..]) {
                    if let Err(error) = self.read(&id).await {
                        self.report(&error);
                    }
                } else if let Err(error) = self.lock().read_as_of(&id, sent) {
                    self.report(&error);
                }
            }
        }
    }

    /// Asks for the heads every `POLL`, from now on.
    pub(crate) async fn ask_heads_forever(self: Arc<Self>) {
        loop {
            self.ask_heads().await;
            let jitter = u64::from_be_bytes(lmk_proto::random::random::<8>()) % (POLL.as_millis() as u64 / 4);
            sleep(POLL - Duration::from_millis(jitter)).await;
        }
    }

    /// Warns once of what the service answered that it is not the group's, or runs another minor. Other failures are
    /// retried at the next poll.
    fn report(&self, error: &anyhow::Error) {
        if (error.is::<WrongDirectory>() || error.is::<Unsupported>()) && self.warned.lock().unwrap().insert(error.to_string()) {
            self.warn(None, error.to_string());
        }
        tracing::debug!("polling the membership service: {error:#}");
    }

    /// Reads a log from its service, through its end; a group's only while the group is in its epoch.
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
                    return Err(error);
                }
            };
            let more = !page.page().entries.is_empty();
            self.stored(id, page)?;
            if !more {
                let mut st = self.lock();
                st.logs.get_mut(id).context("dropped the log")?.at = crate::now();
                return st.save_log(id);
            }
        }
    }

    /// Holds a page the service sent.
    pub(crate) fn stored(&self, id: &[u8], page: VerifiedPage) -> Result<()> {
        let page = page.into_page();
        self.take_entries(&mut self.lock(), id, page.after, page.entries, page.head)
    }

    /// Holds entries of a log that follow position `after` and end at `head`, a head its service signed, from the
    /// service or a peer: the new ones, if they chain on to this session's copy; a head that contradicts it is
    /// reported. Hands the new ones to the log's type.
    pub(crate) fn take_entries(&self, st: &mut State<P>, id: &[u8], after: u64, entries: Vec<Bytes>, head: Head) -> Result<()> {
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
        if fresh {
            self.check(st, id)?;
        }
        Ok(())
    }

    /// Hands a log's new entries to its log type: a group's, while it is the group's current log.
    fn check(&self, st: &mut State<P>, id: &[u8]) -> Result<()> {
        match st.log(id)?.of.clone() {
            Of::Group(group) => match st.groups.get(&group.0) {
                Some(g) if g.rec.log.0 == id => self.advance(st, &group.0),
                _ => Ok(()),
            },
            Of::Public(public) => self.replayed(st, &public.0),
        }
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Reads the public logs of the identities in this session's groups that it holds none of, and once more for each
    /// device a member's certificate names that its identity does not list. A log read is followed from then on.
    pub(crate) async fn refresh_all(self: &Arc<Self>) {
        let unread: Vec<IdentityRef> = {
            let mut st = self.lock();
            let st = &mut *st;
            let mut unread = Vec::new();
            for credential in st.groups.values().flat_map(|g| g.mls.members()).filter_map(|m| m.credential) {
                let Some(certificate) = &credential.certificate else { continue };
                let identity = &certificate.identity;
                let read = match st.public.get(&identity.id.0) {
                    None => true,
                    Some(log) => log.verify(&credential) == Verdict::Unverified && st.unlisted.insert((identity.id.0.clone(), certificate.device.0.clone())),
                };
                if read && !unread.contains(identity) {
                    unread.push(identity.clone());
                }
            }
            unread
        };
        for identity in unread {
            if let Err(error) = timeout(MEMBER_WAIT, self.read_public(&identity)).await.map_err(anyhow::Error::from).and_then(|r| r) {
                tracing::debug!("the public log of {}: {error:#}", hex(&identity.id.0));
            }
        }
    }

    /// Uses a claimant's route only to find the genesis-authenticated service; only that service's history is held
    /// and followed.
    pub(crate) async fn read_public(self: &Arc<Self>, identity: &IdentityRef) -> Result<PublicLog> {
        let address = lmk_proto::public::address(&identity.id.0);
        let followed = self.lock().public_log(&identity.id.0);
        let id = match followed {
            Some(id) => id,
            None => {
                let public_id = identity.id.0.as_slice().try_into()?;
                // Unauthenticated lookups must not seed the shared clients or the persisted route.
                let hint = ServeClient::for_service(self.clients.post.clone(), &identity.membership)?;
                let key = authority(&identity.membership)?;
                let first = hint.read(&address, &Frontier::empty(key, head::reference(&key, &address))).await?;
                let service = PublicLog::replay(public_id, first.page().entries.iter().map(|entry| entry.0.as_slice()))?.membership;
                let (client, key) = (self.clients.client(&service)?, authority(&service)?);
                let mut frontier = Frontier::empty(key, head::reference(&key, &address));
                let mut entries = Vec::new();
                loop {
                    let page = client.read(&address, &frontier).await?;
                    if page.page().entries.is_empty() {
                        break;
                    }
                    frontier = page.frontier().clone();
                    entries.extend(page.into_page().entries);
                }
                let public = PublicLog::replay(public_id, entries.iter().map(|entry| entry.0.as_slice()))?;
                ensure!(public.membership == service, "the public log belongs to another membership service");
                let id = frontier.log_ref().to_vec();
                let mut st = self.lock();
                if !st.logs.contains_key(&id) {
                    st.add_log(&id, Log::new(Of::Public(identity.id.clone()), service))?;
                    self.take_entries(&mut st, &id, 0, entries, frontier.head().cloned().context("the public log has no head")?)?;
                }
                id
            }
        };
        self.read(&id).await?;
        self.lock().public.get(&identity.id.0).cloned().context("the public log has no valid first entry")
    }

    /// Replays a public log: an identity's, against which its sessions' certificates are checked.
    pub(crate) fn replayed(&self, st: &mut State<P>, id: &[u8]) -> Result<()> {
        let Some(log) = st.public_log(id) else { return Ok(()) };
        let entries = st.entries(&log, 0);
        if entries.is_empty() {
            return Ok(());
        }
        let public = PublicLog::replay(id.try_into()?, entries.iter().map(|entry| entry.0.as_slice()))?;
        ensure!(public.membership == st.log(&log)?.service, "the public log belongs to another membership service");
        st.public.insert(id.to_vec(), public);
        st.observe_identities()?;
        st.gate = true;
        for gid in st.groups_of(&log) {
            st.events.push(Event::Heard { group: Bytes(gid.clone()) });
            self.work.send(Work::Duties(gid)).ok();
        }
        st.events.push(Event::Public { identity: Bytes(id.to_vec()) });
        Ok(())
    }

    /// Reports a log that its service showed differently, here and at `there`, unless it reported those two heads of it
    /// already.
    pub(crate) fn contradicted(&self, st: &State<P>, log: &[u8], contradiction: &Contradiction, there: &str) {
        let Contradiction { ours, theirs } = contradiction;
        let mut heads = [(ours.length, ours.hash.to_vec()), (theirs.length, theirs.hash.to_vec())];
        heads.sort();
        if !self.contradictions.lock().unwrap().insert((log.to_vec(), heads)) {
            return;
        }
        let what = match st.logs.get(log).map(|l| &l.of) {
            Some(Of::Public(_)) => "a public log",
            _ => "the group's log",
        };
        let text = format!(
            "the membership service showed {there} another version of {what}: length {} with hash {} here, length {} with hash {} there",
            ours.length,
            hex(&ours.hash),
            theirs.length,
            hex(&theirs.hash)
        );
        let groups = st.groups_of(log);
        if groups.is_empty() {
            self.warn(None, text.clone());
        }
        for gid in groups {
            self.warn(Some(&gid), text.clone());
        }
    }
}

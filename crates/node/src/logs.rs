//! Every log this session follows, alike: a group's log of commits, its kind's log of held messages' ids, and the key
//! logs of the identities its groups' members speak as. Each is read from its membership service, chained, held entry
//! by entry, shown to peers by its newest signed head and caught up from them; what its entries mean is its log type's
//! (`Of`), to which `Inner::check` hands them once held.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use lmk_core::provider::Provider;
use lmk_membership::client::ServeClient;
use lmk_membership::{Chain, Contradiction, Membership};
use lmk_proto::Bytes;
use lmk_proto::group::Service;
use lmk_proto::head::{self, Head};
use lmk_transport::Transport;
use n0_future::task::spawn;
use n0_future::time::{Duration, sleep, timeout};
use serde::{Deserialize, Serialize};

use crate::{Inner, RESYNC, State, Work, get, hex, put};

/// One membership client per service, sharing the session's transport.
pub(crate) struct Clients {
    transport: Arc<dyn Transport>,
    clients: Mutex<HashMap<String, Arc<dyn Membership>>>,
}

impl Clients {
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Clients { transport, clients: Mutex::default() }
    }

    pub fn client(&self, service: &Service) -> Result<Arc<dyn Membership>> {
        let name = serde_json::to_string(service)?;
        let mut clients = self.clients.lock().unwrap();
        if let Some(client) = clients.get(&name) {
            return Ok(client.clone());
        }
        let client: Arc<dyn Membership> = match service {
            Service::Serve { .. } => Arc::new(ServeClient::for_service(self.transport.clone(), service)?),
            #[cfg(not(target_arch = "wasm32"))]
            Service::Folder(path) => Arc::new(lmk_membership::folder::FolderClient::new(path)),
            #[cfg(target_arch = "wasm32")]
            Service::Folder(_) => anyhow::bail!("a browser cannot reach a folder"),
            Service::Newer(_) => anyhow::bail!("a newer letmeknow made this membership service; update letmeknow"),
        };
        clients.insert(name, client.clone());
        Ok(client)
    }
}

/// What a log is, which decides what its entries mean.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Of {
    /// A group's commits; the log's id is the group's.
    Group,
    /// The log of a group's kind, which orders held messages by id.
    Kind(Bytes),
    /// An identity's key log.
    Identity(Bytes),
}

/// What this session holds of a log.
#[derive(Serialize, Deserialize)]
pub(crate) struct Log {
    pub of: Of,
    pub service: Service,
    /// Entries are held from position `start + 1`.
    pub start: u64,
    /// The last position held.
    pub logged: u64,
    /// The chain as far as `logged`, once read.
    pub chain: Option<Chain>,
    /// When it was last read from its service, or the time of the newest head a peer's entries ended at, in
    /// milliseconds.
    pub at: u64,
}

impl Log {
    pub fn new(of: Of, service: Service, start: u64) -> Self {
        Log { of, service, start, logged: start, chain: None, at: 0 }
    }

    /// The newest signed head this session holds, or the empty log's, which needs no signature.
    pub fn head(&self, id: &[u8]) -> Head {
        self.chain.as_ref().map_or_else(|| empty(id), |chain| chain.head.clone())
    }
}

pub(crate) fn empty(log: &[u8]) -> Head {
    Head { log: log.into(), length: 0, hash: head::start(log).into(), time: 0, sig: Bytes::default() }
}

fn log_key(id: &[u8]) -> Vec<u8> {
    [b"node/log/".as_slice(), id].concat()
}

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
        self.logs.get(id).context("this session does not follow that log")
    }

    pub(crate) fn save_log(&self, id: &[u8]) -> Result<()> {
        put(&self.provider, &log_key(id), self.log(id)?)
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

    /// Drops a log's entries; the next are held from position `start + 1`.
    pub(crate) fn restart_log(&mut self, id: &[u8], start: u64) -> Result<()> {
        let log = self.logs.get_mut(id).context("this session does not follow that log")?;
        for position in log.start + 1..=log.logged {
            self.provider.delete(&entry_key(id, position))?;
        }
        (log.start, log.logged, log.chain) = (start, start, None);
        self.save_log(id)
    }

    pub(crate) fn drop_log(&mut self, id: &[u8]) -> Result<()> {
        let Some(log) = self.logs.remove(id) else { return Ok(()) };
        for position in log.start + 1..=log.logged {
            self.provider.delete(&entry_key(id, position))?;
        }
        self.provider.delete(&log_key(id))?;
        self.save_logs()
    }

    /// The entries held after position `after`, if this session holds them all.
    pub(crate) fn entries(&self, id: &[u8], after: u64) -> Vec<Bytes> {
        let Some(log) = self.logs.get(id).filter(|log| after >= log.start) else { return Vec::new() };
        (after + 1..=log.logged).map_while(|position| self.provider.get(&entry_key(id, position)).ok()?.map(Bytes)).collect()
    }

    /// The groups a log concerns.
    pub(crate) fn groups_of(&self, id: &[u8]) -> Vec<Vec<u8>> {
        match self.logs.get(id).map(|log| &log.of) {
            Some(Of::Group) => vec![id.to_vec()],
            Some(Of::Kind(gid)) => vec![gid.0.clone()],
            Some(Of::Identity(identity)) => {
                self.groups.keys().filter(|gid| self.identities(gid).iter().any(|i| i.id == *identity)).cloned().collect()
            }
            None => Vec::new(),
        }
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Follows a log at its service: what is new as the service tells of it, and all of it whenever the subscription
    /// restarts and every 5 minutes, until this session drops the log. The read after subscribing may reach the service
    /// before the subscription does, missing an entry appended in between; a member removed by it learns of it from no
    /// peer, as none serves it the group any more.
    pub(crate) fn follow(self: &Arc<Self>, log: &[u8]) {
        let (inner, id) = (self.clone(), log.to_vec());
        let task = spawn(async move {
            loop {
                let Ok(service) = inner.state.lock().unwrap().log(&id).map(|log| log.service.clone()) else { return };
                let followed = async {
                    let client = inner.clients.client(&service)?;
                    let mut subscription = client.subscribe(vec![Bytes(id.clone())]).await?;
                    inner.read(&id).await?;
                    loop {
                        match timeout(RESYNC, subscription.next()).await {
                            Ok(Some(notice)) => {
                                let notice = notice?;
                                inner.stored(&id, notice.position - 1, vec![notice.entry], client.chain(&id))?;
                            }
                            Ok(None) => break,
                            Err(_) => inner.read(&id).await?,
                        }
                    }
                    anyhow::Ok(())
                };
                if let Err(error) = followed.await {
                    tracing::debug!("following log {}: {error:#}", hex(&id));
                }
                sleep(Duration::from_secs(2)).await;
            }
        });
        if let Some(old) = self.follows.lock().unwrap().insert(log.to_vec(), task) {
            old.abort();
        }
    }

    pub(crate) fn unfollow(&self, id: &[u8]) {
        if let Some(task) = self.follows.lock().unwrap().remove(id) {
            task.abort();
        }
    }

    /// Reads a log from its service, through its end.
    pub(crate) async fn read(&self, id: &[u8]) -> Result<()> {
        let service = self.state.lock().unwrap().log(id)?.service.clone();
        let client = self.clients.client(&service)?;
        loop {
            let after = self.state.lock().unwrap().log(id)?.logged;
            let page = match client.read(id, after).await {
                Ok(page) => page,
                Err(error) => {
                    if let Some(contradiction) = error.downcast_ref::<Contradiction>() {
                        self.contradicted(&self.state.lock().unwrap(), id, contradiction, "this session");
                    }
                    return Err(error);
                }
            };
            if client.chain(id).is_none_or(|chain| chain.length() < after) {
                client.set_chain(Chain::anchored(page.head.clone()));
            }
            let more = !page.entries.is_empty();
            self.stored(id, after, page.entries, client.chain(id))?;
            if !more {
                let mut st = self.state.lock().unwrap();
                st.logs.get_mut(id).context("dropped the log")?.at = crate::now();
                return st.save_log(id);
            }
        }
    }

    /// Holds entries of a log that follow position `after`, and hands the new ones to its log type. `chain` is the
    /// client's, recorded when it covers just what is held, so that the head this session shows its peers matches its
    /// entries.
    pub(crate) fn stored(&self, id: &[u8], after: u64, entries: Vec<Bytes>, chain: Option<Chain>) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let st = &mut *st;
        let logged = st.log(id)?.logged;
        if after > logged {
            self.work.send(Work::Read(id.to_vec())).ok();
            return Ok(());
        }
        let fresh: Vec<Bytes> = entries.into_iter().skip((logged - after) as usize).collect();
        for (position, entry) in (logged + 1..).zip(&fresh) {
            st.provider.put(&entry_key(id, position), &entry.0)?;
        }
        let log = st.logs.get_mut(id).unwrap();
        log.logged += fresh.len() as u64;
        // A joiner's first read anchors its chain: the head it shows its peers is no longer empty, though it took
        // nothing new, and they sync with it only once it shows the head they do.
        let anchored = log.chain.is_none() && chain.as_ref().is_some_and(|chain| chain.length() == log.logged);
        if let Some(chain) = chain.filter(|chain| chain.length() == log.logged) {
            log.chain = Some(chain);
        }
        st.save_log(id)?;
        if !fresh.is_empty() {
            self.check(st, id)?;
        } else if !anchored {
            return Ok(());
        }
        if let Some(net) = self.net.get() {
            for gid in st.groups_of(id) {
                net.changed(&gid);
            }
        }
        Ok(())
    }

    /// Hands a log's new entries to its log type.
    fn check(&self, st: &mut State<P>, id: &[u8]) -> Result<()> {
        match st.log(id)?.of.clone() {
            Of::Group => self.advance(st, id),
            Of::Kind(gid) => self.kind_advance(st, &gid.0),
            Of::Identity(identity) => self.keyed(st, &identity.0),
        }
    }

    /// Takes entries of a log from a peer: they directly follow this session's copy and end at `head`.
    pub(crate) fn take_entries(&self, id: &[u8], entries: Vec<Bytes>, head: Head) -> Result<()> {
        let (after, chain) = {
            let mut st = self.state.lock().unwrap();
            let log = st.logs.get_mut(id).context("this session does not follow that log")?;
            let mut chain = log.chain.clone().context("no chain of the log yet")?;
            let after = chain.length();
            chain.extend(after, &entries, &head)?;
            log.at = log.at.max(head.time);
            self.clients.client(&log.service)?.set_chain(chain.clone());
            (after, chain)
        };
        self.stored(id, after, entries, Some(chain))
    }
}

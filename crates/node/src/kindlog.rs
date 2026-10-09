//! A kind's log: a log of its own at the group's membership service, under the random id in the group's settings.
//! Its entries are sealed as messages are, marked as entries, under the epoch current when appended; members open them
//! in log order and keep them for the kind until it asks to read past them. An entry sealed under an older epoch than
//! the entry taken before it is skipped, as is one that does not open; one sealed under an epoch whose keys this
//! session does not hold leaves it behind, as do entries past the service's retention, and it asks a member for the
//! kind's state.

use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use iroh::EndpointId;
use lmk_core::group::{self as core, Unheld};
use lmk_core::provider::Provider;
use lmk_membership::{Chain, Refused};
use lmk_proto::Bytes;
use lmk_proto::group::Service;
use lmk_proto::head::Head;
use lmk_proto::peer::Frame;
use n0_future::task::spawn;
use n0_future::time::{Duration, sleep, timeout};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::{Entry, Event, Inner, KindLog, Node, SNAPSHOT_WAIT, STATE_ASK, State, Work, get, hex, now, put};

pub(crate) fn entry_key(gid: &[u8], position: u64) -> Vec<u8> {
    [b"node/kindlog/".as_slice(), gid, b"/", &position.to_be_bytes()].concat()
}

impl<P: Provider + Send + 'static> Node<P> {
    /// Follows the kind's log after `position`, whose last entry taken was sealed under `epoch`, as the kind's own state
    /// stands; with none, the kind has no state yet, and this session asks a member for one. Entries kept for the kind
    /// up to `position` go. Opened entries come as `Event::Logged`.
    pub fn follow_log(&self, gid: &[u8], from: Option<(u64, u64)>) -> Result<()> {
        let behind = {
            let mut st = self.inner.state.lock().unwrap();
            let st = &mut *st;
            let g = st.groups.get_mut(gid).context("this session is not in that group")?;
            ensure!(g.mls.settings().log.is_some(), "this group has no log");
            let log = g.rec.log.get_or_insert_with(KindLog::default);
            match from {
                Some((after, _)) if after < log.acked => log.behind = true,
                Some((after, epoch)) => {
                    for position in log.kept.iter().filter(|kept| **kept <= after) {
                        st.provider.delete(&entry_key(gid, *position))?;
                    }
                    log.kept.retain(|kept| *kept > after);
                    log.acked = after;
                    if after >= log.read {
                        (log.read, log.epoch, log.behind) = (after, epoch, false);
                    }
                }
                None => log.behind = true,
            }
            let behind = log.behind;
            st.save(gid)?;
            if behind {
                self.inner.ask_state(st, gid, None);
            }
            behind
        };
        let started = self.inner.state.lock().unwrap().group(gid)?.follow_log.is_some();
        if !started {
            self.inner.subscribe_log(gid);
        } else if !behind {
            self.inner.work.send(Work::ReadLog(gid.to_vec())).ok();
        }
        Ok(())
    }

    /// The entries of the kind's log opened after position `after`, in order.
    pub fn entries(&self, gid: &[u8], after: u64) -> Result<Vec<Entry>> {
        let st = self.inner.state.lock().unwrap();
        let Some(log) = &st.group(gid)?.rec.log else { return Ok(Vec::new()) };
        let kept = log.kept.iter().filter(|kept| **kept > after);
        kept.map(|position| get(&st.provider, &entry_key(gid, *position))?.context("a kept entry is missing")).collect()
    }

    /// Appends a payload to the kind's log, sealed under the current epoch, and reads the log through it: once it
    /// returns its position, every entry up to it is opened, its own among them unless it was skipped.
    pub async fn append(&self, gid: &[u8], payload: &Value) -> Result<u64> {
        self.inner.read(gid).await?;
        let (service, log, entry, hash) = {
            let mut st = self.inner.state.lock().unwrap();
            let st = &mut *st;
            let g = st.groups.get_mut(gid).context("this session is not in that group")?;
            let settings = g.mls.settings();
            let log = settings.log.context("this group has no log")?;
            ensure!(g.rec.log.as_ref().is_some_and(|log| !log.behind), "this session has not caught up on the group's log");
            let (hash, entry) = g.mls.seal_entry(&st.provider, &st.session, payload)?;
            g.rec.log.as_mut().unwrap().own.push((Bytes(hash.to_vec()), payload.clone()));
            st.save(gid)?;
            (settings.membership, log, entry, Bytes(hash.to_vec()))
        };
        let position = match self.inner.logs.client(&service)?.append(&log.0, &entry).await {
            Ok(appended) => appended.position,
            Err(error) => {
                if error.is::<Refused>() {
                    let mut st = self.inner.state.lock().unwrap();
                    st.group_mut(gid)?.rec.log.as_mut().unwrap().own.retain(|(own, _)| *own != hash);
                    st.save(gid)?;
                }
                return Err(error);
            }
        };
        self.inner.read_log(gid).await?;
        let st = self.inner.state.lock().unwrap();
        ensure!(st.group(gid)?.rec.log.as_ref().is_some_and(|log| log.read >= position), "the log did not show the entry it took");
        Ok(position)
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Follows a group's kind log: what is new whenever the service tells of an entry, and all of it whenever the
    /// subscription restarts.
    pub(crate) fn subscribe_log(self: &Arc<Self>, gid: &[u8]) {
        let (inner, key) = (self.clone(), gid.to_vec());
        let handle = spawn(async move {
            let gid = key;
            loop {
                let settings = match inner.state.lock().unwrap().group(&gid) {
                    Ok(g) => g.mls.settings(),
                    Err(_) => return,
                };
                let followed = async {
                    let client = inner.logs.client(&settings.membership)?;
                    let mut subscription = client.subscribe(vec![settings.log.context("no log")?]).await?;
                    inner.read_log(&gid).await?;
                    while let Some(notice) = subscription.next().await {
                        notice?;
                        inner.read_log(&gid).await?;
                    }
                    anyhow::Ok(())
                };
                if let Err(error) = followed.await {
                    tracing::debug!("following the log of {}: {error:#}", hex(&gid));
                }
                sleep(Duration::from_secs(2)).await;
            }
        });
        if let Some(g) = self.state.lock().unwrap().groups.get_mut(gid) {
            g.follow_log = Some(handle);
        }
    }

    /// Reads the kind's log from the service through its end, opening what follows the last position read.
    pub(crate) async fn read_log(&self, gid: &[u8]) -> Result<()> {
        let _reading = self.reading_log.lock().await;
        loop {
            let (settings, after, behind, epoch) = {
                let st = self.state.lock().unwrap();
                let g = st.group(gid)?;
                let log = g.rec.log.as_ref().context("the kind does not follow its log")?;
                (g.mls.settings(), log.read, log.behind, g.mls.epoch())
            };
            if behind {
                return Ok(());
            }
            let id = settings.log.context("this group has no log")?;
            let client = self.logs.client(&settings.membership)?;
            let page = match client.read(&id.0, after).await {
                Ok(page) => page,
                Err(error) if error.is::<Refused>() => {
                    let mut st = self.state.lock().unwrap();
                    self.fell_behind(&mut st, gid, "its entries are past the service's retention")?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            if client.chain(&id.0).is_none_or(|chain| chain.length() < after) {
                client.set_chain(Chain::anchored(page.head.clone()));
            }
            if page.entries.is_empty() {
                return Ok(());
            }
            // An entry sealed under an epoch this session has not reached waits for the group's log.
            if page.entries.iter().any(|entry| core::epoch_of(&entry.0).is_ok_and(|e| e > epoch)) {
                self.read(gid).await?;
            }
            if self.opened(gid, after, page.entries, client.chain(&id.0))? {
                self.events.send(Event::Logged { group: Bytes(gid.to_vec()) }).ok();
            }
        }
    }

    /// Opens entries that follow position `after`, in order, and keeps those taken; returns whether it took any.
    fn opened(&self, gid: &[u8], after: u64, entries: Vec<Bytes>, chain: Option<Chain>) -> Result<bool> {
        let mut st = self.state.lock().unwrap();
        let st = &mut *st;
        let mut took = false;
        for (position, entry) in (after + 1..).zip(entries) {
            let g = st.groups.get_mut(gid).context("left the group")?;
            let log = g.rec.log.as_mut().unwrap();
            let (hash, sealed) = (Sha256::digest(&entry.0).to_vec(), core::epoch_of(&entry.0));
            let taken = match sealed {
                Ok(epoch) if epoch >= log.epoch => match log.own.iter().position(|(own, _)| own.0 == hash) {
                    Some(own) => {
                        let payload = log.own.remove(own).1;
                        let me = g.mls.members().into_iter().find(|m| m.key == st.session.key());
                        me.and_then(|me| st.member(gid, &me)).map(|from| Entry { position, epoch, from, payload })
                    }
                    None if epoch > g.mls.epoch() => None,
                    None => match g.mls.open(&st.provider, &entry.0, 0) {
                        Ok(opened) if opened.log => {
                            let sender = g.mls.members().into_iter().find(|m| m.key == opened.key).unwrap_or(core::Member {
                                index: opened.index,
                                key: opened.key.clone(),
                                credential: Some(opened.sender.clone()),
                                leaf: None,
                            });
                            st.member(gid, &sender).map(|from| Entry { position, epoch, from, payload: opened.payload })
                        }
                        Ok(_) => None,
                        Err(error) if error.is::<Unheld>() => {
                            self.fell_behind(st, gid, "its keys of the epochs it was sealed under are gone")?;
                            return Ok(took);
                        }
                        Err(error) => {
                            tracing::debug!("skipped entry {position} of the log of {}: {error:#}", hex(gid));
                            None
                        }
                    },
                },
                _ => None,
            };
            let log = st.groups.get_mut(gid).unwrap().rec.log.as_mut().unwrap();
            log.read = position;
            if let Some(entry) = taken {
                log.epoch = entry.epoch;
                log.kept.push(position);
                put(&st.provider, &entry_key(gid, position), &entry)?;
                took = true;
            }
        }
        let log = st.groups.get_mut(gid).unwrap().rec.log.as_mut().unwrap();
        if let Some(chain) = chain.filter(|chain| chain.length() == log.read) {
            log.chain = Some(chain);
        }
        st.save(gid)?;
        Ok(took)
    }

    /// The kind's log cannot be followed from where this session read it: it asks a member for the kind's state.
    fn fell_behind(&self, st: &mut State<P>, gid: &[u8], why: &str) -> Result<()> {
        st.group_mut(gid)?.rec.log.as_mut().unwrap().behind = true;
        st.save(gid)?;
        self.warn(Some(gid), format!("this session fell behind the group's log ({why}); it takes the group's state from a member"));
        self.ask_state(st, gid, None);
        Ok(())
    }

    /// Asks a member online, `peer` or else any, for the kind's state, unless this session asked or was handed one in
    /// the last minute.
    pub(crate) fn ask_state(&self, st: &mut State<P>, gid: &[u8], peer: Option<EndpointId>) {
        let me = self.net().id();
        let Ok(g) = st.group_mut(gid) else { return };
        if g.asked + STATE_ASK > now() {
            return;
        }
        let connected = self.net().connected();
        let members = g.mls.members().into_iter().filter_map(|m| crate::endpoint_id(&m.leaf?.key.0));
        let online = members.filter(|key| *key != me && connected.contains(key)).find(|key| peer.is_none_or(|peer| peer == *key));
        if let Some(peer) = online {
            g.asked = now();
            self.net().frame(peer, Frame::State { group: Bytes(gid.to_vec()), link: None });
        }
    }

    /// Hands a member that asked for it the kind's state, if the kind gives one.
    pub(crate) fn hand_snapshot(self: &Arc<Self>, gid: &[u8], by: EndpointId) {
        let (reply, state) = oneshot::channel();
        self.events.send(Event::Snapshot { group: Bytes(gid.to_vec()), reply }).ok();
        let (inner, gid) = (self.clone(), gid.to_vec());
        self.spawn(async move {
            let Some(data) = timeout(SNAPSHOT_WAIT, state).await.ok().and_then(Result::ok).flatten() else { return };
            match inner.state_file(&gid, data).await {
                Ok(link) => _ = inner.net().frame(by, Frame::State { group: Bytes(gid), link: Some(link) }),
                Err(error) => inner.warn(Some(&gid), format!("handing a member the group's state: {error:#}")),
            }
        });
    }

    /// Judges a peer's head of the kind's log against this session's chain: one that contradicts it is reported, and a
    /// longer one has this session read the log.
    pub(crate) fn judge_log_head(&self, peer: EndpointId, gid: &[u8], theirs: Head) {
        let st = self.state.lock().unwrap();
        let Ok(g) = st.group(gid) else { return };
        let (settings, Some(chain)) = (g.mls.settings(), g.rec.log.as_ref().and_then(|log| log.chain.as_ref())) else { return };
        let signed = match &settings.membership {
            Service::Serve { key, .. } => {
                let key: Option<[u8; 32]> = key.0.clone().try_into().ok();
                key.and_then(|key| VerifyingKey::from_bytes(&key).ok()).is_some_and(|key| theirs.verify(&key))
            }
            Service::Folder(_) => true,
        };
        if !signed || Some(&theirs.log) != settings.log.as_ref() {
            return;
        }
        if theirs.length > chain.length() {
            self.work.send(Work::ReadLog(gid.to_vec())).ok();
        } else if chain.check(&theirs).is_err() {
            let text = format!(
                "the membership service showed {} a different log of the group's kind: length {} with hash {} there",
                peer.fmt_short(),
                theirs.length,
                hex(&theirs.hash.0)
            );
            self.warn(Some(gid), text);
        }
    }
}

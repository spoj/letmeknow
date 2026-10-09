//! A kind's log: a log of its own at the group's membership service, under a random id only members know, which orders
//! the group's held messages. An entry is a held message's id; members apply the order as they hold the messages, and
//! keep what they took for the kind until it asks to read past it. An entry that is not an id, names a message an
//! earlier entry named, or names one of the core's own, is skipped. One whose message this session cannot hold leaves it
//! behind, as do entries past the service's retention, and it asks a member for the kind's state.
//!
//! A commit that removes a member moves the order to a new log, whose id derives from the epoch the commit starts, so
//! that the removed member does not know it. Its committer first appends `END` to the old log, and the commit names the
//! position before it: the order goes on in the new log from there, with no position counted twice. A member waits at
//! an `END` until it applies a removal that names a position at or after it.

use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use iroh::EndpointId;
use lmk_core::provider::Provider;
use lmk_membership::Refused;
use lmk_proto::Bytes;
use lmk_proto::group::{Control, type_of};
use lmk_proto::peer::{Frame, KindLog as LogRef};
use n0_future::time::timeout;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::logs::{Log, Of, entry_key};
use crate::{Entry, Event, Inner, Message, Node, Rec, SNAPSHOT_WAIT, STATE_ASK, State, Work, get, message_key, now, put};

/// The entry that ends a kind's log.
pub(crate) const END: &[u8] = b"end";
/// The label under which a kind's log id derives from an epoch's exporter secret.
pub(crate) const LOG_LABEL: &str = "letmeknow kind log";

/// What this session holds of its group's kind log, once the kind follows it. Positions are in the kind's order, across
/// the logs it moved through.
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct KindLog {
    /// The last position applied: every entry up to it was taken or skipped.
    pub read: u64,
    /// Where the kind last asked to read from: it holds what came before.
    pub acked: u64,
    /// The positions of entries taken, kept until the kind asks to read past them.
    pub kept: Vec<u64>,
    /// The log cannot be followed from `read`: the kind has no state yet, or a message an entry names cannot be had.
    pub behind: bool,
}

pub(crate) fn kept_key(gid: &[u8], position: u64) -> Vec<u8> {
    [b"node/kindlog/".as_slice(), gid, b"/", &position.to_be_bytes()].concat()
}

impl Rec {
    /// The log that holds a position of the kind's order: the last that starts before it.
    fn log_at(&self, position: u64) -> Option<&LogRef> {
        self.kind_logs.iter().rev().find(|log| log.after < position)
    }
}

impl<P: Provider + Send + 'static> Node<P> {
    /// Follows the kind's log after position `after`, as the kind's own state stands; with none, the kind has no state
    /// yet, and this session asks a member for one. Entries kept for the kind up to `after` go. Taken entries come as
    /// `Event::Logged`.
    pub fn follow_log(&self, gid: &[u8], after: Option<u64>) -> Result<()> {
        let mut st = self.inner.state.lock().unwrap();
        let st = &mut *st;
        let g = st.groups.get_mut(gid).context("this session is not in that group")?;
        let first = g.rec.kind_logs.first().context("this group has no log")?.after;
        let log = g.rec.log.get_or_insert_with(KindLog::default);
        match after {
            Some(after) if after < log.acked || after < first => log.behind = true,
            Some(after) => {
                for position in log.kept.iter().filter(|kept| **kept <= after) {
                    st.provider.delete(&kept_key(gid, *position))?;
                }
                log.kept.retain(|kept| *kept > after);
                log.acked = after;
                if after >= log.read {
                    (log.read, log.behind) = (after, false);
                }
            }
            None => log.behind = true,
        }
        let behind = log.behind;
        st.save(gid)?;
        if behind {
            self.inner.ask_state(st, gid, None);
            return Ok(());
        }
        for id in self.inner.kind_logs(st, gid)? {
            self.inner.follow(&id);
        }
        self.inner.kind_advance(st, gid)
    }

    /// The entries of the kind's log taken after position `after`, in order.
    pub fn entries(&self, gid: &[u8], after: u64) -> Result<Vec<Entry>> {
        let st = self.inner.state.lock().unwrap();
        let Some(log) = &st.group(gid)?.rec.log else { return Ok(Vec::new()) };
        let kept = log.kept.iter().filter(|kept| **kept > after);
        kept.map(|position| get(&st.provider, &kept_key(gid, *position))?.context("a kept entry is missing")).collect()
    }

    /// Appends the id of a held message of the group to the kind's log, and reads the log through it: once it returns
    /// its position, every entry up to it is taken or skipped.
    pub async fn append(&self, gid: &[u8], message: &[u8]) -> Result<u64> {
        let (log, service) = {
            let st = self.inner.state.lock().unwrap();
            let g = st.group(gid)?;
            let log = g.rec.kind_logs.last().cloned().context("this group has no log")?;
            ensure!(g.rec.items.iter().any(|item| item.id.0 == message), "not a message this group holds");
            (log, g.mls.settings().membership)
        };
        self.inner.read_kind_log(gid, &log.id.0).await?;
        {
            let st = self.inner.state.lock().unwrap();
            let g = st.group(gid)?;
            let read = g.rec.log.as_ref().filter(|read| !read.behind).context("this session has not caught up on the group's log")?.read;
            ensure!(read == log.after + st.log(&log.id.0)?.logged, "the group's log waits for a message it names");
        }
        let position = log.after + self.inner.clients.client(&service)?.append(&log.id.0, message).await?.position;
        self.inner.read_kind_log(gid, &log.id.0).await?;
        let st = self.inner.state.lock().unwrap();
        let g = st.group(gid)?;
        ensure!(g.rec.log.as_ref().is_some_and(|read| read.read >= position), "the log did not show the entry it took");
        ensure!(!g.rec.kind_logs.iter().any(|later| later.after > log.after && later.after < position), "the group's log moved on without the entry");
        Ok(position)
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Reads a log of the kind through its end; one whose entries are past the service's retention leaves this session
    /// behind.
    async fn read_kind_log(&self, gid: &[u8], id: &[u8]) -> Result<()> {
        match self.read(id).await {
            Err(error) if error.is::<Refused>() => {
                let mut st = self.state.lock().unwrap();
                self.fell_behind(&mut st, gid, "its entries are past the service's retention")?;
                Err(error)
            }
            read => read,
        }
    }

    /// Holds the kind's logs this session reads from where it is, from that place in each: a log not held yet is added,
    /// and one held short of it starts there anew. Returns those added, to follow at their service.
    pub(crate) fn kind_logs(&self, st: &mut State<P>, gid: &[u8]) -> Result<Vec<Vec<u8>>> {
        let g = st.group(gid)?;
        let (Some(read), membership) = (g.rec.log.as_ref().map(|log| log.read), g.mls.settings().membership) else { return Ok(Vec::new()) };
        let mut added = Vec::new();
        for log in g.rec.kind_logs.clone() {
            let start = read.saturating_sub(log.after);
            match st.logs.get(&log.id.0) {
                None => {
                    st.add_log(&log.id.0, Log::new(Of::Kind(Bytes(gid.to_vec())), membership.clone(), start))?;
                    added.push(log.id.0);
                }
                Some(held) if held.logged < start => st.restart_log(&log.id.0, start)?,
                Some(_) => {}
            }
        }
        Ok(added)
    }

    /// A removal moved the kind's order to a new log after position `end`: this session follows it if its kind follows
    /// the order.
    pub(crate) fn moved(&self, st: &mut State<P>, gid: &[u8], end: u64) -> Result<()> {
        let g = st.groups.get_mut(gid).context("this session is not in that group")?;
        let Some(last) = g.rec.kind_logs.last() else { return Ok(()) };
        let log = LogRef { id: Bytes(g.mls.exported(&st.provider, LOG_LABEL)?.to_vec()), after: end.max(last.after) };
        if g.rec.kind_logs.last() == Some(&log) {
            return Ok(());
        }
        g.rec.kind_logs.push(log);
        st.save(gid)?;
        for id in self.kind_logs(st, gid)? {
            self.work.send(Work::Follow(id)).ok();
        }
        self.kind_advance(st, gid)
    }

    /// Applies the kind's order as far as this session holds the messages it names, keeping those it takes; drops the
    /// logs it has read past.
    pub(crate) fn kind_advance(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
        let mut took = false;
        loop {
            let g = st.groups.get_mut(gid).context("this session is not in that group")?;
            let Some(read) = g.rec.log.as_ref().filter(|log| !log.behind).map(|log| log.read) else { break };
            let position = read + 1;
            let Some(log) = g.rec.log_at(position).cloned() else { break };
            let local = position - log.after;
            let later = g.rec.kind_logs.iter().any(|later| later.after > log.after);
            if st.logs.get(&log.id.0).is_none_or(|held| held.logged < local) {
                break;
            }
            let entry = st.provider.get(&entry_key(&log.id.0, local))?.context("a stored entry is missing")?;
            let item = g.rec.items.iter_mut().find(|item| item.id.0 == entry);
            match item {
                Some(item) if item.position.is_none() => {
                    item.position = Some(position);
                    let message: Message = get(&st.provider, &message_key(&entry))?.context("a held message is missing")?;
                    if !Control::TYPES.contains(&type_of(&message.payload)) {
                        let taken = Entry { position, id: message.id, from: message.sender, payload: message.payload };
                        put(&st.provider, &kept_key(gid, position), &taken)?;
                        g.rec.log.as_mut().unwrap().kept.push(position);
                        took = true;
                    }
                }
                Some(_) => {}
                None if entry == END && !later => break,
                None if entry.len() != 32 => {}
                None if g.rec.given_up.iter().any(|(_, given)| given.0 == entry) => {
                    self.fell_behind(st, gid, "it could not take a message the log names")?;
                    break;
                }
                None => break,
            }
            st.groups.get_mut(gid).unwrap().rec.log.as_mut().unwrap().read = position;
        }
        let g = st.group_mut(gid)?;
        let read = g.rec.log.as_ref().map(|log| log.read);
        let mut passed = Vec::new();
        while let (Some(read), [_, next, ..]) = (read, &g.rec.kind_logs[..])
            && next.after <= read
        {
            passed.push(g.rec.kind_logs.remove(0).id);
        }
        for id in passed {
            self.unfollow(&id.0);
            st.drop_log(&id.0)?;
        }
        st.save(gid)?;
        if took {
            self.events.send(Event::Logged { group: Bytes(gid.to_vec()) }).ok();
        }
        Ok(())
    }

    /// Whether the kind's order waits for a message, with the entries before it applied.
    pub(crate) fn waits(&self, st: &State<P>, gid: &[u8]) -> bool {
        let Ok(g) = st.group(gid) else { return false };
        let Some(log) = &g.rec.log else { return false };
        let end = g.rec.kind_logs.last().and_then(|last| Some(last.after + st.logs.get(&last.id.0)?.logged));
        log.behind || end.is_some_and(|end| log.read < end)
    }

    /// The kind's log cannot be followed from where this session applied it: it asks a member for the kind's state.
    fn fell_behind(&self, st: &mut State<P>, gid: &[u8], why: &str) -> Result<()> {
        st.group_mut(gid)?.rec.log.as_mut().context("the kind does not follow its log")?.behind = true;
        st.save(gid)?;
        self.warn(Some(gid), format!("this session fell behind the group's log ({why}); it takes the group's state from a member"));
        self.ask_state(st, gid, None);
        Ok(())
    }

    /// Asks a member online, `peer` or else any, for the kind's state, unless this session asked or was handed one in
    /// the last minute.
    pub(crate) fn ask_state(&self, st: &mut State<P>, gid: &[u8], peer: Option<EndpointId>) {
        let Some(net) = self.net.get() else { return };
        let me = net.id();
        let Ok(g) = st.group_mut(gid) else { return };
        if g.asked + STATE_ASK > now() {
            return;
        }
        let connected = net.connected();
        let members = g.mls.members().into_iter().filter_map(|m| crate::endpoint_id(&m.leaf?.key.0));
        let online = members.filter(|key| *key != me && connected.contains(key)).find(|key| peer.is_none_or(|peer| peer == *key));
        if let Some(peer) = online {
            g.asked = now();
            net.frame(peer, Frame::State { group: Bytes(gid.to_vec()), link: None });
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
}

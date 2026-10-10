//! A group's kind takes the group's held messages in log order: the core hands it the next positions as it opens
//! them, keeping what it took until the kind asks to read past it. A kind with no state to follow the log from, as a
//! joiner's before its state comes, or one older than what this session kept, asks a member for the kind's state.

use std::sync::Arc;

use anyhow::{Context, Result};
use iroh::EndpointId;
use lmk_core::provider::Provider;
use lmk_proto::Bytes;
use lmk_proto::group::{Control, type_of};
use lmk_proto::peer::Frame;
use n0_future::time::timeout;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::reading::{Judged, Pos};
use crate::{Entry, Event, Inner, Message, Node, SNAPSHOT_WAIT, STATE_ASK, State, get, message_key, now, put};

/// What a group's kind took of its held messages, once it follows them.
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Kind {
    /// The last position handed on: every one up to it was taken or passed.
    pub read: u64,
    /// Where the kind last asked to read from: it holds what came before.
    pub acked: u64,
    /// The positions of the held messages taken, kept until the kind asks to read past them.
    pub kept: Vec<u64>,
    /// The kind has no state it can follow the log from.
    pub behind: bool,
}

pub(crate) fn kept_key(gid: &[u8], position: u64) -> Vec<u8> {
    [b"node/kind/".as_slice(), gid, b"/", &position.to_be_bytes()].concat()
}

impl<P: Provider + Send + 'static> Node<P> {
    /// Follows the group's held messages after position `after`, as the kind's own state stands; with none, the kind
    /// has no state yet, and this session asks a member for one. A state from before this session's start is as of its
    /// start. What was kept for the kind up to `after` goes. Taken messages come as `Event::Logged`.
    pub fn follow_log(&self, gid: &[u8], after: Option<u64>) -> Result<()> {
        let mut st = self.inner.lock();
        let st = &mut *st;
        let g = st.groups.get_mut(gid).context("this session is not in that group")?;
        let start = g.rec.start;
        let kind = g.rec.kind.get_or_insert_with(Kind::default);
        match after.map(|after| after.max(start)) {
            Some(after) if after < kind.acked => kind.behind = true,
            Some(after) => {
                for position in kind.kept.iter().filter(|kept| **kept <= after) {
                    st.provider.delete(&kept_key(gid, *position))?;
                }
                kind.kept.retain(|kept| *kept > after);
                kind.acked = after;
                if after >= kind.read {
                    (kind.read, kind.behind) = (after, false);
                }
            }
            None => kind.behind = true,
        }
        let behind = kind.behind;
        st.save(gid)?;
        if behind {
            self.inner.ask_state(st, gid, None);
            return Ok(());
        }
        self.inner.kind_advance(st, gid)
    }

    /// The kind's held messages taken after position `after`, in order.
    pub fn entries(&self, gid: &[u8], after: u64) -> Result<Vec<Entry>> {
        let st = self.inner.lock();
        let Some(kind) = &st.group(gid)?.rec.kind else { return Ok(Vec::new()) };
        let kept = kind.kept.iter().filter(|kept| **kept > after);
        kept.map(|position| get(&st.provider, &kept_key(gid, *position))?.context("a kept entry is missing")).collect()
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Hands the kind the next positions in log order, as far as they are opened, lost, or hold no message; keeps the
    /// kind's own payloads it takes.
    pub(crate) fn kind_advance(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
        let g = st.group(gid)?;
        let Some(mut read) = g.rec.kind.as_ref().filter(|kind| !kind.behind).map(|kind| kind.read) else { return Ok(()) };
        let mut taken = Vec::new();
        while read < g.rec.position && !g.rec.unopened.contains_key(&(read + 1)) {
            read += 1;
            let Some(Pos { judged: Judged::Counted { id }, lost: false, .. }) = st.pos(gid, read)? else { continue };
            let Some(message) = get::<Message>(&st.provider, &message_key(&id.0))?.filter(|m| m.position == read) else { continue };
            if !Control::TYPES.contains(&type_of(&message.payload)) {
                put(&st.provider, &kept_key(gid, read), &Entry { position: read, id: message.id, from: message.sender, payload: message.payload })?;
                taken.push(read);
            }
        }
        let kind = st.group_mut(gid)?.rec.kind.as_mut().unwrap();
        kind.read = read;
        let took = !taken.is_empty();
        kind.kept.extend(taken);
        st.save(gid)?;
        if took {
            self.events.send(Event::Logged { group: Bytes(gid.to_vec()) }).ok();
        }
        Ok(())
    }

    /// Asks a member online, `peer` or else any, for the kind's state, unless this session asked or was handed one in
    /// the last minute.
    pub(crate) fn ask_state(&self, st: &mut State<P>, gid: &[u8], peer: Option<EndpointId>) {
        if !st.at_head(gid) || st.group(gid).is_ok_and(|g| g.asked + STATE_ASK > now()) {
            return;
        }
        let group = Bytes(gid.to_vec());
        let mut connected = st.served.iter().filter(|(_, served)| served.contains(&group)).map(|(key, _)| *key);
        let Some(peer) = connected.find(|key| peer.is_none_or(|peer| peer == *key)) else { return };
        if let Ok(g) = st.group_mut(gid) {
            g.asked = now();
        }
        st.emit(gid, peer, Frame::State { group, link: None });
    }

    /// Hands a member that asked for it the kind's state, if the kind gives one.
    pub(crate) fn hand_snapshot(self: &Arc<Self>, gid: &[u8], by: EndpointId) {
        let (reply, state) = oneshot::channel();
        self.events.send(Event::Snapshot { group: Bytes(gid.to_vec()), reply }).ok();
        let (inner, gid) = (self.clone(), gid.to_vec());
        self.spawn(async move {
            let Some(data) = timeout(SNAPSHOT_WAIT, state).await.ok().and_then(Result::ok).flatten() else { return };
            match inner.state_file(&gid, data).await {
                Ok(link) => inner.lock().emit(&gid, by, Frame::State { group: Bytes(gid.clone()), link: Some(link) }),
                Err(error) => inner.warn(Some(&gid), format!("handing a member the group's state: {error:#}")),
            }
        });
    }
}

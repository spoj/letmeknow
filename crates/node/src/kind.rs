//! A group's kind takes the group's held messages in log order, and the losses: the core hands it the next positions as
//! it opens them, or as this session loses them, keeping what it took until the kind asks to read past it. A kind with
//! no state to follow the log from, as a joiner's before its state comes, one older than what this session kept, or one
//! stopped at a loss, asks a member for the kind's state. The kind's payloads also go out as events in position order,
//! passing a position once it no longer holds up later ones (`show`).

use std::sync::Arc;

use anyhow::{Context, Result};
use iroh::EndpointId;
use lmk_core::provider::Provider;
use lmk_proto::Bytes;
use lmk_proto::group::{Control, type_of};
use lmk_proto::links::FileLink;
use lmk_proto::peer::Frame;
use n0_future::time::timeout;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::reading::{Judged, Pos};
use crate::{Entry, Event, Inner, Item, Lost, Member, Message, Node, Observation, SNAPSHOT_WAIT, STATE_ASK, State, get, message_key, now, put};

/// What a group's kind took of its held messages, once it follows them.
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Kind {
    /// The last position handed on: every one up to it was taken or passed.
    pub read: u64,
    /// Where the kind last asked to read from: it holds what came before.
    pub acked: u64,
    /// The positions of the items taken, kept until the kind asks to read past them.
    pub kept: Vec<u64>,
    /// The kind has no state it can follow the log from.
    pub behind: bool,
}

pub(crate) fn kept_key(gid: &[u8], position: u64) -> Vec<u8> {
    [b"node/kind/".as_slice(), gid, b"/", &position.to_be_bytes()].concat()
}

impl<P: Provider + Send + 'static> Node<P> {
    /// Follows the group's held messages after position `after`, as the kind's own state stands; with none, the kind
    /// has no state it can follow the log from, as before its first or once it stopped at a loss, and this session asks a
    /// member for one. A state from before this session's start is as of its start. What was kept for the kind up to
    /// `after` goes. Taken items come as `Event::Logged`.
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
                (kind.acked, kind.read, kind.behind) = (after, kind.read.max(after), false);
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

    /// The kind's items taken after position `after`, in order.
    pub fn entries(&self, gid: &[u8], after: u64) -> Result<Vec<Item>> {
        let st = self.inner.lock();
        let Some(kind) = &st.group(gid)?.rec.kind else { return Ok(Vec::new()) };
        let kept = kind.kept.iter().filter(|kept| **kept > after);
        kept.map(|position| get(&st.provider, &kept_key(gid, *position))?.context("a kept entry is missing")).collect()
    }

    /// The losses members announced in the group, by the position of each announcement: who lost which positions.
    pub fn losses(&self, gid: &[u8]) -> Result<Vec<Lost>> {
        let st = self.inner.lock();
        let g = st.group(gid)?;
        let mut losses = Vec::new();
        for (position, (key, positions)) in &g.rec.losses {
            let member = st.member_by_key(gid, &key.0);
            losses.push(Lost { group: Bytes(gid.to_vec()), position: *position, member, positions: positions.clone(), ids: st.ids(gid, positions)? });
        }
        Ok(losses)
    }
}

impl<P: Provider> State<P> {
    /// The ids of the messages counted at these positions, as far as this session knows them.
    pub(crate) fn ids(&self, gid: &[u8], positions: &[u64]) -> Result<Vec<Bytes>> {
        let mut ids = Vec::new();
        for position in positions {
            if let Some(Pos { judged: Judged::Counted { id }, .. }) = self.pos(gid, *position)? {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// A member by its key: the current one, or a bare one if it is gone.
    pub(crate) fn member_by_key(&self, gid: &[u8], key: &[u8]) -> Member {
        let found = self.groups.get(gid).and_then(|g| self.member(gid, &g.mls.members().into_iter().find(|m| m.key == key)?));
        found.unwrap_or_else(|| Member {
            key: Bytes(key.to_vec()),
            iroh: Bytes::default(),
            revision: 0,
            name: String::new(),
            device_name: String::new(),
            identity: None,
            added: None,
        })
    }

    /// This session as a member of the group.
    fn myself(&self, gid: &[u8]) -> Member {
        self.member_by_key(gid, self.me(gid))
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Hands the kind the next positions in log order, as far as they are opened, lost, or hold no message; keeps the
    /// kind's own payloads it takes, this session's losses, and the losses other members announce. Then hands the
    /// group's messages on in position order (`show`).
    pub(crate) fn kind_advance(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
        self.show(st, gid)?;
        let g = st.group(gid)?;
        let Some(mut read) = g.rec.kind.as_ref().filter(|kind| !kind.behind).map(|kind| kind.read) else { return Ok(()) };
        let mut taken = Vec::new();
        while read < g.rec.position && !g.rec.unopened.contains_key(&(read + 1)) {
            read += 1;
            let Some(Pos { judged: Judged::Counted { id }, lost, .. }) = st.pos(gid, read)? else { continue };
            let group = Bytes(gid.to_vec());
            let item = if lost {
                Item::Lost(Lost { group, position: read, member: st.myself(gid), positions: vec![read], ids: vec![id] })
            } else {
                let Some(message) = get::<Message>(&st.provider, &message_key(&id.0))?.filter(|m| m.position == read) else { continue };
                match serde_json::from_value::<Control>(message.payload.clone()) {
                    Ok(Control::Lost { positions }) if message.sender.key.0 != st.me(gid) => {
                        let ids = st.ids(gid, &positions)?;
                        Item::Lost(Lost { group, position: read, member: message.sender, positions, ids })
                    }
                    _ if Control::TYPES.contains(&type_of(&message.payload)) => continue,
                    _ => Item::Entry(Entry { position: read, id: message.id, from: message.sender, payload: message.payload }),
                }
            };
            put(&st.provider, &kept_key(gid, read), &item)?;
            taken.push(read);
        }
        let kind = st.group(gid)?.mls.settings().kind;
        if kind != lmk_proto::group::CHAT {
            for position in &taken {
                st.observe(|| Observation::Handed { group: Bytes(gid.to_vec()), kind: kind.clone(), position: *position });
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

    /// Hands the group's held messages on as events in position order, but this session's own and the core's. A counted
    /// position not opened yet is passed once it no longer holds up later ones (`holds_up`), and the next message
    /// handed on names it `missing`; it goes out when it opens, if it does.
    pub(crate) fn show(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
        let g = st.group(gid)?;
        let (mut shown, mut missing) = (g.rec.shown, g.rec.missing.clone());
        let me = st.me(gid).to_vec();
        while shown < g.rec.position {
            let position = shown + 1;
            if let Some(Pos { judged: Judged::Counted { id }, lost, .. }) = st.pos(gid, position)? {
                if let Some((_, at)) = g.rec.unopened.get(&position) {
                    if st.held(gid, position)? || self.holds_up(st, gid, position, *at) {
                        break;
                    }
                    missing.push(position);
                } else if lost {
                    missing.push(position);
                } else if let Some(mut message) = get::<Message>(&st.provider, &message_key(&id.0))?.filter(|m| m.position == position)
                    && message.sender.key.0 != me
                    && !Control::TYPES.contains(&type_of(&message.payload))
                {
                    message.missing = std::mem::take(&mut missing);
                    self.events.send(Event::Message(message)).ok();
                }
            }
            shown = position;
        }
        let rec = &mut st.group_mut(gid)?.rec;
        (rec.shown, rec.missing) = (shown, missing);
        st.save(gid)
    }

    /// A counted `lost`: recorded, and told where it concerns this session's user: all of its own, and of another
    /// member's, the positions of this session's messages.
    pub(crate) fn announced(&self, st: &mut State<P>, gid: &[u8], position: u64, by: Member, positions: Vec<u64>) -> Result<()> {
        let me = st.me(gid).to_vec();
        if by.key.0 == me {
            let positions = positions.clone();
            st.observe(|| Observation::Announced { group: Bytes(gid.to_vec()), position, positions });
        }
        st.group_mut(gid)?.rec.losses.insert(position, (by.key.clone(), positions.clone()));
        st.save(gid)?;
        let positions = if by.key.0 == me {
            positions
        } else {
            let mut ours = Vec::new();
            for lost in positions {
                if let Some(Pos { judged: Judged::Counted { id }, .. }) = st.pos(gid, lost)?
                    && get::<Message>(&st.provider, &message_key(&id.0))?.is_some_and(|m| m.position == lost && m.sender.key.0 == me)
                {
                    ours.push(lost);
                }
            }
            ours
        };
        if !positions.is_empty() {
            let ids = st.ids(gid, &positions)?;
            self.events.send(Event::Lost(Lost { group: Bytes(gid.to_vec()), position, member: by, positions, ids })).ok();
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

impl<P: Provider + Send + 'static> Inner<P> {
    /// Takes a state `by` handed this session, once it is fetched, and tells the group's kind.
    pub(crate) fn state_from(self: &Arc<Self>, gid: &[u8], link: String, by: EndpointId) {
        let (inner, gid) = (self.clone(), gid.to_vec());
        self.spawn(async move {
            let taken = async {
                let file = FileLink::parse(&link)?;
                {
                    let mut st = inner.lock();
                    st.group_mut(&gid)?.rec.link(link.clone());
                    st.save(&gid)?;
                }
                inner.fetched(&gid, &file).await?;
                let mut data = Vec::new();
                inner.net().read_file(&file, &mut data).await?;
                let from = {
                    let mut st = inner.lock();
                    let from = st.by_iroh(&gid, &by);
                    st.observe(|| Observation::State { group: Bytes(gid.clone()), from: from.key.clone() });
                    from
                };
                inner.events.send(Event::State { group: Bytes(gid.clone()), from, data }).ok();
                anyhow::Ok(())
            };
            if let Err(error) = taken.await {
                inner.warn(Some(&gid), format!("the group's state did not arrive: {error:#}"));
            }
        });
    }

    /// Seals a state of the group's kind as a file to hand a member; holds it.
    pub(crate) async fn state_file(&self, gid: &[u8], data: Vec<u8>) -> Result<String> {
        let link = self.net().add_file(std::io::Cursor::new(data)).await?.link();
        let mut st = self.lock();
        st.group_mut(gid)?.rec.link(link.clone());
        st.save(gid)?;
        Ok(link)
    }
}

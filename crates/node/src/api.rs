//! The node's public API, but for admission (`admission`) and the peers' summaries (`peering`).


use anyhow::{Context, Result, ensure};
use iroh::RelayUrl;
use lmk_core::group::{Change, Group};
use lmk_net::Net;
use lmk_proto::directory::relay_url;
use lmk_proto::group::Settings;
use lmk_proto::Bytes;
use serde_json::{Value, json};

use crate::{G, Member, Message, Node, Rec, State, now};

impl Node {
    /// Stops the peers and every task, and closes the provider.
    pub async fn shutdown(&self) -> Result<()> {
        for task in self.inner.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
        self.inner.net().shutdown().await?;
        // Not a step (`lock`), which commits when it ends: after the close.
        self.inner.state.lock().unwrap().provider.close()
    }

    /// This session's key: its MLS signature key.
    pub fn key(&self) -> Bytes {
        Bytes(self.inner.lock().session.key().to_vec())
    }

    pub fn net(&self) -> &Net {
        self.inner.net()
    }

    /// This session's iroh key and the relay it lives on.
    pub fn address(&self) -> ([u8; 32], RelayUrl) {
        (*self.inner.net().id().as_bytes(), relay_url(&self.inner.home).parse().expect("parsed as the node started"))
    }

    pub fn groups(&self) -> Vec<Bytes> {
        self.inner.lock().groups.keys().map(|gid| Bytes(gid.clone())).collect()
    }

    pub fn settings(&self, gid: &[u8]) -> Result<Settings> {
        Ok(self.inner.lock().group(gid)?.mls.settings())
    }

    pub fn epoch(&self, gid: &[u8]) -> Result<u64> {
        Ok(self.inner.lock().group(gid)?.mls.epoch())
    }

    pub fn members(&self, gid: &[u8]) -> Result<Vec<Member>> {
        self.inner.lock().members(gid)
    }

    /// The members this session is connected to now: above seven members, only some of those online.
    pub fn connected(&self, gid: &[u8]) -> Result<Vec<Member>> {
        let connected = self.inner.net().connected();
        let members = self.members(gid)?;
        Ok(members.into_iter().filter(|m| connected.iter().any(|peer| peer.as_bytes()[..] == m.iroh.0[..])).collect())
    }

    /// A new group with this session its only member.
    pub fn create(&self, settings: Settings) -> Result<Bytes> {
        let gid = {
            let mut st = self.inner.lock();
            let st = &mut *st;
            let mls = Group::create(&st.provider, &st.session, &settings)?;
            st.add_group(mls, Rec { updated: now(), ..Rec::default() })?
        };
        Ok(Bytes(gid))
    }

    /// Removes a member. Returns whether this session's commit removed it, which it need not once another's did.
    pub async fn remove(&self, gid: &[u8], key: &[u8]) -> Result<bool> {
        ensure!(self.inner.lock().group(gid)?.mls.members().iter().any(|m| m.key == key), "not a member");
        let remove = |_: &State, g: &G| Ok(g.mls.members().into_iter().find(|m| m.key == key).map(|member| Change { remove: vec![member.index], ..Change::default() }));
        Ok(self.inner.commit(gid, remove).await?.is_some())
    }

    /// Removes every other member, in one commit: the group is then this session's alone.
    pub async fn remove_others(&self, gid: &[u8]) -> Result<()> {
        let others = |_: &State, g: &G| {
            let remove: Vec<u32> = g.mls.members().into_iter().map(|m| m.index).filter(|index| *index != g.mls.own_index()).collect();
            Ok((!remove.is_empty()).then(|| Change { remove, ..Change::default() }))
        };
        self.inner.commit(gid, others).await?;
        Ok(())
    }

    /// Whether this session asked to leave the group, which it is in until a member removes it.
    pub fn leaving(&self, gid: &[u8]) -> bool {
        self.inner.lock().groups.get(gid).is_some_and(|g| g.rec.leaving)
    }

    /// Marks the group as one this session leaves, and sends its `leave`: the others remove it once a cut keeps the
    /// `leave`, and it is in the group until then. Forgets a group it is alone in. Returns the `leave`'s id; none once
    /// this session is out of the group.
    pub fn leave(&self, gid: &[u8]) -> Result<Option<Bytes>> {
        let mut st = self.inner.lock();
        st.group_mut(gid)?.rec.leaving = true;
        st.save(gid)?;
        let g = st.group(gid)?;
        let me = st.me().to_vec();
        if g.mls.members().len() == 1 {
            self.inner.forget(&mut st, gid)?;
            Ok(None)
        } else if let Some(seq) = g.left(&me) {
            st.id_at(gid, &me, g.mls.joined(&me).context("a member of its group")?, seq)
        } else {
            Ok(Some(self.inner.send(&mut st, gid, &json!({ "type": "leave" }), None)?))
        }
    }

    /// Sends a held payload, a reply to the delivered message `reply_to` if given. The node first asks the membership
    /// service about the group's log, and catches up if it moved, waiting at most 5 seconds; then it seals the payload to
    /// the members as of then, keeps it, delivers it to this session and pushes it to the members online, and seals it
    /// again in each epoch until a cut keeps it. Answers its id. Fails with `SendError` when this session sends faster
    /// than members take, the message is too large, the service let the log go, or the session did not catch up.
    pub async fn send(&self, gid: &[u8], payload: &Value, reply_to: Option<&[u8]>) -> Result<Bytes> {
        self.inner.refresh(gid).await?;
        self.inner.send(&mut self.inner.lock(), gid, payload, reply_to)
    }

    /// A held message of the group this session delivered.
    pub fn message(&self, gid: &[u8], id: &[u8]) -> Result<Option<Message>> {
        self.inner.lock().message(gid, id)
    }

    /// The group's held messages this session delivered and holds, in delivery order.
    pub fn messages(&self, gid: &[u8]) -> Result<Vec<Message>> {
        self.inner.lock().messages(gid)
    }

    /// Replaces a held message's payload, as when its text is forgotten; it is still served to members as ciphertext.
    pub fn redact(&self, gid: &[u8], id: &[u8], payload: Value) -> Result<()> {
        let mut st = self.inner.lock();
        let Some(mut record) = st.record(gid, id)? else { return Ok(()) };
        record.header.payload = payload;
        st.store(gid, &record)?;
        st.scrub = true;
        Ok(())
    }

    /// Leaves in this session's files no copy of what it deleted.
    pub fn scrub(&self) -> Result<()> {
        self.inner.lock().scrub = true;
        Ok(())
    }

    /// Waits until this session has read the group's logs on to their heads, through each epoch a commit moves it to.
    pub async fn caught_up(&self, gid: &[u8]) -> Result<()> {
        self.inner.caught_up(gid).await
    }

    /// Asks the services whether the logs the group's members are behind in were let go, as a commit does first.
    pub async fn ask_behind(&self, gid: &[u8]) -> Result<()> {
        self.inner.ask_behind(gid).await
    }

    /// The reference of a group's current log, its epoch's, at its membership service.
    pub fn log(&self, gid: &[u8]) -> Result<Bytes> {
        Ok(self.inner.lock().group(gid)?.rec.log.clone())
    }

    /// Reads a group's logs from their service through the current one's end, applying what they hold.
    pub async fn read_group(&self, gid: &[u8]) -> Result<()> {
        self.inner.read_group(gid).await
    }
}

//! The node's public API, but for admission (`admission`) and the peers' summaries (`peering`).


use anyhow::{Context, Result, ensure};
use iroh::RelayUrl;
use lmk_core::group::{Change, Group};
use lmk_core::identity::KeyLog;
use lmk_core::provider::Provider;
use lmk_net::Net;
use lmk_proto::group::{Certificate, DEVICES, IdentityRef, Opening, Settings};
use lmk_proto::links::FileLink;
use lmk_proto::peer::Frame;
use lmk_proto::ranges::Ranges;
use lmk_proto::Bytes;
use n0_future::{FutureExt, MergeUnbounded, StreamExt};
use n0_future::time::{Duration, sleep, timeout};
use serde_json::{Value, json};

use crate::groups::renaming;
use crate::{Dropped, G, MEMBER_WAIT, Member, Message, Node, Observation, Positions, Rec, SEND_WAIT, Sent, State, UNFINISHED, Work, device_key_key, endpoint_id, get, kind_key, message_key, put, sending};

impl<P: Provider + Send + 'static> Node<P> {
    /// Stops the peers and every task.
    pub async fn shutdown(&self) -> Result<()> {
        for task in self.inner.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
        for (_, follow) in self.inner.follows.lock().unwrap().drain() {
            follow.abort();
        }
        self.inner.net().shutdown().await
    }

    /// This session's key: its MLS signature key.
    pub fn key(&self) -> Bytes {
        Bytes(self.inner.lock().session.key().to_vec())
    }

    /// Its peers: what a transport of the caller's hands the connections peers open, and the files they fetch.
    pub fn net(&self) -> &Net {
        self.inner.net()
    }

    /// This session's iroh key and relay.
    pub fn address(&self) -> ([u8; 32], RelayUrl) {
        (*self.inner.net().id().as_bytes(), self.inner.relay.clone())
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

    /// The members connected now.
    pub fn online(&self, gid: &[u8]) -> Result<Vec<Member>> {
        let connected = self.inner.net().connected();
        let members = self.members(gid)?;
        Ok(members.into_iter().filter(|m| connected.iter().any(|peer| peer.as_bytes()[..] == m.iroh.0[..])).collect())
    }

    /// The files this session added to a group that no other member held yet.
    pub fn pending_files(&self, gid: &[u8]) -> Result<Vec<[u8; 32]>> {
        Ok(self.inner.lock().group(gid)?.rec.pending.clone())
    }

    /// The kinds this session supports.
    pub fn kinds(&self) -> &[String] {
        &self.inner.kinds
    }

    /// A new group with this session its only member, speaking as `identity`; a devices group with a new device key.
    pub fn create(&self, settings: Settings, identity: Option<Certificate>) -> Result<Bytes> {
        ensure!(self.inner.kinds.contains(&settings.kind), "this session does not support {} groups", settings.kind);
        let gid = {
            let mut st = self.inner.lock();
            let st = &mut *st;
            st.speak(identity);
            let device_key = (settings.kind == DEVICES).then(|| st.device_key()).transpose()?;
            let session = device_key.as_ref().map_or(&st.session, |(_, session)| session);
            let mls = Group::create(&st.provider, session, &settings)?;
            let gid = st.add_group(mls, Rec::default())?;
            if let Some((seed, session)) = device_key {
                put(&st.provider, &device_key_key(&gid), &Bytes(seed.to_vec()))?;
                st.device_keys.insert(gid.clone(), (seed, session));
            }
            gid
        };
        self.inner.follow(&gid);
        Ok(Bytes(gid))
    }

    /// Removes a member. Returns whether this session's commit removed it, which it need not once another's did.
    pub async fn remove(&self, gid: &[u8], key: &[u8]) -> Result<bool> {
        ensure!(self.inner.lock().group(gid)?.mls.members().iter().any(|m| m.key == key), "not a member");
        let remove = |_: &State<P>, g: &G| Ok(g.mls.members().into_iter().find(|m| m.key == key).map(|member| Change { remove: vec![member.index], ..Change::default() }));
        Ok(self.inner.commit(gid, remove).await?.is_some())
    }

    /// Changes the group's settings, from the current ones.
    pub async fn change_settings(&self, gid: &[u8], change: impl Fn(Settings) -> Settings) -> Result<Settings> {
        self.inner
            .commit(gid, |_, g| {
                let settings = change(g.mls.settings());
                Ok((settings != g.mls.settings()).then(|| Change { settings: Some(settings), ..Change::default() }))
            })
            .await?;
        self.settings(gid)
    }

    /// Marks the group as one this session leaves, and asks the others to remove it; or forgets a group it is alone
    /// in. Until a member removes it, its duties ask again (`duties`). None once this session is out of the group: it
    /// was alone in it, or was removed before its `leave` counted.
    pub async fn leave(&self, gid: &[u8]) -> Result<Option<Sent>> {
        let (id, counted) = {
            let mut st = self.inner.lock();
            st.group_mut(gid)?.rec.leaving = true;
            st.save(gid)?;
            if st.group(gid)?.mls.members().len() > 1 {
                self.inner.start_send(&mut st, gid, &json!({ "type": "leave" }))?
            } else {
                st.observe(|| Observation::Dropped { group: Bytes(gid.to_vec()), reason: Dropped::Forgotten });
                drop(st);
                self.inner.forget(gid)?;
                return Ok(None);
            }
        };
        match self.answered(id, counted).await {
            Err(_) if !self.inner.lock().groups.contains_key(gid) => Ok(None),
            sent => sent.map(Some),
        }
    }

    /// Sends a held payload: the node seals it, appends its entry to the group's log, and pushes it to the members
    /// online once the entry counts. Answers its position once it counts; or after a few seconds without the service's
    /// answer, that it is pending: the node finishes the send, after a restart too, and tells `Event::Sent`. Fails only
    /// when the service certainly did not take it (`SendError`).
    pub async fn send(&self, gid: &[u8], payload: &Value) -> Result<Sent> {
        let (id, counted) = self.inner.held_send(gid, payload)?;
        self.answered(id, counted).await
    }

    /// What `send` answers: a send's position once it counts, or that it is pending after a few seconds.
    async fn answered(&self, id: Bytes, mut counted: sending::Counted) -> Result<Sent> {
        let outcome = match timeout(SEND_WAIT, &mut counted).await {
            Ok(outcome) => outcome,
            Err(_) if self.inner.pending(&id)? => return Ok(Sent { id, position: None }),
            Err(_) => counted.await,
        };
        let (position, id) = outcome.context(UNFINISHED)?.map_err(|error| anyhow::anyhow!(error))?;
        Ok(Sent { id, position: Some(position) })
    }

    /// Sends a held payload and waits as long as it takes for its entry to count; answers its position.
    pub async fn send_counted(&self, gid: &[u8], payload: &Value) -> Result<u64> {
        let (_, counted) = self.inner.held_send(gid, payload)?;
        Ok(counted.await.context(UNFINISHED)?.map_err(|error| anyhow::anyhow!(error))?.0)
    }

    /// Seals a live payload, not held, and sends it to the members online, or to the one with fingerprint `to`; none
    /// while this session has not applied the group's log to its head.
    pub fn send_live(&self, gid: &[u8], payload: &Value, to: Option<&str>) -> Result<()> {
        let mut st = self.inner.lock();
        let st = &mut *st;
        let peer = to.map(|fp| st.by_fp(gid, fp)).transpose()?;
        if !st.at_head(gid) {
            return Ok(());
        }
        let g = st.groups.get_mut(gid).context("this session is not in that group")?;
        let session = st.device_keys.get(gid).map_or(&st.session, |(_, session)| session);
        let ciphertext = g.mls.seal(&st.provider, session, payload, true)?.1;
        let frame = Frame::Live { group: Bytes(gid.to_vec()), items: vec![Bytes(ciphertext)] };
        match peer {
            Some(peer) => st.emit(gid, peer, frame),
            None => st.broadcast(gid, frame),
        }
        Ok(())
    }

    /// Holds files for the group's H from now, as those a held message links, unless it holds them already; fetches
    /// those within this session's limit.
    pub fn hold(&self, gid: &[u8], links: &[String]) -> Result<()> {
        let parsed = links.iter().map(|link| FileLink::parse(link)).collect::<Result<Vec<_>>>()?;
        let mut st = self.inner.lock();
        let rec = &mut st.group_mut(gid)?.rec;
        for link in links {
            if !rec.files.iter().any(|(held, _)| held == link) {
                rec.link(link.clone());
            }
        }
        st.save(gid)?;
        self.inner.fetch_within_limit(gid, parsed);
        Ok(())
    }

    /// The files the group's kind links now, held while it does; fetches those new within this session's limit.
    pub fn set_links(&self, gid: &[u8], links: Vec<String>) -> Result<()> {
        let mut st = self.inner.lock();
        let rec = &mut st.group_mut(gid)?.rec;
        let new = links.iter().filter(|link| !rec.links.contains(link)).map(|link| FileLink::parse(link)).collect::<Result<Vec<_>>>()?;
        rec.links = links;
        st.save(gid)?;
        self.inner.fetch_within_limit(gid, new);
        Ok(())
    }

    /// Hands the member with fingerprint `to` a state of the group's kind, as a file it fetches.
    pub async fn hand_state(&self, gid: &[u8], to: &str, data: Vec<u8>) -> Result<()> {
        let peer = self.inner.lock().by_fp(gid, to)?;
        let link = self.inner.state_file(gid, data).await?;
        self.inner.lock().emit(gid, peer, Frame::State { group: Bytes(gid.to_vec()), link: Some(link) });
        Ok(())
    }

    /// The files a group holds.
    pub fn linked(&self, gid: &[u8]) -> Vec<FileLink> {
        lmk_net::Groups::files(&*self.inner, gid)
    }

    /// Whether this session lost a held message: its entry counted, and it can no longer open it.
    pub fn lost(&self, gid: &[u8], id: &[u8]) -> bool {
        let st = self.inner.lock();
        st.position_of(gid, id).ok().flatten().and_then(|position| st.pos(gid, position).ok().flatten()).is_some_and(|pos| pos.lost)
    }

    /// The group's counted positions as this session stands, as a simulator checks them.
    pub fn positions(&self, gid: &[u8]) -> Result<Positions> {
        let st = self.inner.lock();
        let rec = &st.group(gid)?.rec;
        let unopened: Ranges = rec.unopened.keys().copied().collect();
        Ok(Positions {
            start: rec.start,
            head: rec.position,
            held: rec.messages.difference(&rec.lacking).difference(&rec.lost),
            opened: rec.messages.difference(&unopened).difference(&rec.lost),
            lost: rec.lost.clone(),
        })
    }

    /// A held message, opened.
    pub fn message(&self, id: &[u8]) -> Result<Option<Message>> {
        get(&self.inner.lock().provider, &message_key(id))
    }

    /// The group's held messages this session opened and holds, in log order.
    pub fn messages(&self, gid: &[u8]) -> Result<Vec<Message>> {
        self.inner.lock().messages(gid)
    }

    /// Replaces a held message's payload, as when its text is forgotten; it is still served to members as ciphertext.
    pub fn redact(&self, id: &[u8], payload: Value) -> Result<()> {
        let mut st = self.inner.lock();
        let Some(mut message) = get::<Message>(&st.provider, &message_key(id))? else {
            return Ok(());
        };
        message.payload = payload;
        put(&st.provider, &message_key(id), &message)?;
        st.scrub = true;
        Ok(())
    }

    /// A record of a kind built into the client, kept with the session's own.
    pub fn record(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner.lock().provider.get(&kind_key(key))
    }

    pub fn put_record(&self, key: &str, value: &[u8]) -> Result<()> {
        self.inner.lock().provider.put(&kind_key(key), value)
    }

    pub fn delete_record(&self, key: &str) -> Result<()> {
        self.inner.lock().provider.delete(&kind_key(key))
    }

    /// Leaves in this session's files no copy of what it deleted.
    pub fn scrub(&self) -> Result<()> {
        self.inner.lock().scrub = true;
        Ok(())
    }

    /// Seals a file and holds it for a group.
    pub async fn add_file(&self, gid: &[u8], bytes: Vec<u8>) -> Result<FileLink> {
        let link = self.inner.net().add_file(std::io::Cursor::new(bytes)).await?;
        let mut st = self.inner.lock();
        st.group_mut(gid)?.rec.link(link.link());
        st.save(gid)?;
        Ok(link)
    }

    /// A file's plaintext, if it is held whole.
    pub async fn file(&self, link: &FileLink) -> Result<Option<Vec<u8>>> {
        if !self.inner.net().has(link.hash).await? {
            return Ok(None);
        }
        let mut plain = Vec::new();
        self.inner.net().read_file(link, &mut plain).await?;
        Ok(Some(plain))
    }

    /// The files this session's groups link now, which it holds.
    pub fn files(&self) -> Vec<FileLink> {
        self.groups().iter().flat_map(|gid| lmk_net::Groups::files(&*self.inner, &gid.0)).collect()
    }

    /// Fetches a file the group links, whatever its size; `Event::File` follows.
    pub fn fetch(&self, gid: &[u8], link: FileLink) {
        self.inner.work.send(Work::Fetch { group: gid.to_vec(), link }).ok();
    }

    /// The first member online found to hold a file whole, waiting up to `wait`; none at once if no member is online.
    pub async fn holders(&self, gid: &[u8], link: &FileLink, wait: Duration) -> Vec<Member> {
        // Asks again every half second, as a member may take the file meanwhile, keeping the earlier asks' answers.
        let first = async {
            let mut asks = MergeUnbounded::default();
            loop {
                if self.online(gid).is_ok_and(|online| online.is_empty()) {
                    return None;
                }
                asks.push(self.inner.net().holders(gid, link.hash));
                let answered = async {
                    match asks.next().await {
                        Some(holder) => Some(holder),
                        None => std::future::pending().await,
                    }
                };
                let tick = async {
                    sleep(Duration::from_millis(500)).await;
                    None
                };
                if let Some(holder) = answered.or(tick).await {
                    return Some(holder);
                }
            }
        };
        let holder = timeout(wait, first).await.ok().flatten();
        let st = self.inner.lock();
        holder.iter().map(|peer| st.by_iroh(gid, peer)).collect()
    }

    /// Waits until another member online holds a file this session added, or a few seconds; returns them. If none does,
    /// the file is pending until one fetches it.
    pub async fn spread(&self, gid: &[u8], link: &FileLink) -> Vec<Member> {
        let holders = self.holders(gid, link, MEMBER_WAIT).await;
        let mut st = self.inner.lock();
        if holders.is_empty()
            && let Ok(g) = st.group_mut(gid)
        {
            g.rec.pending.push(link.hash);
            st.save(gid).ok();
        }
        holders
    }

    /// An identity's key log, read from its service now.
    pub async fn read_key_log(&self, identity: &IdentityRef) -> Result<KeyLog> {
        self.inner.read_keys(identity).await
    }

    /// Appends a sealed entry to an identity's key log, and reads the log.
    pub async fn append_identity(&self, identity: &IdentityRef, entry: &[u8]) -> Result<KeyLog> {
        let log = lmk_proto::identity::address(&identity.id.0);
        self.inner.clients.client(&identity.membership)?.append(&log, &[entry.to_vec()]).await?;
        self.inner.read_keys(identity).await
    }

    /// The identities this session speaks as in its groups.
    pub fn spoken(&self) -> Vec<IdentityRef> {
        let st = self.inner.lock();
        let mut spoken: Vec<IdentityRef> = Vec::new();
        for g in st.groups.values() {
            let me = g.mls.members().into_iter().find(|m| m.key == st.session.key());
            if let Some(identity) = me.and_then(|me| Some(me.credential?.certificate?.identity))
                && !spoken.contains(&identity)
            {
                spoken.push(identity);
            }
        }
        spoken
    }

    /// This session's key in a group: in a devices group, the device's key on its identity.
    pub fn key_in(&self, gid: &[u8]) -> Bytes {
        Bytes(self.inner.lock().me(gid).to_vec())
    }

    /// A signature over `bytes` by the device's key in a devices group.
    pub fn sign(&self, gid: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
        let st = self.inner.lock();
        let (seed, _) = st.device_keys.get(gid).context("not a devices group of this node")?;
        Ok(lmk_core::identity::sign(seed, bytes))
    }

    /// Reads a group's log from its service through its end, applying what it holds.
    pub async fn read_group(&self, gid: &[u8]) -> Result<()> {
        self.inner.read(gid).await
    }

    /// Asks a member online, by its iroh key, for the state of the group's kind.
    pub fn ask_state(&self, gid: &[u8], peer: &[u8]) -> Result<()> {
        let peer = endpoint_id(peer).context("an iroh key")?;
        self.inner.lock().emit(gid, peer, Frame::State { group: Bytes(gid.to_vec()), link: None });
        Ok(())
    }

    /// Tells this session's user something about a group, as a warning.
    pub fn warn(&self, gid: &[u8], text: String) {
        self.inner.warn(Some(gid), text);
    }

    /// The device's name, where this is a device's node.
    pub fn device_name(&self) -> Option<String> {
        self.inner.lock().device.clone()
    }

    /// Renames the device, in its credential in each devices group.
    pub async fn rename_device(&self, name: &str) -> Result<()> {
        self.inner.lock().device = Some(name.into());
        for gid in self.groups() {
            self.inner.commit(&gid.0, |_, g| Ok(renaming(&g.mls, Some(name)).map(|name| Change { name: Some(name), ..Change::default() }))).await?;
        }
        Ok(())
    }

    /// What a group this session is in looks like as an opening.
    pub fn opening(&self, gid: &[u8]) -> Result<Opening> {
        let st = self.inner.lock();
        let g = st.group(gid)?;
        let settings = g.mls.settings();
        let members = g.mls.members().into_iter().filter_map(|m| Some(m.leaf?.key)).collect();
        Ok(Opening {
            group: Bytes(gid.to_vec()),
            kind: settings.kind,
            name: settings.name,
            membership: settings.membership,
            members,
            rest: Default::default(),
        })
    }
}

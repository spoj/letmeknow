//! Changing a group: commits built on its current epoch, retried until one wins (`commit`), what applied commits tell,
//! and leaving the group behind.

use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use lmk_core::group::{self as core, Change, Group};
use lmk_core::provider::Provider;
use lmk_membership::Refused;
use lmk_proto::Bytes;
use lmk_proto::group::{DEVICES, How};

use crate::{Event, G, Inner, Member, State, device_key_key, kind, logs, peering, reading, rec_key, sending};

const COMMIT_TRIES: u32 = 5;

impl<P: Provider + Send + 'static> Inner<P> {
    /// Commits a change built on the group's current epoch, posts its entry, and reads the log until it is known whether
    /// it won its epoch; if another commit won, builds it again. Returns the Welcome, if it adds, and the position; none
    /// once the change has no effect (`None`), and it commits nothing. An entry posted before, which the log may or may
    /// not have taken, as when the service's answer was lost, is posted again first: only the service's refusal drops it.
    /// This call's own entry is found in the log by its bytes.
    pub(crate) async fn commit(&self, gid: &[u8], change: impl Fn(&State<P>, &G) -> Result<Option<Change>>) -> Result<Option<(Option<Vec<u8>>, u64)>> {
        let _committing = self.committing.lock().await;
        let mut built: Option<(Vec<u8>, Option<Vec<u8>>)> = None;
        for _ in 0..COMMIT_TRIES {
            self.caught_up(gid).await?;
            let (entry, service, before) = {
                let mut st = self.lock();
                let st = &mut *st;
                let g = st.group(gid)?;
                let (service, before) = (g.mls.settings().membership, g.rec.position);
                match g.mls.posted() {
                    Some(posted) => (posted.to_vec(), service, before),
                    None => {
                        let Some(change) = change(st, g)? else { return Ok(None) };
                        let g = st.groups.get_mut(gid).unwrap();
                        let session = st.device_keys.get(gid).map_or(&st.session, |(_, session)| session);
                        let commit = g.mls.commit(&st.provider, session, change)?;
                        built = Some((commit.entry.clone(), commit.welcome));
                        (commit.entry, service, before)
                    }
                }
            };
            self.durable().await?;
            match self.clients.client(&service)?.append(gid, std::slice::from_ref(&entry)).await {
                Ok(_) => {}
                Err(error) if error.is::<Refused>() => {
                    let mut st = self.lock();
                    let st = &mut *st;
                    st.groups.get_mut(gid).context("left the group")?.mls.cancel(&st.provider)?;
                    return Err(error);
                }
                Err(error) => tracing::debug!("appending a commit, which the log may show: {error:#}"),
            }
            self.caught_up(gid).await?;
            let Some((ours, welcome)) = built.as_ref().filter(|(ours, _)| *ours == entry) else { continue };
            let st = self.lock();
            for position in before + 1..=st.group(gid)?.rec.position {
                let own = st.pos(gid, position)?.is_some_and(|pos| pos.judged == reading::Judged::Commit { own: true });
                if own && st.provider.get(&logs::entry_key(gid, position))?.as_deref() == Some(ours.as_slice()) {
                    return Ok(Some((welcome.clone(), position)));
                }
            }
        }
        bail!("the group kept changing over {COMMIT_TRIES} tries; try again")
    }

    /// Reads the group's log, and waits until this session applied it to the head it read.
    pub(crate) async fn caught_up(&self, gid: &[u8]) -> Result<()> {
        self.read(gid).await?;
        loop {
            let advanced = self.advanced.notified();
            {
                let st = self.lock();
                let g = st.group(gid)?;
                ensure!(g.mls.active(), "this session was removed from the group");
                if g.rec.position >= st.log(gid)?.logged {
                    return Ok(());
                }
            }
            advanced.await;
        }
    }

    /// Leaves a group behind: its state and records go.
    pub(crate) fn forget(&self, gid: &[u8]) -> Result<()> {
        let mut st = self.lock();
        st.expire_to(gid, u64::MAX)?;
        let st = &mut *st;
        let g = st.groups.remove(gid).context("this session is not in that group")?;
        self.unfollow(gid);
        st.drop_log(gid)?;
        for id in &g.rec.sends {
            st.provider.delete(&sending::send_key(&id.0))?;
            st.waiters.remove(&id.0);
        }
        for position in g.rec.kind.iter().flat_map(|kind| &kind.kept) {
            st.provider.delete(&kind::kept_key(gid, *position))?;
        }
        peering::forget_heard(&st.provider, gid, g.heard.keys())?;
        st.peers.forget(&Bytes(gid.to_vec()));
        st.gate = true;
        st.provider.delete(&rec_key(gid))?;
        st.provider.delete(&device_key_key(gid))?;
        st.device_keys.remove(gid);
        g.mls.delete(&st.provider)?;
        st.save_groups()?;
        st.scrub = true;
        self.advanced.notify_waiters();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn applied(
        self: &Arc<Self>,
        gid: &[u8],
        by: Option<core::Member>,
        added: Vec<core::Member>,
        how: Option<How>,
        invite: Option<Bytes>,
        removed: Vec<core::Member>,
        settings: bool,
        gone: bool,
    ) {
        if !added.is_empty() {
            self.refresh_all().await;
            self.dial_all();
        }
        let group = Bytes(gid.to_vec());
        let mut st = self.lock();
        let by = by.and_then(|by| st.member(gid, &by));
        if gone {
            drop(st);
            self.gone(gid, by);
            return;
        }
        let Some(by) = by else { return };
        let how = how.unwrap_or(How::Invite);
        let me = st.me(gid).to_vec();
        let rule = st.group(gid).ok().and_then(|g| g.rec.invites.iter().find(|rule| Some(&rule.hash) == invite.as_ref()).cloned());
        let introduces = match how {
            How::Open => by.key.0 == me,
            _ => rule.as_ref().is_some_and(|rule| rule.by.0 == me),
        };
        let label = rule.and_then(|rule| rule.label).filter(|_| introduces);
        for member in &added {
            if let Some(member) = st.member(gid, member) {
                let event = Event::Joined { group: group.clone(), member, by: by.clone(), how: how.clone(), introduces, label: label.clone() };
                st.events.push(event);
            }
        }
        for member in &removed {
            if let Some(member) = st.member(gid, member) {
                st.events.push(Event::Left { group: group.clone(), member, by: by.clone() });
            }
        }
        if settings && let Ok(g) = st.group(gid) {
            let settings = g.mls.settings();
            st.events.push(Event::Settings { group, settings, by });
        }
    }

    /// Tells that this session is out of a group, then forgets it, unless it did so already.
    pub(crate) fn gone(&self, gid: &[u8], by: Option<Member>) {
        if !self.lock().groups.contains_key(gid) {
            return;
        }
        self.events.send(Event::Removed { group: Bytes(gid.to_vec()), by }).ok();
        if let Err(error) = self.forget(gid) {
            self.warn(Some(gid), format!("{error:#}"));
        }
    }
}

/// The name this session takes in a group: in a devices group, the device's, where its credential names another.
pub(crate) fn renaming(g: &Group, device: Option<&str>) -> Option<String> {
    let own = g.members().into_iter().find(|m| m.index == g.own_index())?.credential?;
    let device = device.filter(|device| g.settings().kind == DEVICES && own.name != *device)?;
    Some(device.to_owned())
}

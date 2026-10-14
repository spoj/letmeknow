//! Changing a group: commits built on its current epoch, retried until one wins (`commit`), what applied commits tell,
//! and leaving the group behind.

use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use lmk_core::group::{self as core, Change, Group};
use lmk_core::provider::Provider;
use lmk_membership::Refused;
use lmk_proto::Bytes;
use lmk_proto::group::{IDENTITY, How};

use crate::held::delivered_key;
use crate::{Event, G, Inner, Member, State, device_key_key, get, reading, rec_key};

const COMMIT_TRIES: u32 = 5;

impl<P: Provider + Send + 'static> Inner<P> {
    /// Commits a change built on the group's current epoch, with the cut this session can make, posts its entry to the
    /// epoch's log, and reads the log until it is known whether it won its epoch; if another commit won, builds it
    /// again. Returns the epoch it ended; none once the change has no effect (`None`), and it commits nothing. An entry
    /// posted before, which the log may or may not have taken, as when the service's answer was lost, is posted again
    /// first: only the service's refusal drops it.
    pub(crate) async fn commit(&self, gid: &[u8], change: impl Fn(&State<P>, &G) -> Result<Option<Change>>) -> Result<Option<u64>> {
        let _committing = self.committing.lock().await;
        let mut built = None;
        for _ in 0..COMMIT_TRIES {
            self.caught_up(gid).await?;
            let (entry, service, capability, epoch) = {
                let mut st = self.lock();
                let st = &mut *st;
                let g = st.group(gid)?;
                let (service, capability, epoch) = (g.mls.settings().membership, g.mls.capability(&st.provider)?, g.mls.epoch());
                match g.mls.posted() {
                    Some(posted) => (posted.to_vec(), service, capability, epoch),
                    None => {
                        let Some(mut change) = change(st, g)? else { return Ok(None) };
                        change.cut = st.cut_for(gid)?;
                        let g = st.groups.get_mut(gid).unwrap();
                        let session = st.device_keys.get(gid).map_or(&st.session, |(_, session)| session);
                        let commit = g.mls.commit(&st.provider, session, change)?;
                        built = Some(commit.entry.clone());
                        (commit.entry, service, capability, epoch)
                    }
                }
            };
            self.durable().await?;
            match self.clients.client(&service)?.append(&capability, std::slice::from_ref(&entry), false).await {
                Ok(_) => {}
                // A refusal that may pass keeps the entry posted, as an earlier attempt may have landed.
                Err(error) if error.downcast_ref::<Refused>().is_some_and(|refused| matches!(refused.0.as_str(), "busy" | "rate" | "quota")) => return Err(error),
                Err(error) if error.is::<Refused>() => {
                    let mut st = self.lock();
                    let st = &mut *st;
                    st.groups.get_mut(gid).context("left the group")?.mls.cancel(&st.provider)?;
                    return Err(error);
                }
                Err(error) => tracing::debug!("appending a commit, which the log may show: {error:#}"),
            }
            self.caught_up(gid).await?;
            // The one commit of this session's that can apply is the one it posted.
            if built.as_ref() == Some(&entry) && self.lock().group(gid)?.rec.committed == epoch + 1 {
                return Ok(Some(epoch));
            }
        }
        bail!("the group kept changing over {COMMIT_TRIES} tries; try again")
    }

    /// Reads a group's logs from their service, each epoch's it moves to, through the current one's end.
    pub(crate) async fn read_group(&self, gid: &[u8]) -> Result<()> {
        loop {
            let log = self.lock().group(gid)?.rec.log.0.clone();
            self.read(&log).await?;
            if self.lock().group(gid)?.rec.log.0 == log {
                return Ok(());
            }
        }
    }

    /// Reads the group's logs, and waits until this session applied them to the head it read.
    pub(crate) async fn caught_up(&self, gid: &[u8]) -> Result<()> {
        let mut read = Vec::new();
        loop {
            let advanced = self.advanced.notified();
            let (log, at_head) = {
                let st = self.lock();
                let g = st.group(gid)?;
                ensure!(g.mls.active(), "this session was removed from the group");
                (g.rec.log.0.clone(), st.at_head(gid))
            };
            if log != read {
                self.read(&log).await?;
                read = log;
            } else if at_head {
                return Ok(());
            } else {
                advanced.await;
            }
        }
    }

    /// Leaves a group behind: its state and records go.
    pub(crate) fn forget(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
        for log in st.group_logs(gid) {
            self.unfollow(&log);
            st.drop_log(&log)?;
        }
        let rec = &st.group(gid)?.rec;
        let (authors, commits, delivered) = (rec.authors.clone(), rec.commits.clone(), rec.first.max(1)..=rec.index);
        for index in delivered {
            if let Some(id) = get::<Bytes>(&st.provider, &delivered_key(gid, index))?
                && let Some(record) = st.record(gid, &id.0)?
            {
                st.unstore(gid, &record)?;
            }
        }
        for author in authors {
            for seq in author.held.iter() {
                if let Some(record) = st.record_at(gid, &author.key.0, author.joined, seq)? {
                    st.unstore(gid, &record)?;
                }
            }
        }
        for (epoch, _) in commits {
            st.provider.delete(&reading::commit_key(gid, epoch))?;
            st.provider.delete(&reading::admitted_key(gid, epoch))?;
        }
        st.forget_heard(gid)?;
        let g = st.groups.remove(gid).context("this session is not in that group")?;
        st.unhint(g.mls.members().iter().filter_map(|member| member.leaf.as_ref().map(|leaf| leaf.key.clone())).collect())?;
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
        removed: Vec<core::Member>,
        settings: bool,
        gone: bool,
    ) {
        if !added.is_empty() {
            self.refresh_all().await;
        }
        let group = Bytes(gid.to_vec());
        let mut st = self.lock();
        let by = by.and_then(|by| st.member(gid, &by));
        if gone {
            drop(st);
            self.gone(gid, by);
            return;
        }
        if st.groups.contains_key(gid) {
            st.reverify(gid).ok();
        }
        let Some(by) = by else { return };
        let how = how.unwrap_or(How::Invite);
        for member in &added {
            if let Some(member) = st.member(gid, member) {
                st.events.push(Event::Joined { group: group.clone(), member, by: by.clone(), how: how.clone() });
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

    /// Forgets a removed group and reports removal once that step is durable, with this session's messages that no cut
    /// kept, which its records still show.
    pub(crate) fn gone(&self, gid: &[u8], by: Option<Member>) {
        let mut st = self.lock();
        let Some(kind) = st.groups.get(gid).map(|g| g.mls.settings().kind) else { return };
        let not_kept = match st.not_kept(gid) {
            Ok(not_kept) => not_kept,
            Err(error) => return self.warn(Some(gid), format!("{error:#}")),
        };
        match self.forget(&mut st, gid) {
            Ok(()) => st.events.push(Event::Removed { group: Bytes(gid.to_vec()), kind, by, not_kept }),
            Err(error) => self.warn(Some(gid), format!("{error:#}")),
        }
    }
}

/// The name this session takes in a group: in an identity group, the device's, where its credential names another.
pub(crate) fn renaming(g: &Group, device: Option<&str>) -> Option<String> {
    let own = g.members().into_iter().find(|m| m.index == g.own_index())?.credential?;
    let device = device.filter(|device| g.settings().kind == IDENTITY && own.name != *device)?;
    Some(device.to_owned())
}

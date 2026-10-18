//! Changing a group: commits built on its current epoch, retried until one wins (`commit`), what applied commits tell,
//! and leaving the group behind.

use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use lmk_core::group::{self as core, Change};
use lmk_membership::Refused;
use lmk_proto::Bytes;

use crate::held::delivered_key;
use crate::{Event, G, Inner, Member, State, get, reading, rec_key};

const COMMIT_TRIES: u32 = 5;

impl Inner {
    /// Commits a change built on the group's current epoch, with the cut this session can make, posts its entry to the
    /// epoch's log, and reads the log until it is known whether it won its epoch; if another commit won, builds it
    /// again. Returns the epoch it ended; none once the change has no effect (`None`), and it commits nothing. An entry
    /// posted before, which the log may or may not have taken, as when the service's answer was lost, is posted again
    /// first: only the service's refusal drops it.
    pub(crate) async fn commit(&self, gid: &[u8], change: impl Fn(&State, &G) -> Result<Option<Change>>) -> Result<Option<u64>> {
        let lock = self.committing.lock().unwrap().entry(gid.to_vec()).or_default().clone();
        let _committing = lock.lock().await;
        let mut built = None;
        for _ in 0..COMMIT_TRIES {
            self.caught_up(gid).await?;
            let (entry, service, capability, epoch) = {
                let mut st = self.lock();
                let st = &mut *st;
                let g = st.group(gid)?;
                let (service, capability, epoch) = (g.mls.settings().membership, st.capability(&g.rec.log.0)?, g.mls.epoch());
                match g.mls.posted() {
                    Some(posted) => (posted.to_vec(), service, capability, epoch),
                    None => {
                        let Some(mut change) = change(st, g)? else { return Ok(None) };
                        change.cut = st.cut_for(gid)?;
                        let g = st.groups.get_mut(gid).unwrap();
                        let commit = g.mls.commit(&st.provider, &st.session, change)?;
                        built = Some(commit.entry.clone());
                        (commit.entry, service, capability, epoch)
                    }
                }
            };
            match self.clients.client(&service)?.append(&capability, std::slice::from_ref(&entry)).await {
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
    pub(crate) fn forget(&self, st: &mut State, gid: &[u8]) -> Result<()> {
        for log in st.group_logs(gid) {
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
        }
        st.forget_heard(gid)?;
        let g = st.groups.remove(gid).context("this session is not in that group")?;
        st.unhint(g.mls.members().iter().filter_map(|member| member.leaf.as_ref().map(|leaf| leaf.key.clone())).collect())?;
        st.peers.forget(&Bytes(gid.to_vec()));
        st.gate = true;
        st.provider.delete(&rec_key(gid))?;
        self.committing.lock().unwrap().remove(gid);
        g.mls.delete(&st.provider)?;
        st.save_groups()?;
        st.scrub = true;
        self.advanced.notify_waiters();
        Ok(())
    }

    pub(crate) async fn applied(self: &Arc<Self>, gid: &[u8], by: Option<core::Member>, added: Vec<core::Member>, removed: Vec<core::Member>, gone: bool) {
        let group = Bytes(gid.to_vec());
        let mut st = self.lock();
        let by = by.map(|by| st.member(gid, &by));
        if gone {
            drop(st);
            self.gone(gid, by);
            return;
        }
        if st.groups.contains_key(gid) {
            st.reverify(gid).ok();
        }
        let Some(by) = by else { return };
        for member in &added {
            let member = st.member(gid, member);
            st.events.push(Event::Joined { group: group.clone(), member, by: by.clone() });
        }
        for member in &removed {
            let member = st.member(gid, member);
            st.events.push(Event::Left { group: group.clone(), member, by: by.clone() });
        }
    }

    /// Forgets a removed group and reports removal once that step is durable, with this session's messages that no cut
    /// kept, which its records still show.
    pub(crate) fn gone(&self, gid: &[u8], by: Option<Member>) {
        let mut st = self.lock();
        if !st.groups.contains_key(gid) {
            return;
        }
        let not_kept = match st.not_kept(gid) {
            Ok(not_kept) => not_kept,
            Err(error) => return self.warn(Some(gid), format!("{error:#}")),
        };
        match self.forget(&mut st, gid) {
            Ok(()) => st.events.push(Event::Removed { group: Bytes(gid.to_vec()), by, not_kept }),
            Err(error) => self.warn(Some(gid), format!("{error:#}")),
        }
    }
}

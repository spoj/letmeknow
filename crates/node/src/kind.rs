//! The state of a group's kind, handed between members as a file: to a joiner beside its Welcome, and to a member that
//! the kind's own comparison found behind.

use std::sync::Arc;

use anyhow::Result;
use iroh::EndpointId;
use lmk_core::group::seal_link;
use lmk_core::provider::Provider;
use lmk_proto::Bytes;
use lmk_proto::group::CHAT;
use lmk_proto::links::FileLink;
use lmk_proto::peer::Frame;
use n0_future::time::timeout;
use tokio::sync::oneshot;

use crate::{Event, Inner, SNAPSHOT_WAIT, State};

impl<P: Provider> State<P> {
    /// The frame that hands a member a link to the group's state, sealed in the group's current epoch, which it names.
    pub(crate) fn state_frame(&self, gid: &[u8], link: &str) -> Result<Frame> {
        let g = self.group(gid)?;
        let sealed = seal_link(&g.mls.state_secret(&self.provider)?, link)?;
        Ok(Frame::State { group: Bytes(gid.to_vec()), epoch: g.mls.epoch(), link: Some(Bytes(sealed)) })
    }

    /// Asks the member wanted for the state, once this session is at or past the epoch it wants it of.
    pub(crate) fn ask_state(&mut self, gid: &[u8]) -> Result<()> {
        let current = self.group(gid)?.mls.epoch();
        if let Some((peer, epoch)) = self.group(gid)?.rec.wanted && epoch <= current {
            let frame = Frame::State { group: Bytes(gid.to_vec()), epoch: current, link: None };
            self.emit(gid, EndpointId::from_bytes(&peer)?, frame);
        }
        Ok(())
    }

    /// Whether a request for the state, made in `epoch`, is answered: only in this session's epoch, and once per member
    /// in each epoch, as each answer takes a snapshot and a file.
    pub(crate) fn may_answer(&mut self, gid: &[u8], peer: EndpointId, epoch: u64) -> Result<bool> {
        let g = self.group_mut(gid)?;
        let current = g.mls.epoch();
        g.rec.answered.retain(|(_, at)| *at == current);
        if epoch != current || g.rec.answered.iter().any(|(member, _)| member == peer.as_bytes()) {
            return Ok(false);
        }
        g.rec.answered.push((*peer.as_bytes(), current));
        Ok(true)
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Answers a member's request for the state with a fresh link, in this session's epoch as it is then.
    pub(crate) fn answer_state(self: &Arc<Self>, gid: &[u8], peer: EndpointId) {
        let (inner, gid) = (self.clone(), gid.to_vec());
        self.spawn(async move {
            let answered = async {
                let Some(link) = inner.state_link(&gid).await else { return anyhow::Ok(()) };
                let mut st = inner.lock();
                let frame = st.state_frame(&gid, &link)?;
                st.emit(&gid, peer, frame);
                anyhow::Ok(())
            };
            if let Err(error) = answered.await {
                inner.warn(Some(&gid), format!("answering a request for the group's state: {error:#}"));
            }
        });
    }

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
                let mut st = inner.lock();
                let from = st.by_iroh(&gid, &by);
                st.events.push(Event::State { group: Bytes(gid.clone()), from, data });
                anyhow::Ok(())
            };
            if let Err(error) = taken.await {
                inner.warn(Some(&gid), format!("the group's state did not arrive: {error:#}"));
            }
        });
    }

    /// A file link to the group's kind's state as its snapshot is now: none for a chat, or when the kind gives none.
    pub(crate) async fn state_link(self: &Arc<Self>, gid: &[u8]) -> Option<String> {
        if self.lock().group(gid).ok()?.mls.settings().kind == CHAT {
            return None;
        }
        let (reply, asked) = oneshot::channel();
        self.events.send(Event::Snapshot { group: Bytes(gid.to_vec()), reply }).ok();
        let state = timeout(SNAPSHOT_WAIT, asked).await.ok().and_then(Result::ok).flatten()?;
        match self.state_file(gid, state).await {
            Ok(link) => Some(link),
            Err(error) => {
                self.warn(Some(gid), format!("the group's state could not be handed: {error:#}"));
                None
            }
        }
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

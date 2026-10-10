//! The send path: the node owns a held send until its entry counts. It saves the plaintext and the ciphertext in the
//! step that seals it, appends the entry, batched with the group's other sends, again with the same bytes after a lost
//! answer, seals it again after a commit, and finishes it after a restart.

use std::sync::Arc;

use anyhow::{Context, Result};
use lmk_core::group::{FRAMING, MAX_MESSAGE};
use lmk_core::provider::Provider;
use lmk_membership::{Refused, Unreached};
use lmk_proto::Bytes;
use n0_future::time::{Duration, sleep};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::oneshot;

use crate::reading::{Judged, ciphertext_key};
use crate::{Event, Inner, Message, Out, SendError, State, get, now, put};

/// How long a send waits before it appends again after an answer that did not come.
const RETRY: Duration = Duration::from_secs(5);

/// A held send, until its entry counts.
#[derive(Serialize, Deserialize)]
pub(crate) struct Held {
    payload: Value,
    /// The epoch it is sealed in, its id there, its ciphertext and its log entry; sealed again after a commit.
    epoch: u64,
    id: Bytes,
    ciphertext: Bytes,
    entry: Bytes,
    /// Its entry may have reached the service.
    appended: bool,
    /// `send` answered that it is pending: `Event::Sent` tells once it counts.
    pending: bool,
}

/// A send, by the id it started with.
pub(crate) fn send_key(handle: &[u8]) -> Vec<u8> {
    [b"node/send/".as_slice(), handle].concat()
}

/// A send's position once its entry counts, or why it failed.
pub(crate) type Outcome = Result<u64, Arc<SendError>>;
pub(crate) type Counted = oneshot::Receiver<Outcome>;

impl<P: Provider> State<P> {
    /// This session's send whose current ciphertext has this id, with the id it started with.
    pub(crate) fn own_send(&self, gid: &[u8], id: &[u8]) -> Result<Option<(Bytes, Held)>> {
        for handle in &self.group(gid)?.rec.sends {
            let send: Held = get(&self.provider, &send_key(&handle.0))?.context("a send without its record")?;
            if send.id.0 == id {
                return Ok(Some((handle.clone(), send)));
            }
        }
        Ok(None)
    }

    /// Seals a send's payload in the current epoch.
    fn seal(&mut self, gid: &[u8], send: &mut Held) -> Result<()> {
        let st = &mut *self;
        let g = st.groups.get_mut(gid).context("this session is not in that group")?;
        let (id, ciphertext) = g.mls.seal(&st.provider, &st.session, &send.payload, false)?;
        send.entry = Bytes(g.mls.entry(&st.provider, &id)?);
        (send.epoch, send.id, send.ciphertext, send.appended) = (g.mls.epoch(), Bytes(id.to_vec()), Bytes(ciphertext), false);
        Ok(())
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Starts a held send: seals it, and saves it, in one step. Answers the id it starts with, and its outcome.
    pub(crate) fn held_send(&self, gid: &[u8], payload: &Value) -> Result<(Bytes, Counted)> {
        let size = serde_json::to_vec(payload)?.len() + FRAMING;
        if size > MAX_MESSAGE {
            return Err(SendError::Size(format!("the message is {size} bytes, over the 1 MiB members take")).into());
        }
        let mut st = self.lock();
        let mut send = Held {
            payload: payload.clone(),
            epoch: 0,
            id: Bytes::default(),
            ciphertext: Bytes::default(),
            entry: Bytes::default(),
            appended: false,
            pending: false,
        };
        st.seal(gid, &mut send)?;
        let handle = send.id.clone();
        put(&st.provider, &send_key(&handle.0), &send)?;
        st.group_mut(gid)?.rec.sends.push(handle.clone());
        st.save(gid)?;
        let (counted, outcome) = oneshot::channel();
        st.waiters.entry(handle.0.clone()).or_default().push(counted);
        self.work.send(crate::Work::Send(gid.to_vec())).ok();
        Ok((handle, outcome))
    }

    /// `send` answered that a send is pending: once it counts, `Event::Sent` tells. Unless it counted just now: then
    /// its position.
    pub(crate) fn pending(&self, handle: &Bytes, outcome: &mut Counted) -> Result<Option<u64>> {
        let st = self.lock();
        if let Ok(counted) = outcome.try_recv() {
            return Ok(Some(counted.map_err(|error| anyhow::anyhow!(error))?));
        }
        if let Some(mut send) = get::<Held>(&st.provider, &send_key(&handle.0))? {
            send.pending = true;
            put(&st.provider, &send_key(&handle.0), &send)?;
        }
        Ok(None)
    }

    /// The id of the message counted at a position.
    pub(crate) fn sent_id(&self, gid: &[u8], position: u64) -> Result<Bytes> {
        match self.lock().pos(gid, position)?.context("a counted position has its record")?.judged {
            Judged::Counted { id } => Ok(id),
            _ => anyhow::bail!("not a counted position"),
        }
    }

    /// A send's entry counts at `position`: its ciphertext goes to the members online, and its plaintext is that
    /// position's, as this session never opens its own messages.
    pub(crate) fn counted(&self, st: &mut State<P>, gid: &[u8], position: u64, handle: Bytes, send: Held) -> Result<()> {
        st.provider.put(&ciphertext_key(gid, position), &send.ciphertext.0)?;
        st.provider.delete(&send_key(&handle.0))?;
        let g = st.group_mut(gid)?;
        g.rec.unopened.remove(&position);
        g.rec.sends.retain(|sent| *sent != handle);
        let me = g.mls.members().into_iter().find(|m| m.index == g.mls.own_index()).context("a member of its group")?;
        let sender = st.member(gid, &me).context("this session has a letmeknow credential")?;
        let message = Message { id: send.id, group: Bytes(gid.to_vec()), epoch: send.epoch, position, at: now(), sender, payload: send.payload };
        self.deliver(st, gid, message, true)?;
        st.out.push(Out::Push { group: gid.to_vec(), ciphertext: send.ciphertext.0 });
        for waiter in st.waiters.remove(&handle.0).unwrap_or_default() {
            waiter.send(Ok(position)).ok();
        }
        if send.pending {
            self.events.send(Event::Sent { group: Bytes(gid.to_vec()), id: handle, position }).ok();
        }
        Ok(())
    }

    /// Appends the group's held sends, batched, until each counts or fails.
    pub(crate) async fn sends(&self, gid: &[u8]) {
        loop {
            let batch = loop {
                let advanced = self.advanced.notified();
                match self.batch(gid) {
                    Ok(Some(batch)) => break batch,
                    Ok(None) => advanced.await,
                    Err(error) => return self.warn(Some(gid), format!("sending: {error:#}")),
                }
            };
            let Some((service, sends)) = batch else { return };
            let appended = async {
                self.durable().await?;
                let entries: Vec<Vec<u8>> = sends.iter().map(|(_, entry)| entry.clone()).collect();
                self.clients.client(&service)?.append(gid, &entries).await
            };
            match appended.await {
                Ok(_) => {
                    if let Err(error) = self.read(gid).await {
                        tracing::debug!("reading the group's log after an append: {error:#}");
                    }
                }
                Err(error) if error.is::<Refused>() => {
                    let reason = error.downcast::<Refused>().expect("refused").0;
                    let error = Arc::new(match reason.as_str() {
                        "rate" => SendError::Rate,
                        "size" => SendError::Size("over the size the group's membership service takes".into()),
                        _ => SendError::Refused(reason),
                    });
                    self.fail(gid, sends.iter().map(|(handle, _)| handle), error);
                }
                Err(error) => {
                    tracing::debug!("appending held sends: {error:#}");
                    let unreached = error.is::<Unreached>();
                    let never: Vec<Bytes> = self.appended(gid, &sends, unreached);
                    self.fail(gid, never.iter(), Arc::new(SendError::Unavailable));
                    sleep(RETRY).await;
                }
            }
        }
    }

    /// The group's sends to append, each sealed in the current epoch, once this session has read the log to its head
    /// as last read: none while it has not; an empty batch once there are no more.
    #[allow(clippy::type_complexity)]
    fn batch(&self, gid: &[u8]) -> Result<Option<Option<(lmk_proto::group::Service, Vec<(Bytes, Vec<u8>)>)>>> {
        let mut st = self.lock();
        let Ok(g) = st.group(gid) else { return Ok(Some(None)) };
        if g.rec.position < st.log(gid)?.logged || g.wait.is_some() {
            return Ok(None);
        }
        if g.rec.sends.is_empty() {
            return Ok(Some(None));
        }
        let (epoch, service, handles) = (g.mls.epoch(), g.mls.settings().membership, g.rec.sends.clone());
        let mut sends = Vec::new();
        for handle in handles {
            let mut send: Held = get(&st.provider, &send_key(&handle.0))?.context("a send without its record")?;
            if send.epoch != epoch {
                st.seal(gid, &mut send)?;
                put(&st.provider, &send_key(&handle.0), &send)?;
            }
            sends.push((handle, send.entry.0));
        }
        Ok(Some(Some((service, sends))))
    }

    /// Records that these sends' entries may have reached the service, unless it certainly was not reached; returns
    /// those that never may have.
    fn appended(&self, gid: &[u8], sends: &[(Bytes, Vec<u8>)], unreached: bool) -> Vec<Bytes> {
        let st = self.lock();
        let mut never = Vec::new();
        for (handle, _) in sends {
            let Ok(Some(mut send)) = get::<Held>(&st.provider, &send_key(&handle.0)) else { continue };
            if unreached && !send.appended {
                never.push(handle.clone());
            } else if !send.appended {
                send.appended = true;
                if let Err(error) = put(&st.provider, &send_key(&handle.0), &send) {
                    self.warn(Some(gid), format!("{error:#}"));
                }
            }
        }
        never
    }

    /// Drops sends the service certainly did not take, and tells why.
    fn fail<'a>(&self, gid: &[u8], handles: impl Iterator<Item = &'a Bytes>, error: Arc<SendError>) {
        let mut st = self.lock();
        for handle in handles {
            let Ok(Some(send)) = get::<Held>(&st.provider, &send_key(&handle.0)) else { continue };
            st.provider.delete(&send_key(&handle.0)).ok();
            if let Ok(g) = st.group_mut(gid) {
                g.rec.sends.retain(|sent| sent != handle);
            }
            st.save(gid).ok();
            for waiter in st.waiters.remove(&handle.0).unwrap_or_default() {
                waiter.send(Err(error.clone())).ok();
            }
            if send.pending {
                self.warn(Some(gid), format!("a pending send ({}) failed: {error}", crate::hex(&handle.0)));
            }
        }
    }
}

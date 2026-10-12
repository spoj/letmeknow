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

use lmk_proto::peer::{Frame, Item};

use crate::reading::ciphertext_key;
use crate::{Event, Inner, Message, Out, SendError, State, get, now, put};

/// How long a send waits before it appends again after an answer that did not come.
const RETRY: Duration = Duration::from_secs(5);

/// A held send, until its entry counts.
#[derive(Serialize, Deserialize)]
pub(crate) struct Held {
    payload: Value,
    /// The epoch it is sealed in, its id there, its ciphertext and its log entry; sealed again after a commit.
    source: lmk_proto::epoch::Anchor,
    id: Bytes,
    ciphertext: Bytes,
    entry: Bytes,
    /// Its entry may have reached the service.
    appended: bool,
    /// `send` answered that it is pending: `Event::Sent` tells once it counts.
    pending: bool,
}

struct Batch {
    service: lmk_proto::group::Service,
    capability: [u8; 32],
    source: lmk_proto::epoch::Anchor,
    sends: Vec<(Bytes, Vec<u8>, bool)>,
}

/// A send, by the id it started with.
pub(crate) fn send_key(handle: &[u8]) -> Vec<u8> {
    [b"node/send/".as_slice(), handle].concat()
}

/// A send's position and final id once its entry counts, or why it failed.
pub(crate) type Outcome = Result<(u64, Bytes), Arc<SendError>>;
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

    /// This session's held sends whose entries have not counted yet: the ids they started with, and their payloads.
    pub(crate) fn sending(&self, gid: &[u8]) -> Result<Vec<(Bytes, Value)>> {
        let mut sends = Vec::new();
        for handle in &self.group(gid)?.rec.sends {
            let send: Held = get(&self.provider, &send_key(&handle.0))?.context("a send without its record")?;
            sends.push((handle.clone(), send.payload));
        }
        Ok(sends)
    }

    /// Seals a send's payload in the current epoch.
    fn seal(&mut self, gid: &[u8], send: &mut Held) -> Result<()> {
        let st = &mut *self;
        let g = st.groups.get_mut(gid).context("this session is not in that group")?;
        let session = st.device_keys.get(gid).map_or(&st.session, |(_, session)| session);
        let (id, ciphertext) = g.mls.seal(&st.provider, session, &send.payload, false)?;
        send.entry = Bytes(g.mls.entry(&st.provider, &id)?);
        (send.id, send.ciphertext, send.appended) = (Bytes(id.to_vec()), Bytes(ciphertext), false);
        send.source = st.active(gid)?.anchor()?.clone();
        Ok(())
    }
}

impl<P: Provider + Send + 'static> crate::Node<P> {
    /// This session's held sends whose entries have not counted yet, oldest first: the ids `send` answered, and their
    /// payloads.
    pub fn sending(&self, gid: &[u8]) -> Result<Vec<(Bytes, Value)>> {
        self.inner.lock().sending(gid)
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Starts a held send: seals it, and saves it, in one step. Answers the id it starts with, and its outcome.
    pub(crate) fn held_send(&self, gid: &[u8], payload: &Value) -> Result<(Bytes, Counted)> {
        self.start_send(&mut self.lock(), gid, payload)
    }

    /// Starts a held send in a step.
    pub(crate) fn start_send(&self, st: &mut State<P>, gid: &[u8], payload: &Value) -> Result<(Bytes, Counted)> {
        let size = serde_json::to_vec(payload)?.len() + FRAMING;
        if size > MAX_MESSAGE {
            return Err(SendError::Size(format!("the message is {size} bytes, over the 1 MiB members take")).into());
        }
        let mut send = Held {
            payload: payload.clone(),
            source: st.active(gid)?.anchor()?.clone(),
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

    /// `send` answers that a send is pending: once it counts, `Event::Sent` tells. False if it is no longer held, as
    /// it counted or failed just now: its outcome is on its way.
    pub(crate) fn pending(&self, handle: &Bytes) -> Result<bool> {
        let st = self.lock();
        let Some(mut send) = get::<Held>(&st.provider, &send_key(&handle.0))? else { return Ok(false) };
        send.pending = true;
        put(&st.provider, &send_key(&handle.0), &send)?;
        Ok(true)
    }

    /// A send's entry counts at `position`: its ciphertext goes to the members online, and its plaintext is that
    /// position's, as this session never opens its own messages.
    pub(crate) fn counted(&self, st: &mut State<P>, gid: &[u8], position: u64, handle: Bytes, send: Held) -> Result<()> {
        st.provider.put(&ciphertext_key(gid, position), &send.ciphertext.0)?;
        st.provider.delete(&send_key(&handle.0))?;
        let g = st.group_mut(gid)?;
        g.rec.unopened.remove(&position);
        g.rec.own.insert(position);
        g.rec.sends.retain(|sent| *sent != handle);
        let me = g.mls.members().into_iter().find(|m| m.index == g.mls.own_index()).context("a member of its group")?;
        let sender = st.member(gid, &me).context("this session has a letmeknow credential")?;
        let message = Message { id: send.id.clone(), group: Bytes(gid.to_vec()), epoch: send.source.epoch, position, at: now(), sender, payload: send.payload, missing: Vec::new() };
        self.deliver(st, gid, message, true)?;
        let item = Item { position, ciphertext: send.ciphertext };
        st.broadcast(gid, Frame::Messages { group: Bytes(gid.to_vec()), anchor: st.active(gid)?.anchor()?.clone(), items: vec![item], answers: None });
        let waiters = st.waiters.remove(&handle.0).unwrap_or_default();
        if send.pending {
            st.events.push(Event::Sent { group: Bytes(gid.to_vec()), id: send.id.clone(), answered: handle, position });
        }
        st.out.push(Out::Outcome { waiters, outcome: Ok((position, send.id)) });
        Ok(())
    }

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
            let Some(batch) = batch else { return };
            if let Err(error) = self.durable().await { return self.warn(Some(gid), format!("{error:#}")); }
            let entries: Vec<Vec<u8>> = batch.sends.iter().map(|(_, entry, _)| entry.clone()).collect();
            let appended = match self.clients.client(&batch.service) {
                Ok(client) => client.append(&batch.capability, &entries, false).await,
                Err(error) => Err(error),
            };
            match appended {
                Ok(_) => {
                    if let Err(error) = self.read(&batch.source.log_ref).await { tracing::debug!("reading append source: {error:#}"); }
                }
                Err(error) => {
                    let known = error.is::<Unreached>() || error.is::<Refused>();
                    if known {
                        let reason = error.downcast_ref::<Refused>().map(|refused| refused.0.as_str());
                        let error = Arc::new(match reason {
                            None => SendError::Unavailable,
                            Some("rate") => SendError::Rate,
                            Some("size") => SendError::Size("over the service entry size limit".into()),
                            Some(reason) => SendError::Refused(reason.to_owned()),
                        });
                        if let Err(error) = self.fail(gid, &batch, error) {
                            self.warn(Some(gid), format!("{error:#}"));
                            return;
                        }
                    }
                    if let Err(error) = self.read(&batch.source.log_ref).await { tracing::debug!("reconciling uncertain append: {error:#}"); }
                    sleep(RETRY).await;
                }
            }
        }
    }

    fn batch(&self, gid: &[u8]) -> Result<Option<Option<Batch>>> {
        let mut st = self.lock();
        let Ok(g) = st.group(gid) else { return Ok(Some(None)) };
        if !st.at_head(gid) { return Ok(None); }
        if g.rec.sends.is_empty() { return Ok(Some(None)); }
        if st.active(gid)?.rotate() {
            self.work.send(crate::Work::Duties(gid.to_vec())).ok();
            return Ok(None);
        }
        let source = st.active(gid)?.anchor()?.clone();
        let service = g.mls.settings().membership;
        let capability = st.capability(&source.log_ref)?;
        let handles = g.rec.sends.clone();
        let mut sends = Vec::new();
        for handle in handles.into_iter().take(64) {
            let mut send: Held = get(&st.provider, &send_key(&handle.0))?.context("a send without its record")?;
            if send.source != source {
                anyhow::ensure!(st.log(&send.source.log_ref)?.closed.is_some(), "uncertain source not yet closed");
                st.seal(gid, &mut send)?;
            }
            let uncertain = send.appended;
            send.appended = true;
            put(&st.provider, &send_key(&handle.0), &send)?;
            sends.push((handle, send.entry.0, uncertain));
        }
        Ok(Some(Some(Batch { service, capability, source, sends })))
    }

    fn fail(&self, gid: &[u8], batch: &Batch, error: Arc<SendError>) -> Result<()> {
        let mut st = self.lock();
        for (handle, wire, uncertain) in &batch.sends {
            if *uncertain { continue; }
            let Some(send) = get::<Held>(&st.provider, &send_key(&handle.0))? else { continue };
            if send.source != batch.source || send.entry.0 != *wire { continue; }
            st.provider.delete(&send_key(&handle.0))?;
            st.group_mut(gid)?.rec.sends.retain(|sent| sent != handle);
            st.save(gid)?;
            let waiters = st.waiters.remove(&handle.0).unwrap_or_default();
            st.out.push(Out::Outcome { waiters, outcome: Err(error.clone()) });
        }
        Ok(())
    }

}

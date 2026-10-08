//! What the peers need from the group logic (`Groups`), what an inviter decides (`Admit`), and taking in a message.

use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use iroh::EndpointId;
use lmk_core::group::{self as core, Change, key_package_credential};
use lmk_core::identity::{Verdict, check};
use lmk_core::invite::Target;
use lmk_core::provider::Provider;
use lmk_membership::Chain;
use lmk_net::{Admit, Groups, Taken};
use lmk_proto::group::{How, Kind, Payload, Service};
use lmk_proto::head::{self, Head};
use lmk_proto::links::FileLink;
use lmk_proto::peer::{Admitted, Hello, InviteRequest};
use lmk_proto::{Answer, Bytes};
use n0_future::boxed::BoxFuture;
use sha2::{Digest, Sha256};

use crate::{
    Event, Inner, Item, MAX_MESSAGE, Message, State, Work, ciphertext_key, doc, doc_like,
    entry_key, message_key, now, put,
};

/// A head that needs no signature: the empty log's.
fn empty(log: &[u8]) -> Head {
    Head {
        log: log.into(),
        length: 0,
        hash: head::start(log).into(),
        time: 0,
        sig: Bytes::default(),
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Takes in a ciphertext from a peer: what became of it is told to the peer.
    pub(crate) fn take(&self, st: &mut State<P>, gid: &[u8], ciphertext: &[u8]) -> Taken {
        self.open(st, gid, ciphertext)
            .unwrap_or_else(|error| Taken::Refused(format!("{error:#}")))
    }

    fn open(&self, st: &mut State<P>, gid: &[u8], ciphertext: &[u8]) -> Result<Taken> {
        let id: [u8; 32] = Sha256::digest(ciphertext).into();
        let g = st.group_mut(gid)?;
        if g.rec.items.iter().any(|item| item.id.0 == id) {
            return Ok(Taken::Held);
        }
        ensure!(
            !g.rec.given_up.iter().any(|(_, given)| given.0 == id),
            "beyond the key window"
        );
        ensure!(ciphertext.len() <= MAX_MESSAGE, "larger than 1 MiB");
        let epoch = core::epoch_of(ciphertext)?;
        if epoch > g.mls.epoch() {
            if !g.future.iter().any(|waiting| waiting == ciphertext) {
                g.future.push(ciphertext.to_vec());
            }
            self.work.send(Work::Read(gid.to_vec())).ok();
            return Ok(Taken::Waiting);
        }
        let g = st.groups.get_mut(gid).unwrap();
        let opened = match g.mls.open(&st.provider, ciphertext, now()) {
            Ok(opened) => opened,
            Err(error) => {
                g.rec.given_up.push((epoch, Bytes(id.to_vec())));
                st.save(gid)?;
                return Err(error);
            }
        };
        let sender = g
            .mls
            .members()
            .into_iter()
            .find(|m| m.key == opened.key)
            .unwrap_or(core::Member {
                index: opened.index,
                key: opened.key.clone(),
                credential: Some(opened.sender.clone()),
                leaf: None,
            });
        let sender = st
            .member(gid, &sender)
            .context("the sender has no letmeknow credential")?;
        let group = Bytes(gid.to_vec());
        match opened.payload {
            payload @ (Payload::Message { .. } | Payload::Leave) => {
                let g = st.groups.get_mut(gid).unwrap();
                if let Payload::Message {
                    attachment: Some(attachment),
                    ..
                } = &payload
                {
                    let link = FileLink::parse(&attachment.link)?;
                    g.rec.files.push(attachment.link.clone());
                    if link.size <= self.file_limit {
                        self.work
                            .send(Work::Fetch {
                                group: gid.to_vec(),
                                link,
                            })
                            .ok();
                    }
                }
                if payload == Payload::Leave && opened.current.is_some() {
                    self.work
                        .send(Work::Remove {
                            group: gid.to_vec(),
                            key: opened.key.clone(),
                        })
                        .ok();
                }
                let at = now();
                g.rec.items.push(Item {
                    epoch,
                    id: Bytes(id.to_vec()),
                    at,
                });
                st.provider.put(&ciphertext_key(&id), ciphertext)?;
                let message = Message {
                    id: Bytes(id.to_vec()),
                    group,
                    epoch,
                    at,
                    sender,
                    payload,
                };
                put(&st.provider, &message_key(&id), &message)?;
                st.save(gid)?;
                if matches!(message.payload, Payload::Message { .. }) {
                    self.events.send(Event::Message(message)).ok();
                }
            }
            Payload::Edit { update } | Payload::Diff { update } => {
                let settings = st.group(gid)?.mls.settings();
                ensure!(doc_like(&settings), "an edit outside a doc");
                let old = st.doc_state(gid)?;
                let new = doc::apply(&old, &update.0)?;
                st.provider.put(&crate::doc_key(gid), &new)?;
                if settings.kind == Kind::Doc {
                    let before = doc::links(&doc::text(&old)?);
                    for link in doc::links(&doc::text(&new)?) {
                        if !before.contains(&link) && link.size <= self.file_limit {
                            self.work
                                .send(Work::Fetch {
                                    group: gid.to_vec(),
                                    link,
                                })
                                .ok();
                        }
                    }
                }
                self.events.send(Event::Edited { group, by: sender }).ok();
            }
            Payload::Introduce {
                identity,
                name,
                how,
            } => {
                self.events
                    .send(Event::Introduced {
                        group,
                        by: sender,
                        identity,
                        name,
                        how,
                    })
                    .ok();
            }
        }
        Ok(Taken::Held)
    }

    /// Answers an invite stream's request.
    async fn redeemed(self: &Arc<Self>, request: InviteRequest) -> Result<Admitted> {
        let (secret, key_package, now) = (request.secret.0, request.key_package.0, now());
        let (joiner, bound) = {
            let st = self.state.lock().unwrap();
            let (joiner, _) = key_package_credential(&st.provider, &key_package)?;
            (joiner, st.invites.bound(&secret, now).is_some())
        };
        let list = match (bound, &joiner.identity) {
            (true, Some(identity)) => self.list(identity).await.ok(),
            _ => None,
        };
        let redeemed = {
            let mut st = self.state.lock().unwrap();
            let st = &mut *st;
            st.invites
                .redeem(&st.provider, &secret, &key_package, list.as_ref(), now)?
        };
        match redeemed.target {
            Target::Group(gid) => {
                self.admit(&gid, key_package, How::Invite, redeemed.label)
                    .await
            }
            Target::Device(id) => {
                let identity = {
                    let st = self.state.lock().unwrap();
                    st.device
                        .identities
                        .iter()
                        .find(|identity| identity.id.0 == id)
                        .cloned()
                };
                let identity = identity.context("this device left the identity")?;
                let list = self.list(&identity).await?;
                let entry = list.add(
                    &self.state.lock().unwrap().device,
                    &redeemed.joiner.device.0,
                    &redeemed.joiner.device_name,
                );
                self.logs
                    .client(&identity.membership)?
                    .append(&lmk_proto::identity::address(&id), &entry)
                    .await?;
                self.list(&identity).await?;
                let gid = self
                    .state
                    .lock()
                    .unwrap()
                    .devices_group(&id)
                    .context("no devices group")?;
                self.admit(&gid, key_package, How::Invite, None).await
            }
        }
    }

    /// Answers a request to join a group open to the joiner's identity.
    async fn open_join(self: &Arc<Self>, gid: &[u8], key_package: Vec<u8>) -> Result<Admitted> {
        let (joiner, key, open) = {
            let st = self.state.lock().unwrap();
            let (joiner, key) = key_package_credential(&st.provider, &key_package)?;
            (joiner, key, st.group(gid)?.mls.settings().open)
        };
        let identity = joiner
            .identity
            .clone()
            .filter(|identity| open.iter().any(|named| named.id == identity.id));
        let identity = identity.context("it speaks as no identity the group is open to")?;
        let list = self.list(&identity).await?;
        ensure!(
            check(&joiner, &key, Some(&list)) == Verdict::Verified,
            "its device is not on its identity's device list"
        );
        self.admit(gid, key_package, How::Open, None).await
    }

    /// Commits the Add, and answers with the Welcome and, for a doc, its state as a file.
    async fn admit(
        self: &Arc<Self>,
        gid: &[u8],
        key_package: Vec<u8>,
        how: How,
        label: Option<String>,
    ) -> Result<Admitted> {
        if let Some(label) = label {
            let mut st = self.state.lock().unwrap();
            let (_, key) = key_package_credential(&st.provider, &key_package)?;
            st.labels.insert(key, label);
        }
        let add = Change {
            add: vec![key_package],
            how: Some(how),
            ..Change::default()
        };
        let (welcome, position) = self.commit(gid, |_| Ok(add.clone())).await?;
        let state = {
            let st = self.state.lock().unwrap();
            doc_like(&st.group(gid)?.mls.settings())
                .then(|| st.doc_state(gid))
                .transpose()?
        };
        let doc = match state {
            Some(state) => {
                let link = self
                    .net()
                    .add_file(std::io::Cursor::new(state))
                    .await?
                    .link();
                let mut st = self.state.lock().unwrap();
                st.group_mut(gid)?.rec.files.push(link.clone());
                st.save(gid)?;
                Some(link)
            }
            None => None,
        };
        Ok(Admitted {
            welcome: Bytes(welcome.context("an add makes a Welcome")?),
            position,
            doc,
        })
    }

    fn answer(&self, group: Option<&[u8]>, admitted: Result<Admitted>) -> Answer<Admitted> {
        match admitted {
            Ok(admitted) => Answer::Ok(admitted),
            Err(error) => {
                self.warn(group, format!("refused a join: {error:#}"));
                Answer::Refused {
                    refused: format!("{error:#}"),
                }
            }
        }
    }
}

impl<P: Provider + Send + 'static> Groups for Inner<P> {
    fn groups(&self) -> Vec<Vec<u8>> {
        self.state.lock().unwrap().groups.keys().cloned().collect()
    }

    fn is_member(&self, group: &[u8], peer: &EndpointId) -> bool {
        let st = self.state.lock().unwrap();
        st.groups.get(group).is_some_and(|g| {
            g.mls.members().iter().any(|m| {
                m.leaf
                    .as_ref()
                    .is_some_and(|leaf| leaf.key.0 == peer.as_bytes())
            })
        })
    }

    fn hello(&self, group: &[u8]) -> Hello {
        let st = self.state.lock().unwrap();
        let Some(g) = st.groups.get(group) else {
            return Hello {
                group: group.into(),
                epoch: 0,
                head: empty(group),
                floor: 0,
                joined: 0,
            };
        };
        let (epoch, joined) = (g.mls.epoch(), g.mls.joined());
        let head = g
            .rec
            .chain
            .as_ref()
            .map_or_else(|| empty(group), |chain| chain.head.clone());
        let floor = joined.max(epoch.saturating_sub(self.window.epochs as u64));
        Hello {
            group: group.into(),
            epoch,
            head,
            floor,
            joined,
        }
    }

    fn verify_head(&self, group: &[u8], head: &Head) -> bool {
        if *head == empty(group) || head.length == 0 && head.hash.0 == head::start(group) {
            return true;
        }
        let st = self.state.lock().unwrap();
        let Some(g) = st.groups.get(group) else {
            return false;
        };
        match g.mls.settings().membership {
            Service::Serve { key, .. } => {
                let key: Option<[u8; 32]> = key.0.try_into().ok();
                key.and_then(|key| VerifyingKey::from_bytes(&key).ok())
                    .is_some_and(|key| head.verify(&key))
            }
            Service::Folder(_) => true,
        }
    }

    fn chain(&self, group: &[u8], position: u64) -> Option<[u8; 32]> {
        let st = self.state.lock().unwrap();
        st.groups.get(group)?.rec.chain.as_ref()?.hash_at(position)
    }

    fn entries(&self, group: &[u8], after: u64) -> Vec<Bytes> {
        let st = self.state.lock().unwrap();
        let Some(g) = st.groups.get(group) else {
            return Vec::new();
        };
        (after + 1..=g.rec.logged)
            .filter_map(|position| {
                st.provider
                    .get(&entry_key(group, position))
                    .ok()?
                    .map(Bytes)
            })
            .collect()
    }

    fn apply(&self, group: &[u8], entries: Vec<Bytes>, head: Head) -> Result<()> {
        let (after, chain) = {
            let st = self.state.lock().unwrap();
            let g = st.group(group)?;
            let mut chain: Chain = g
                .rec
                .chain
                .clone()
                .context("no chain of the group's log yet")?;
            let after = chain.length();
            chain.extend(after, &entries, &head)?;
            self.logs
                .client(&g.mls.settings().membership)?
                .set_chain(chain.clone());
            (after, chain)
        };
        self.logged(group, after, entries, Some(chain))
    }

    fn items(&self, group: &[u8], from: u64) -> Vec<(u64, [u8; 32])> {
        let st = self.state.lock().unwrap();
        let Some(g) = st.groups.get(group) else {
            return Vec::new();
        };
        let held = g.rec.items.iter().map(|item| (item.epoch, &item.id));
        let given_up = g.rec.given_up.iter().map(|(epoch, id)| (*epoch, id));
        held.chain(given_up)
            .filter(|(epoch, _)| *epoch >= from)
            .filter_map(|(epoch, id)| Some((epoch, id.0.as_slice().try_into().ok()?)))
            .collect()
    }

    fn message(&self, group: &[u8], id: &[u8; 32]) -> Option<Vec<u8>> {
        let st = self.state.lock().unwrap();
        st.groups
            .get(group)?
            .rec
            .items
            .iter()
            .any(|item| item.id.0 == id)
            .then_some(())?;
        st.provider.get(&ciphertext_key(id)).ok()?
    }

    fn receive(&self, group: &[u8], ciphertext: &[u8]) -> Taken {
        let mut st = self.state.lock().unwrap();
        self.take(&mut st, group, ciphertext)
    }

    fn doc(&self, group: &[u8]) -> Option<[u8; 32]> {
        let st = self.state.lock().unwrap();
        doc_like(&st.groups.get(group)?.mls.settings()).then_some(())?;
        doc::snapshot(&st.doc_state(group).ok()?).ok()
    }

    fn doc_sv(&self, group: &[u8]) -> Vec<u8> {
        let st = self.state.lock().unwrap();
        st.doc_state(group)
            .and_then(|state| doc::state_vector(&state))
            .unwrap_or_default()
    }

    fn diff(&self, group: &[u8], sv: &[u8]) -> Result<Vec<u8>> {
        let mut st = self.state.lock().unwrap();
        let st = &mut *st;
        let update = doc::diff(&st.doc_state(group)?, sv)?;
        let g = st.groups.get_mut(group).context("not in that group")?;
        Ok(g.mls
            .seal(
                &st.provider,
                &st.session,
                &Payload::Diff {
                    update: Bytes(update),
                },
            )?
            .1)
    }

    fn files(&self, group: &[u8]) -> Vec<FileLink> {
        let st = self.state.lock().unwrap();
        let Some(g) = st.groups.get(group) else {
            return Vec::new();
        };
        let mut files: Vec<FileLink> = g
            .rec
            .files
            .iter()
            .filter_map(|link| FileLink::parse(link).ok())
            .collect();
        if g.mls.settings().kind == Kind::Doc
            && let Ok(text) = st.doc_state(group).and_then(|state| doc::text(&state))
        {
            files.extend(doc::links(&text));
        }
        files
    }
}

pub(crate) struct Admitter<P>(pub Arc<Inner<P>>);

impl<P: Provider + Send + 'static> Admit for Admitter<P> {
    fn invite(&self, _: EndpointId, request: InviteRequest) -> BoxFuture<Answer<Admitted>> {
        let inner = self.0.clone();
        Box::pin(async move {
            let admitted = inner.redeemed(request).await;
            inner.answer(None, admitted)
        })
    }

    fn join(
        &self,
        _: EndpointId,
        group: Vec<u8>,
        key_package: Vec<u8>,
    ) -> BoxFuture<Answer<Admitted>> {
        let inner = self.0.clone();
        Box::pin(async move {
            let admitted = inner.open_join(&group, key_package).await;
            inner.answer(Some(&group), admitted)
        })
    }
}

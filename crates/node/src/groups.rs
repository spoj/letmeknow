//! What the peers need from the group logic to serve files (`Groups`), and whom a member admits (`Admit`).

use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use iroh::EndpointId;
use lmk_core::group::{self as core, Change, key_package_credential, key_package_leaf};
use lmk_core::identity::Verdict;
use lmk_core::provider::Provider;
use lmk_net::{Admit, Groups};
use lmk_proto::entry::Entry;
use lmk_proto::group::{CHAT, Credential, How};
use lmk_proto::links::FileLink;
use lmk_proto::peer::{Admitted, Join};
use lmk_proto::{Answer, Bytes};
use n0_future::boxed::BoxFuture;
use n0_future::time::timeout;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::reading::Judged;
use crate::{Event, Inner, SNAPSHOT_WAIT, State, now};

/// The answer to a secret no rule admits by: whether it is unknown, used or expired is not told.
const UNKNOWN: &str = "unknown, used or expired invite";
const NOT_OPEN: &str = "it speaks as no identity the group is open to";

/// Whether `g`, as it stands, admits a joiner by the invite with this hash and expiry, or else by an opening: checked
/// when its request comes, and each time the commit that adds it is built.
fn admits(g: &core::Group, joiner: &Credential, invite: &Option<(Bytes, u64)>) -> Result<()> {
    match invite {
        Some((hash, expires)) => ensure!(now() < *expires && !g.used(&hash.0), UNKNOWN),
        None => ensure!(joiner.identity().is_some_and(|identity| g.settings().open.iter().any(|named| named.id == identity.id)), NOT_OPEN),
    }
    ensure!(g.members().iter().all(|member| member.key != joiner.key.0), "this session is a member already");
    Ok(())
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Answers a joiner's request: it brings an invite's secret, or speaks as an identity the group is open to.
    async fn admit_join(self: &Arc<Self>, join: Join) -> Result<Admitted> {
        let Join { secret, group, key_package } = join;
        let joiner = key_package_credential(&self.lock().provider, &key_package.0)?;
        let (gid, how, invite, to) = match (secret, group) {
            (Some(secret), _) => {
                let hash = Bytes(Sha256::digest(&secret.0).to_vec());
                let st = self.lock();
                let found = st.groups.iter().find_map(|(gid, g)| Some((gid.clone(), g.rec.invites.iter().find(|rule| rule.hash == hash)?.clone())));
                let (gid, rule) = found.context(UNKNOWN)?;
                (gid, How::Invite, Some((hash, rule.expires)), rule.to)
            }
            (None, Some(gid)) => (gid.0, How::Open, None, Some(joiner.identity().context(NOT_OPEN)?.id.clone())),
            (None, None) => bail!("a request names an invite's secret or a group"),
        };
        // A joiner the log shows added, whose answer was lost, asks again with the same KeyPackage.
        self.caught_up(&gid).await?;
        let logged = self.lock().logged_welcome(&gid, &joiner, &key_package.0)?;
        if let Some((welcome, position)) = logged {
            return self.admitted(&gid, welcome, position).await;
        }
        admits(&self.lock().group(&gid)?.mls, &joiner, &invite)?;
        // Its identity's key log, read afresh, must list the device that certified it.
        if let Some(to) = to {
            let identity = joiner.identity().filter(|identity| identity.id == to).context("this invite is for another identity")?;
            match self.read_keys(identity).await?.verify(&joiner) {
                Verdict::Verified { .. } => {}
                Verdict::Unverified => bail!("its device is not on its identity's list"),
                Verdict::Dropped => bail!("its device was taken off its identity"),
            }
        }
        self.admit(&gid, key_package.0, &joiner, how, invite).await
    }

    /// Commits the Add, naming the invite the joiner came in by, and answers with the Welcome and the state of the group's
    /// kind, as a file. Each build of the commit checks the joiner's rule again. A joiner whose session does not support
    /// the group's kind is refused.
    async fn admit(self: &Arc<Self>, gid: &[u8], key_package: Vec<u8>, joiner: &Credential, how: How, invite: Option<(Bytes, u64)>) -> Result<Admitted> {
        {
            let st = self.lock();
            let kind = st.group(gid)?.mls.settings().kind;
            let leaf = key_package_leaf(&st.provider, &key_package)?;
            ensure!(leaf.kinds.contains(&kind), "its session does not support {kind} groups");
        }
        let add = Change { add: vec![key_package], how: Some(how), invite: invite.as_ref().map(|(hash, _)| hash.clone()), ..Change::default() };
        let (welcome, position) = self
            .commit(gid, |_, g| {
                admits(&g.mls, joiner, &invite)?;
                Ok(Some(add.clone()))
            })
            .await?
            .context("an Add has effect")?;
        self.admitted(gid, welcome.context("an add makes a Welcome")?, position).await
    }

    /// The answer to a joiner added at `position`: the Welcome, and the state of the group's kind, as a file.
    async fn admitted(self: &Arc<Self>, gid: &[u8], welcome: Vec<u8>, position: u64) -> Result<Admitted> {
        let state = {
            let st = self.lock();
            let g = st.group(gid)?;
            (g.mls.settings().kind != CHAT).then(|| {
                let (reply, state) = oneshot::channel();
                self.events.send(Event::Snapshot { group: Bytes(gid.to_vec()), reply }).ok();
                state
            })
        };
        let state = match state {
            Some(asked) => timeout(SNAPSHOT_WAIT, asked).await.ok().and_then(Result::ok).flatten(),
            None => None,
        };
        let doc = match state {
            Some(state) => Some(self.state_file(gid, state).await?),
            None => None,
        };
        self.durable().await?;
        Ok(Admitted { welcome: Bytes(welcome), position, doc })
    }
}

impl<P: Provider> State<P> {
    /// The Welcome and position of the commit entry that added the joiner with this KeyPackage, if the joiner is a member
    /// whose leaf has not updated since.
    fn logged_welcome(&self, gid: &[u8], joiner: &Credential, key_package: &[u8]) -> Result<Option<(Vec<u8>, u64)>> {
        let g = self.group(gid)?;
        if !g.mls.unchanged(&self.provider, key_package)? {
            return Ok(None);
        }
        let Some(added) = g.mls.added().iter().rev().find(|added| added.member.key == joiner.key) else { return Ok(None) };
        for position in (g.rec.expired + 1..=g.rec.position).rev() {
            let Some(pos) = self.pos(gid, position)? else { continue };
            if matches!(pos.judged, Judged::Commit { .. }) && pos.epoch + 1 == added.epoch {
                let entry = self.provider.get(&crate::logs::entry_key(gid, position))?.context("a stored entry is missing")?;
                let Entry::Commit { welcome: Some(welcome), .. } = Entry::parse(&entry)? else { return Ok(None) };
                return Ok(Some((welcome, position)));
            }
        }
        Ok(None)
    }
}

impl<P: Provider + Send + 'static> Groups for Inner<P> {
    fn groups(&self) -> Vec<Vec<u8>> {
        self.lock().groups.keys().cloned().collect()
    }

    fn is_member(&self, group: &[u8], peer: &EndpointId) -> bool {
        self.lock().serves(group, peer)
    }

    fn files(&self, group: &[u8]) -> Vec<FileLink> {
        let st = self.lock();
        let Some(g) = st.groups.get(group) else {
            return Vec::new();
        };
        g.rec.held(g.mls.settings().carry)
    }
}

pub(crate) struct Admitter<P>(pub Arc<Inner<P>>);

impl<P: Provider + Send + 'static> Admit for Admitter<P> {
    fn join(&self, _: EndpointId, join: Join) -> BoxFuture<Answer<Admitted>> {
        let inner = self.0.clone();
        Box::pin(async move {
            match inner.admit_join(join).await {
                Ok(admitted) => Answer::Ok(admitted),
                Err(error) => {
                    inner.warn(None, format!("refused a join: {error:#}"));
                    Answer::Refused { refused: format!("{error:#}") }
                }
            }
        })
    }
}

//! What the peers need from the group logic (`Groups`), and whom a member admits (`Admit`).

use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::VerifyingKey;
use iroh::EndpointId;
use lmk_core::group::{self as core, Change, key_package_credential, key_package_leaf};
use lmk_core::identity::{certified, check};
use lmk_core::provider::Provider;
use lmk_net::{Admit, Groups};
use lmk_proto::group::{CHAT, Credential, How, Service};
use lmk_proto::head::Head;
use lmk_proto::identity::Envelope;
use lmk_proto::links::FileLink;
use lmk_proto::peer::{Admitted, Hello, Join};
use lmk_proto::{Answer, Bytes};
use n0_future::boxed::BoxFuture;
use n0_future::time::timeout;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::logs::empty;
use crate::{Event, Inner, Out, SNAPSHOT_WAIT, State, Work, now};

/// The answer to a secret no rule admits by: whether it is unknown, used or expired is not told.
const UNKNOWN: &str = "unknown, used or expired invite";
const NOT_OPEN: &str = "it speaks as no identity the group is open to";

/// Whether `g`, as it stands, admits a joiner by the invite with this hash and expiry, or else by an opening: checked
/// when its request comes, and each time the commit that adds it is built.
fn admits(g: &core::Group, joiner: &Credential, invite: &Option<(Bytes, u64)>) -> Result<()> {
    match invite {
        Some((hash, expires)) => ensure!(now() < *expires && !g.used(&hash.0), UNKNOWN),
        None => ensure!(joiner.identity.as_ref().is_some_and(|identity| g.settings().open.iter().any(|named| named.id == identity.id)), NOT_OPEN),
    }
    ensure!(g.members().iter().all(|member| member.key != joiner.key.0), "this session is a member already");
    Ok(())
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Answers a joiner's request: it brings an invite's secret, or speaks as an identity the group is open to.
    async fn admit_join(self: &Arc<Self>, join: Join) -> Result<Admitted> {
        let Join { secret, group, key_package, certificate } = join;
        let joiner = key_package_credential(&self.lock().provider, &key_package.0)?;
        let (gid, how, invite, to) = match (secret, group) {
            (Some(secret), _) => {
                let hash = Bytes(Sha256::digest(&secret.0).to_vec());
                let st = self.lock();
                let found = st.groups.iter().find_map(|(gid, g)| Some((gid.clone(), g.rec.invites.iter().find(|rule| rule.hash == hash)?.clone())));
                let (gid, rule) = found.context(UNKNOWN)?;
                (gid, How::Invite, Some((hash, rule.expires)), rule.to)
            }
            (None, Some(gid)) => (gid.0, How::Open, None, Some(joiner.identity.as_ref().context(NOT_OPEN)?.id.clone())),
            (None, None) => bail!("a request names an invite's secret or a group"),
        };
        admits(&self.lock().group(&gid)?.mls, &joiner, &invite)?;
        if let Some(to) = to {
            let identity = joiner.identity.clone().filter(|identity| identity.id == to).context("this invite is for another identity")?;
            let log = self.read_keys(&identity).await?;
            if let Err(error) = check(certificate.as_ref(), &joiner, &log, now()) {
                bail!("{error}");
            }
        }
        if let Some(certificate) = certificate {
            self.certified(&joiner, certificate);
        }
        self.admit(&gid, key_package.0, &joiner, how, invite).await
    }

    /// Holds a joiner's certificate.
    fn certified(&self, joiner: &Credential, certificate: Envelope) {
        if let Some(identity) = &joiner.identity {
            self.lock().certificates.insert((joiner.key.0.clone(), identity.id.0.clone()), certificate);
        }
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
            .commit(gid, |g| {
                admits(g, joiner, &invite)?;
                Ok(Some(add.clone()))
            })
            .await?
            .context("an Add has effect")?;
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
        let certificates = lmk_net::Groups::certificates(&**self, &[gid.to_vec()]);
        self.durable().await?;
        Ok(Admitted { welcome: Bytes(welcome.context("an add makes a Welcome")?), position, doc, certificates })
    }

}

impl<P: Provider + Send + 'static> Groups for Inner<P> {
    fn groups(&self) -> Vec<Vec<u8>> {
        self.lock().groups.keys().cloned().collect()
    }

    fn in_leaf(&self, group: &[u8], peer: &EndpointId) -> bool {
        self.lock().in_leaf(group, peer).is_some()
    }

    fn is_member(&self, group: &[u8], peer: &EndpointId) -> bool {
        self.lock().serves(group, peer)
    }

    fn revision(&self, group: &[u8], peer: &EndpointId) -> u32 {
        self.lock().in_leaf(group, peer).and_then(|m| m.leaf).map_or(0, |leaf| leaf.revision)
    }

    fn hello(&self, group: &[u8]) -> Hello {
        let st = self.lock();
        let Some(g) = st.groups.get(group) else {
            return Hello { group: group.into(), epoch: 0, floor: 0, joined: 0, anew: false };
        };
        let (epoch, joined) = (g.mls.epoch(), g.mls.joined());
        Hello { group: group.into(), epoch, floor: joined, joined, anew: false }
    }

    fn logs(&self, group: &[u8]) -> Vec<Vec<u8>> {
        let st = self.lock();
        if !st.groups.contains_key(group) {
            return Vec::new();
        }
        let identities = st.identities(group).into_iter().map(|identity| lmk_proto::identity::address(&identity.id.0).to_vec());
        let mut logs: Vec<Vec<u8>> = [group.to_vec()].into_iter().chain(identities).filter(|id| st.logs.contains_key(id)).collect();
        logs.sort();
        logs.dedup();
        logs
    }

    fn head(&self, log: &[u8]) -> Head {
        self.lock().logs.get(log).map_or_else(|| empty(log), |l| l.head(log))
    }

    fn verify_head(&self, log: &[u8], head: &Head) -> bool {
        if head.length == 0 && head.hash == empty(log).hash {
            return true;
        }
        let st = self.lock();
        match st.logs.get(log).map(|l| &l.service) {
            Some(Service::Serve { key, .. }) => {
                let key: Option<[u8; 32]> = key.0.clone().try_into().ok();
                key.and_then(|key| VerifyingKey::from_bytes(&key).ok()).is_some_and(|key| head.verify(&key))
            }
            Some(Service::Folder(_)) => true,
            Some(Service::Newer(_)) | None => false,
        }
    }

    fn chain(&self, log: &[u8], position: u64) -> Option<[u8; 32]> {
        self.lock().logs.get(log)?.chain.as_ref()?.hash_at(position)
    }

    fn entries(&self, log: &[u8], after: u64) -> Vec<Bytes> {
        self.lock().entries(log, after)
    }

    fn apply(&self, log: &[u8], entries: Vec<Bytes>, head: Head) -> Result<()> {
        self.take_entries(log, entries, head)
    }

    fn items(&self, group: &[u8], from: u64) -> Vec<(u64, [u8; 32])> {
        self.lock().carried(group, from).unwrap_or_default()
    }

    fn message(&self, group: &[u8], epoch: u64, id: &[u8; 32]) -> Option<Vec<u8>> {
        self.lock().ciphertext(group, epoch, id).ok()?
    }

    fn receive(&self, group: &[u8], ciphertext: &[u8]) {
        let mut st = self.lock();
        if let Err(error) = self.take(&mut st, group, ciphertext) {
            self.warn(Some(group), format!("{error:#}"));
        }
    }

    fn state(&self, group: &[u8], peer: EndpointId, link: Option<String>) {
        match link {
            Some(link) => self.work.send(Work::State { group: group.to_vec(), link, by: peer }).ok(),
            None => self.work.send(Work::StateWanted { group: group.to_vec(), by: peer }).ok(),
        };
    }

    fn files(&self, group: &[u8]) -> Vec<FileLink> {
        let st = self.lock();
        let Some(g) = st.groups.get(group) else {
            return Vec::new();
        };
        g.rec.held(g.mls.settings().carry)
    }

    fn certificates(&self, groups: &[Vec<u8>]) -> Vec<Envelope> {
        let st = self.lock();
        let mut certificates: Vec<Envelope> = Vec::new();
        for member in groups.iter().filter_map(|gid| st.groups.get(gid)).flat_map(|g| g.mls.members()) {
            let Some(credential) = &member.credential else { continue };
            let Some(identity) = &credential.identity else { continue };
            if let Some(certificate) = st.certificate(credential, &identity.id.0)
                && !certificates.contains(certificate)
            {
                certificates.push(certificate.clone());
            }
        }
        certificates
    }

    /// A certificate may be of a member other than the peer that showed it, and make this session serve that one.
    fn certificate(&self, certificate: Envelope) {
        let peers = self.net().connected();
        let mut st = self.lock();
        let before = st.served(&peers);
        take_certificate(&mut st, certificate);
        for (group, peer) in st.served(&peers).into_iter().filter(|served| !before.contains(served)) {
            st.out.push(Out::Served { peer, group });
        }
    }
}

/// Holds a certificate a peer showed, even of a session not yet a member here, as one whose Add is still on its way.
/// A valid certificate beats one that is not, and else the later one wins.
pub(crate) fn take_certificate<P: Provider>(st: &mut State<P>, certificate: Envelope) {
    let Some(certified) = certified(&certificate) else { return };
    let members = st.groups.values().flat_map(|g| g.mls.members());
    let credential = members.filter_map(|m| m.credential).find(|c| c.key == certified.key && c.identity.as_ref().is_some_and(|i| i.id == certified.identity));
    let log = st.keys.get(&certified.identity.0);
    let valid = |c: &Envelope| matches!((&credential, log), (Some(credential), Some(log)) if check(Some(c), credential, log, now()).is_ok());
    let key = (certified.key.0.clone(), certified.identity.0.clone());
    let fresh = valid(&certificate);
    let newer = st.certificates.get(&key).is_none_or(|held| match (fresh, valid(held)) {
        (true, false) => true,
        (false, true) => false,
        _ => certified.expires > lmk_core::identity::certified(held).map_or(0, |held| held.expires),
    });
    if newer {
        st.certificates.insert(key, certificate);
        if let Err(error) = st.save_certificates() {
            tracing::warn!("saving certificates: {error:#}");
        }
    } else if credential.is_some() && !fresh {
        st.ahead.insert(key, certificate);
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

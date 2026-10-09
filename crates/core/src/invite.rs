//! The inviter's side of an invite: its secret, and checking whoever presents it.

use anyhow::{Context, Result, ensure};
use lmk_proto::group::Credential;
use lmk_proto::identity::Envelope;

use crate::group::key_package_credential;
use crate::identity::{KeyLog, check};
use crate::provider::Provider;

/// How long an invite is valid, in milliseconds.
pub const VALID_FOR: u64 = 10 * 60 * 1000;

#[derive(Clone, Debug)]
pub struct Invite {
    pub secret: [u8; 16],
    pub group: Vec<u8>,
    /// Milliseconds since the Unix epoch.
    pub made: u64,
    /// `--for`: whom it is meant for; the joiner becomes this contact, verified.
    pub label: Option<String>,
    /// `--to`: the only identity that may redeem it.
    pub to: Option<Vec<u8>>,
}

/// An inviter's open invites. They live in memory: an invite needs its inviter online anyway.
#[derive(Default)]
pub struct Invites(Vec<Invite>);

/// A redeemed invite: commit the Add of the joiner's KeyPackage, and once the log has taken it, answer with the
/// Welcome.
pub struct Redeemed {
    pub group: Vec<u8>,
    /// The joiner, as its KeyPackage names it.
    pub joiner: Credential,
    pub label: Option<String>,
}

impl Invites {
    pub fn make(&mut self, group: Vec<u8>, label: Option<String>, to: Option<Vec<u8>>, now: u64) -> &Invite {
        self.0.push(Invite { secret: crate::random(), group, made: now, label, to });
        self.0.last().unwrap()
    }

    /// The identity an invite's secret is bound to, if it is valid and bound: fetch its key log for `redeem`.
    pub fn bound(&self, secret: &[u8], now: u64) -> Option<&[u8]> {
        let invite = self.0.iter().find(|invite| invite.secret == secret && now < invite.made + VALID_FOR)?;
        invite.to.as_deref()
    }

    /// A joiner presents a secret with its KeyPackage and, if it speaks as an identity, its certificate. `log` is the
    /// key log of the identity its credential names, needed only for an invite made `--to` an identity. Only a
    /// successful redemption uses the invite up.
    pub fn redeem<P: Provider>(
        &mut self,
        provider: &P,
        secret: &[u8],
        key_package: &[u8],
        certificate: Option<&Envelope>,
        log: Option<&KeyLog>,
        now: u64,
    ) -> Result<Redeemed> {
        let joiner = key_package_credential(provider, key_package)?;
        self.0.retain(|invite| now < invite.made + VALID_FOR);
        let at = self.0.iter().position(|invite| invite.secret == secret).context("unknown, used or expired invite")?;
        if let Some(to) = &self.0[at].to {
            let certified = log.filter(|log| log.id[..] == to[..]).is_some_and(|log| check(certificate, &joiner, log, now).is_ok());
            ensure!(certified, "this link is for another identity");
        }
        let invite = self.0.remove(at);
        Ok(Redeemed { group: invite.group, joiner, label: invite.label })
    }
}

#[cfg(test)]
mod tests {
    use lmk_proto::Bytes;
    use lmk_proto::group::{Control, How, IdentityRef, Service};
    use lmk_proto::identity::Certified;
    use lmk_proto::links;
    use lmk_proto::peer::{Admitted, InviteRequest};

    use super::*;
    use crate::group::tests::{Member, settings};
    use crate::group::{Change, Group, Window};
    use crate::identity::{DAY, certify, create};
    use crate::provider::MemoryProvider;

    fn member(name: &str) -> Member {
        Member::new(MemoryProvider::default(), name)
    }

    #[test]
    fn group_invite_end_to_end() {
        let mut alice = member("Alice");
        let mut bob = member("Bob");
        let mut log: Vec<Vec<u8>> = Vec::new();
        alice.group =
            Some(Group::create(&alice.provider, &alice.session, &settings("Plan"), Window::default()).unwrap());
        let mut invites = Invites::default();
        let id = alice.g().id().to_vec();
        let invite = invites.make(id, Some("Bob (Acme)".into()), None, 1_000);
        let link = links::Invite { device: false, key: [7; 32], secret: invite.secret, relay: None }.link();

        // Bob, holding the link, sends his KeyPackage with the secret.
        let parsed = links::Invite::parse(&link).unwrap();
        let request = InviteRequest {
            secret: parsed.secret.into(),
            key_package: Bytes(bob.session.key_package(&bob.provider).unwrap()),
            certificate: None,
        };
        let request: InviteRequest = serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        let key_package = &request.key_package;

        assert!(invites.redeem(&alice.provider, &[0; 16], &key_package.0, None, None, 2_000).is_err());
        let redeemed = invites.redeem(&alice.provider, &request.secret.0, &key_package.0, None, None, 2_000).unwrap();
        assert_eq!((redeemed.joiner.name.as_str(), redeemed.label.as_deref()), ("Bob", Some("Bob (Acme)")));
        let commit = alice.commit(Change { add: vec![key_package.0.clone()], how: Some(How::Invite), ..Change::default() });
        log.push(commit.commit);
        let applied = alice.read(&log, 2_000);
        let crate::group::Applied::Commit { own: true, how, added, .. } = &applied[0] else { panic!() };
        assert_eq!((*how, added[0].index), (Some(How::Invite), 1));
        let admitted = Admitted { welcome: Bytes(commit.welcome.unwrap()), position: log.len() as u64, doc: None, before: Vec::new() };

        // A used secret is refused.
        assert!(invites.redeem(&alice.provider, &request.secret.0, &key_package.0, None, None, 2_000).is_err());

        let admitted: Admitted = serde_json::from_str(&serde_json::to_string(&admitted).unwrap()).unwrap();
        bob.join(&admitted.welcome.0, admitted.position as usize);
        assert_eq!(bob.g().settings().name, "Plan");
        let hi = bob.send("hello");
        assert_eq!(alice.open(&hi, 3_000).unwrap().sender.name, "Bob");
        let reply = alice.send("welcome");
        assert_eq!(bob.open(&reply, 3_000).unwrap().payload["type"], "message");
        assert_eq!(alice.g().added()[0].member.name, "Bob");

        // Alice tells the group who Bob is to her.
        let carol = IdentityRef { id: Bytes(vec![3; 32]), membership: Service::Folder("/tmp/lmk".into()) };
        let introduce = Control::Introduce { identity: carol, name: "Carol".into(), how: How::Invite, to: Vec::new() };
        let introduce = serde_json::to_value(introduce).unwrap();
        let (_, sealed) = alice.group.as_mut().unwrap().seal(&alice.provider, &alice.session, &introduce, false).unwrap();
        let opened = bob.open(&sealed, 4_000).unwrap();
        assert_eq!((opened.payload, opened.held), (introduce, false));
    }

    #[test]
    fn invites_expire_and_bind_to_an_identity() {
        let mut alice = member("Alice");
        let carol = member("Carol");
        alice.group =
            Some(Group::create(&alice.provider, &alice.session, &settings("Plan"), Window::default()).unwrap());
        let id = alice.g().id().to_vec();
        let mut invites = Invites::default();
        let kp = carol.session.key_package(&carol.provider).unwrap();

        let secret = invites.make(id.clone(), None, None, 0).secret;
        assert!(invites.redeem(&alice.provider, &secret, &kp, None, None, VALID_FOR).is_err());

        // `--to Bob`: Carol cannot redeem it, and her try does not use it up; nor can Bob without a certificate.
        let seed = crate::random();
        let (bob_id, first) = create(&seed, "Bob", Service::Folder("/tmp/lmk".into()));
        let bob_log = KeyLog::replay(&bob_id, [first.as_slice()]).unwrap();
        let secret = invites.make(id, None, Some(bob_id.to_vec()), 0).secret;
        assert_eq!(invites.bound(&secret, 1), Some(bob_id.as_slice()));
        assert!(invites.redeem(&alice.provider, &secret, &kp, None, Some(&bob_log), 1).is_err());
        let mut bob = member("Bob");
        bob.session.credential.identity = Some(IdentityRef { id: bob_id.into(), membership: Service::Folder("/tmp/lmk".into()) });
        let kp = bob.session.key_package(&bob.provider).unwrap();
        assert!(invites.redeem(&alice.provider, &secret, &kp, None, Some(&bob_log), 2).is_err());
        let me = &bob.session.credential;
        let certified = Certified { identity: bob_id.into(), key: me.key.clone(), name: me.name.clone(), device: "laptop".into(), added_by: None, expires: DAY };
        let certificate = certify(&seed, &certified);
        assert!(invites.redeem(&alice.provider, &secret, &kp, Some(&certificate), Some(&bob_log), 2).is_ok());
    }
}

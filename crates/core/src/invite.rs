//! The inviter's side of an invite: its secret, and checking whoever presents it.

use anyhow::{Context, Result, ensure};
use lmk_proto::group::Credential;

use crate::device::signed_by_device;
use crate::group::key_package_credential;
use crate::identity::{DeviceList, Verdict, check};
use crate::provider::Provider;

/// How long an invite is valid, in milliseconds.
pub const VALID_FOR: u64 = 10 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A group, by id.
    Group(Vec<u8>),
    /// A device link to one of this device's identities, by id.
    Device(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct Invite {
    pub secret: [u8; 16],
    pub target: Target,
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

/// A redeemed invite: commit the Add of `key_package` (for a device link, after appending the device to the list),
/// and once the log has taken it, answer with the Welcome.
pub struct Redeemed {
    pub target: Target,
    /// The joiner, as its KeyPackage names it.
    pub joiner: Credential,
    pub label: Option<String>,
}

impl Invites {
    pub fn make(&mut self, target: Target, label: Option<String>, to: Option<Vec<u8>>, now: u64) -> &Invite {
        self.0.push(Invite { secret: crate::random(), target, made: now, label, to });
        self.0.last().unwrap()
    }

    /// The identity an invite's secret is bound to, if it is valid and bound: fetch its device list for `redeem`.
    pub fn bound(&self, secret: &[u8], now: u64) -> Option<&[u8]> {
        let invite = self.0.iter().find(|invite| invite.secret == secret && now < invite.made + VALID_FOR)?;
        invite.to.as_deref()
    }

    /// A joiner presents a secret with its KeyPackage. `list` is the device list of the identity its credential names,
    /// needed only for an invite made `--to` an identity. For a device link, the KeyPackage's credential names the
    /// device and must be its own. Only a successful redemption uses the invite up.
    pub fn redeem<P: Provider>(
        &mut self,
        provider: &P,
        secret: &[u8],
        key_package: &[u8],
        list: Option<&DeviceList>,
        now: u64,
    ) -> Result<Redeemed> {
        let (joiner, key) = key_package_credential(provider, key_package)?;
        self.0.retain(|invite| now < invite.made + VALID_FOR);
        let at = self.0.iter().position(|invite| invite.secret == secret).context("unknown, used or expired invite")?;
        let invite = &self.0[at];
        match &invite.target {
            Target::Group(_) => {
                if let Some(to) = &invite.to {
                    let named = joiner.identity.as_ref().is_some_and(|identity| identity.id.0 == *to);
                    ensure!(named && check(&joiner, &key, list) == Verdict::Verified, "this link is for another identity");
                }
            }
            Target::Device(_) => ensure!(signed_by_device(&joiner, &key), "the KeyPackage is not the device's"),
        }
        let invite = self.0.remove(at);
        Ok(Redeemed { target: invite.target, joiner, label: invite.label })
    }
}

#[cfg(test)]
mod tests {
    use lmk_proto::Bytes;
    use lmk_proto::group::{How, IdentityRef, Kind, Opening, Payload, Service};
    use lmk_proto::links;
    use lmk_proto::peer::{Admitted, InviteRequest};

    use super::*;
    use crate::contacts::{self, Contact, Contacts};
    use crate::device::Device;
    use crate::group::tests::{Member, leaf, settings};
    use crate::group::{Change, Group, Session, Window, with_opening};
    use crate::identity::create;
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
        let invite = invites.make(Target::Group(id), Some("Bob (Acme)".into()), None, 1_000);
        let link = links::Invite { device: false, key: [7; 32], secret: invite.secret, relay: None }.link();

        // Bob, holding the link, sends his KeyPackage with the secret.
        let parsed = links::Invite::parse(&link).unwrap();
        let request = InviteRequest {
            secret: parsed.secret.into(),
            key_package: Bytes(bob.session.key_package(&bob.provider).unwrap()),
        };
        let request: InviteRequest = serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        let key_package = &request.key_package;

        assert!(invites.redeem(&alice.provider, &[0; 16], &key_package.0, None, 2_000).is_err());
        let redeemed = invites.redeem(&alice.provider, &request.secret.0, &key_package.0, None, 2_000).unwrap();
        assert_eq!((redeemed.joiner.name.as_str(), redeemed.label.as_deref()), ("Bob", Some("Bob (Acme)")));
        let commit = alice.commit(Change { add: vec![key_package.0.clone()], how: Some(How::Invite), ..Change::default() });
        log.push(commit.commit);
        let applied = alice.read(&log, 2_000);
        let crate::group::Applied::Commit { own: true, how, added, .. } = &applied[0] else { panic!() };
        assert_eq!((*how, added[0].index), (Some(How::Invite), 1));
        let admitted = Admitted { welcome: Bytes(commit.welcome.unwrap()), position: log.len() as u64, doc: None, before: Vec::new() };

        // A used secret is refused.
        assert!(invites.redeem(&alice.provider, &request.secret.0, &key_package.0, None, 2_000).is_err());

        let admitted: Admitted = serde_json::from_str(&serde_json::to_string(&admitted).unwrap()).unwrap();
        bob.join(&admitted.welcome.0, admitted.position as usize);
        assert_eq!(bob.g().settings().name, "Plan");
        let hi = bob.send("hello");
        assert_eq!(alice.open(&hi, 3_000).unwrap().sender.name, "Bob");
        let reply = alice.send("welcome");
        assert!(matches!(bob.open(&reply, 3_000).unwrap().payload, Payload::Message { .. }));
        assert_eq!(alice.g().added()[0].member.name, "Bob");

        // Alice tells the group who Bob is to her.
        let carol = IdentityRef { id: Bytes(vec![3; 32]), membership: Service::Folder("/tmp/lmk".into()) };
        let introduce = Payload::Introduce { identity: carol, name: "Carol".into(), how: How::Invite, to: Vec::new() };
        let (_, sealed) = alice.group.as_mut().unwrap().seal(&alice.provider, &alice.session, &introduce).unwrap();
        assert_eq!(bob.open(&sealed, 4_000).unwrap().payload, introduce);
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

        let secret = invites.make(Target::Group(id.clone()), None, None, 0).secret;
        assert!(invites.redeem(&alice.provider, &secret, &kp, None, VALID_FOR).is_err());

        // `--to Bob`: Carol cannot redeem it, and her try does not use it up.
        let bob_device = Device::new("bob's laptop");
        let (bob_id, first) = create(&bob_device, "Bob", Service::Folder("/tmp/lmk".into()));
        let bob_list = DeviceList::replay(&bob_id, [first.as_slice()]).unwrap();
        let secret = invites.make(Target::Group(id), None, Some(bob_id.to_vec()), 0).secret;
        assert_eq!(invites.bound(&secret, 1), Some(bob_id.as_slice()));
        assert!(invites.redeem(&alice.provider, &secret, &kp, Some(&bob_list), 1).is_err());
        let bob_provider = MemoryProvider::default();
        let identity = IdentityRef { id: bob_id.into(), membership: Service::Folder("/tmp/lmk".into()) };
        let bob = Session::create(&bob_provider, &bob_device, "Bob", Some(identity), leaf("Bob")).unwrap();
        let kp = bob.key_package(&bob_provider).unwrap();
        assert!(invites.redeem(&alice.provider, &secret, &kp, Some(&bob_list), 2).is_ok());
    }

    #[test]
    fn device_link_end_to_end() {
        let membership = Service::Folder("/tmp/lmk".into());
        let mut laptop = member("laptop");
        let (id, first) = create(&laptop.device, "Matthew", membership.clone());
        let mut list_log = vec![first];
        let list = DeviceList::replay(&id, list_log.iter().map(Vec::as_slice)).unwrap();
        let settings = crate::group::devices_settings(&id, "Matthew", membership.clone());
        laptop.group = Some(Group::create(&laptop.provider, &laptop.session, &settings, Window::default()).unwrap());
        let mut log: Vec<Vec<u8>> = Vec::new();
        let contacts = Contacts::default();
        contacts.set(&[9; 32], &Contact { name: "Bob (Acme)".into(), how: contacts::How::Verified, by: None, at: 1 });

        let mut invites = Invites::default();
        let secret = invites.make(Target::Device(id.to_vec()), None, None, 0).secret;

        // The new device, which does not know the identity yet: its credential names only the device.
        let phone_provider = MemoryProvider::default();
        let phone_device = Device::new("phone");
        let phone_session = Session::create(&phone_provider, &phone_device, "phone", None, leaf("phone")).unwrap();
        let request = InviteRequest {
            secret: secret.into(),
            key_package: Bytes(phone_session.key_package(&phone_provider).unwrap()),
        };

        let redeemed =
            invites.redeem(&laptop.provider, &request.secret.0, &request.key_package.0, None, 5).unwrap();
        assert_eq!(redeemed.target, Target::Device(id.to_vec()));
        list_log.push(list.add(&laptop.device, &redeemed.joiner.device.0, &redeemed.joiner.device_name));
        let commit = laptop.commit(Change { add: vec![request.key_package.0.clone()], ..Change::default() });
        log.push(commit.commit);
        laptop.read(&log, 5);
        let admitted = Admitted { welcome: Bytes(commit.welcome.unwrap()), position: log.len() as u64, doc: None, before: Vec::new() };

        let list = DeviceList::replay(&id, list_log.iter().map(Vec::as_slice)).unwrap();
        assert!(list.has(&phone_device.public()));
        let mut phone =
            Member { provider: phone_provider, device: phone_device, session: phone_session, group: None, pos: 0 };
        phone.join(&admitted.welcome.0, admitted.position as usize);
        assert_eq!(phone.g().settings().devices_of, Some(id.into()));
        let members = phone.g().members();
        assert!(
            members.iter().all(|m| check(m.credential.as_ref().unwrap(), &m.key, Some(&list)) != Verdict::BadSignature)
        );

        // The contacts reach the phone: their state, then a live edit.
        let phone_contacts = Contacts::load(&contacts.state()).unwrap();
        let edit = contacts.set(
            &[8; 32],
            &Contact { name: "Carol".into(), how: contacts::How::Introduced, by: Some(Bytes(vec![9; 32])), at: 2 },
        );
        let group = laptop.group.as_mut().unwrap();
        let (_, sealed) =
            group.seal(&laptop.provider, &laptop.session, &Payload::Edit { update: Bytes(edit) }).unwrap();
        let Payload::Edit { update } = phone.open(&sealed, 6).unwrap().payload else { panic!() };
        phone_contacts.apply(&update.0).unwrap();
        assert_eq!(phone_contacts.get(&[9; 32]).unwrap().name, "Bob (Acme)");
        assert_eq!(phone_contacts.get(&[8; 32]).unwrap().how, contacts::How::Introduced);
        let hi = phone.send("from the phone");
        assert_eq!(laptop.open(&hi, 7).unwrap().sender.device_name, "phone");

        // An opening, kept in the devices group's context, reaches every device.
        let opening = Opening {
            group: Bytes(vec![1; 16]),
            kind: Kind::Doc,
            name: "Spec".into(),
            membership: Service::Folder("/tmp/lmk".into()),
            members: vec![Bytes(b"someone".to_vec())],
        };
        let settings = with_opening(laptop.g().settings(), opening.clone());
        let commit = laptop.commit(Change { settings: Some(settings), ..Change::default() });
        log.push(commit.commit);
        laptop.read(&log, 8);
        phone.read(&log, 8);
        assert_eq!(phone.g().settings().openings, [opening]);
    }
}

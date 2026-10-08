//! The inviter's side of an invite: its secret, and admitting whoever presents it.

use anyhow::{Context, Result, bail, ensure};
use lmk_proto::Bytes;
use lmk_proto::group::Credential;
use lmk_proto::peer::Admitted;

use crate::device::{Device, signed_by_device};
use crate::group::{Change, Group, Session, key_package_credential};
use crate::identity::{DeviceList, Verdict, check};
use crate::provider::Provider;

/// How long an invite is valid, in milliseconds.
pub const VALID_FOR: u64 = 10 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A group, by id.
    Group(Vec<u8>),
    /// A device link to this device's identity.
    Device,
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

/// An admission under way: append `entry` (a device link's) to the device list, post `commit`, and once the log has
/// taken the commit, answer with `admitted`.
pub struct Admitting {
    pub entry: Option<Vec<u8>>,
    pub commit: Vec<u8>,
    welcome: Vec<u8>,
    /// The joiner, as its KeyPackage names it.
    pub joiner: Credential,
    pub label: Option<String>,
}

impl Admitting {
    /// `position`: where the joiner starts reading the log; `doc`: for a doc, a file link to its state.
    pub fn admitted(self, position: u64, doc: Option<String>) -> Admitted {
        Admitted { welcome: Bytes(self.welcome), position, doc }
    }
}

impl Invites {
    pub fn make(&mut self, target: Target, label: Option<String>, to: Option<Vec<u8>>, now: u64) -> &Invite {
        self.0.push(Invite { secret: crate::random(), target, made: now, label, to });
        self.0.last().unwrap()
    }

    /// The invite a secret opens, if it is valid; `accept` decides whether this joiner may use it. Only a
    /// successful redemption uses the invite up.
    fn redeem(&mut self, secret: &[u8], now: u64, accept: impl Fn(&Invite) -> Result<()>) -> Result<Invite> {
        self.0.retain(|invite| now < invite.made + VALID_FOR);
        let at = self.0.iter().position(|invite| invite.secret == secret).context("no such invite")?;
        accept(&self.0[at])?;
        Ok(self.0.remove(at))
    }

    #[allow(clippy::too_many_arguments)]
    /// A joiner presents the secret of a group invite with its KeyPackage. `list` is the device list of the identity
    /// its credential names, needed only for an invite made `--to` an identity.
    pub fn admit_member<P: Provider>(
        &mut self,
        provider: &P,
        session: &Session,
        group: &mut Group,
        secret: &[u8],
        key_package: &[u8],
        list: Option<&DeviceList>,
        now: u64,
    ) -> Result<Admitting> {
        let (joiner, key) = key_package_credential(provider, key_package)?;
        let invite = self.redeem(secret, now, |invite| {
            ensure!(invite.target == Target::Group(group.id().to_vec()), "an invite to another group");
            if let Some(to) = &invite.to {
                let named = joiner.identity.as_ref().is_some_and(|identity| identity.id.0 == *to);
                ensure!(named && check(&joiner, &key, list) == Verdict::Verified, "an invite for another identity");
            }
            Ok(())
        })?;
        let commit =
            group.commit(provider, session, Change { add: vec![key_package.to_vec()], ..Change::default() })?;
        Ok(Admitting {
            entry: None,
            commit: commit.commit,
            welcome: commit.welcome.unwrap(),
            joiner,
            label: invite.label,
        })
    }

    /// A new device presents the secret of a device link with its device key and its KeyPackage for the devices
    /// group: it goes on `list` (by this device, `by`) and into `devices`.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_device<P: Provider>(
        &mut self,
        provider: &P,
        session: &Session,
        by: &Device,
        list: &DeviceList,
        devices: &mut Group,
        secret: &[u8],
        device: &[u8],
        device_name: &str,
        key_package: &[u8],
        now: u64,
    ) -> Result<Admitting> {
        let (joiner, key) = key_package_credential(provider, key_package)?;
        if joiner.device.0 != device || !signed_by_device(&joiner, &key) {
            bail!("the KeyPackage is not the device's");
        }
        self.redeem(secret, now, |invite| {
            ensure!(invite.target == Target::Device, "not a device link");
            Ok(())
        })?;
        let entry = list.add(by, device, device_name);
        let commit =
            devices.commit(provider, session, Change { add: vec![key_package.to_vec()], ..Change::default() })?;
        Ok(Admitting {
            entry: Some(entry),
            commit: commit.commit,
            welcome: commit.welcome.unwrap(),
            joiner,
            label: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use lmk_proto::group::{IdentityRef, Kind, Opening, Payload, Service};
    use lmk_proto::links;
    use lmk_proto::peer::{InviteRequest, Joiner};

    use super::*;
    use crate::contacts::{Contact, Contacts, How};
    use crate::group::tests::{Member, leaf, settings};
    use crate::group::{Window, introduction, with_opening};
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
            joiner: Joiner::Member { key_package: Bytes(bob.session.key_package(&bob.provider).unwrap()) },
        };
        let request: InviteRequest = serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        let Joiner::Member { key_package } = &request.joiner else { panic!() };

        let group = alice.group.as_mut().unwrap();
        assert!(
            invites
                .admit_member(&alice.provider, &alice.session, group, &[0; 16], &key_package.0, None, 2_000)
                .is_err()
        );
        let admitting = invites
            .admit_member(&alice.provider, &alice.session, group, &request.secret.0, &key_package.0, None, 2_000)
            .unwrap();
        assert_eq!((admitting.joiner.name.as_str(), admitting.label.as_deref()), ("Bob", Some("Bob (Acme)")));
        log.push(admitting.commit.clone());
        assert!(matches!(alice.read(&log, 2_000)[0], crate::group::Applied::Commit { own: true, .. }));
        let admitted = admitting.admitted(log.len() as u64, None);

        // A used secret is refused.
        let group = alice.group.as_mut().unwrap();
        let again = invites.admit_member(
            &alice.provider,
            &alice.session,
            group,
            &request.secret.0,
            &key_package.0,
            None,
            2_000,
        );
        assert!(again.is_err());

        let admitted: Admitted = serde_json::from_str(&serde_json::to_string(&admitted).unwrap()).unwrap();
        bob.join(&admitted.welcome.0, admitted.position as usize);
        assert_eq!(bob.g().settings().name, "Plan");
        let hi = bob.send("hello");
        assert_eq!(alice.open(&hi, 3_000).unwrap().sender.name, "Bob");
        let reply = alice.send("welcome");
        assert!(matches!(bob.open(&reply, 3_000).unwrap().payload, Payload::Message { .. }));
        assert_eq!(alice.g().added()[0].member.name, "Bob");

        // Alice tells the group who Bob is to her; Bob records who first introduced each identity.
        let carol = IdentityRef { id: Bytes(vec![3; 32]), membership: Service::Folder("/tmp/lmk".into()) };
        for (name, now) in [("Carol", 4_000), ("Not Carol", 5_000)] {
            let introduce =
                Payload::Introduce { identity: carol.clone(), name: name.into(), how: lmk_proto::group::How::Invite };
            let group = alice.group.as_mut().unwrap();
            let (_, sealed) = group.seal(&alice.provider, &alice.session, &introduce).unwrap();
            bob.open(&sealed, now).unwrap();
        }
        let introduction = introduction(&bob.provider, &[3; 32]).unwrap().unwrap();
        assert_eq!((introduction.name.as_str(), introduction.by.name.as_str()), ("Carol", "Alice"));
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
        let group = alice.group.as_mut().unwrap();
        assert!(invites.admit_member(&alice.provider, &alice.session, group, &secret, &kp, None, VALID_FOR).is_err());

        // `--to Bob`: Carol cannot redeem it, and her try does not use it up.
        let bob_device = Device::new("bob's laptop");
        let (bob_id, first) = create(&bob_device, "Bob", Service::Folder("/tmp/lmk".into()));
        let bob_list = DeviceList::replay(&bob_id, [first.as_slice()]).unwrap();
        let secret = invites.make(Target::Group(id), None, Some(bob_id.to_vec()), 0).secret;
        assert!(
            invites.admit_member(&alice.provider, &alice.session, group, &secret, &kp, Some(&bob_list), 1).is_err()
        );
        let bob_provider = MemoryProvider::default();
        let identity = IdentityRef { id: bob_id.into(), membership: Service::Folder("/tmp/lmk".into()) };
        let bob = Session::create(&bob_provider, &bob_device, "Bob", Some(identity), leaf("Bob")).unwrap();
        let kp = bob.key_package(&bob_provider).unwrap();
        assert!(invites.admit_member(&alice.provider, &alice.session, group, &secret, &kp, Some(&bob_list), 2).is_ok());
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
        contacts.set(&[9; 32], &Contact { name: "Bob (Acme)".into(), how: How::Verified, by: None, at: 1 });

        let mut invites = Invites::default();
        let secret = invites.make(Target::Device, None, None, 0).secret;

        // The new device: its device key, and a member of the devices group speaking as the identity.
        let phone_provider = MemoryProvider::default();
        let phone_device = Device::new("phone");
        let identity = IdentityRef { id: id.into(), membership };
        let phone_session =
            Session::create(&phone_provider, &phone_device, "phone", Some(identity), leaf("phone")).unwrap();
        let request = InviteRequest {
            secret: secret.into(),
            joiner: Joiner::Device { device: phone_device.public().into(), device_name: "phone".into() },
        };
        let Joiner::Device { device, device_name } = &request.joiner else { panic!() };
        let kp = phone_session.key_package(&phone_provider).unwrap();

        let group = laptop.group.as_mut().unwrap();
        let admitting = invites
            .admit_device(
                &laptop.provider,
                &laptop.session,
                &laptop.device,
                &list,
                group,
                &request.secret.0,
                &device.0,
                device_name,
                &kp,
                5,
            )
            .unwrap();
        list_log.push(admitting.entry.clone().unwrap());
        log.push(admitting.commit.clone());
        laptop.read(&log, 5);
        let admitted = admitting.admitted(log.len() as u64, None);

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
            &Contact { name: "Carol".into(), how: How::Introduced, by: Some(Bytes(vec![9; 32])), at: 2 },
        );
        let group = laptop.group.as_mut().unwrap();
        let (_, sealed) =
            group.seal(&laptop.provider, &laptop.session, &Payload::Edit { update: Bytes(edit) }).unwrap();
        let Payload::Edit { update } = phone.open(&sealed, 6).unwrap().payload else { panic!() };
        phone_contacts.apply(&update.0).unwrap();
        assert_eq!(phone_contacts.get(&[9; 32]).unwrap().name, "Bob (Acme)");
        assert_eq!(phone_contacts.get(&[8; 32]).unwrap().how, How::Introduced);
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

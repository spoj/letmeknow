use super::*;
use openmls_traits::storage::StorageProvider as _;
use tls_codec::Serialize as _;

fn exports<P: Provider>(member: &Member<P>) -> ([u8; 32], [u8; 32], Vec<u8>) {
    let group = member.group.as_ref().unwrap();
    let Service::Serve { key, .. } = group.settings().membership else { panic!() };
    assert_eq!(group.id().len(), 16);
    let context = [group.id(), &group.epoch().to_be_bytes(), key.0.as_slice()].concat();
    let c: [u8; 32] = group.mls.export_secret(member.provider.crypto(), "letmeknow epoch log address v1", &context, 32).unwrap().try_into().unwrap();
    let k: [u8; 32] = group.mls.export_secret(member.provider.crypto(), "letmeknow epoch log sealing v1", &context, 32).unwrap().try_into().unwrap();
    assert_eq!(group.capability(&member.provider).unwrap(), c);
    assert_ne!(c, k);
    (c, k, context)
}

fn aad<P: Provider>(member: &Member<P>, bucket: usize) -> Vec<u8> {
    let (c, _, context) = exports(member);
    let reference = Sha256::digest([b"letmeknow log reference v1\0".as_slice(), &context[24..], &c].concat());
    [b"letmeknow epoch envelope v1\0".as_slice(), &context, reference.as_slice(), &(bucket as u32).to_be_bytes()].concat()
}

fn wire(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let nonce = crate::random::<24>();
    let ciphertext = XChaCha20Poly1305::new(key.into()).encrypt((&nonce).into(), Payload { msg: plaintext, aad }).unwrap();
    [&[1], nonce.as_slice(), &ciphertext].concat()
}

fn decrypt(key: &[u8; 32], aad: &[u8], wire: &[u8]) -> Result<Vec<u8>> {
    let nonce: &[u8; 24] = wire[1..25].try_into().unwrap();
    Ok(XChaCha20Poly1305::new(key.into()).decrypt(nonce.into(), Payload { msg: &wire[25..], aad })?)
}

/// An inner entry for an envelope that no test judges.
fn filler() -> Vec<u8> {
    Entry { commit: vec![1; 32], sig: vec![2; 64] }.encode()
}

#[test]
fn epoch_zero_and_every_accepted_commit_rotate_once() {
    let mut w = World::new(&["A", "B", "C"]);
    let a = &mut w.m[0];
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan")).unwrap());
    let zero = exports(a);
    assert_eq!(a.g().epoch(), 0);
    for (i, label) in [(1, "Add-first"), (2, "Add-observed")] {
        let package = w.key_package(i);
        let reference = key_package_reference(&w.m[i].provider, &package).unwrap();
        let before = exports(&w.m[0]);
        let epoch = w.m[0].g().epoch();
        let cut = w.m[0].cut();
        let commit = w.m[0].commit(Change { cut, add: vec![package.clone()], how: Some(How::Invite), ..Change::default() });
        assert_eq!(exports(&w.m[0]), before, "staging must not select successor exporters");
        let inner = w.m[0].open_inner(&commit.entry);
        let admission = commit.admission.clone().unwrap();
        println!("entry sizes: {label} inner={} bucket={}", inner.len(), commit.entry.len());
        let position = w.post(commit.entry.clone());
        w.read(&(0..i).collect::<Vec<_>>());
        w.m[i].join(&inner, &admission, position, &package);
        let after = exports(&w.m[0]);
        assert_ne!(before.0, after.0);
        assert_ne!(before.1, after.1);
        let wire = w.m[0].seal_inner(&inner);
        for m in &mut w.m[..=i] {
            assert_eq!(m.open_inner(&wire), inner);
            assert_eq!(exports(m), after);
            assert_eq!(m.g().epoch(), epoch + 1);
            assert!(matches!(m.group.as_mut().unwrap().judge(&m.provider, &commit.entry).unwrap(), Verdict::Skipped { .. }));
            assert_eq!(m.g().epoch(), epoch + 1);
        }
        for m in &mut w.m[..i] {
            assert_eq!(m.g().added().last().unwrap().key_package_ref, reference);
        }
    }
    assert_ne!(exports(&w.m[0]).0, zero.0);
    let changed = Settings { name: "Plan renamed".into(), ..w.m[0].g().settings() };
    let changes = [
        ("update", Change::default()),
        ("name", Change { name: Some("A renamed".into()), ..Change::default() }),
        ("settings", Change { settings: Some(changed), ..Change::default() }),
        ("leaf", Change { leaf: Some(leaf("new route")), ..Change::default() }),
    ];
    for (label, change) in changes {
        let before = exports(&w.m[0]);
        let epoch = w.m[0].g().epoch();
        let cut = w.m[0].cut();
        let commit = w.m[0].commit(Change { cut, ..change });
        assert_eq!(exports(&w.m[0]), before);
        let a = &w.m[0];
        println!("entry sizes: {label} inner={} bucket={}", a.group.as_ref().unwrap().open_entry(&a.provider, &commit.entry).unwrap().len(), commit.entry.len());
        w.post(commit.entry.clone());
        w.read(&[0, 1, 2]);
        let after = exports(&w.m[0]);
        assert_ne!(before.0, after.0);
        assert_ne!(before.1, after.1);
        for m in &mut w.m {
            assert_eq!(exports(m), after);
            assert_eq!(m.g().epoch(), epoch + 1);
            assert!(m.group.as_ref().unwrap().open_entry(&m.provider, &commit.entry).is_err());
        }
    }
    let before = exports(&w.m[2]);
    let mut retained = w.m[2].copy();
    let removed = w.m[0].index_of("C");
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, remove: vec![removed], ..Change::default() });
    let a = &w.m[0];
    println!("entry sizes: Remove inner={} bucket={}", a.group.as_ref().unwrap().open_entry(&a.provider, &commit.entry).unwrap().len(), commit.entry.len());
    w.post(commit.entry.clone());
    w.read(&[0, 1, 2]);
    let after = exports(&w.m[0]);
    assert_eq!(after, exports(&w.m[1]));
    assert_ne!(before.0, after.0);
    assert_ne!(before.1, after.1);
    let successor = w.m[0].seal_inner(&filler());
    let aad = aad(&w.m[0], successor.len());
    assert!(decrypt(&after.1, &aad, &successor).is_ok());
    assert!(decrypt(&before.1, &aad, &successor).is_err(), "retained old key with the correct successor AAD cannot open it");
    assert!(decrypt(&after.0, &aad, &successor).is_err(), "the current capability is not the sealing key");
    assert_eq!(exports(&retained), before, "the stolen pre-removal provider still has its secrets");
    assert!(retained.group.as_ref().unwrap().open_entry(&retained.provider, &successor).is_err());
    retained.read(&w.log);
    assert!(!retained.g().active());
    assert!(retained.group.as_ref().unwrap().capability(&retained.provider).is_err());
}

#[test]
fn envelopes_require_exact_context_framing_and_padding() {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, ..Change::default() });
    let a = &w.m[0];
    let group = a.group.as_ref().unwrap();
    let inner = group.open_entry(&a.provider, &commit.entry).unwrap();
    let first = commit.entry.clone();
    let second = group.seal_entry(&a.provider, &inner).unwrap();
    assert_ne!(first, second);
    assert_ne!(&first[1..25], &second[1..25]);
    assert_eq!(group.open_entry(&a.provider, &second).unwrap(), inner);
    assert_eq!(w.m[1].group.as_ref().unwrap().open_entry(&w.m[1].provider, &first).unwrap(), inner);
    let (c, k, context) = exports(a);
    let bucket = first.len();
    let associated = aad(a, bucket);
    assert!(decrypt(&c, &associated, &first).is_err());
    let plain = decrypt(&k, &associated, &first).unwrap();
    assert_eq!(plain.len(), bucket - 41);
    assert_eq!(&plain[..4], &(inner.len() as u32).to_be_bytes());
    assert_eq!(&plain[4..4 + inner.len()], inner);
    assert!(plain[4 + inner.len()..].iter().all(|b| *b == 0));
    let original = a.provider.records();
    let mut malformed = vec![vec![], inner.clone(), first[..bucket - 1].to_vec(), [first.clone(), vec![0; bucket]].concat()];
    for offset in [0, 1, 24, 25, bucket - 1] {
        let mut changed = first.clone();
        changed[offset] ^= 1;
        malformed.push(changed);
    }
    for offset in [0, ENVELOPE_DOMAIN.len(), ENVELOPE_DOMAIN.len() + 16, ENVELOPE_DOMAIN.len() + 24, ENVELOPE_DOMAIN.len() + 56, associated.len() - 1] {
        let mut wrong_aad = associated.clone();
        wrong_aad[offset] ^= 1;
        malformed.push(wire(&k, &wrong_aad, &plain));
    }
    for offset in [0, 16, 24] {
        let mut wrong_context = context.clone();
        wrong_context[offset] ^= 1;
        let wrong_key: [u8; 32] = group.mls.export_secret(a.provider.crypto(), SEALING_LABEL, &wrong_context, 32).unwrap().try_into().unwrap();
        assert_ne!(wrong_key, k);
        malformed.push(wire(&wrong_key, &associated, &plain));
    }
    let mut nonzero_padding = plain.clone();
    *nonzero_padding.last_mut().unwrap() = 1;
    malformed.push(wire(&k, &associated, &nonzero_padding));
    let mut impossible_length = plain.clone();
    impossible_length[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    malformed.push(wire(&k, &associated, &impossible_length));
    let mut malformed_inner = plain.clone();
    malformed_inner[4] = 3;
    malformed.push(wire(&k, &associated, &malformed_inner));
    let mut trailing = plain.clone();
    trailing[..4].copy_from_slice(&(inner.len() as u32 + 1).to_be_bytes());
    malformed.push(wire(&k, &associated, &trailing));
    let mut noncanonical = plain.clone();
    noncanonical.resize(2 * bucket - 41, 0);
    malformed.push(wire(&k, &aad(a, 2 * bucket), &noncanonical));
    for wire in malformed {
        assert!(group.open_entry(&a.provider, &wire).is_err());
    }
    assert_eq!(a.provider.records(), original);
    let b = &mut w.m[1];
    let cut = b.cut();
    let pending = b.commit(Change { cut, ..Change::default() });
    let original = b.provider.records();
    let wrong = wire(&k, &associated, &nonzero_padding);
    assert!(matches!(b.group.as_mut().unwrap().judge(&b.provider, &wrong).unwrap(), Verdict::Skipped { lost: false, .. }));
    assert!(b.group.as_mut().unwrap().apply(&b.provider, &wrong).is_err());
    assert_eq!(b.group.as_ref().unwrap().posted().unwrap(), pending.entry);
    assert_eq!(b.provider.records(), original);
}

#[test]
fn exact_binary_bucket_boundaries() {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let a = &w.m[0];
    let group = a.group.as_ref().unwrap();
    let before = a.provider.records();
    for (length, bucket) in [(979, 1024), (980, 2048), (1_048_531, 1_048_576)] {
        let inner = Entry { commit: vec![7; length - 69], sig: vec![8; 64] }.encode();
        assert_eq!(inner.len(), length);
        let wire = group.seal_entry(&a.provider, &inner).unwrap();
        assert_eq!(wire.len(), bucket);
        assert_eq!(group.open_entry(&a.provider, &wire).unwrap(), inner);
        assert_eq!(w.m[1].group.as_ref().unwrap().open_entry(&w.m[1].provider, &wire).unwrap(), inner);
    }
    let too_large = Entry { commit: vec![7; 1_048_532 - 69], sig: vec![8; 64] }.encode();
    assert!(group.seal_entry(&a.provider, &too_large).unwrap_err().to_string().contains("1 MiB"));
    assert!(group.seal_entry(&a.provider, b"not an Entry").is_err());
    assert_eq!(a.provider.records(), before);
}

#[test]
fn staged_oversize_and_malformed_builds_restore_everything() {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let a = &mut w.m[0];
    let cut = a.cut();
    let probe = a.commit(Change { cut, name: Some("x".into()), ..Change::default() });
    let minimum = a.group.as_ref().unwrap().open_entry(&a.provider, &probe.entry).unwrap().len();
    a.cancel();
    for (length, bucket) in [(8147, 8192), (8148, 16384)] {
        let cut = a.cut();
        let commit = a.commit(Change { cut, name: Some("x".repeat(1 + length - minimum)), ..Change::default() });
        assert_eq!(a.group.as_ref().unwrap().open_entry(&a.provider, &commit.entry).unwrap().len(), length);
        assert_eq!(commit.entry.len(), bucket);
        a.cancel();
    }
    let cut = a.cut();
    let probe = a.commit(Change { cut, name: Some("x".repeat(1_040_000)), ..Change::default() });
    let group = a.group.as_mut().unwrap();
    let probe_size = group.open_entry(&a.provider, &probe.entry).unwrap().len();
    group.cancel(&a.provider).unwrap();
    let largest_name = 1_040_000 + MAX_INNER - probe_size;
    let cut = a.cut();
    let largest = a.commit(Change { cut, name: Some("x".repeat(largest_name)), ..Change::default() });
    let group = a.group.as_mut().unwrap();
    assert_eq!(group.open_entry(&a.provider, &largest.entry).unwrap().len(), MAX_INNER);
    assert_eq!(largest.entry.len(), 1 << 20);
    group.cancel(&a.provider).unwrap();
    group.mls.set_aad(b"transient AAD before a failed build".to_vec());
    group.state.aad = Aad { how: Some(How::Other("future".into())), invite: Some([3; 32].into()), cut: group.cut().to_vec() };
    group.save(&a.provider).unwrap();
    let before = a.provider.records();
    let before_state = serde_json::to_vec(&group.state).unwrap();
    let before_aad = group.mls.aad().to_vec();
    let before_epoch = (group.epoch(), group.epoch_authenticator().to_vec(), group.capability(&a.provider).unwrap());
    let cut = group.cut().to_vec();
    for (index, change) in [
        Change { cut: cut.clone(), name: Some("x".repeat(largest_name + 1)), ..Change::default() },
        Change { cut: cut.clone(), add: vec![b"malformed package".to_vec()], how: Some(How::Invite), ..Change::default() },
        Change { cut: cut.clone(), settings: Some(Settings { kind: "another kind".into(), ..group.settings() }), how: Some(How::Invite), ..Change::default() },
    ].into_iter().enumerate() {
        let error = group.commit(&a.provider, &a.session, change).err().unwrap();
        if index == 0 {
            assert!(error.to_string().contains("1 MiB envelope limit"), "{error}");
        }
        assert_eq!(a.provider.records(), before);
        assert_eq!(serde_json::to_vec(&group.state).unwrap(), before_state);
        assert_eq!(group.mls.aad(), before_aad);
        assert!(group.mls.pending_commit().is_none());
        assert_eq!((group.epoch(), group.epoch_authenticator().to_vec(), group.capability(&a.provider).unwrap()), before_epoch);
        let loaded = Group::load(&a.provider, group.id()).unwrap();
        assert_eq!(serde_json::to_vec(&loaded.state).unwrap(), before_state);
    }
    let failure: Result<()> = group.guarded(&a.provider, Result::is_ok, |g| {
        let cut = g.cut().to_vec();
        g.commit(&a.provider, &a.session, Change { cut, ..Change::default() })?;
        g.mls.set_aad(b"changed late".to_vec());
        bail!("late failure after posted and MLS writes")
    });
    assert!(failure.is_err());
    assert_eq!(a.provider.records(), before);
    assert_eq!(serde_json::to_vec(&group.state).unwrap(), before_state);
    assert_eq!(group.mls.aad(), before_aad);
    assert!(group.posted().is_none());
    assert!(group.mls.pending_commit().is_none());
    group.mls.set_aad(vec![]);
    let cut = a.cut();
    let small = a.commit(Change { cut, ..Change::default() });
    w.post(small.entry);
    w.read(&[0, 1]);
    w.agree(&[0, 1]);
}

#[test]
fn accepted_package_refs_survive_pending_serde_and_reenveloping() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1]);
    let packages = [w.key_package(2), w.key_package(3)];
    let refs: Vec<_> = packages.iter().map(|package| {
        let p = &w.m[0].provider;
        let kp = key_package_in(p, package).unwrap();
        let reference = key_package_reference(p, package).unwrap();
        assert_ne!(reference, <[u8; 32]>::from(Sha256::digest(package)));
        assert_ne!(reference, <[u8; 32]>::from(Sha256::digest(kp.tls_serialize_detached().unwrap())));
        let roundtrip: KeyPackage = serde_json::from_slice(&serde_json::to_vec(&kp).unwrap()).unwrap();
        assert_eq!(kp.hash_ref(p.crypto()).unwrap(), roundtrip.hash_ref(p.crypto()).unwrap());
        reference
    }).collect();
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, add: packages.to_vec(), how: Some(How::Other("future method".into())), invite: Some([5; 32].into()), ..Change::default() });
    let admission = commit.admission.clone().unwrap();
    let a = &w.m[0];
    assert_eq!(a.group.as_ref().unwrap().state.posted.as_ref().unwrap().add_refs, refs);
    let b = &w.m[1];
    let inner = b.group.as_ref().unwrap().open_entry(&b.provider, &commit.entry).unwrap();
    let rewrapped = b.group.as_ref().unwrap().seal_entry(&b.provider, &inner).unwrap();
    assert_ne!(rewrapped, commit.entry);
    w.m[0] = w.m[0].copy();
    assert_eq!(w.m[0].g().posted().unwrap(), commit.entry);
    assert_eq!(w.m[0].g().state.posted.as_ref().unwrap().add_refs, refs);
    let a = &mut w.m[0];
    let epoch = a.g().epoch();
    let records = a.provider.records();
    assert_eq!(a.group.as_mut().unwrap().judge(&a.provider, &rewrapped).unwrap(), Verdict::Commit { removes: false });
    assert_eq!(a.provider.records(), records);
    let pos = w.post(rewrapped);
    let read = w.read(&[0, 1]);
    assert!(applied(&read[0][0]).own);
    assert!(!applied(&read[1][0]).own);
    for i in 0..2 {
        assert_eq!(w.m[i].g().epoch(), epoch + 1);
        let added: Vec<_> = w.m[i].g().added().iter().filter(|add| add.epoch == epoch + 1).cloned().collect();
        assert_eq!(added.iter().map(|add| add.key_package_ref).collect::<Vec<_>>(), refs);
        assert!(added.iter().all(|add| add.how == Some(How::Other("future method".into())) && add.invite == Some([5; 32].into())));
        w.m[i] = w.m[i].copy();
        assert!(w.m[i].g().posted().is_none());
        assert_eq!(w.m[i].g().added().iter().filter(|add| add.epoch == epoch + 1).cloned().collect::<Vec<_>>(), added);
    }
    for (i, package) in packages.iter().enumerate() {
        w.m[i + 2].join(&inner, &admission, pos, package);
        assert_eq!(exports(&w.m[i + 2]), exports(&w.m[0]));
    }
}

#[test]
fn welcome_must_use_the_intended_package_and_checkpoint_failure_restores_it() {
    let mut w = World::new(&["A", "B"]);
    let a = &mut w.m[0];
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan")).unwrap());
    let intended = w.key_package(1);
    let other = w.key_package(1);
    let intended_ref = key_package_reference(&w.m[1].provider, &intended).unwrap();
    let other_ref = key_package_reference(&w.m[1].provider, &other).unwrap();
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, add: vec![other], how: Some(How::Invite), ..Change::default() });
    let entry = w.m[0].open_inner(&commit.entry);
    let Admission { welcome, sig } = commit.admission.clone().unwrap();
    let b = &w.m[1];
    let before = b.provider.records();
    b.provider.savepoint().unwrap();
    let error = Group::join(&b.provider, &entry, &welcome, &sig, &intended_ref).err().unwrap();
    assert!(error.to_string().contains("another KeyPackage"), "{error}");
    b.provider.rollback_to().unwrap();
    assert_eq!(b.provider.records(), before);

    // Control: OpenMLS really consumes the other operation's package before into_group.
    b.provider.savepoint().unwrap();
    let MlsMessageBodyIn::Welcome(parsed) = parse::<MlsMessageIn>(&welcome).unwrap().extract() else { panic!() };
    let builder = StagedWelcome::build_from_welcome(&b.provider, &join_config(), parsed).unwrap();
    assert_eq!(builder.processed_welcome().own_key_package().unwrap().hash_ref(b.provider.crypto()).unwrap().as_slice(), other_ref);
    assert_ne!(b.provider.records(), before);
    drop(builder);
    b.provider.rollback_to().unwrap();
    assert_eq!(b.provider.records(), before);

    b.provider.savepoint().unwrap();
    let joined = Group::join(&b.provider, &entry, &welcome, &sig, &other_ref).unwrap();
    assert_eq!(joined.members().len(), 2);
    assert_ne!(b.provider.records(), before);
    drop(joined);
    b.provider.rollback_to().unwrap();
    assert_eq!(b.provider.records(), before, "a bad node checkpoint restores the successfully consumed package and group writes");
    assert!(Group::join(&b.provider, &entry, &welcome, &sig, &other_ref).is_ok());
}

#[test]
fn a_multi_package_welcome_cannot_select_another_saved_operation() {
    let mut w = World::new(&["A", "B"]);
    let a = &mut w.m[0];
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan")).unwrap());
    let b = &w.m[1];
    let other_session = Session::with_signer(&b.provider, stranger(), "B's other operation", leaf("other")).unwrap();
    let packages = [b.session.key_package(&b.provider).unwrap(), other_session.key_package(&b.provider).unwrap()];
    let refs: Vec<_> = packages.iter().map(|kp| key_package_reference(&b.provider, kp).unwrap()).collect();
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, add: packages.to_vec(), how: Some(How::Invite), ..Change::default() });
    let entry = w.m[0].open_inner(&commit.entry);
    let Admission { welcome, sig } = commit.admission.clone().unwrap();
    let MlsMessageBodyIn::Welcome(parsed) = parse::<MlsMessageIn>(&welcome).unwrap().extract() else { panic!() };
    let first: [u8; 32] = parsed.secrets()[0].new_member().as_slice().try_into().unwrap();
    let intended = refs.iter().find(|reference| **reference != first).unwrap();
    assert!(parsed.secrets().iter().any(|secret| secret.new_member().as_slice() == intended));
    let b = &w.m[1];
    let before = b.provider.records();
    assert!(Group::join(&b.provider, &entry, &welcome, &sig, intended).err().unwrap().to_string().contains("another KeyPackage"));
    assert_eq!(b.provider.records(), before);
    assert!(Group::join(&b.provider, &entry, &welcome, &sig, &first).is_ok());
}

#[test]
fn identical_leaf_and_signature_keys_are_not_package_identity() {
    let mut w = World::new(&["A", "B"]);
    let a = &mut w.m[0];
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan")).unwrap());
    let p1 = w.key_package(1);
    let p2 = w.key_package(1);
    let b = &w.m[1];
    let kp1 = key_package_in(&b.provider, &p1).unwrap();
    let kp2 = key_package_in(&b.provider, &p2).unwrap();
    let bundle1: KeyPackageBundle = b.provider.storage().key_package(&kp1.hash_ref(b.provider.crypto()).unwrap()).unwrap().unwrap();
    let bundle2: KeyPackageBundle = b.provider.storage().key_package(&kp2.hash_ref(b.provider.crypto()).unwrap()).unwrap().unwrap();
    let first = serde_json::to_value(bundle1).unwrap();
    let mut second = serde_json::to_value(bundle2).unwrap();
    second["key_package"]["payload"]["leaf_node"] = first["key_package"]["payload"]["leaf_node"].clone();
    second["private_encryption_key"] = first["private_encryption_key"].clone();
    let unsigned: KeyPackage = serde_json::from_value(second["key_package"].clone()).unwrap();
    let signature: Signature = serde_json::from_value(second["key_package"]["signature"].clone()).unwrap();
    let mut payload = unsigned.tls_serialize_detached().unwrap();
    payload.truncate(payload.len() - signature.tls_serialized_len());
    let signed = SignContent::new("KeyPackageTBS", payload.into()).tls_serialize_detached().unwrap();
    let signature: Signature = b.session.signer.sign(&signed).unwrap().into();
    second["key_package"]["signature"] = serde_json::to_value(signature).unwrap();
    let bundle: KeyPackageBundle = serde_json::from_value(second).unwrap();
    let reference = bundle.key_package().hash_ref(b.provider.crypto()).unwrap();
    b.provider.storage().write_key_package(&reference, &bundle).unwrap();
    let p2 = MlsMessageOut::from(bundle.key_package().clone()).to_bytes().unwrap();
    let kp2 = key_package_in(&b.provider, &p2).unwrap();
    assert_eq!(kp1.leaf_node(), kp2.leaf_node());
    assert_ne!(kp1.hpke_init_key(), kp2.hpke_init_key());
    let r1 = key_package_reference(&b.provider, &p1).unwrap();
    let r2 = key_package_reference(&b.provider, &p2).unwrap();
    assert_ne!(r1, r2);
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, add: vec![p2.clone()], how: Some(How::Invite), ..Change::default() });
    let inner = w.m[0].open_inner(&commit.entry);
    let Admission { welcome, sig } = commit.admission.clone().unwrap();
    w.post(commit.entry);
    w.read(&[0]);
    let a = &w.m[0];
    assert!(a.group.as_ref().unwrap().unchanged(&a.provider, &p1).unwrap(), "unchanged alone cannot identify the Add");
    assert!(a.group.as_ref().unwrap().unchanged(&a.provider, &p2).unwrap());
    assert_eq!(a.group.as_ref().unwrap().added().last().unwrap().key_package_ref, r2);
    let b = &w.m[1];
    let before = b.provider.records();
    assert!(Group::join(&b.provider, &inner, &welcome, &sig, &r1).err().unwrap().to_string().contains("another KeyPackage"));
    assert_eq!(b.provider.records(), before);
    let joined = Group::join(&b.provider, &inner, &welcome, &sig, &r2).unwrap();
    assert_eq!(joined.capability(&b.provider).unwrap(), a.group.as_ref().unwrap().capability(&a.provider).unwrap());
}

#[test]
fn last_resort_packages_do_not_bypass_exact_welcome_matching() {
    let mut w = World::new(&["A", "B"]);
    let a = &mut w.m[0];
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan")).unwrap());
    let intended = w.key_package(1);
    let b = &w.m[1];
    let intended_ref = key_package_reference(&b.provider, &intended).unwrap();
    let extensions = [ExtensionType::Unknown(SETTINGS_EXTENSION), ExtensionType::Unknown(LEAF_EXTENSION), ExtensionType::LastResort];
    let capabilities = Capabilities::new(None, Some(&[CIPHERSUITE]), Some(&extensions), None, None);
    let bundle = KeyPackage::builder().mark_as_last_resort()
        .leaf_node_capabilities(capabilities).leaf_node_extensions(leaf_extensions(&b.session.leaf).unwrap())
        .key_package_lifetime(Lifetime::init(0, u64::MAX))
        .build(CIPHERSUITE, &b.provider, &b.session.signer, b.session.with_key()).unwrap();
    let package = MlsMessageOut::from(bundle.key_package().clone()).to_bytes().unwrap();
    let reference = key_package_reference(&b.provider, &package).unwrap();
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, add: vec![package], how: Some(How::Invite), ..Change::default() });
    let entry = w.m[0].open_inner(&commit.entry);
    let Admission { welcome, sig } = commit.admission.clone().unwrap();
    let b = &w.m[1];
    let before = b.provider.records();
    assert!(Group::join(&b.provider, &entry, &welcome, &sig, &intended_ref).err().unwrap().to_string().contains("another KeyPackage"));
    assert_eq!(b.provider.records(), before);
    b.provider.savepoint().unwrap();
    let MlsMessageBodyIn::Welcome(parsed) = parse::<MlsMessageIn>(&welcome).unwrap().extract() else { panic!() };
    let builder = StagedWelcome::build_from_welcome(&b.provider, &join_config(), parsed).unwrap();
    assert!(builder.processed_welcome().own_key_package().unwrap().last_resort());
    assert_eq!(b.provider.records(), before, "last resort leaves the saved package present, so consumption is not an identity test");
    drop(builder);
    b.provider.rollback_to().unwrap();
    assert!(Group::join(&b.provider, &entry, &welcome, &sig, &reference).is_ok());
}

#[test]
fn unsupported_authorities_fail_without_partial_state() {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let invalid = (0..=255).map(|byte| [byte; 32]).find(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_err()).unwrap();
    let authorities = [
        Service::Newer(serde_json::json!({"future": {"key": "unknown"}})),
        Service::Serve { key: Bytes(vec![1; 31]), domain: "r.example".into(), rest: Default::default() },
        Service::Serve { key: invalid.into(), domain: "r.example".into(), rest: Default::default() },
        Service::Serve { key: [0; 32].into(), domain: "r.example".into(), rest: Default::default() },
    ];
    for membership in authorities {
        let changed = Settings { membership, ..w.m[0].g().settings() };
        let a = &mut w.m[0];
        let before = a.provider.records();
        assert!(Group::create(&a.provider, &a.session, &changed).is_err());
        assert_eq!(a.provider.records(), before);
        let group = a.group.as_mut().unwrap();
        let epoch = group.epoch_authenticator().to_vec();
        let state = serde_json::to_vec(&group.state).unwrap();
        let cut = group.cut().to_vec();
        assert!(group.commit(&a.provider, &a.session, Change { cut: cut.clone(), settings: Some(changed.clone()), ..Change::default() }).is_err());
        assert_eq!(a.provider.records(), before);
        assert_eq!(group.epoch_authenticator(), epoch);
        assert_eq!(serde_json::to_vec(&group.state).unwrap(), state);
        group.mls.set_aad(cut_aad(&cut));
        let bundle = group.mls.commit_builder().force_self_update(true)
            .propose_group_context_extensions(context_extensions(&changed).unwrap()).unwrap()
            .load_psks(a.provider.storage()).unwrap().build(a.provider.rand(), a.provider.crypto(), &a.session.signer, |_| true).unwrap()
            .stage_commit(&a.provider).unwrap();
        let inner = entry_of(&a.session.signer, bundle.into_messages().0.to_bytes().unwrap());
        let sealed = group.seal_entry(&a.provider, &inner).unwrap();
        group.mls.clear_pending_commit(a.provider.storage()).unwrap();
        let b = &mut w.m[1];
        let before = b.provider.records();
        let group = b.group.as_mut().unwrap();
        let verdict = group.judge(&b.provider, &sealed).unwrap();
        assert!(matches!(verdict, Verdict::Skipped { reason, .. } if reason.contains("service authority")));
        assert_eq!(b.provider.records(), before);
        assert!(group.apply(&b.provider, &sealed).is_err());
        assert_eq!(b.provider.records(), before);
        assert_eq!(group.epoch_authenticator(), epoch);
    }
}

#[test]
fn unsupported_welcome_authority_rolls_back_consumption() {
    let mut w = World::new(&["A", "B"]);
    let a = &mut w.m[0];
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan")).unwrap());
    let package = w.key_package(1);
    let reference = key_package_reference(&w.m[1].provider, &package).unwrap();
    let a = &mut w.m[0];
    let group = a.group.as_mut().unwrap();
    let changed = Settings { membership: Service::Newer(serde_json::json!({"future": {}})), ..group.settings() };
    let cut = group.cut().to_vec();
    group.mls.set_aad(cut_aad(&cut));
    let kp = key_package_in(&a.provider, &package).unwrap();
    let bundle = group.mls.commit_builder().propose_adds([kp])
        .propose_group_context_extensions(context_extensions(&changed).unwrap()).unwrap()
        .load_psks(a.provider.storage()).unwrap().build(a.provider.rand(), a.provider.crypto(), &a.session.signer, |_| true).unwrap()
        .stage_commit(&a.provider).unwrap();
    let (commit, welcome, _) = bundle.into_messages();
    let entry = entry_of(&a.session.signer, commit.to_bytes().unwrap());
    let welcome = welcome.unwrap().to_bytes().unwrap();
    let sig = a.session.signer.sign(&welcome_signed(&entry, &welcome)).unwrap();
    let b = &w.m[1];
    let before = b.provider.records();
    assert!(Group::join(&b.provider, &entry, &welcome, &sig, &reference).err().unwrap().to_string().contains("unsupported membership service authority"));
    assert_eq!(b.provider.records(), before);
}

#[test]
fn private_service_changes_bind_both_authorities_and_keep_future_settings() {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let (old_c, old_k, old_context) = exports(&w.m[0]);
    let new_service = ed25519_dalek::SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
    let mut changed = w.m[0].g().settings();
    changed.membership = Service::Serve {
        key: new_service.into(), domain: "new.example".into(),
        rest: [("future-service-setting".into(), serde_json::json!(7))].into_iter().collect(),
    };
    changed.rest.insert("future-group-setting".into(), serde_json::json!({"x": true}));
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, settings: Some(changed.clone()), ..Change::default() });
    let a = &w.m[0];
    let associated = aad(a, commit.entry.len());
    assert!(decrypt(&old_k, &associated, &commit.entry).is_ok());
    let mut new_context = old_context;
    new_context[24..].copy_from_slice(&new_service);
    let wrong_k: [u8; 32] = a.group.as_ref().unwrap().mls.export_secret(a.provider.crypto(), SEALING_LABEL, &new_context, 32).unwrap().try_into().unwrap();
    assert!(decrypt(&wrong_k, &associated, &commit.entry).is_err(), "the source commit uses old S");
    w.post(commit.entry);
    w.read(&[0, 1]);
    assert_eq!(exports(&w.m[0]), exports(&w.m[1]));
    let (new_c, new_k, context) = exports(&w.m[1]);
    assert_eq!(&context[24..], new_service);
    assert_ne!(old_c, new_c);
    assert_ne!(old_k, new_k);
    let later = w.m[1].seal_inner(&filler());
    assert!(decrypt(&new_k, &aad(&w.m[1], later.len()), &later).is_ok());
    assert_eq!(w.m[1].g().settings(), changed);
    changed.name = "renamed later".into();
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, settings: Some(changed.clone()), ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1]);
    assert_eq!(w.m[0].g().settings(), changed);
}

#[test]
fn identity_authority_cannot_change_but_its_route_can() {
    let mut w = World::new(&["A", "B"]);
    let a = &mut w.m[0];
    let identity = Settings { kind: IDENTITY.into(), public: Some([6; 32].into()), ..settings("identity") };
    a.group = Some(Group::create(&a.provider, &a.session, &identity).unwrap());
    let package = w.key_package(1);
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, add: vec![package.clone()], how: Some(How::Invite), ..Change::default() });
    let inner = w.m[0].open_inner(&commit.entry);
    let admission = commit.admission.clone().unwrap();
    let pos = w.post(commit.entry);
    w.read(&[0]);
    w.m[1].join(&inner, &admission, pos, &package);
    let a = &mut w.m[0];
    let group = a.group.as_mut().unwrap();
    let mut changed = group.settings();
    let Service::Serve { key, .. } = &mut changed.membership else { panic!() };
    *key = ed25519_dalek::SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes().into();
    let before = a.provider.records();
    let cut = group.cut().to_vec();
    let error = group.commit(&a.provider, &a.session, Change { cut: cut.clone(), settings: Some(changed.clone()), ..Change::default() }).err().unwrap();
    assert!(error.to_string().contains("identity group's service authority changed"));
    assert_eq!(a.provider.records(), before);
    group.mls.set_aad(cut_aad(&cut));
    let bundle = group.mls.commit_builder().force_self_update(true)
        .propose_group_context_extensions(context_extensions(&changed).unwrap()).unwrap()
        .load_psks(a.provider.storage()).unwrap().build(a.provider.rand(), a.provider.crypto(), &a.session.signer, |_| true).unwrap()
        .stage_commit(&a.provider).unwrap();
    let inner = entry_of(&a.session.signer, bundle.into_messages().0.to_bytes().unwrap());
    let sealed = group.seal_entry(&a.provider, &inner).unwrap();
    group.mls.clear_pending_commit(a.provider.storage()).unwrap();
    let b = &mut w.m[1];
    let before = b.provider.records();
    let group = b.group.as_mut().unwrap();
    assert!(matches!(group.judge(&b.provider, &sealed).unwrap(), Verdict::Skipped { reason, .. } if reason.contains("identity group's service authority changed")));
    assert_eq!(b.provider.records(), before);
    assert!(group.apply(&b.provider, &sealed).is_err());
    assert_eq!(b.provider.records(), before);
    let mut routed = group.settings();
    let Service::Serve { domain, .. } = &mut routed.membership else { panic!() };
    *domain = "new-route.example".into();
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, settings: Some(routed.clone()), ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1]);
    assert_eq!(w.m[0].g().settings(), routed);
    assert_eq!(w.m[1].g().settings(), routed);
    assert_eq!(exports(&w.m[0]), exports(&w.m[1]));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn sqlite_welcome_rollback_keeps_both_packages_across_restart() {
    use crate::provider::SqliteProvider;
    let dir = std::env::temp_dir().join(format!("lmk-core-epoch-join-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("joiner.db");
    let mut a = Member::new(MemoryProvider::default(), "A");
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan")).unwrap());
    let b = Member::new(SqliteProvider::open(&path).unwrap(), "B");
    let packages = [b.session.key_package(&b.provider).unwrap(), b.session.key_package(&b.provider).unwrap()];
    let refs: Vec<_> = packages.iter().map(|kp| key_package_in(&b.provider, kp).unwrap().hash_ref(b.provider.crypto()).unwrap()).collect();
    let cut = a.cut();
    let commit = a.commit(Change { cut, add: vec![packages[1].clone()], how: Some(How::Invite), ..Change::default() });
    let entry = a.open_inner(&commit.entry);
    let Admission { welcome, sig } = commit.admission.clone().unwrap();
    let id = a.g().id().to_vec();
    b.provider.begin().unwrap();
    b.provider.savepoint().unwrap();
    assert!(Group::join(&b.provider, &entry, &welcome, &sig, &refs[0].as_slice().try_into().unwrap()).err().unwrap().to_string().contains("another KeyPackage"));
    b.provider.rollback_to().unwrap();
    b.provider.commit().unwrap();
    drop(b);
    let provider = SqliteProvider::open(&path).unwrap();
    for reference in &refs {
        let bundle: Option<KeyPackageBundle> = provider.storage().key_package(reference).unwrap();
        assert!(bundle.is_some());
    }
    assert!(MlsGroup::load(provider.storage(), &GroupId::from_slice(&id)).unwrap().is_none());
    assert!(provider.get(&state_key(&id)).unwrap().is_none());
    provider.begin().unwrap();
    provider.savepoint().unwrap();
    let joined = Group::join(&provider, &entry, &welcome, &sig, &refs[1].as_slice().try_into().unwrap()).unwrap();
    drop(joined);
    provider.rollback_to().unwrap();
    provider.commit().unwrap();
    drop(provider);
    let provider = SqliteProvider::open(&path).unwrap();
    for reference in &refs {
        let bundle: Option<KeyPackageBundle> = provider.storage().key_package(reference).unwrap();
        assert!(bundle.is_some());
    }
    assert!(MlsGroup::load(provider.storage(), &GroupId::from_slice(&id)).unwrap().is_none());
    assert!(provider.get(&state_key(&id)).unwrap().is_none());
    let joined = Group::join(&provider, &entry, &welcome, &sig, &refs[1].as_slice().try_into().unwrap()).unwrap();
    assert_eq!(joined.members().len(), 2);
    drop((provider, joined));
    std::fs::remove_dir_all(dir).unwrap();
}

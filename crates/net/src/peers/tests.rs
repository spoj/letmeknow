use super::*;

fn id() -> Bytes {
    Bytes(vec![7])
}

fn key(n: u8) -> Key {
    [n; 32]
}

fn member(n: u8) -> Membership {
    (Bytes(vec![n]), 0)
}

fn gs() -> BTreeSet<Bytes> {
    BTreeSet::from([id()])
}

fn seqs(n: u8, ranges: &[(u64, u64)]) -> Seqs {
    Seqs { key: Bytes(vec![n]), joined: 0, seqs: Ranges::from(ranges.to_vec()) }
}

/// The group with members `key(n)` for each `n`, at `epoch`; this member is `member(100)`.
fn own(epoch: u64, members: &[u8]) -> Own {
    Own {
        me: member(100),
        epoch,
        log: [7; 32],
        head: None,
        public: vec![],
        earlier: vec![],
        members: members.iter().map(|&n| (member(n), key(n))).collect(),
        wanted: vec![],
    }
}

fn peers() -> Peers {
    Peers::new(0, 1, key(100))
}

/// Member `n`'s summary of version `version`, signed and heard at `time`, holding `held`.
fn heard(n: u8, version: u64, time: u64, held: Vec<Seqs>) -> Heard {
    let summary = Summary { group: id(), member: Bytes(vec![n]), joined: 0, version, time, epoch: 1, relay: None, held, shown: vec![], lost: vec![] };
    Heard { signed: Signed { body: Bytes(vec![]), sig: Bytes(vec![]) }, summary, at: time }
}

fn dials(out: &[Out]) -> Vec<Key> {
    out.iter()
        .filter_map(|o| match o {
            Out::Dial(k) => Some(*k),
            _ => None,
        })
        .collect()
}

fn closes(out: &[Out]) -> Vec<Key> {
    out.iter()
        .filter_map(|o| match o {
            Out::Close(k) => Some(*k),
            _ => None,
        })
        .collect()
}

fn summaries_to(out: &[Out]) -> Vec<Key> {
    out.iter()
        .filter_map(|o| match o {
            Out::Frame(k, Frame::Summaries { .. }) => Some(*k),
            _ => None,
        })
        .collect()
}

fn wants(out: &[Out]) -> Vec<(Key, Vec<Seqs>)> {
    out.iter()
        .filter_map(|o| match o {
            Out::Frame(k, Frame::Want { wants, .. }) => Some((*k, wants.clone())),
            _ => None,
        })
        .collect()
}

/// A full mesh dials every other member, four at a time: the rest once those dials end.
#[test]
fn a_full_mesh_dials_every_member_four_at_a_time() {
    let mut p = peers();
    p.group(id(), own(1, &[1, 2, 3, 4, 5, 6]), 0);
    let first = dials(&p.poll(0));
    assert_eq!(first.len(), DIALS);
    for k in &first {
        p.dialed(k, true, 0);
        p.connect(*k, gs(), true, 0);
    }
    let rest = dials(&p.poll(REDIAL));
    assert_eq!(rest.len(), 2);
    let all: BTreeSet<Key> = first.iter().chain(&rest).copied().collect();
    assert_eq!(all, (1..=6).map(key).collect());
}

/// Above seven members, a member targets its six best by pair rank, and dials four of them at once.
#[test]
fn a_larger_group_targets_its_six_best_ranked_members() {
    let mut p = peers();
    let others: Vec<u8> = (1..=19).collect();
    p.group(id(), own(1, &others), 0);
    let mut best: Vec<Key> = others.iter().map(|&n| key(n)).collect();
    best.sort_by_key(|k| rank(&id(), &key(100), k));
    best.truncate(K);
    assert_eq!(p.targets(&id(), 0).iter().collect::<BTreeSet<_>>(), best.iter().collect::<BTreeSet<_>>());
    let dialed = dials(&p.poll(0));
    assert_eq!(dialed.len(), DIALS);
    assert!(dialed.iter().all(|k| best.contains(k)));
}

/// The pair rank is the same from either side, and differs between pairs.
#[test]
fn the_pair_rank_is_symmetric() {
    assert_eq!(rank(&id(), &key(3), &key(9)), rank(&id(), &key(9), &key(3)));
    assert_ne!(rank(&id(), &key(3), &key(9)), rank(&id(), &key(3), &key(8)));
}

/// A failed dial backs the peer off 10 s, then 20 s after the next failure; a connection clears the backoff.
#[test]
fn a_failed_dial_backs_off_and_a_connection_clears_it() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    assert_eq!(dials(&p.poll(0)), vec![key(1)]);
    p.dialed(&key(1), false, 0);
    assert_eq!(dials(&p.poll(10_000)), vec![key(1)]);
    p.dialed(&key(1), false, 10_000);
    assert!(dials(&p.poll(20_000)).is_empty());
    assert_eq!(dials(&p.poll(30_000)), vec![key(1)]);
    p.dialed(&key(1), false, 30_000);
    p.connect(key(1), gs(), false, 35_000);
    p.disconnect(&key(1));
    assert_eq!(dials(&p.poll(40_000)), vec![key(1)], "a connection cleared the backoff");
}

/// A member seen recently is a target ahead of a better-ranked member that is not.
#[test]
fn recently_seen_members_are_targets_before_stale_ones() {
    let mut p = peers();
    let others: Vec<u8> = (1..=19).collect();
    p.group(id(), own(1, &others), 0);
    let mut ranked = others.clone();
    ranked.sort_by_key(|&n| rank(&id(), &key(100), &key(n)));
    let last = *ranked.last().unwrap();
    assert!(!p.targets(&id(), 0).contains(&key(last)));
    p.summary(&id(), heard(last, 1, 0, vec![]), Some(key(last)));
    assert!(p.targets(&id(), 0).contains(&key(last)));
}

/// Once a minute the member dials one recently seen member it is not connected to.
#[test]
fn the_minute_probe_dials_one_recent_member_not_connected() {
    let mut p = peers();
    p.group(id(), own(1, &(1..=19).collect::<Vec<_>>()), 0);
    for n in 1..=8 {
        p.summary(&id(), heard(n, 1, 0, vec![]), Some(key(n)));
    }
    let targets = p.targets(&id(), 0);
    for k in &targets {
        p.connect(*k, gs(), false, 0);
    }
    assert!(dials(&p.poll(0)).is_empty(), "every target is connected");
    let probed = dials(&p.poll(PROBE));
    assert_eq!(probed.len(), 1);
    assert!(!targets.contains(&probed[0]) && (1..=8).any(|n| key(n) == probed[0]));
}

/// A dialed connection no group targets closes after five idle minutes; a targeted one stays.
#[test]
fn an_idle_dialed_connection_closes_unless_targeted() {
    let mut p = peers();
    p.group(id(), own(1, &(1..=19).collect::<Vec<_>>()), 0);
    let targets = p.targets(&id(), 0);
    for k in &targets {
        p.connect(*k, gs(), true, 0);
    }
    let other = (1..=19).map(key).find(|k| !targets.contains(k)).unwrap();
    p.connect(other, gs(), true, 0);
    assert!(closes(&p.poll(IDLE - 1)).is_empty());
    assert_eq!(closes(&p.poll(IDLE)), vec![other]);
}

/// A connection that serves no group closes after 30 s.
#[test]
fn a_stranger_connection_closes_after_thirty_seconds() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    p.connect(key(50), BTreeSet::new(), false, 0);
    assert!(closes(&p.poll(STRANGER - 1)).is_empty());
    assert_eq!(closes(&p.poll(STRANGER)), vec![key(50)]);
}

/// Over 128 connections, the longest-idle one that no group targets closes.
#[test]
fn over_128_connections_close_the_longest_idle_untargeted_one() {
    let mut p = peers();
    p.group(id(), own(1, &[]), 0);
    for n in 1..=129 {
        p.connect(key(n), gs(), false, n as u64 * 10);
    }
    assert_eq!(closes(&p.poll(2_000)), vec![key(1)]);
}

/// On connecting, a member lists the versions of its kept summaries to the peer.
#[test]
fn connecting_sends_the_versions_of_kept_summaries() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    p.summary(&id(), heard(1, 3, 0, vec![]), Some(key(1)));
    p.connect(key(1), gs(), false, 0);
    let versions = vec![Version { key: Bytes(vec![1]), joined: 0, version: 3 }];
    assert!(p.poll(0).contains(&Out::Frame(key(1), Frame::Versions { group: id(), versions })));
}

/// `hello` on connecting carries each served group's position and the heads of the public logs.
#[test]
fn hello_on_connect_carries_the_served_groups_and_public_heads() {
    let mut p = peers();
    let public = Head { log_ref: [9; 32], length: 3, hash: [0; 32], time: 0, sig: Bytes::default() };
    p.group(id(), Own { public: vec![public.clone()], ..own(1, &[1]) }, 0);
    p.connect(key(1), gs(), false, 0);
    let groups = vec![At { group: id(), epoch: 1, log: [7; 32], head: None }];
    assert!(p.poll(0).contains(&Out::Frame(key(1), Frame::Hello { groups, heads: vec![public] })));
}

/// A peer's versions get back the summaries it lacks or holds older, and nothing it holds at the same version.
#[test]
fn versions_are_answered_with_what_the_peer_lacks() {
    let mut p = peers();
    p.group(id(), own(1, &[1, 2]), 0);
    p.summary(&id(), heard(1, 3, 0, vec![]), Some(key(1)));
    p.summary(&id(), heard(2, 5, 0, vec![]), Some(key(2)));
    p.connect(key(1), gs(), false, 0);
    p.poll(0);
    let theirs = |one: u64, two: u64| Frame::Versions {
        group: id(),
        versions: vec![Version { key: Bytes(vec![1]), joined: 0, version: one }, Version { key: Bytes(vec![2]), joined: 0, version: two }],
    };
    let out = p.frame(&key(1), &theirs(2, 5), 1);
    let [Out::Frame(k, Frame::Summaries { items, .. })] = &out[..] else { panic!("{out:?}") };
    assert_eq!((*k, items.len()), (key(1), 1));
    assert!(p.frame(&key(1), &theirs(3, 5), 2).is_empty());
}

/// A new summary from one peer goes on to the others the group is served to, once, and not back to its source.
#[test]
fn a_new_summary_goes_on_to_the_other_peers_once() {
    let mut p = peers();
    p.group(id(), own(1, &[1, 2]), 0);
    p.connect(key(1), gs(), false, 0);
    p.connect(key(2), gs(), false, 0);
    p.poll(0);
    assert!(p.summary(&id(), heard(1, 2, 0, vec![]), Some(key(1))));
    assert_eq!(summaries_to(&p.poll(1)), vec![key(2)]);
    assert!(p.poll(2).is_empty());
}

/// A summary of a membership that has been removed is dropped, and not forwarded even if it was queued.
#[test]
fn a_removed_membership_s_summary_is_dropped_and_not_forwarded() {
    let mut p = peers();
    p.group(id(), own(1, &[1, 2]), 0);
    p.connect(key(1), gs(), false, 0);
    p.connect(key(2), gs(), false, 0);
    p.poll(0);
    p.summary(&id(), heard(1, 2, 0, vec![]), Some(key(1)));
    p.group(id(), own(2, &[2]), 1);
    assert!(p.heard(&id()).all(|h| h.summary.member != Bytes(vec![1])));
    assert!(summaries_to(&p.poll(2)).is_empty());
    assert!(!p.summary(&id(), heard(1, 3, 2, vec![]), Some(key(2))));
}

/// A summary whose version is not above the one held is not kept.
#[test]
fn a_lower_or_equal_version_is_not_kept() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    assert!(p.summary(&id(), heard(1, 4, 0, vec![]), Some(key(1))));
    assert!(!p.summary(&id(), heard(1, 3, 0, vec![]), Some(key(1))));
    assert!(!p.summary(&id(), heard(1, 4, 0, vec![]), Some(key(1))));
    assert_eq!(p.heard(&id()).map(|h| h.summary.version).collect::<Vec<_>>(), vec![4]);
}

fn ask() -> Vec<Seqs> {
    vec![seqs(1, &[(1, 2)])]
}

/// Members 1 and 2 both hold seqs 1 and 2 of membership 1, which member 100 wants; both are connected.
fn both_hold() -> Peers {
    let mut p = peers();
    let mut o = own(1, &[1, 2]);
    o.wanted = ask();
    p.group(id(), o, 0);
    for n in [1, 2] {
        p.connect(key(n), gs(), false, 0);
        p.summary(&id(), heard(n, 1, 0, ask()), Some(key(n)));
    }
    p
}

/// Repair asks the holder of the lowest wanted seq, and keeps one request outstanding at a time.
#[test]
fn repair_asks_the_holder_of_the_lowest_wanted_seq_one_at_a_time() {
    let mut p = peers();
    let mut o = own(1, &[1, 2]);
    o.wanted = vec![seqs(1, &[(1, 5)])];
    p.group(id(), o, 0);
    for n in [1, 2] {
        p.connect(key(n), gs(), false, 0);
    }
    p.summary(&id(), heard(1, 1, 0, vec![seqs(1, &[(5, 5)])]), Some(key(1)));
    p.summary(&id(), heard(2, 1, 0, ask()), Some(key(2)));
    assert_eq!(wants(&p.poll(0)), vec![(key(2), ask())]);
    assert!(wants(&p.poll(1)).is_empty());
}

/// A holder silent for 10 s is struck for what it was asked, and the next holder is asked.
#[test]
fn a_silent_holder_is_struck_and_the_next_one_asked() {
    let mut p = both_hold();
    assert_eq!(wants(&p.poll(0)), vec![(key(1), ask())]);
    assert!(wants(&p.poll(TIMEOUT - 1)).is_empty());
    assert_eq!(wants(&p.poll(TIMEOUT)), vec![(key(2), ask())]);
}

/// An answer that covers seqs without sending them strikes them for its holder, and the next holder is asked.
#[test]
fn an_answer_strikes_what_it_covered_and_the_next_holder_is_asked() {
    let mut p = both_hold();
    assert_eq!(wants(&p.poll(0)), vec![(key(1), ask())]);
    let answer = Frame::Held { group: id(), items: vec![], answers: Some(ask()) };
    assert!(p.frame(&key(1), &answer, 100).is_empty());
    assert_eq!(wants(&p.poll(100)), vec![(key(2), ask())]);
}

/// An answer that covers nothing, as a holder that refuses gives, strikes all that was asked of it: the next holder is
/// asked, not it again.
#[test]
fn an_answer_covering_nothing_strikes_all_asked() {
    let mut p = both_hold();
    assert_eq!(wants(&p.poll(0)), vec![(key(1), ask())]);
    p.frame(&key(1), &Frame::Held { group: id(), items: vec![], answers: Some(vec![]) }, 100);
    assert_eq!(wants(&p.poll(100)), vec![(key(2), ask())]);
}

/// An answer cut at `ANSWER` bytes strikes only what it covered: the rest is asked of the same holder again.
#[test]
fn an_answer_cut_at_its_size_strikes_only_what_it_covered() {
    let mut p = both_hold();
    p.poll(0);
    let items = vec![Bytes(vec![0; ANSWER])];
    p.frame(&key(1), &Frame::Held { group: id(), items, answers: Some(vec![seqs(1, &[(1, 1)])]) }, 100);
    p.group(id(), Own { wanted: vec![seqs(1, &[(2, 2)])], ..own(1, &[1, 2]) }, 100);
    assert_eq!(wants(&p.poll(100)), vec![(key(1), vec![seqs(1, &[(2, 2)])])]);
}

/// A request times out 10 s after it was made, however busy the connection is with other frames.
#[test]
fn a_request_times_out_though_the_holder_sends_other_frames() {
    let mut p = both_hold();
    p.poll(0);
    p.frame(&key(1), &Frame::Hello { groups: vec![], heads: vec![] }, TIMEOUT - 1);
    assert_eq!(wants(&p.poll(TIMEOUT)), vec![(key(2), ask())]);
}

/// The commit wait dials holders four at a time, those that hold the lowest lacking seq first.
#[test]
fn the_commit_wait_dials_four_holders_at_a_time() {
    let mut p = peers();
    p.group(id(), own(1, &[1, 2, 3, 4, 5, 6]), 0);
    let lacking = vec![seqs(1, &[(5, 9)])];
    for n in 1..=6 {
        p.summary(&id(), heard(n, 1, 0, vec![seqs(1, &[(10 - u64::from(n), 9)])]), Some(key(n)));
    }
    assert_eq!(p.wait(&id(), &lacking, 0, 0), Decision::Wait);
    assert_eq!(dials(&p.poll(0)), vec![key(5), key(6), key(4), key(3)]);
}

/// A summary sent to a peer is not assumed held: a peer whose versions do not show it is sent it again.
#[test]
fn a_summary_a_peer_lacks_is_sent_again() {
    let mut p = peers();
    p.group(id(), own(1, &[1, 2]), 0);
    p.connect(key(1), gs(), false, 0);
    p.poll(0);
    assert!(p.summary(&id(), heard(100, 2, 0, vec![]), None));
    assert_eq!(summaries_to(&p.poll(1)), vec![key(1)]);
    let answered = p.frame(&key(1), &Frame::Versions { group: id(), versions: vec![] }, 2);
    assert_eq!(summaries_to(&answered), vec![key(1)]);
}

/// A peer that stops being served a group, and is served it again, is sent the group's summaries anew: what it held
/// before is not assumed.
#[test]
fn a_peer_served_a_group_again_is_sent_its_summaries_anew() {
    let mut p = peers();
    p.group(id(), own(1, &[1, 2]), 0);
    p.connect(key(1), gs(), false, 0);
    p.summary(&id(), heard(2, 1, 0, ask()), Some(key(2)));
    p.poll(0);
    p.served(&key(1), BTreeSet::new(), 10);
    p.served(&key(1), gs(), 20);
    let answered = p.frame(&key(1), &Frame::Versions { group: id(), versions: vec![] }, 30);
    assert_eq!(summaries_to(&answered), vec![key(1)]);
}

/// Strikes last for the epoch: when it grows, the struck holder is asked again.
#[test]
fn strikes_clear_when_the_epoch_grows() {
    let mut p = peers();
    let mut o = own(1, &[1]);
    o.wanted = ask();
    p.group(id(), o.clone(), 0);
    p.connect(key(1), gs(), false, 0);
    p.summary(&id(), heard(1, 1, 0, ask()), Some(key(1)));
    assert_eq!(wants(&p.poll(0)), vec![(key(1), ask())]);
    p.frame(&key(1), &Frame::Held { group: id(), items: vec![], answers: Some(ask()) }, 100);
    assert!(wants(&p.poll(100)).is_empty(), "struck");
    p.group(id(), Own { epoch: 2, ..o }, 200);
    assert_eq!(wants(&p.poll(200)), vec![(key(1), ask())]);
}

/// An answer to a request made in an earlier epoch strikes nothing: its holder may have sealed what was asked again in
/// the later one, and is asked again.
#[test]
fn an_answer_to_a_request_of_an_earlier_epoch_strikes_nothing() {
    let mut p = peers();
    let mut o = own(1, &[1]);
    o.wanted = ask();
    p.group(id(), o.clone(), 0);
    p.connect(key(1), gs(), false, 0);
    p.summary(&id(), heard(1, 1, 0, ask()), Some(key(1)));
    assert_eq!(wants(&p.poll(0)), vec![(key(1), ask())]);
    p.group(id(), Own { epoch: 2, ..o }, 50);
    p.frame(&key(1), &Frame::Held { group: id(), items: vec![], answers: Some(vec![]) }, 100);
    assert_eq!(wants(&p.poll(100)), vec![(key(1), ask())]);
}

/// A wanted seq that only an unconnected member holds dials that member.
#[test]
fn a_wanted_seq_held_only_by_an_unconnected_member_is_dialed() {
    let mut p = peers();
    let mut o = own(1, &[1]);
    o.wanted = ask();
    p.group(id(), o, 0);
    p.summary(&id(), heard(1, 1, 0, ask()), Some(key(1)));
    let out = p.poll(0);
    assert_eq!(dials(&out), vec![key(1)]);
    assert!(wants(&out).is_empty());
}

/// Nothing lacking applies at once.
#[test]
fn wait_applies_when_nothing_is_lacking() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    assert_eq!(p.wait(&id(), &[], 0, 0), Decision::Apply);
}

/// A wait holds while a connected holder has not been asked for a lacking seq, and asks for it at once.
#[test]
fn wait_holds_while_a_connected_holder_is_untried() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    p.connect(key(1), gs(), false, 0);
    let lacking = vec![seqs(1, &[(5, 5)])];
    p.summary(&id(), heard(1, 1, 0, lacking.clone()), Some(key(1)));
    assert_eq!(p.wait(&id(), &lacking, 0, 1_000), Decision::Wait);
    assert_eq!(wants(&p.poll(1_000)), vec![(key(1), lacking.clone())]);
}

/// Once every holder is struck for the lacking seqs, the wait loses them.
#[test]
fn wait_loses_once_every_holder_is_struck() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    p.connect(key(1), gs(), false, 0);
    let lacking = vec![seqs(1, &[(5, 5)])];
    p.summary(&id(), heard(1, 1, 0, lacking.clone()), Some(key(1)));
    assert_eq!(p.wait(&id(), &lacking, 0, 0), Decision::Wait);
    p.poll(0);
    p.frame(&key(1), &Frame::Held { group: id(), items: vec![], answers: Some(lacking.clone()) }, 100);
    assert_eq!(p.wait(&id(), &lacking, 0, HEAR), Decision::Lose(lacking.clone()));
}

/// A wait holds `HEAR` after the member came online though no summary shows a holder yet: a member back from offline
/// hears the summaries that show them within it.
#[test]
fn a_wait_holds_for_summaries_after_coming_online() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    let lacking = vec![seqs(1, &[(5, 5)])];
    p.connect(key(1), gs(), false, 1_000);
    assert_eq!(p.wait(&id(), &lacking, 0, 1_000), Decision::Wait);
    p.summary(&id(), heard(1, 1, 1_500, lacking.clone()), Some(key(1)));
    assert_eq!(p.wait(&id(), &lacking, 0, 1_000 + HEAR), Decision::Wait, "a holder is untried");
    p.disconnect(&key(1));
    p.dialed(&key(1), false, 1_000 + HEAR);
    assert_eq!(p.wait(&id(), &lacking, 0, 1_000 + HEAR), Decision::Lose(lacking.clone()));
}

/// A wait gives up two minutes after the commit was read, even with an untried holder.
#[test]
fn wait_gives_up_two_minutes_after_the_commit_was_read() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    p.connect(key(1), gs(), false, 0);
    let lacking = vec![seqs(1, &[(5, 5)])];
    p.summary(&id(), heard(1, 1, 0, lacking.clone()), Some(key(1)));
    assert_eq!(p.wait(&id(), &lacking, 0, WAIT - 1), Decision::Wait);
    assert_eq!(p.wait(&id(), &lacking, 0, WAIT), Decision::Lose(lacking.clone()));
}

/// A holder whose backoff has ended is untried again: a wait that starts then dials it.
#[test]
fn a_holder_past_its_backoff_is_dialed_when_the_wait_starts() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    let lacking = vec![seqs(1, &[(5, 5)])];
    p.summary(&id(), heard(1, 1, 0, lacking.clone()), Some(key(1)));
    p.dialed(&key(1), false, HEAR - 1);
    assert_eq!(p.wait(&id(), &lacking, 0, HEAR), Decision::Lose(lacking.clone()), "backing off");
    assert_eq!(p.wait(&id(), &lacking, 31_000, 31_000), Decision::Wait);
    assert_eq!(dials(&p.poll(31_000)), vec![key(1)]);
}

/// A live payload seen lately is dropped; otherwise it goes to the neighbours but not back to its source, and not on at hops 0.
#[test]
fn live_payloads_are_deduped_and_forwarded_by_hops() {
    let mut p = peers();
    p.group(id(), own(1, &(1..=19).collect::<Vec<_>>()), 0);
    for n in 1..=7 {
        p.connect(key(n), gs(), false, 0);
    }
    let others: Vec<Key> = (2..=7).map(key).collect();
    assert_eq!(p.live(&id(), [1; 32], Some(key(1)), 6, 0), Some(others));
    assert_eq!(p.live(&id(), [1; 32], Some(key(2)), 6, 1), None);
    assert_eq!(p.live(&id(), [2; 32], Some(key(2)), 0, 1), Some(vec![]));
    assert!(p.live(&id(), [1; 32], None, 0, LIVE_AGE).is_some(), "expired after two minutes");
}

/// In a full mesh nothing is forwarded, while an own payload goes to every neighbour.
#[test]
fn a_full_mesh_forwards_nothing_and_own_payloads_go_to_all() {
    let mut p = peers();
    p.group(id(), own(1, &[1, 2]), 0);
    p.connect(key(1), gs(), false, 0);
    p.connect(key(2), gs(), false, 0);
    assert_eq!(p.live(&id(), [9; 32], Some(key(1)), 6, 0), Some(vec![]));
    assert_eq!(p.live(&id(), [8; 32], None, 6, 0), Some(vec![key(1), key(2)]));
}

/// An answer stops near a mebibyte and covers the asked seqs up to where it stopped.
#[test]
fn an_answer_stops_near_a_mebibyte_and_covers_what_it_reached() {
    let asked = vec![seqs(1, &[(1, 6)])];
    let held = vec![seqs(1, &[(1, 2), (4, 6)])];
    let Frame::Held { items, answers, .. } = answer(id(), &asked, &held, |_, _, _| Some(vec![0; ANSWER / 2])) else { panic!() };
    assert_eq!(items.len(), 2);
    assert_eq!(answers, Some(vec![seqs(1, &[(1, 3)])]));
    let Frame::Held { items, answers, .. } = answer(id(), &asked, &[], |_, _, _| unreachable!()) else { panic!() };
    assert!(items.is_empty());
    assert_eq!(answers, Some(asked));
}

/// `hello` and `entries` are taken from anyone; the rest from admitted peers, and live payloads only at the head.
#[test]
fn the_gate() {
    let hello = Frame::Hello { groups: vec![], heads: vec![] };
    assert!(takes(&hello, false, false) && !sends(&hello, false, false));
    let want = Frame::Want { group: id(), epoch: 1, wants: vec![], ids: vec![] };
    assert!(!takes(&want, false, true) && takes(&want, true, false));
    let state = Frame::State { group: id(), epoch: 1, link: None };
    assert!(!takes(&state, false, true) && takes(&state, true, false) && sends(&state, true, false));
    let live = Frame::Live { group: id(), hops: 1, item: Bytes(vec![]) };
    assert!(!takes(&live, true, false) && takes(&live, true, true));
    assert!(!sends(&live, true, false) && sends(&live, true, true));
}

const N: usize = 12;

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

enum Ev {
    Frame { from: usize, to: usize, frame: Frame },
    Dialed { from: usize, to: usize, ok: bool },
}

struct Sim {
    now: u64,
    chaos: bool,
    rng: Rng,
    peers: Vec<Peers>,
    versions: Vec<u64>,
    links: BTreeSet<(usize, usize)>,
    queue: BTreeMap<(u64, u64), Ev>,
    sent: u64,
}

fn pair(a: usize, b: usize) -> (usize, usize) {
    (a.min(b), a.max(b))
}

impl Sim {
    fn schedule(&mut self, delay: u64, ev: Ev) {
        self.sent += 1;
        self.queue.insert((self.now + delay, self.sent), ev);
    }

    fn connect(&mut self, dialer: usize, to: usize) {
        self.links.insert(pair(dialer, to));
        self.peers[dialer].connect(key(to as u8), gs(), true, self.now);
        self.peers[to].connect(key(dialer as u8), gs(), false, self.now);
    }

    fn unlink(&mut self, a: usize, b: usize) {
        self.links.remove(&pair(a, b));
        self.peers[a].disconnect(&key(b as u8));
        self.peers[b].disconnect(&key(a as u8));
    }

    fn act(&mut self, at: usize, outs: Vec<Out>) {
        for out in outs {
            match out {
                Out::Frame(to, frame) => {
                    let to = to[0] as usize;
                    if self.links.contains(&pair(at, to)) && !(self.chaos && self.rng.below(10) == 0) {
                        let delay = 50 + self.rng.below(400);
                        self.schedule(delay, Ev::Frame { from: at, to, frame });
                    }
                }
                Out::Dial(to) => {
                    let ok = !self.chaos || self.rng.below(10) < 8;
                    let delay = 100 + self.rng.below(2_000);
                    self.schedule(delay, Ev::Dialed { from: at, to: to[0] as usize, ok });
                }
                Out::Close(to) => self.unlink(at, to[0] as usize),
                Out::Entries { .. } => unreachable!("no member has a head"),
            }
        }
    }

    fn deliver(&mut self, ev: Ev) {
        match ev {
            Ev::Frame { from, to, frame } => {
                if !self.links.contains(&pair(from, to)) {
                    return;
                }
                if let Frame::Summaries { group, items } = frame {
                    for signed in items {
                        let summary: Summary = serde_json::from_slice(&signed.body.0).unwrap();
                        let heard = Heard { signed, summary, at: self.now };
                        self.peers[to].summary(&group, heard, Some(key(from as u8)));
                    }
                } else {
                    let outs = self.peers[to].frame(&key(from as u8), &frame, self.now);
                    self.act(to, outs);
                }
            }
            Ev::Dialed { from, to, ok } => {
                if ok && !self.links.contains(&pair(from, to)) {
                    self.connect(from, to);
                }
                self.peers[from].dialed(&key(to as u8), ok, self.now);
            }
        }
    }

    fn publish(&mut self, i: usize) {
        self.versions[i] += 1;
        let summary = Summary { group: id(), member: Bytes(vec![i as u8]), joined: 0, version: self.versions[i], time: self.now, epoch: 1, relay: None, held: vec![], shown: vec![], lost: vec![] };
        let body = serde_json::to_vec(&summary).unwrap();
        let heard = Heard { signed: Signed { body: Bytes(body), sig: Bytes(vec![]) }, summary, at: self.now };
        self.peers[i].summary(&id(), heard, None);
    }
}

/// Twelve members on a simulated network: for five minutes frames are delayed, reordered and lost, dials fail and links
/// drop; then nothing is. Each member ends with every member's latest summary, within the connection cap.
#[test]
fn twelve_members_converge_through_loss_and_reconnection() {
    const TICK: u64 = 250;
    const CHAOS: u64 = 5 * 60_000;
    const END: u64 = 20 * 60_000;
    let mut sim = Sim { now: 0, chaos: true, rng: Rng(0x9e37_79b9_7f4a_7c15), peers: Vec::new(), versions: vec![0; N], links: BTreeSet::new(), queue: BTreeMap::new(), sent: 0 };
    for i in 0..N {
        let members = (0..N).filter(|&j| j != i).map(|j| ((Bytes(vec![j as u8]), 0), key(j as u8))).collect();
        let own = Own { me: (Bytes(vec![i as u8]), 0), epoch: 1, log: [1; 32], head: None, public: vec![], earlier: vec![], members, wanted: vec![] };
        sim.peers.push(Peers::new(0, i as u64 + 1, key(i as u8)));
        sim.peers[i].group(id(), own, 0);
    }
    for i in 0..N {
        sim.publish(i);
    }
    let mut now = 0;
    while now < END {
        sim.now = now;
        sim.chaos = now < CHAOS;
        if sim.chaos {
            if sim.rng.below(40) == 0 {
                let i = sim.rng.below(N as u64) as usize;
                sim.publish(i);
            }
            let (a, b) = (sim.rng.below(N as u64) as usize, sim.rng.below(N as u64) as usize);
            if a != b && sim.links.contains(&pair(a, b)) && sim.rng.below(4) == 0 {
                sim.unlink(a, b);
            }
        }
        let due: Vec<(u64, u64)> = sim.queue.range(..=(now, u64::MAX)).map(|(k, _)| *k).collect();
        for k in due {
            let ev = sim.queue.remove(&k).unwrap();
            sim.deliver(ev);
        }
        for i in 0..N {
            let outs = sim.peers[i].poll(now);
            sim.act(i, outs);
        }
        now += TICK;
    }
    for i in 0..N {
        assert!(sim.peers[i].neighbours(&id()).len() <= MAX_CONNECTIONS);
        for j in 0..N {
            let heard = sim.peers[i].heard(&id()).find(|h| h.summary.member == Bytes(vec![j as u8]));
            assert_eq!(heard.map(|h| h.summary.version), Some(sim.versions[j]), "member {i} holds member {j}'s latest summary");
        }
    }
}

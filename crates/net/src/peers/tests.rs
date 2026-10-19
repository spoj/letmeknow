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
        earlier: vec![],
        members: members.iter().map(|&n| (member(n), key(n))).collect(),
        wanted: vec![],
        stale: vec![],
    }
}

fn peers() -> Peers {
    Peers::new(0, key(100))
}

/// Member `n`'s summary of version `version`, signed and heard at `time`, holding `held`.
fn heard(n: u8, version: u64, time: u64, held: Vec<Seqs>) -> Heard {
    let summary = Summary { group: id(), member: Bytes(vec![n]), joined: 0, version, time, epoch: 1, relay: None, held, sealed: vec![] };
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
            Out::Frame(k, Frame::Summary { .. }) => Some(*k),
            _ => None,
        })
        .collect()
}

/// A `hello` of the group at no position, telling these sightings, each `ago` milliseconds old.
fn telling(seen: &[(Key, u64)]) -> Frame {
    let seen = seen.iter().map(|(k, ago)| (Bytes(k.to_vec()), *ago)).collect();
    Frame::Hello { groups: vec![At { group: id(), log: [7; 32], head: None, seen }] }
}

/// The sightings each `hello` in `out` tells, by peer.
fn told(out: &[Out]) -> BTreeMap<Key, BTreeMap<Bytes, u64>> {
    out.iter()
        .filter_map(|o| match o {
            Out::Frame(k, Frame::Hello { groups }) => Some((*k, groups[0].seen.clone())),
            _ => None,
        })
        .collect()
}

/// The other members of a group of twenty, best-ranked first.
fn ranked() -> Vec<Key> {
    let mut ranked: Vec<Key> = (1..=19).map(key).collect();
    ranked.sort_by_key(|k| rank(&id(), &key(100), k));
    ranked
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
    assert_eq!(p.next(0), Some(0), "the rest are due once dials end");
    let rest = dials(&p.poll(1));
    assert_eq!(rest.len(), 2);
    assert!(dials(&p.poll(2)).is_empty());
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

/// Nothing dials again by itself: a push dials the targets not connected, but a failed one only past its backoff, 10 s,
/// then 20 s after the next failure; a connection clears the backoff.
#[test]
fn a_push_dials_again_past_the_backoff_and_a_connection_clears_it() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    assert_eq!(dials(&p.poll(0)), vec![key(1)]);
    p.dialed(&key(1), false, 0);
    assert!(dials(&p.poll(1)).is_empty(), "backing off");
    p.poll(DEBOUNCE);
    assert_eq!(p.next(DEBOUNCE), None, "idle");
    assert!(dials(&p.poll(10_000)).is_empty(), "no redial");
    p.push(&id());
    assert_eq!(dials(&p.poll(10_000)), vec![key(1)]);
    p.dialed(&key(1), false, 10_000);
    p.push(&id());
    assert!(dials(&p.poll(20_000)).is_empty());
    p.push(&id());
    assert_eq!(dials(&p.poll(30_000)), vec![key(1)]);
    p.dialed(&key(1), false, 30_000);
    p.connect(key(1), gs(), false, 35_000);
    p.disconnect(&key(1), 36_000);
    p.push(&id());
    assert_eq!(dials(&p.poll(40_000)), vec![key(1)], "a connection cleared the backoff");
}

/// A failed dial dials the group's next target in its place.
#[test]
fn a_failed_dial_dials_the_next_target() {
    let mut p = peers();
    p.group(id(), own(1, &(1..=19).collect::<Vec<_>>()), 0);
    let targets = p.targets(&id(), 0);
    for k in dials(&p.poll(0)) {
        p.dialed(&k, true, 0);
        p.connect(k, gs(), true, 0);
    }
    let second = dials(&p.poll(1));
    assert_eq!(second.len(), K - DIALS);
    p.dialed(&second[0], false, 1);
    let next = dials(&p.poll(2));
    assert_eq!(next.len(), 1);
    assert!(!targets.contains(&next[0]));
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
    p.summary(&id(), heard(last, 1, 0, vec![]), false);
    assert!(p.targets(&id(), 0).contains(&key(last)));
}

/// Targets are the connected members first, then those seen online, then those heard from, then the best-ranked rest.
#[test]
fn targets_are_the_members_surest_to_be_online() {
    let mut p = peers();
    p.group(id(), own(1, &(1..=19).collect::<Vec<_>>()), 0);
    let r = ranked();
    let worst: Vec<Key> = r.iter().rev().take(4).copied().collect();
    p.connect(worst[0], gs(), true, 0);
    p.frame(&worst[0], &telling(&[(worst[1], 0), (worst[2], 0)]), 0);
    p.summary(&id(), heard(worst[3][0], 1, 0, vec![]), false);
    assert_eq!(p.targets(&id(), 1), vec![worst[0], worst[2], worst[1], worst[3], r[0], r[1]]);
}

/// A sighting of a member this member did not know to be online is news: it dials the member, and tells its other
/// neighbours, but not the one that told it.
#[test]
fn news_of_a_member_online_is_dialed_and_passed_on() {
    let mut p = peers();
    p.group(id(), own(1, &(1..=19).collect::<Vec<_>>()), 0);
    let r = ranked();
    let (a, b, far) = (r[18], r[17], r[16]);
    p.connect(a, gs(), false, 0);
    p.connect(b, gs(), false, 0);
    p.frame(&a, &telling(&[(far, 0)]), 0);
    let out = p.poll(0);
    assert_eq!(dials(&out)[0], far);
    let told = told(&out);
    assert!(told[&b].contains_key(&Bytes(far.to_vec())));
    assert!(!told[&a].contains_key(&Bytes(far.to_vec())));
}

/// A failed dial outweighs the sightings from before it, not those after.
#[test]
fn a_failed_dial_outweighs_the_sightings_before_it() {
    let mut p = peers();
    p.group(id(), own(1, &(1..=19).collect::<Vec<_>>()), 0);
    let r = ranked();
    let (a, far) = (r[18], r[17]);
    p.connect(a, gs(), false, 0);
    p.frame(&a, &telling(&[(far, 0)]), 0);
    assert!(p.targets(&id(), 0).contains(&far));
    p.dialed(&far, false, 5_000);
    assert!(!p.targets(&id(), 20_000).contains(&far), "past its backoff");
    p.frame(&a, &telling(&[(far, 0)]), 20_000);
    assert!(p.targets(&id(), 20_000).contains(&far));
}

/// A `hello` tells a neighbour each sighting once, and again only once it is `RETELL` fresher.
#[test]
fn a_sighting_is_told_again_only_once_it_is_retell_fresher() {
    let mut p = peers();
    let members: Vec<u8> = (1..=8).collect();
    p.group(id(), own(1, &members), 0);
    p.connect(key(1), gs(), false, 0);
    p.connect(key(2), gs(), false, 0);
    let to_1 = |out: Vec<Out>| told(&out).remove(&key(1)).expect("a hello to 1");
    let sighted = BTreeMap::from([(Bytes(key(2).to_vec()), 0)]);
    assert_eq!(to_1(p.poll(0)), sighted);
    let moved = |length| Own { head: Some(Head { log_ref: [7; 32], length, hash: [0; 32], time: 0, sig: Bytes::default() }), ..own(1, &members) };
    p.group(id(), moved(1), 10);
    assert_eq!(to_1(p.poll(10 + DEBOUNCE)), BTreeMap::new());
    p.group(id(), moved(2), RETELL);
    assert_eq!(to_1(p.poll(RETELL + DEBOUNCE)), sighted);
}

/// Sightings count only of current members, from neighbours the group is served to, and for `RECENT`.
#[test]
fn sightings_count_of_members_from_neighbours_of_the_group_for_recent() {
    let mut p = peers();
    p.group(id(), own(1, &(1..=19).collect::<Vec<_>>()), 0);
    let r = ranked();
    let (a, far) = (r[18], r[17]);
    p.connect(key(50), BTreeSet::new(), false, 0);
    p.frame(&key(50), &telling(&[(far, 0)]), 0);
    assert!(!p.targets(&id(), 0).contains(&far), "told by a stranger");
    p.connect(a, gs(), false, 0);
    p.frame(&a, &telling(&[(key(60), 0), (far, 0)]), 0);
    assert!(!p.groups[&id()].seen.contains_key(&key(60)), "not a member");
    assert!(p.targets(&id(), RECENT - 1).contains(&far));
    assert!(!p.targets(&id(), RECENT).contains(&far));
}

/// A neighbour that disconnects was online until then.
#[test]
fn a_neighbour_that_disconnects_was_online_until_then() {
    let mut p = peers();
    p.group(id(), own(1, &(1..=19).collect::<Vec<_>>()), 0);
    let far = ranked()[18];
    p.connect(far, gs(), true, 0);
    p.disconnect(&far, 1_000);
    assert!(p.targets(&id(), 1_000 + RECENT - 1).contains(&far));
    assert!(!p.targets(&id(), 1_000 + RECENT).contains(&far));
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

/// On connecting, a member sends the peer its own summary, and no other.
#[test]
fn connecting_sends_the_own_summary() {
    let mut p = peers();
    p.group(id(), own(1, &[1, 2]), 0);
    p.summary(&id(), heard(2, 3, 0, vec![]), false);
    p.summary(&id(), heard(100, 4, 0, vec![]), true);
    p.connect(key(1), gs(), false, 0);
    let summary = Signed { body: Bytes(vec![]), sig: Bytes(vec![]) };
    let out = p.poll(0);
    assert!(out.contains(&Out::Frame(key(1), Frame::Summary { group: id(), summary })));
    assert_eq!(summaries_to(&out), vec![key(1)]);
}

/// `hello` on connecting carries each served group's position, with the newest signed head of its log.
#[test]
fn hello_on_connect_carries_the_served_groups_positions() {
    let mut p = peers();
    let head = Head { log_ref: [7; 32], length: 3, hash: [0; 32], time: 0, sig: Bytes::default() };
    p.group(id(), Own { head: Some(head.clone()), ..own(1, &[1]) }, 0);
    p.connect(key(1), gs(), false, 0);
    let groups = vec![At { group: id(), log: [7; 32], head: Some(head), seen: BTreeMap::new() }];
    assert!(p.poll(0).contains(&Out::Frame(key(1), Frame::Hello { groups })));
}

/// A neighbour's summary goes no further; this member's own goes to every neighbour, once.
#[test]
fn only_the_own_summary_goes_to_the_neighbours_once() {
    let mut p = peers();
    p.group(id(), own(1, &[1, 2]), 0);
    p.connect(key(1), gs(), false, 0);
    p.connect(key(2), gs(), false, 0);
    p.poll(0);
    assert!(p.summary(&id(), heard(1, 2, 0, vec![]), false));
    assert!(summaries_to(&p.poll(1)).is_empty());
    assert!(p.summary(&id(), heard(100, 2, 0, vec![]), true));
    assert_eq!(summaries_to(&p.poll(2)), vec![key(1), key(2)]);
    assert!(p.poll(3).is_empty());
}

/// A summary of a membership that has been removed is dropped, and a later one is not kept.
#[test]
fn a_removed_membership_s_summary_is_dropped() {
    let mut p = peers();
    p.group(id(), own(1, &[1, 2]), 0);
    p.summary(&id(), heard(1, 2, 0, vec![]), false);
    p.group(id(), own(2, &[2]), 1);
    assert!(p.heard(&id()).all(|h| h.summary.member != Bytes(vec![1])));
    assert!(!p.summary(&id(), heard(1, 3, 2, vec![]), false));
}

/// A summary whose version is not above the one held is not kept.
#[test]
fn a_lower_or_equal_version_is_not_kept() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    assert!(p.summary(&id(), heard(1, 4, 0, vec![]), false));
    assert!(!p.summary(&id(), heard(1, 3, 0, vec![]), false));
    assert!(!p.summary(&id(), heard(1, 4, 0, vec![]), false));
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
        p.summary(&id(), heard(n, 1, 0, ask()), false);
    }
    p
}

/// A seq held only sealed in an ended epoch is asked of holders whose summary of this epoch lists it sealed, and of none
/// else, though every holder lists it held.
#[test]
fn a_seq_held_in_an_ended_epoch_is_asked_only_of_a_holder_that_shows_it_sealed_now() {
    let mut p = peers();
    let mut o = own(2, &[1, 2]);
    o.stale = ask();
    p.group(id(), o, 0);
    for n in [1, 2] {
        p.connect(key(n), gs(), false, 0);
    }
    p.summary(&id(), heard(1, 1, 0, ask()), false);
    let mut sealed_now = heard(2, 1, 0, ask());
    (sealed_now.summary.epoch, sealed_now.summary.sealed) = (2, ask());
    p.summary(&id(), sealed_now, false);
    assert_eq!(wants(&p.poll(0)), vec![(key(2), ask())]);
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
    p.summary(&id(), heard(1, 1, 0, vec![seqs(1, &[(5, 5)])]), false);
    p.summary(&id(), heard(2, 1, 0, ask()), false);
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
    p.frame(&key(1), &answer, 100);
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

/// A peer that announced what this member wants is asked for it, though no summary shows it held, and is given
/// `LARGE_TIMEOUT` to answer, as what it announced is large, before the next holder is asked.
#[test]
fn an_announcer_is_asked_and_given_long_to_answer() {
    let mut p = peers();
    let mut o = own(1, &[1, 2]);
    o.wanted = ask();
    p.group(id(), o, 0);
    for n in [1, 2] {
        p.connect(key(n), gs(), false, 0);
    }
    p.frame(&key(1), &Frame::Have { group: id(), held: ask() }, 0);
    p.summary(&id(), heard(2, 1, 0, ask()), false);
    assert_eq!(wants(&p.poll(0)), vec![(key(1), ask())]);
    assert!(wants(&p.poll(LARGE_TIMEOUT - 1)).is_empty());
    assert_eq!(wants(&p.poll(LARGE_TIMEOUT)), vec![(key(2), ask())]);
}

/// What a peer announced holds for its connection only: a new one starts with nothing announced.
#[test]
fn an_announcement_ends_with_its_connection() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    p.connect(key(1), gs(), false, 0);
    p.frame(&key(1), &Frame::Have { group: id(), held: ask() }, 0);
    assert!(p.holder(&id(), &ask(), 0));
    p.connect(key(1), gs(), false, 10);
    assert!(!p.holder(&id(), &ask(), 10));
}

/// A request times out 10 s after it was made, however busy the connection is with other frames.
#[test]
fn a_request_times_out_though_the_holder_sends_other_frames() {
    let mut p = both_hold();
    p.poll(0);
    p.frame(&key(1), &Frame::Hello { groups: vec![] }, TIMEOUT - 1);
    assert_eq!(wants(&p.poll(TIMEOUT)), vec![(key(2), ask())]);
}

/// The commit wait dials holders four at a time, those that hold the lowest lacking seq first.
#[test]
fn the_commit_wait_dials_four_holders_at_a_time() {
    let mut p = peers();
    p.group(id(), own(1, &[1, 2, 3, 4, 5, 6]), 0);
    let lacking = vec![seqs(1, &[(5, 9)])];
    for n in 1..=6 {
        p.summary(&id(), heard(n, 1, 0, vec![seqs(1, &[(10 - u64::from(n), 9)])]), false);
    }
    assert!(p.wait(&id(), &lacking, 0, 0));
    assert_eq!(dials(&p.poll(0)), vec![key(5), key(6), key(4), key(3)]);
}

/// A peer that stops being served a group, and is served it again, is sent the own summary anew: what it held before
/// is not assumed.
#[test]
fn a_peer_served_a_group_again_is_sent_the_own_summary_anew() {
    let mut p = peers();
    p.group(id(), own(1, &[1, 2]), 0);
    p.summary(&id(), heard(100, 1, 0, vec![]), true);
    p.connect(key(1), gs(), false, 0);
    assert_eq!(summaries_to(&p.poll(0)), vec![key(1)]);
    p.served(&key(1), BTreeSet::new(), 10);
    p.served(&key(1), gs(), 20);
    assert_eq!(summaries_to(&p.poll(30)), vec![key(1)]);
}

/// Strikes last for the epoch: when it grows, the struck holder is asked again.
#[test]
fn strikes_clear_when_the_epoch_grows() {
    let mut p = peers();
    let mut o = own(1, &[1]);
    o.wanted = ask();
    p.group(id(), o.clone(), 0);
    p.connect(key(1), gs(), false, 0);
    p.summary(&id(), heard(1, 1, 0, ask()), false);
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
    p.summary(&id(), heard(1, 1, 0, ask()), false);
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
    p.summary(&id(), heard(1, 1, 0, ask()), false);
    let out = p.poll(0);
    assert_eq!(dials(&out), vec![key(1)]);
    assert!(wants(&out).is_empty());
}

/// Nothing lacking applies at once.
#[test]
fn wait_applies_when_nothing_is_lacking() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    assert!(!p.wait(&id(), &[], 0, 0));
}

/// A wait holds while a connected holder has not been asked for a lacking seq, and asks for it at once.
#[test]
fn wait_holds_while_a_connected_holder_is_untried() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    p.connect(key(1), gs(), false, 0);
    let lacking = vec![seqs(1, &[(5, 5)])];
    p.summary(&id(), heard(1, 1, 0, lacking.clone()), false);
    assert!(p.wait(&id(), &lacking, 0, 1_000));
    assert_eq!(wants(&p.poll(1_000)), vec![(key(1), lacking.clone())]);
}

/// Once every holder is struck for the lacking seqs, the wait loses them.
#[test]
fn wait_loses_once_every_holder_is_struck() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    p.connect(key(1), gs(), false, 0);
    let lacking = vec![seqs(1, &[(5, 5)])];
    p.summary(&id(), heard(1, 1, 0, lacking.clone()), false);
    assert!(p.wait(&id(), &lacking, 0, 0));
    p.poll(0);
    p.frame(&key(1), &Frame::Held { group: id(), items: vec![], answers: Some(lacking.clone()) }, 100);
    assert!(!p.wait(&id(), &lacking, 0, HEAR));
}

/// A wait holds `HEAR` after the member came online though no summary shows a holder yet: a member back from offline
/// hears the summaries that show them within it.
#[test]
fn a_wait_holds_for_summaries_after_coming_online() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    let lacking = vec![seqs(1, &[(5, 5)])];
    p.connect(key(1), gs(), false, 1_000);
    assert!(p.wait(&id(), &lacking, 0, 1_000));
    p.summary(&id(), heard(1, 1, 1_500, lacking.clone()), false);
    assert!(p.wait(&id(), &lacking, 0, 1_000 + HEAR), "a holder is untried");
    p.disconnect(&key(1), 1_000 + HEAR);
    p.dialed(&key(1), false, 1_000 + HEAR);
    assert!(!p.wait(&id(), &lacking, 0, 1_000 + HEAR));
}

/// A wait gives up two minutes after the commit was read, even with an untried holder.
#[test]
fn wait_gives_up_two_minutes_after_the_commit_was_read() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    p.connect(key(1), gs(), false, 0);
    let lacking = vec![seqs(1, &[(5, 5)])];
    p.summary(&id(), heard(1, 1, 0, lacking.clone()), false);
    assert!(p.wait(&id(), &lacking, 0, WAIT - 1));
    assert!(!p.wait(&id(), &lacking, 0, WAIT));
}

/// A holder whose backoff has ended is untried again: a wait that starts then dials it.
#[test]
fn a_holder_past_its_backoff_is_dialed_when_the_wait_starts() {
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    let lacking = vec![seqs(1, &[(5, 5)])];
    p.summary(&id(), heard(1, 1, 0, lacking.clone()), false);
    p.dialed(&key(1), false, HEAR - 1);
    assert!(!p.wait(&id(), &lacking, 0, HEAR), "backing off");
    assert!(p.wait(&id(), &lacking, 31_000, 31_000));
    assert_eq!(dials(&p.poll(31_000)), vec![key(1)]);
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

/// `hello` is taken from anyone; the rest only from admitted peers.
#[test]
fn the_gate() {
    let hello = Frame::Hello { groups: vec![] };
    assert!(takes(&hello, false));
    let want = Frame::Want { group: id(), epoch: 1, wants: vec![] };
    assert!(!takes(&want, false) && takes(&want, true));
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
    /// Members whose dials fail after 32 s, as iroh's do to a key nobody holds.
    offline: BTreeSet<usize>,
    /// Per member, its dials to members offline.
    offline_dials: Vec<u64>,
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
        self.peers[a].disconnect(&key(b as u8), self.now);
        self.peers[b].disconnect(&key(a as u8), self.now);
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
                    let to = to[0] as usize;
                    if self.offline.contains(&to) {
                        self.offline_dials[at] += 1;
                        self.schedule(32_000, Ev::Dialed { from: at, to, ok: false });
                    } else {
                        let ok = !self.chaos || self.rng.below(10) < 8;
                        let delay = 100 + self.rng.below(2_000);
                        self.schedule(delay, Ev::Dialed { from: at, to, ok });
                    }
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
                if let Frame::Summary { group, summary: signed } = frame {
                    let summary: Summary = serde_json::from_slice(&signed.body.0).unwrap();
                    self.peers[to].summary(&group, Heard { signed, summary, at: self.now }, false);
                } else {
                    self.peers[to].frame(&key(from as u8), &frame, self.now);
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

    /// Member `i` signs a new summary, and has something to push, as a member that sends.
    fn publish(&mut self, i: usize) {
        self.versions[i] += 1;
        let summary = Summary { group: id(), member: Bytes(vec![i as u8]), joined: 0, version: self.versions[i], time: self.now, epoch: 1, relay: None, held: vec![], sealed: vec![] };
        let body = serde_json::to_vec(&summary).unwrap();
        let heard = Heard { signed: Signed { body: Bytes(body), sig: Bytes(vec![]) }, summary, at: self.now };
        self.peers[i].summary(&id(), heard, true);
        self.peers[i].push(&id());
    }
}

/// Twelve members on a simulated network: for five minutes frames are delayed, reordered and lost, dials fail and links
/// drop, and members send; then nothing is lost, and each sends once more. Each member ends connected, within the cap,
/// with each neighbour's latest summary, and nothing due.
#[test]
fn twelve_members_converge_through_loss_and_reconnection() {
    const TICK: u64 = 250;
    const CHAOS: u64 = 5 * 60_000;
    const END: u64 = 20 * 60_000;
    let mut sim = Sim { now: 0, chaos: true, rng: Rng(0x9e37_79b9_7f4a_7c15), peers: Vec::new(), versions: vec![0; N], links: BTreeSet::new(), queue: BTreeMap::new(), sent: 0, offline: BTreeSet::new(), offline_dials: vec![0; N] };
    for i in 0..N {
        let members = (0..N).filter(|&j| j != i).map(|j| ((Bytes(vec![j as u8]), 0), key(j as u8))).collect();
        let own = Own { me: (Bytes(vec![i as u8]), 0), epoch: 1, log: [1; 32], head: None, earlier: vec![], members, wanted: vec![], stale: vec![] };
        sim.peers.push(Peers::new(0, key(i as u8)));
        sim.peers[i].group(id(), own, 0);
    }
    for i in 0..N {
        sim.publish(i);
    }
    let mut now = 0;
    while now < END {
        sim.now = now;
        if sim.chaos && now >= CHAOS {
            sim.chaos = false;
            for i in 0..N {
                sim.publish(i);
            }
        }
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
        let neighbours = sim.peers[i].neighbours(&id());
        assert!(!neighbours.is_empty() && neighbours.len() <= MAX_CONNECTIONS);
        for j in neighbours.iter().map(|k| k[0] as usize) {
            let heard = sim.peers[i].heard(&id()).find(|h| h.summary.member == Bytes(vec![j as u8]));
            assert_eq!(heard.map(|h| h.summary.version), Some(sim.versions[j]), "member {i} holds neighbour {j}'s latest summary");
        }
        assert!(sim.peers[i].next(now).is_none_or(|at| at > now + 60_000), "member {i} is idle");
    }
}

/// A peer that sent what shows it is past this member, as a message of a later epoch, is sent a `hello`, so that it sends
/// the entries this member lacks: nothing else would tell it where this member is.
#[test]
fn a_peer_past_this_member_is_told_where_it_is() {
    let hellos = |out: &[Out]| out.iter().filter(|o| matches!(o, Out::Frame(_, Frame::Hello { .. }))).count();
    let mut p = peers();
    p.group(id(), own(1, &[1]), 0);
    p.connect(key(1), gs(), false, 0);
    assert_eq!(hellos(&p.poll(DEBOUNCE)), 1, "on connecting");
    assert_eq!(hellos(&p.poll(DEBOUNCE + 1)), 0);
    p.behind(&key(1));
    assert_eq!(p.next(DEBOUNCE + 2), Some(DEBOUNCE + 2));
    assert_eq!(hellos(&p.poll(DEBOUNCE + 2)), 1);
}

/// Of 200 members only 20 are online, linked in a ring at first; a dial to any other fails after 32 s. The 20 learn of
/// each other from the sightings their neighbours tell: past the dials of their first poll, they dial no member
/// offline, and end in one piece. A newcomer that takes its admitter's `hello` before its first poll, as a joiner does,
/// has six neighbours within a minute, without dialing a member offline.
#[test]
fn members_online_in_a_mostly_offline_group_find_each_other() {
    const MEMBERS: usize = 200;
    const ONLINE: usize = 20;
    const JOIN: u64 = 10 * 60_000;
    const TICK: u64 = 1_000;
    let newcomer = ONLINE;
    let offline = (ONLINE + 1..MEMBERS).collect();
    let mut sim = Sim { now: 0, chaos: false, rng: Rng(0x2545_f491_4f6c_dd1d), peers: Vec::new(), versions: vec![0; MEMBERS], links: BTreeSet::new(), queue: BTreeMap::new(), sent: 0, offline, offline_dials: vec![0; MEMBERS] };
    for i in 0..MEMBERS {
        let members = (0..MEMBERS).filter(|&j| j != i).map(|j| ((Bytes(vec![j as u8]), 0), key(j as u8))).collect();
        let own = Own { me: (Bytes(vec![i as u8]), 0), epoch: 1, log: [1; 32], head: None, earlier: vec![], members, wanted: vec![], stale: vec![] };
        sim.peers.push(Peers::new(0, key(i as u8)));
        sim.peers[i].group(id(), own, 0);
    }
    for i in 0..ONLINE {
        sim.connect(i, (i + 1) % ONLINE);
    }
    let mut now = 0;
    while now <= JOIN + 60_000 {
        sim.now = now;
        if now == JOIN {
            sim.connect(newcomer, 0);
            for out in sim.peers[0].poll(now) {
                match out {
                    Out::Frame(to, frame) if to == key(newcomer as u8) => sim.peers[newcomer].frame(&key(0), &frame, now),
                    out => sim.act(0, vec![out]),
                }
            }
        }
        let due: Vec<(u64, u64)> = sim.queue.range(..=(now, u64::MAX)).map(|(k, _)| *k).collect();
        for k in due {
            let ev = sim.queue.remove(&k).unwrap();
            sim.deliver(ev);
        }
        for i in (0..ONLINE).chain((now >= JOIN).then_some(newcomer)) {
            let outs = sim.peers[i].poll(now);
            sim.act(i, outs);
        }
        now += TICK;
    }
    assert!(sim.offline_dials[..ONLINE].iter().all(|&n| n <= DIALS as u64), "{:?}", &sim.offline_dials[..ONLINE]);
    assert_eq!(sim.offline_dials[newcomer], 0);
    assert!(sim.peers[newcomer].neighbours(&id()).len() >= K);
    let mut reached = BTreeSet::from([0]);
    let mut next = vec![0];
    while let Some(i) = next.pop() {
        for k in sim.peers[i].neighbours(&id()) {
            if reached.insert(k[0] as usize) {
                next.push(k[0] as usize);
            }
        }
    }
    assert_eq!(reached, (0..=ONLINE).collect(), "one piece");
}

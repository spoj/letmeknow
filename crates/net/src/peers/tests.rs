use super::*;

const G: u8 = 7;

fn head(log: u8, length: u64) -> Head {
    Head { log: Bytes(vec![log]), length, hash: Bytes::default(), time: 0, sig: Bytes::default() }
}

fn id(n: u8) -> Bytes {
    Bytes(vec![n])
}

fn key(n: u8) -> Key {
    [n; 32]
}

fn r(ranges: &[(u64, u64)]) -> Ranges {
    Ranges::from(ranges.to_vec())
}

fn served(groups: &[u8]) -> BTreeSet<Bytes> {
    groups.iter().map(|&g| id(g)).collect()
}

fn own(group: u8, length: u64, held: Ranges, lacking: Ranges) -> Own {
    Own { head: head(group, length), held, read: Ranges::default(), lacking, keys: vec![] }
}

fn summary(group: u8, length: u64, held: Ranges, fetching: Ranges) -> Summary {
    Summary { group: id(group), head: head(group, length), held, read: Ranges::default(), fetching }
}

fn hello(summaries: Vec<Summary>) -> Frame {
    Frame::Hello { groups: summaries, heads: vec![] }
}

fn hellos(out: &[Out]) -> Vec<(Key, Vec<u8>)> {
    out.iter()
        .filter_map(|o| match o {
            Out::Frame(k, Frame::Hello { groups, .. }) => Some((*k, groups.iter().map(|s| s.group.0[0]).collect())),
            _ => None,
        })
        .collect()
}

fn wants(out: &[Out]) -> Vec<(Key, Ranges)> {
    out.iter()
        .filter_map(|o| match o {
            Out::Frame(k, Frame::Want { positions, .. }) => Some((*k, positions.clone())),
            _ => None,
        })
        .collect()
}

fn answered(items: &[u64], asked: Ranges) -> Frame {
    let items = items.iter().map(|&position| Item { position, ciphertext: Bytes(vec![0]) }).collect();
    Frame::Messages { group: id(G), items, answers: Some(asked) }
}

/// A member in group G at head 10, lacking `lacking`, with its first summaries sent.
fn member(lacking: Ranges) -> Peers {
    let mut p = Peers::new(0);
    p.group(id(G), own(G, 10, r(&[(1, 10)]).difference(&lacking), lacking), 0);
    p.poll(DEBOUNCE);
    p
}

#[test]
fn hello_on_connect_carries_every_served_group_and_their_key_heads() {
    let mut p = Peers::new(0);
    for (g, keys) in [(1, vec![head(100, 3)]), (2, vec![head(100, 3), head(101, 1)]), (3, vec![head(102, 1)])] {
        p.group(id(g), Own { keys, ..own(g, 5, r(&[(1, 5)]), Ranges::default()) }, 0);
    }
    p.poll(DEBOUNCE);
    p.connect(key(1), served(&[1, 2]), DEBOUNCE);
    let out = p.poll(DEBOUNCE);
    let [Out::Frame(k, Frame::Hello { groups, heads })] = &out[..] else { panic!("{out:?}") };
    assert_eq!(*k, key(1));
    assert_eq!(groups.iter().map(|s| s.group.clone()).collect::<Vec<_>>(), vec![id(1), id(2)]);
    assert_eq!(heads, &vec![head(100, 3), head(101, 1)]);
    assert!(p.poll(DEBOUNCE + 1).is_empty());
}

#[test]
fn a_change_goes_after_about_a_second_with_only_the_changed_groups() {
    let mut p = Peers::new(0);
    for g in [1, 2, 3] {
        p.group(id(g), own(g, 5, r(&[(1, 5)]), Ranges::default()), 0);
    }
    p.poll(DEBOUNCE);
    p.connect(key(1), served(&[1, 2]), DEBOUNCE);
    p.connect(key(2), served(&[2, 3]), DEBOUNCE);
    p.connect(key(3), served(&[1]), DEBOUNCE);
    p.poll(DEBOUNCE);
    p.group(id(2), own(2, 6, r(&[(1, 6)]), Ranges::default()), 2_000);
    assert!(p.poll(2_500).is_empty());
    p.group(id(2), own(2, 7, r(&[(1, 7)]), Ranges::default()), 2_800);
    p.group(id(1), own(1, 5, r(&[(1, 5)]), Ranges::default()), 2_900);
    assert_eq!(hellos(&p.poll(3_000)), vec![(key(1), vec![2]), (key(2), vec![2])]);
    assert!(p.poll(5_000).is_empty(), "an unchanged state sends nothing");
}

#[test]
fn every_summary_goes_on_the_period() {
    let mut p = Peers::new(0);
    for g in [1, 2] {
        p.group(id(g), own(g, 5, r(&[(1, 5)]), Ranges::default()), 0);
    }
    p.connect(key(1), served(&[1, 2]), 0);
    p.poll(0);
    p.poll(DEBOUNCE);
    assert!(p.poll(PERIOD - 1).is_empty());
    assert_eq!(hellos(&p.poll(PERIOD)), vec![(key(1), vec![1, 2])]);
}

#[test]
fn a_gate_opening_sends_the_group_at_once() {
    let mut p = Peers::new(0);
    for g in [1, 2] {
        p.group(id(g), own(g, 5, r(&[(1, 5)]), Ranges::default()), 0);
    }
    p.poll(DEBOUNCE);
    p.connect(key(1), served(&[1]), DEBOUNCE);
    p.poll(DEBOUNCE);
    p.served(&key(1), served(&[1, 2]), 1_500);
    assert_eq!(hellos(&p.poll(1_500)), vec![(key(1), vec![2])]);
}

/// A member that just joined a group has dialed its members only now: it waits as one that just came online.
#[test]
fn a_group_just_joined_waits_for_dials_before_a_loss() {
    let mut p = Peers::new(0);
    p.connect(key(1), served(&[]), 0);
    p.group(id(G), own(G, 10, r(&[(1, 9)]), r(&[(10, 10)])), 60_000);
    assert_eq!(p.wait(&id(G), &r(&[(10, 10)]), 60_000 + ONLINE - 1), Decision::Wait);
    assert_eq!(p.wait(&id(G), &r(&[(10, 10)]), 60_000 + ONLINE), Decision::Lose(r(&[(10, 10)])));
}

/// A joiner takes none of the summaries members send it as they apply its Add, before its Welcome comes: its own first
/// summary of the group draws theirs again, once.
#[test]
fn a_peer_s_first_summary_of_a_group_is_answered_with_ours() {
    let mut p = member(Ranges::default());
    p.connect(key(1), served(&[G]), DEBOUNCE);
    assert_eq!(hellos(&p.poll(DEBOUNCE)), vec![(key(1), vec![G])]);
    let theirs = summary(G, 10, Ranges::default(), Ranges::default());
    p.frame(&key(1), &hello(vec![theirs.clone()]), 1_500);
    assert_eq!(hellos(&p.poll(1_500)), vec![(key(1), vec![G])]);
    p.frame(&key(1), &hello(vec![theirs]), 1_600);
    assert!(hellos(&p.poll(1_600)).is_empty());
}

#[test]
fn summaries_are_saved_whatever_the_gate_but_used_only_while_it_admits() {
    let mut p = member(r(&[(4, 4)]));
    p.connect(key(1), served(&[]), DEBOUNCE);
    let theirs = summary(G, 10, r(&[(1, 10)]), Ranges::default());
    let heard = p.frame(&key(1), &hello(vec![theirs.clone()]), 1_100);
    assert_eq!(heard, vec![Heard { peer: Bytes::from(key(1)), summary: theirs, at: 1_100 }]);
    assert!(wants(&p.poll(1_100)).is_empty());
    assert_eq!(p.wait(&id(G), &r(&[(4, 4)]), 4_000), Decision::Lose(r(&[(4, 4)])), "an unadmitted holder does not hold the wait");
    p.served(&key(1), served(&[G]), 4_000);
    assert_eq!(wants(&p.poll(4_000)), vec![(key(1), r(&[(4, 4)]))]);
    p.served(&key(1), served(&[]), 4_100);
    p.connect(key(2), served(&[G]), 4_100);
    p.frame(&key(2), &hello(vec![summary(G, 10, r(&[(1, 10)]), Ranges::default())]), 4_100);
    assert_eq!(wants(&p.poll(4_100)), vec![(key(2), r(&[(4, 4)]))], "a closed gate gives up its request");
}

#[test]
fn repair_asks_in_position_order_of_the_lowest_key_holder_one_request_at_a_time() {
    let mut p = member(r(&[(3, 4), (7, 7)]));
    for (k, held) in [(5, r(&[(1, 10)])), (2, r(&[(1, 2), (4, 10)])), (1, r(&[(1, 2), (4, 10)]))] {
        p.connect(key(k), served(&[G]), DEBOUNCE);
        p.frame(&key(k), &hello(vec![summary(G, 10, held, Ranges::default())]), DEBOUNCE);
    }
    assert_eq!(wants(&p.poll(DEBOUNCE)), vec![(key(5), r(&[(3, 4), (7, 7)]))], "only 5 holds the first, 3");
    assert!(wants(&p.poll(2_000)).is_empty(), "one request outstanding");
    p.frame(&key(5), &answered(&[3], r(&[(3, 4), (7, 7)])), 2_000);
    p.group(id(G), own(G, 10, r(&[(1, 3), (5, 6), (8, 10)]), r(&[(4, 4), (7, 7)])), 2_000);
    assert_eq!(wants(&p.poll(2_000)), vec![(key(1), r(&[(4, 4), (7, 7)]))], "omitted, so asked of the lowest key left");
}

#[test]
fn an_answer_settles_its_request_until_the_holders_next_summary() {
    let mut p = member(r(&[(3, 4)]));
    for k in [1, 2] {
        p.connect(key(k), served(&[G]), DEBOUNCE);
        p.frame(&key(k), &hello(vec![summary(G, 10, r(&[(1, 10)]), Ranges::default())]), DEBOUNCE);
    }
    assert_eq!(wants(&p.poll(DEBOUNCE)), vec![(key(1), r(&[(3, 4)]))]);
    p.frame(&key(1), &answered(&[3], r(&[(3, 4)])), 1_100);
    p.group(id(G), own(G, 10, r(&[(1, 3), (5, 10)]), r(&[(4, 4)])), 1_100);
    assert_eq!(wants(&p.poll(1_100)), vec![(key(2), r(&[(4, 4)]))]);
    p.frame(&key(2), &answered(&[], r(&[(4, 4)])), 1_200);
    assert!(wants(&p.poll(1_200)).is_empty(), "both omitted 4");
    assert!(p.summary(&id(G)).fetching.is_empty());
    p.frame(&key(1), &hello(vec![summary(G, 10, r(&[(1, 10)]), Ranges::default())]), 1_300);
    assert_eq!(wants(&p.poll(1_300)), vec![(key(1), r(&[(4, 4)]))]);
}

#[test]
fn the_timeout_runs_from_the_last_frame_from_the_holder() {
    let mut p = member(r(&[(4, 4)]));
    for k in [1, 2] {
        p.connect(key(k), served(&[G]), DEBOUNCE);
        p.frame(&key(k), &hello(vec![summary(G, 10, r(&[(1, 10)]), Ranges::default())]), DEBOUNCE);
    }
    assert_eq!(wants(&p.poll(DEBOUNCE)), vec![(key(1), r(&[(4, 4)]))]);
    let push = Frame::Messages { group: id(9), items: vec![], answers: None };
    p.frame(&key(1), &push, 8_000);
    assert!(wants(&p.poll(8_000 + TIMEOUT - 1)).is_empty());
    assert_eq!(wants(&p.poll(8_000 + TIMEOUT)), vec![(key(2), r(&[(4, 4)]))]);
    p.frame(&key(2), &answered(&[], r(&[(4, 4)])), 19_000);
    assert!(wants(&p.poll(19_000)).is_empty(), "1 is stalled until it sends again");
    p.frame(&key(1), &push, 20_000);
    assert_eq!(wants(&p.poll(20_000)), vec![(key(1), r(&[(4, 4)]))]);
}

#[test]
fn a_position_read_under_two_seconds_ago_waits_except_before_a_commit() {
    let mut p = member(Ranges::default());
    p.connect(key(1), served(&[G]), DEBOUNCE);
    p.frame(&key(1), &hello(vec![summary(G, 12, r(&[(1, 12)]), Ranges::default())]), DEBOUNCE);
    p.group(id(G), own(G, 11, r(&[(1, 10)]), r(&[(11, 11)])), 5_000);
    assert!(wants(&p.poll(5_000 + HOLD_OFF - 1)).is_empty());
    assert_eq!(wants(&p.poll(5_000 + HOLD_OFF)), vec![(key(1), r(&[(11, 11)]))]);
    assert_eq!(p.summary(&id(G)).fetching, r(&[(11, 11)]));

    p.group(id(G), own(G, 12, r(&[(1, 11)]), r(&[(12, 12)])), 8_000);
    p.frame(&key(1), &answered(&[11], r(&[(11, 11)])), 8_000);
    assert!(wants(&p.poll(8_000)).is_empty());
    assert_eq!(p.wait(&id(G), &r(&[(12, 12)]), 8_000), Decision::Wait);
    assert_eq!(wants(&p.poll(8_000)), vec![(key(1), r(&[(12, 12)]))]);
}

#[test]
fn repair_and_the_wait_use_only_summaries_heard_on_the_current_connection() {
    let mut p = member(r(&[(4, 4)]));
    p.connect(key(1), served(&[G]), DEBOUNCE);
    p.frame(&key(1), &hello(vec![summary(G, 10, r(&[(1, 10)]), Ranges::default())]), DEBOUNCE);
    assert_eq!(wants(&p.poll(DEBOUNCE)), vec![(key(1), r(&[(4, 4)]))]);
    p.connect(key(1), served(&[G]), 1_500);
    assert!(wants(&p.poll(1_500)).is_empty());
    assert_eq!(p.wait(&id(G), &r(&[(4, 4)]), 4_000), Decision::Lose(r(&[(4, 4)])));
    p.frame(&key(1), &hello(vec![summary(G, 10, r(&[(1, 10)]), Ranges::default())]), 4_000);
    assert_eq!(wants(&p.poll(4_000)), vec![(key(1), r(&[(4, 4)]))]);
    p.disconnect(&key(1));
    assert!(wants(&p.poll(4_100)).is_empty());
}

#[test]
fn a_member_comes_online_as_it_starts_or_connects_after_none() {
    let lacking = r(&[(4, 4)]);
    let mut p = member(lacking.clone());
    assert_eq!(p.wait(&id(G), &lacking, ONLINE - 1), Decision::Wait);
    p.connect(key(1), served(&[G]), 10_000);
    assert_eq!(p.wait(&id(G), &lacking, 10_000 + ONLINE - 1), Decision::Wait, "its first connection after none");
    p.connect(key(2), served(&[G]), 20_000);
    p.connect(key(1), served(&[G]), 20_000);
    assert_eq!(p.wait(&id(G), &lacking, 20_000), Decision::Lose(lacking.clone()), "another, or one replaced, is not");
    p.disconnect(&key(1));
    p.disconnect(&key(2));
    p.connect(key(1), served(&[G]), 30_000);
    assert_eq!(p.wait(&id(G), &lacking, 30_000), Decision::Wait);
}

#[test]
fn entries_go_once_to_a_peer_whose_head_is_shorter() {
    let mut p = Peers::new(0);
    p.group(id(G), Own { keys: vec![head(100, 4)], ..own(G, 10, r(&[(1, 10)]), Ranges::default()) }, 0);
    p.connect(key(1), served(&[G]), 0);
    p.poll(0);
    p.frame(&key(1), &Frame::Hello { groups: vec![summary(G, 6, r(&[(1, 6)]), Ranges::default())], heads: vec![head(100, 2)] }, 100);
    let entries: Vec<Out> = p.poll(100).into_iter().filter(|o| matches!(o, Out::Entries { .. })).collect();
    assert_eq!(entries, vec![Out::Entries { peer: key(1), log: id(G), after: 6 }, Out::Entries { peer: key(1), log: id(100), after: 2 }]);
    assert!(p.poll(200).iter().all(|o| !matches!(o, Out::Entries { .. })));
    p.group(id(G), Own { keys: vec![head(100, 4)], ..own(G, 11, r(&[(1, 11)]), Ranges::default()) }, 300);
    assert_eq!(p.poll(300), vec![Out::Entries { peer: key(1), log: id(G), after: 10 }]);
}

#[test]
fn the_wait_rule() {
    let lacking = r(&[(4, 5)]);
    let holds = summary(G, 10, r(&[(1, 4)]), Ranges::default());
    let fetches = summary(G, 10, r(&[(1, 3)]), r(&[(5, 5)]));
    let neither = summary(G, 10, r(&[(1, 3), (6, 10)]), r(&[(6, 6)]));
    assert_eq!(wait(&Ranges::default(), &[], 0, 0), Decision::Apply, "nothing lacking applies at once");
    assert_eq!(wait(&lacking, &[&neither, &holds], 60_000, 9_999), Decision::Wait);
    assert_eq!(wait(&lacking, &[&fetches], 60_000, 9_999), Decision::Wait);
    assert_eq!(wait(&lacking, &[&holds], 60_000, QUIET), Decision::Lose(lacking.clone()), "10 s without progress");
    assert_eq!(wait(&lacking, &[&neither], ONLINE - 1, 0), Decision::Wait, "dials may land");
    assert_eq!(wait(&lacking, &[&neither], ONLINE, 0), Decision::Lose(lacking.clone()));
    assert_eq!(wait(&lacking, &[], ONLINE, 0), Decision::Lose(lacking));
}

#[test]
fn progress_is_a_new_summary_a_connection_or_a_ciphertext() {
    let lacking = r(&[(4, 5)]);
    let mut p = member(lacking.clone());
    p.connect(key(1), served(&[G]), DEBOUNCE);
    let holds = hello(vec![summary(G, 10, r(&[(1, 10)]), Ranges::default())]);
    p.frame(&key(1), &holds, 2_000);
    assert_eq!(p.wait(&id(G), &lacking, 2_000 + QUIET - 1), Decision::Wait);
    p.frame(&key(1), &holds, 11_000);
    assert_eq!(p.wait(&id(G), &lacking, 2_000 + QUIET), Decision::Lose(lacking.clone()), "the same summary again is no progress");
    p.group(id(G), own(G, 10, r(&[(1, 4), (6, 10)]), r(&[(5, 5)])), 12_500);
    assert_eq!(p.wait(&id(G), &r(&[(5, 5)]), 22_499), Decision::Wait);
    p.connect(key(1), served(&[G]), 22_600);
    assert_eq!(p.wait(&id(G), &r(&[(5, 5)]), 31_000), Decision::Lose(r(&[(5, 5)])), "1's summary went with its connection");
}

#[test]
fn an_answer_stops_at_about_a_mebibyte() {
    let asked = r(&[(1, 6)]);
    let held = r(&[(1, 2), (4, 6)]);
    let Frame::Messages { items, answers, .. } = answer(id(G), &asked, &held, |_| Some(vec![0; ANSWER / 2])) else { panic!() };
    assert_eq!(items.iter().map(|i| i.position).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(answers, Some(r(&[(1, 3)])), "3, not held, is settled too");
    let Frame::Messages { items, answers, .. } = answer(id(G), &asked, &Ranges::default(), |_| unreachable!()) else { panic!() };
    assert!(items.is_empty());
    assert_eq!(answers, Some(asked));
}

#[test]
fn the_gate() {
    let g = || id(G);
    let checked = [hello(vec![]), Frame::Entries { log: g(), entries: vec![], head: head(G, 0) }, answered(&[], Ranges::default())];
    for frame in &checked {
        assert!(takes(frame, false, false));
        assert!(!sends(frame, false, true));
    }
    for frame in [Frame::Want { group: g(), positions: Ranges::default() }, Frame::WantFiles { group: g(), files: vec![] }, Frame::Have { group: g(), files: vec![] }] {
        assert!(!takes(&frame, false, true) && takes(&frame, true, false));
    }
    for frame in [Frame::State { group: g(), link: None }, Frame::Live { group: g(), items: vec![] }] {
        assert!(!takes(&frame, true, false) && !takes(&frame, false, true) && takes(&frame, true, true));
        assert!(!sends(&frame, true, false) && sends(&frame, true, true));
    }
}

mod schedules;

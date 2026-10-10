//! The simulation replays a seed exactly, and the runs that found bugs pass: each with the actions it shrank to, as the
//! generator of the time made them.

use std::sync::Mutex;

use lmk_sim::{Act, Action, Options, Outcome, generate, run};

/// A process runs one simulation at a time: its randomness is the process's.
static ONE: Mutex<()> = Mutex::new(());

fn replay(seed: u64, options: Options, actions: &[Action]) -> Outcome {
    let _one = ONE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    run(seed, actions, options)
}

/// The run passes, checking every property.
fn passes(seed: u64, members: usize, actions: Vec<(u64, Act)>) {
    let options = Options { members, actions: actions.len() };
    let actions: Vec<Action> = actions.into_iter().map(|(at, act)| Action { at, act }).collect();
    let outcome = replay(seed, options, &actions);
    assert!(outcome.failure.is_none(), "{}", outcome.log.join("\n"));
}

#[test]
fn a_seed_replays_exactly() {
    let actions: Vec<Action> = generate(7, Options::default()).into_iter().take(30).collect();
    assert_eq!(replay(7, Options::default(), &actions).trace, replay(7, Options::default(), &actions).trace);
}

/// Lost answers, crashes as a member writes, members down and woken, and an attacker's entries replay exactly too.
#[test]
fn the_world_s_own_actions_replay_exactly() {
    use lmk_sim::{Forgery, Output};
    let invite = |m, group, n| Act::Invite { m, group, n, label: false, to: None, wait: 0, race: None };
    let actions: Vec<Action> = [
        (0, Act::CreateIdentity { m: 0 }),
        (1_000, invite(0, None, 1)),
        (2_000, Act::LoseAnswer { m: 0 }),
        (2_100, Act::CrashAfter { m: 1, what: Output::Frame }),
        (3_000, invite(0, Some(0), 2)),
        (20_000, Act::Send { m: 1, group: 0 }),
        (21_000, Act::Down { m: 2, ms: 3_600_000 }),
        (22_000, Act::Forge { m: 0, group: 0, what: Forgery::Junk }),
        (23_000, Act::Forge { m: 0, group: 0, what: Forgery::Replay }),
        (60_000, Act::Wake { m: 2, ms: 5_000 }),
        (70_000, Act::Quiesce),
    ]
    .into_iter()
    .map(|(at, act)| Action { at, act })
    .collect();
    let options = Options { members: 3, actions: actions.len() };
    let first = replay(3, options, &actions);
    assert!(first.failure.is_none(), "{}", first.log.join("\n"));
    assert_eq!(first.trace, replay(3, options, &actions).trace);
}

/// The read a member sends after subscribing to a log reached the service before the subscription, missing the commit
/// that removed the member, of which no peer told it either.
#[test]
fn a_read_that_overtakes_its_subscription() {
    passes(
        1445,
        5,
        vec![
            (78, Act::CreateIdentity { m: 0 }),
            (1772, Act::CreateIdentity { m: 2 }),
            (2439, Act::CreateIdentity { m: 3 }),
            (7192, Act::Invite { m: 0, group: None, n: 4, label: false, to: None, wait: 0, race: None }),
            (8053, Act::Invite { m: 2, group: None, n: 1, label: true, to: None, wait: 0, race: None }),
            (24186, Act::Offline { m: 2 }),
            (66354, Act::Offline { m: 1 }),
            (71026, Act::Leave { m: 1, group: 1 }),
            (73546, Act::Invite { m: 0, group: Some(0), n: 3, label: false, to: None, wait: 0, race: None }),
            (77095, Act::Offline { m: 4 }),
            (87716, Act::Send { m: 1, group: 0 }),
            (92954, Act::Remove { m: 3, group: 1, n: 1 }),
            (96337, Act::CreateIdentity { m: 4 }),
            (145516, Act::Quiesce),
        ],
    );
}

/// A joiner that dialed its inviter twice at once, for two invites, had the first connection replaced by the second,
/// which dropped the introduction the first kept until the joiner's hello.
#[test]
fn a_replaced_connection_hands_on_what_it_kept() {
    passes(
        140,
        8,
        vec![
            (1699, Act::CreateIdentity { m: 0 }),
            (2380, Act::CreateIdentity { m: 1 }),
            (3755, Act::CreateIdentity { m: 2 }),
            (4015, Act::CreateIdentity { m: 3 }),
            (5640, Act::CreateIdentity { m: 4 }),
            (6238, Act::CreateIdentity { m: 5 }),
            (6595, Act::CreateIdentity { m: 6 }),
            (8544, Act::CreateIdentity { m: 7 }),
            (13792, Act::Invite { m: 4, group: None, n: 6, label: true, to: None, wait: 0, race: None }),
            (14917, Act::Invite { m: 5, group: Some(0), n: 6, label: false, to: None, wait: 0, race: None }),
        ],
    );
}

/// A joiner offline from its join on showed peers an empty head of the group's log until its first read anchored its
/// chain, and then, having taken no new entry, told no peer of its head, so no sync started until the resync.
#[test]
fn a_first_read_that_takes_no_entry() {
    passes(
        4901,
        5,
        vec![
            (801, Act::CreateIdentity { m: 0 }),
            (1845, Act::CreateIdentity { m: 1 }),
            (3502, Act::CreateIdentity { m: 3 }),
            (20919634, Act::Invite { m: 0, group: None, n: 1, label: true, to: None, wait: 0, race: None }),
            (27436155, Act::Send { m: 3, group: 1 }),
            (27437121, Act::Send { m: 2, group: 0 }),
            (27441883, Act::Leave { m: 2, group: 0 }),
            (27452185, Act::Leave { m: 3, group: 0 }),
            (27456770, Act::CreateIdentity { m: 2 }),
            (27851199, Act::Offline { m: 2 }),
            (27858313, Act::Quiesce),
            (36967060, Act::Invite { m: 1, group: None, n: 0, label: false, to: None, wait: 0, race: None }),
            (36969354, Act::Offline { m: 0 }),
            (43013780, Act::Leave { m: 4, group: 1 }),
        ],
    );
}

/// A member removed while offline sent its summary when it came back, before it read its removal; a member took it and
/// kept it, of a peer no longer in the group, for good.
#[test]
fn a_removed_member_s_summary_is_not_kept() {
    passes(
        33,
        5,
        vec![
            (1378, Act::CreateIdentity { m: 0 }),
            (2990, Act::CreateIdentity { m: 4 }),
            (6655, Act::Invite { m: 4, group: None, n: 1, label: true, to: None, wait: 0, race: None }),
            (7825, Act::Invite { m: 4, group: Some(0), n: 3, label: true, to: None, wait: 0, race: None }),
            (20034, Act::Drop { m: 4, n: 1 }),
            (30345, Act::Settle { ms: 48072 }),
            (8764656, Act::Offline { m: 4 }),
            (8772488, Act::Remove { m: 1, group: 0, n: 0 }),
            (8810996, Act::Quiesce),
            (8822160, Act::Down { m: 3, ms: 60000 }),
        ],
    );
}

/// The service took an Add, and its answer was lost: the admitting member refused the joiner, which gave up its
/// KeyPackage, leaving its leaf stranded, instead of reading the log for the entry it posted.
#[test]
fn an_add_whose_answer_was_lost_admits_its_joiner() {
    passes(
        58,
        5,
        vec![
            (1855, Act::CreateIdentity { m: 0 }),
            (22367, Act::Invite { m: 0, group: None, n: 1, label: false, to: None, wait: 273899, race: None }),
            (48211, Act::LoseAnswer { m: 0 }),
            (2480581, Act::Invite { m: 4, group: Some(1), n: 1, label: true, to: None, wait: 0, race: None }),
            (2480581, Act::Remove { m: 2, group: 1, n: 2 }),
        ],
    );
}

/// A member pushed its message as it counted, in a step before the one that applied a peer's removal; the push left
/// after that step, to a peer no longer in its current epoch.
#[test]
fn a_push_leaves_only_to_peers_still_admitted() {
    use lmk_sim::Forgery;
    passes(
        121,
        5,
        vec![
            (985, Act::CreateIdentity { m: 0 }),
            (2583, Act::CreateIdentity { m: 1 }),
            (3167, Act::CreateIdentity { m: 2 }),
            (3712, Act::CreateIdentity { m: 3 }),
            (4542, Act::CreateIdentity { m: 4 }),
            (25300, Act::Invite { m: 2, group: None, n: 0, label: true, to: None, wait: 126164, race: None }),
            (64316, Act::Invite { m: 3, group: None, n: 4, label: true, to: None, wait: 74966, race: None }),
            (87372, Act::Send { m: 1, group: 1 }),
            (1235802, Act::Down { m: 1, ms: 40453974 }),
            (2757252, Act::Wake { m: 1, ms: 4047 }),
            (5763909, Act::Wake { m: 1, ms: 3421 }),
            (6934591, Act::Partition { mask: 627417265 }),
            (6943076, Act::Down { m: 2, ms: 1800000 }),
            (51934058, Act::Offline { m: 2 }),
            (51934058, Act::Offline { m: 3 }),
            (51936895, Act::Send { m: 1, group: 0 }),
            (51936977, Act::Send { m: 1, group: 0 }),
            (51938283, Act::Leave { m: 1, group: 0 }),
            (51953221, Act::Down { m: 1, ms: 106031036 }),
            (52080802, Act::Online { m: 2 }),
            (52123651, Act::Online { m: 3 }),
            (52168604, Act::Offline { m: 3 }),
            (52171862, Act::Send { m: 4, group: 0 }),
            (52172420, Act::Forge { m: 4, group: 1, what: Forgery::Copy }),
            (52631072, Act::Rename { m: 2, group: 1 }),
            (52631072, Act::Invite { m: 4, group: Some(1), n: 3, label: false, to: None, wait: 0, race: None }),
            (96457598, Act::Quiesce),
        ],
    );
}

/// A joiner read its group's log before its members' key logs, so its gate admitted no member whose summary held the
/// message counted as it joined, and it applied the commit deleting that epoch's keys as soon as it could, losing it.
#[test]
fn a_joiner_reads_its_members_key_logs_before_it_applies_their_commits() {
    passes(
        611,
        5,
        vec![
            (1655, Act::CreateIdentity { m: 0 }),
            (2691, Act::CreateIdentity { m: 1 }),
            (4013, Act::CreateIdentity { m: 2 }),
            (5752, Act::CreateIdentity { m: 3 }),
            (7738, Act::Invite { m: 1, group: None, n: 0, label: false, to: None, wait: 0, race: None }),
            (11105, Act::Settle { ms: 89908 }),
            (1406584, Act::Send { m: 2, group: 0 }),
            (1406808, Act::Send { m: 4, group: 0 }),
            (1420249, Act::Down { m: 2, ms: 33142946 }),
            (4143961, Act::Wake { m: 2, ms: 3607 }),
            (9574188, Act::Wake { m: 2, ms: 3332 }),
            (9576142, Act::Invite { m: 2, group: None, n: 1, label: false, to: None, wait: 0, race: None }),
            (9576204, Act::Leave { m: 3, group: 0 }),
            (11101561, Act::Send { m: 3, group: 0 }),
            (11137792, Act::Send { m: 2, group: 2 }),
            (11141255, Act::Leave { m: 0, group: 0 }),
            (11165410, Act::Quiesce),
            (11170122, Act::Partition { mask: 2147483648 }),
            (11305136, Act::Heal),
            (13224236, Act::Down { m: 3, ms: 607486767 }),
            (13459727, Act::Quiesce),
            (45951748, Act::Invite { m: 4, group: Some(1), n: 4, label: true, to: None, wait: 0, race: None }),
            (45954390, Act::Remove { m: 3, group: 1, n: 4 }),
            (45954390, Act::Open { m: 0, group: 1, n: 2, close: false }),
            (45954390, Act::Send { m: 4, group: 1 }),
            (45975745, Act::Restart { m: 0 }),
        ],
    );
}

/// A member waiting before a key-deleting commit took the first ciphertext of an answer, applied the commit at once as
/// its summaries had shown no progress for a while, and dropped the rest of the answer, losing what it brought.
#[test]
fn an_answer_is_taken_whole_before_reading_on() {
    passes(
        659,
        5,
        vec![
            (462, Act::CreateIdentity { m: 0 }),
            (1221, Act::CreateIdentity { m: 4 }),
            (2793, Act::Invite { m: 4, group: None, n: 3, label: true, to: None, wait: 0, race: Some(2) }),
            (4125, Act::Invite { m: 0, group: None, n: 3, label: false, to: None, wait: 0, race: None }),
            (42198, Act::Offline { m: 4 }),
            (42198, Act::Offline { m: 3 }),
            (42198, Act::Offline { m: 0 }),
            (43569, Act::Send { m: 2, group: 0 }),
            (60589, Act::Down { m: 2, ms: 149732524 }),
            (82682, Act::Online { m: 4 }),
            (97648, Act::Online { m: 3 }),
            (230117, Act::Offline { m: 4 }),
            (230117, Act::Offline { m: 3 }),
            (233338, Act::Send { m: 0, group: 1 }),
            (235583, Act::Leave { m: 0, group: 1 }),
            (254360, Act::Down { m: 0, ms: 96431414 }),
            (263707, Act::Online { m: 4 }),
            (304838, Act::Online { m: 3 }),
            (353104, Act::Rename { m: 2, group: 0 }),
            (461170, Act::Leave { m: 0, group: 1 }),
            (461170, Act::Remove { m: 0, group: 1, n: 3 }),
            (472616, Act::Settle { ms: 48714 }),
            (472791, Act::Partition { mask: 2147483648 }),
            (475914, Act::Settle { ms: 75289 }),
            (1551625, Act::Leave { m: 3, group: 0 }),
            (1554605, Act::Quiesce),
            (1559597, Act::Invite { m: 2, group: Some(0), n: 0, label: false, to: None, wait: 0, race: None }),
            (1559597, Act::Invite { m: 2, group: Some(0), n: 0, label: false, to: None, wait: 0, race: Some(1) }),
            (1559597, Act::Leave { m: 1, group: 0 }),
            (1559597, Act::Invite { m: 0, group: Some(0), n: 0, label: true, to: None, wait: 0, race: None }),
            (4540823, Act::Invite { m: 1, group: Some(0), n: 1, label: false, to: None, wait: 281784, race: None }),
            (4544064, Act::CreateIdentity { m: 1 }),
            (4548487, Act::CreateIdentity { m: 1 }),
        ],
    );
}

/// Chat passed two positions with no message after them to name them; when the second came, it went out naming neither,
/// so the first was passed over silently.
#[test]
fn a_late_message_names_the_positions_passed_before_it() {
    use lmk_sim::{Forgery, Output};
    passes(
        290,
        5,
        vec![
            (4729, Act::CreateIdentity { m: 4 }),
            (6321, Act::Invite { m: 4, group: None, n: 0, label: true, to: None, wait: 0, race: None }),
            (3225765, Act::Send { m: 4, group: 1 }),
            (3244269, Act::CrashAfter { m: 0, what: Output::Frame }),
            (3250753, Act::Send { m: 1, group: 0 }),
            (3338462, Act::Send { m: 0, group: 0 }),
            (4795565, Act::Leave { m: 2, group: 1 }),
            (49264521, Act::Settle { ms: 35409 }),
            (49694653, Act::Settle { ms: 53914 }),
            (49703864, Act::Invite { m: 4, group: Some(1), n: 0, label: false, to: None, wait: 0, race: None }),
            (49724706, Act::Offline { m: 0 }),
            (49751369, Act::Forge { m: 4, group: 1, what: Forgery::Message { mac: true } }),
            (49759766, Act::Send { m: 0, group: 1 }),
        ],
    );
}

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

//! The simulation replays a seed exactly, and the seeds that found bugs pass, each with the actions it shrank to.

use std::sync::Mutex;

use lmk_sim::{Options, Outcome, generate, run};

/// A process runs one simulation at a time: its randomness is the process's.
static ONE: Mutex<()> = Mutex::new(());

fn replay(seed: u64, options: Options, keep: &[usize]) -> Outcome {
    let _one = ONE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let actions = generate(seed, options);
    let kept: Vec<_> = keep.iter().map(|i| actions[*i].clone()).collect();
    run(seed, &kept, options)
}

fn passes(seed: u64, keep: &[usize]) {
    passes_with(seed, Options::default(), keep);
}

fn passes_with(seed: u64, options: Options, keep: &[usize]) {
    let outcome = replay(seed, options, keep);
    assert!(outcome.failure.is_none(), "{}", outcome.log.join("\n"));
}

#[test]
fn a_seed_replays_exactly() {
    let keep: Vec<usize> = (0..30).collect();
    assert_eq!(replay(7, Options::default(), &keep).trace, replay(7, Options::default(), &keep).trace);
}

/// The read a member sends after subscribing to a log reached the service before the subscription, missing the commit
/// that removed the member, of which no peer told it either.
#[test]
fn a_read_that_overtakes_its_subscription() {
    passes(1445, &[0, 1, 2, 3, 4, 5, 7, 9, 10, 11, 14, 17, 18, 19]);
}

/// A joiner that dialed its inviter twice at once, for two invites, had the first connection replaced by the second,
/// which dropped the introduction the first kept until the joiner's hello.
#[test]
fn a_replaced_connection_hands_on_what_it_kept() {
    passes_with(140, Options { members: 8, actions: 150 }, &[0, 1, 2, 3, 4, 5, 6, 7, 9, 10]);
}

/// A joiner offline from its join on showed peers an empty head of the group's log until its first read anchored its
/// chain, and then, having taken no new entry, told no peer of its head, so no sync started until the resync.
#[test]
fn a_first_read_that_takes_no_entry() {
    passes(4901, &[0, 1, 2, 4, 5, 6, 7, 12, 14, 17, 19, 24, 25, 56]);
}

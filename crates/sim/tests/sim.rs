//! The simulation replays a seed exactly, and the seeds that found bugs pass, each with the actions it shrank to.

use std::sync::Mutex;

use lmk_sim::{Options, Outcome, generate, run};

/// A process runs one simulation at a time: its randomness is the process's.
static ONE: Mutex<()> = Mutex::new(());

fn replay(seed: u64, keep: &[usize]) -> Outcome {
    let _one = ONE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let options = Options::default();
    let actions = generate(seed, options);
    let kept: Vec<_> = keep.iter().map(|i| actions[*i].clone()).collect();
    run(seed, &kept, options)
}

fn passes(seed: u64, keep: &[usize]) {
    let outcome = replay(seed, keep);
    assert!(outcome.failure.is_none(), "{}", outcome.log.join("\n"));
}

#[test]
fn a_seed_replays_exactly() {
    let keep: Vec<usize> = (0..30).collect();
    assert_eq!(replay(7, &keep).trace, replay(7, &keep).trace);
}

/// A certificate of a member, shown by another peer after the Add that names it was applied, made a session serve it
/// without a hello, so live messages to it waited for the 5-minute resync.
#[test]
fn a_certificate_shown_by_another_peer() {
    passes(46, &[0, 1, 2, 3, 5, 7, 8, 9, 12, 13, 15, 16, 17, 18, 19, 23, 24, 26, 27, 28, 31, 32, 33, 34, 35, 37, 39]);
}

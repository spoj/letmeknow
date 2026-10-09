//! Runs seeds of the simulation, and prints each failing one with the command that replays it and its shrunk trace.
//!
//! `lmk-sim [--seeds A..B] [--members N] [--actions N]`, or `lmk-sim --seed S [--keep I,J,...]` to replay one, printing
//! its log.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use lmk_sim::{Options, generate, run, shrink};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |name: &str| args.iter().position(|a| a == name).map(|i| args[i + 1].clone());
    let mut options = Options::default();
    if let Some(members) = value("--members") {
        options.members = members.parse().expect("--members N");
    }
    if let Some(actions) = value("--actions") {
        options.actions = actions.parse().expect("--actions N");
    }
    let flags = format!("--members {} --actions {}", options.members, options.actions);
    if let Some(seed) = value("--seed") {
        let seed: u64 = seed.parse().expect("--seed S");
        let mut actions = generate(seed, options);
        if let Some(keep) = value("--keep") {
            let keep: Vec<usize> = keep.split(',').map(|i| i.parse().expect("--keep I,J,...")).collect();
            actions = keep.iter().map(|i| actions[*i].clone()).collect();
        }
        if args.iter().any(|a| a == "--list") {
            for action in &actions {
                println!("{action}");
            }
            return;
        }
        let outcome = run(seed, &actions, options);
        for line in &outcome.log {
            println!("{line}");
        }
        println!("trace {}", hex(&outcome.trace));
        std::process::exit(i32::from(outcome.failure.is_some()));
    }
    let (from, to) = value("--seeds").map_or((0, 100), |range| {
        let (from, to) = range.split_once("..").expect("--seeds A..B");
        (from.parse().unwrap(), to.parse().unwrap())
    });
    let next = AtomicU64::new(from);
    let failed = Mutex::new(Vec::new());
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let seed = next.fetch_add(1, Ordering::Relaxed);
                    if seed >= to {
                        return;
                    }
                    let actions = generate(seed, options);
                    let Some(failure) = run(seed, &actions, options).failure else { continue };
                    let kept = shrink(seed, &actions, options, &failure);
                    let shrunk: Vec<_> = kept.iter().map(|i| actions[*i].clone()).collect();
                    let outcome = run(seed, &shrunk, options);
                    let keep: Vec<String> = kept.iter().map(usize::to_string).collect();
                    let mut report = format!("seed {seed}: {failure}\n  replay: cargo run -p lmk-sim --release -- {flags} --seed {seed} --keep {}\n", keep.join(","));
                    if let Some(failure) = &outcome.failure {
                        report += &format!("  shrunk to {} actions: {failure}\n", kept.len());
                    }
                    for (i, action) in kept.iter().zip(&shrunk) {
                        report += &format!("    #{i} {action}\n");
                    }
                    println!("{report}");
                    failed.lock().unwrap().push(seed);
                }
            });
        }
    });
    let failed = failed.into_inner().unwrap();
    println!("{} of {} seeds failed: {failed:?}", failed.len(), to - from);
    std::process::exit(i32::from(!failed.is_empty()));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

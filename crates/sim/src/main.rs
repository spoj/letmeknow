//! Runs seeds of the simulation, and prints each failing one with the command that replays it and its shrunk trace.
//!
//! `lmk-sim [--seeds A..B] [--jobs J] [--members N] [--actions N]` runs each seed in a process of its own, as the
//! simulation's randomness is the process's; `lmk-sim --check S` runs one and shrinks it if it fails, and every eighth
//! seed runs twice to check that it replays exactly; a seed fails as slow when its runs take over `SLOW`, and shrinking
//! stops after `SHRINKING`. `lmk-sim --seed S [--keep I,J,...] [--list]` replays one, printing its log, or lists its
//! actions. `lmk-sim --properties` lists the properties.

use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lmk_sim::{Options, generate, run, shrink};

const SLOW: Duration = Duration::from_secs(60);
const SHRINKING: Duration = Duration::from_secs(300);

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
    if args.iter().any(|a| a == "--properties") {
        for property in lmk_sim::props::PROPERTIES {
            println!("{}", property.name);
        }
        return;
    }
    let flags = ["--members".to_owned(), options.members.to_string(), "--actions".to_owned(), options.actions.to_string()];
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
    if let Some(seed) = value("--check") {
        let seed: u64 = seed.parse().expect("--check S");
        let watch = Arc::new(Mutex::new((Instant::now() + SLOW, format!("seed {seed}: slow (no outcome within {}s)", SLOW.as_secs()))));
        let watched = watch.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(250));
                let (at, said) = &*watched.lock().unwrap();
                if Instant::now() > *at {
                    println!("{said}");
                    std::process::exit(1);
                }
            }
        });
        let actions = generate(seed, options);
        let outcome = run(seed, &actions, options);
        let failure = match outcome.failure {
            None if seed.is_multiple_of(8) && run(seed, &actions, options).trace != outcome.trace => {
                println!("seed {seed}: replay-deterministic: a second run in this process left another trace");
                println!("  replay: cargo run -p lmk-sim --release -- {} --check {seed}", flags.join(" "));
                std::process::exit(1);
            }
            None => return,
            Some(failure) => failure,
        };
        println!("seed {seed}: {failure}");
        println!("  replay: cargo run -p lmk-sim --release -- {} --check {seed}", flags.join(" "));
        *watch.lock().unwrap() = (Instant::now() + SHRINKING, format!("  shrinking stopped after {}s", SHRINKING.as_secs()));
        let kept = shrink(seed, &actions, options, &failure);
        let shrunk: Vec<_> = kept.iter().map(|i| actions[*i].clone()).collect();
        let keep: Vec<String> = kept.iter().map(usize::to_string).collect();
        println!("  shrunk: cargo run -p lmk-sim --release -- {} --seed {seed} --keep {}", flags.join(" "), keep.join(","));
        if let Some(failure) = run(seed, &shrunk, options).failure {
            println!("  shrunk to {} actions: {failure}", kept.len());
        }
        for (i, action) in kept.iter().zip(&shrunk) {
            println!("    #{i} {action}");
        }
        std::process::exit(1);
    }
    let (from, to): (u64, u64) = value("--seeds").map_or((0, 100), |range| {
        let (from, to) = range.split_once("..").expect("--seeds A..B");
        (from.parse().unwrap(), to.parse().unwrap())
    });
    let jobs = value("--jobs").map_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()), |j| j.parse().expect("--jobs J"));
    let exe = std::env::current_exe().unwrap();
    let mut running: Vec<(u64, Child)> = Vec::new();
    let mut failed = Vec::new();
    let mut failed_by: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut seeds = from..to;
    loop {
        while running.len() < jobs
            && let Some(seed) = seeds.next()
        {
            let child = Command::new(&exe).args(&flags).args(["--check", &seed.to_string()]).stdout(Stdio::piped()).spawn().unwrap();
            running.push((seed, child));
        }
        if running.is_empty() {
            break;
        }
        let Some(done) = running.iter_mut().position(|(_, child)| child.try_wait().unwrap().is_some()) else {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        let (seed, child) = running.swap_remove(done);
        let output = child.wait_with_output().unwrap();
        if !output.status.success() {
            match output.stdout.is_empty() {
                true => println!("seed {seed}: {}\n", output.status),
                false => println!("{}", String::from_utf8_lossy(&output.stdout)),
            }
            let text = String::from_utf8_lossy(&output.stdout);
            let property = text.split_once(": ").and_then(|(_, rest)| rest.split(' ').next()).unwrap_or("crash").to_owned();
            failed_by.entry(property).or_insert(seed);
            failed.push(seed);
        }
    }
    failed.sort();
    println!("{} of {} seeds failed: {failed:?}", failed.len(), to - from);
    for (property, seed) in failed_by {
        println!("  {property}: first seed {seed}");
    }
    std::process::exit(i32::from(!failed.is_empty()));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

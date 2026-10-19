//! The store at the target's load: 100,000 devices, each starting 10 sessions a day in two groups, about 2.5 million
//! appends and 22 million reads a day, peaking at 10 times that rate (290 appends and 2,500 reads a second). Run with
//! `cargo test --release -p lmk-membership --test load -- --ignored --nocapture`; deploy/README.md sizes a server by it.

use std::time::Instant;

use lmk_membership::store::Store;
use lmk_proto::Bytes;

/// Appends and reads, interleaved as the target's peak has them: about nine reads per append, of 8 KiB commits, over
/// logs of a few entries each, as each commit moves its group to a new log.
#[test]
#[ignore]
fn the_store_takes_the_targets_peak() {
    const APPENDS: usize = 20_000;
    const LOGS: usize = 5_000;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::initialize(&dir.path().join("state")).unwrap();
    let logs: Vec<_> = (0..LOGS).map(|_| store.log(&lmk_proto::random::random::<32>())).collect();
    let entry = Bytes(vec![7; 8 << 10]);
    let started = Instant::now();
    let (mut appends, mut reads) = (0, 0);
    for i in 0..APPENDS {
        store.append(&logs[i % LOGS], std::slice::from_ref(&entry)).unwrap();
        appends += 1;
        for j in 0..9 {
            store.read(&logs[(i + j * 7) % LOGS], 0).unwrap();
            reads += 1;
        }
    }
    let seconds = started.elapsed().as_secs_f64();
    println!("{appends} appends and {reads} reads in {seconds:.1} s: {:.0} appends/s with {:.0} reads/s", appends as f64 / seconds, reads as f64 / seconds);
}

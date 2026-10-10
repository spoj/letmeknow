//! Deterministic simulation of letmeknow: members on the client core, as the browser runs it, over a simulated network
//! and clock in one thread, where one seed decides every delay, reorder, loss, partition, crash and choice. They are
//! driven through random actions while properties drawn from DESIGN.md and PROTOCOL.md are checked; a failing run
//! replays exactly from its seed, and shrinks to the fewest actions that still fail.

pub mod net;
pub mod props;
pub mod trace;
mod world;

use std::fmt;

pub use world::Failure;

/// SplitMix64: the simulator's own choices, apart from those the members draw through `lmk_proto::random`.
#[derive(Clone)]
pub struct Rng(pub u64);

impl Rng {
    pub fn draw(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.draw() % n.max(1)
    }

    fn index(&mut self, n: usize) -> usize {
        self.below(n as u64) as usize
    }
}

/// What a member, or the world, does. Members and groups are indices, groups in the order they were made, taken modulo
/// what exists when the action runs, so that an action keeps a meaning when others are cut away.
#[derive(Clone, Debug)]
pub enum Act {
    CreateIdentity { m: usize },
    /// `m` invites `n`'s device onto its identity.
    LinkDevice { m: usize, n: usize },
    /// `m` invites `n` into a group, a new one if none, `--for` a contact name, or `--to` `n`'s identity; `n` joins.
    Invite { m: usize, group: Option<usize>, n: usize, label: bool, to: bool },
    /// `n` joins a group open to its identity.
    JoinOpen { n: usize, group: usize },
    Send { m: usize, group: usize },
    Live { m: usize, group: usize },
    Rename { m: usize, group: usize },
    /// `m` opens a group to `n`'s identity, or closes it.
    Open { m: usize, group: usize, n: usize, close: bool },
    Leave { m: usize, group: usize },
    Remove { m: usize, group: usize, n: usize },
    /// `m` takes `n`'s device off their identity.
    TakeOff { m: usize, n: usize },
    Offline { m: usize },
    Online { m: usize },
    Restart { m: usize },
    /// Members whose bit is set, and the membership service with bit 31, on one side.
    Partition { mask: u32 },
    Heal,
    Drop { m: usize, n: usize },
    /// Every member stops for this many milliseconds, as a browser closed, and starts again from its storage.
    Sleep { ms: u64 },
    /// Every member online and reachable for a while, then convergence, delivery and revocation are checked.
    Quiesce,
}

/// An action, at milliseconds after the start: it waits as long after the action before it, or after the end of a
/// quiet period before it.
#[derive(Clone, Debug)]
pub struct Action {
    pub at: u64,
    pub act: Act,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {:?}", clock(self.at), self.act)
    }
}

/// Simulated time as days, hours, minutes and seconds.
pub(crate) fn clock(ms: u64) -> String {
    let s = ms / 1000;
    format!("{}d{:02}:{:02}:{:02}.{:03}", s / 86400, s / 3600 % 24, s / 60 % 60, s % 60, ms % 1000)
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub members: usize,
    pub actions: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options { members: 5, actions: 60 }
    }
}

/// The actions a seed makes: first some members make identities and groups, then actions weighted at random, with
/// time passing between them, mostly seconds, now and then minutes or hours; now and then every member stops for days,
/// past the key window and past a monthly key rotation; every 20, a quiet period.
pub fn generate(seed: u64, options: Options) -> Vec<Action> {
    let mut rng = Rng(seed);
    let n = options.members;
    let mut actions = Vec::new();
    let mut at = 0;
    let mut groups = 0;
    for m in 0..n {
        if rng.below(10) < 7 {
            at += rng.below(2_000);
            actions.push(Action { at, act: Act::CreateIdentity { m } });
        }
    }
    while actions.len() < options.actions {
        at += match rng.below(1000) {
            0..700 => rng.below(5_000),
            700..900 => 5_000 + rng.below(55_000),
            900..970 => 60_000 + rng.below(30 * 60_000),
            970..995 => 3_600_000 + rng.below(12 * 3_600_000),
            _ => {
                let ms = if rng.below(5) == 0 { 31 * 86_400_000 } else { 86_400_000 + rng.below(8 * 86_400_000) };
                actions.push(Action { at, act: Act::Sleep { ms } });
                continue;
            }
        };
        let (m, other) = (rng.index(n), rng.index(n));
        let group = rng.index(groups.max(1));
        let act = if actions.len() % 20 == 19 {
            Act::Quiesce
        } else if groups < 2 || rng.below(100) < 12 {
            let new = groups < 2 || rng.below(3) == 0;
            groups += usize::from(new);
            Act::Invite { m, group: (!new).then_some(group), n: other, label: rng.below(2) == 0, to: rng.below(4) == 0 }
        } else {
            match rng.below(100) {
                0..3 => Act::CreateIdentity { m },
                3..8 => Act::LinkDevice { m, n: other },
                8..12 => Act::JoinOpen { n: m, group },
                12..40 => Act::Send { m, group },
                40..45 => Act::Live { m, group },
                45..48 => Act::Rename { m, group },
                48..54 => Act::Open { m, group, n: other, close: rng.below(4) == 0 },
                54..58 => Act::Leave { m, group },
                58..62 => Act::Remove { m, group, n: other },
                62..65 => Act::TakeOff { m, n: other },
                65..71 => Act::Offline { m },
                71..78 => Act::Online { m },
                78..82 => Act::Restart { m },
                82..85 => Act::Partition { mask: rng.draw() as u32 },
                85..89 => Act::Heal,
                _ => Act::Drop { m, n: other },
            }
        };
        actions.push(Action { at, act });
    }
    actions
}

/// What a run did: a hash of every event, the first property it broke, if any, and its log.
pub struct Outcome {
    pub trace: [u8; 32],
    pub failure: Option<Failure>,
    pub log: Vec<String>,
}

/// Runs these actions in a world the seed decides; one at a time in a process, whose randomness it seeds.
pub fn run(seed: u64, actions: &[Action], options: Options) -> Outcome {
    world::run(seed, actions, options)
}

/// The fewest of a failing run's actions, by index, that still fail as it did.
pub fn shrink(seed: u64, actions: &[Action], options: Options, failure: &Failure) -> Vec<usize> {
    let fails = |kept: &[usize]| {
        let actions: Vec<Action> = kept.iter().map(|i| actions[*i].clone()).collect();
        run(seed, &actions, options).failure.is_some_and(|f| f.kind == failure.kind)
    };
    let mut kept: Vec<usize> = (0..actions.len()).collect();
    let mut chunk = kept.len().div_ceil(2);
    while chunk > 0 {
        let mut start = 0;
        while start < kept.len() {
            let candidate: Vec<usize> = kept[..start].iter().chain(kept.get(start + chunk..).unwrap_or_default()).copied().collect();
            if fails(&candidate) {
                kept = candidate;
            } else {
                start += chunk;
            }
        }
        chunk /= 2;
    }
    kept
}

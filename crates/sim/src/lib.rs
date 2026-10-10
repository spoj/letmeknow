//! Deterministic simulation of letmeknow: members on the client core, as the browser runs it, over a simulated network
//! and clock in one thread, where one seed decides every delay, reorder, loss, partition, crash and choice. They are
//! driven through random actions while the world records what they observe (`trace`), and the properties of 0.13's
//! design (`props`) are checked over that record; a failing run replays exactly from its seed, and shrinks to the
//! fewest actions that still fail.

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
/// what exists when the action runs, so that an action keeps a meaning when others are cut away. A member acting in a
/// group acts itself if it holds the group, else through a member running that does.
#[derive(Clone, Debug)]
pub enum Act {
    CreateIdentity { m: usize },
    /// `m` invites `n`'s device onto its identity.
    LinkDevice { m: usize, n: usize },
    /// `m` invites `n` into a group, a new one if none, `--for` a contact name, or `--to` the identity of `to`'s device;
    /// `n` joins `wait` milliseconds later, and `race` by the same link at once.
    Invite { m: usize, group: Option<usize>, n: usize, label: bool, to: Option<usize>, wait: u64, race: Option<usize> },
    /// `n` joins a group open to its identity.
    JoinOpen { n: usize, group: usize },
    Send { m: usize, group: usize },
    Live { m: usize, group: usize },
    Rename { m: usize, group: usize },
    /// `m` opens a group to `n`'s identity, or closes it.
    Open { m: usize, group: usize, n: usize, close: bool },
    Leave { m: usize, group: usize },
    /// `m` removes its `n`th other member.
    Remove { m: usize, group: usize, n: usize },
    /// `m` takes `n`'s device off their identity.
    TakeOff { m: usize, n: usize },
    Offline { m: usize },
    Online { m: usize },
    Restart { m: usize },
    /// `m` stops as by a crash, and starts again from its storage this many milliseconds later, while the others go on.
    Down { m: usize, ms: u64 },
    /// `m`, if down, runs for this many milliseconds and stops again: a phone woken briefly.
    Wake { m: usize, ms: u64 },
    /// Members whose bit is set, and the membership service with bit 31, on one side.
    Partition { mask: u32 },
    Heal,
    Drop { m: usize, n: usize },
    /// The service takes `m`'s next append, and the answer is lost with its connection.
    LoseAnswer { m: usize },
    /// `m` crashes right after it next writes this, and starts again.
    CrashAfter { m: usize, what: Output },
    /// An attacker appends to a group's log, as `Forgery` says.
    Forge { m: usize, group: usize, what: Forgery },
    /// A member that still holds a group it was removed from hands the group's members a state.
    PushState { m: usize, group: usize },
    /// Every member stops for this many milliseconds, as a browser closed, and starts again from its storage.
    Sleep { ms: u64 },
    /// Nothing happens for this many milliseconds; partitions and members offline or down stay as they are.
    Settle { ms: u64 },
    /// Every member running online and reachable for a while, then the properties are checked.
    Quiesce,
}

/// What a member writes, that `CrashAfter` crashes it after.
#[derive(Clone, Copy, Debug)]
pub enum Output {
    /// An append to the service.
    Append,
    /// A frame of a group to a peer.
    Frame,
    /// The answer that admits a joiner.
    Admitted,
}

#[derive(Clone, Copy, Debug)]
pub enum Forgery {
    /// Random bytes.
    Junk,
    /// An entry of the log, again.
    Replay,
    /// Another log's last entry.
    Foreign,
    /// From a copy of `m`'s state: a message with a valid AEAD, signed by another key.
    Message,
    /// From a copy of `m`'s state: a commit signed by another key.
    Commit,
    /// From a copy of `m`'s state: a commit as `m` signs it, the state copied.
    Copy,
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
    /// Whether the pending properties are checked too, and the actions that need 0.13 made.
    pub pending: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options { members: 5, actions: 60, pending: false }
    }
}

const SECOND: u64 = 1000;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

/// The actions a seed makes: first some members make identities and groups, then actions weighted at random, with
/// time passing between them, mostly seconds, now and then minutes or hours; now and then every member stops for days,
/// past the key window, a monthly key rotation or the log's retention; now and then several members act on one group
/// at the same millisecond, or members come and go in a pattern; every 20, a quiet period.
pub fn generate(seed: u64, options: Options) -> Vec<Action> {
    let mut rng = Rng(seed);
    let n = options.members;
    let mut actions = Vec::new();
    let mut at = 0;
    let mut groups = 0;
    let mut since_quiet = 0;
    for m in 0..n {
        if rng.below(10) < 7 {
            at += rng.below(2 * SECOND);
            actions.push(Action { at, act: Act::CreateIdentity { m } });
        }
    }
    while actions.len() < options.actions {
        at += match rng.below(1000) {
            0..700 => rng.below(5 * SECOND),
            700..900 => 5 * SECOND + rng.below(55 * SECOND),
            900..970 => MINUTE + rng.below(30 * MINUTE),
            970..995 => HOUR + rng.below(12 * HOUR),
            _ => {
                let ms = match rng.below(20) {
                    0 => 91 * DAY,
                    1..5 => 31 * DAY,
                    5..7 => rng.below(2 * SECOND),
                    _ => DAY + rng.below(8 * DAY),
                };
                actions.push(Action { at, act: Act::Sleep { ms } });
                continue;
            }
        };
        since_quiet += 1;
        if since_quiet == 20 {
            since_quiet = 0;
            actions.push(Action { at, act: Act::Quiesce });
            continue;
        }
        if groups >= 2 && rng.below(100) < 6 {
            actions.extend(burst(&mut rng, n, groups).into_iter().map(|act| Action { at, act }));
            continue;
        }
        if groups >= 1 && rng.below(100) < 4 {
            presence(&mut rng, n, groups, &mut at, &mut actions);
            continue;
        }
        let (m, other) = (rng.index(n), rng.index(n));
        let group = rng.index(groups.max(1));
        let act = if groups < 2 || rng.below(100) < 12 {
            let new = groups < 2 || rng.below(3) == 0;
            groups += usize::from(new);
            invite(&mut rng, n, m, (!new).then_some(group), other)
        } else {
            match rng.below(1000) {
                0..25 => Act::CreateIdentity { m },
                25..70 => Act::LinkDevice { m, n: other },
                70..110 => Act::JoinOpen { n: m, group },
                110..330 => Act::Send { m, group },
                330..370 => Act::Live { m, group },
                370..400 => Act::Rename { m, group },
                400..450 => Act::Open { m, group, n: other, close: rng.below(4) == 0 },
                450..490 => Act::Leave { m, group },
                490..530 => Act::Remove { m, group, n: rng.index(n) },
                530..560 => Act::TakeOff { m, n: other },
                560..610 => Act::Offline { m },
                610..680 => Act::Online { m },
                680..705 => Act::Restart { m },
                705..725 => Act::Down { m, ms: [MINUTE, 30 * MINUTE, 25 * HOUR, 7 * DAY - HOUR + rng.below(2 * HOUR)][rng.index(4)] },
                725..740 => Act::LoseAnswer { m },
                740..760 => Act::CrashAfter { m, what: [Output::Append, Output::Frame, Output::Admitted][rng.index(3)] },
                760..780 => {
                    // A forged message or commit, and a copied state, break 0.12 and need 0.13's entries: pending too.
                    let kinds = if options.pending { 6 } else { 3 };
                    let what = [Forgery::Junk, Forgery::Replay, Forgery::Foreign, Forgery::Message, Forgery::Commit, Forgery::Copy][rng.index(kinds)];
                    Act::Forge { m, group, what }
                }
                780..785 => Act::PushState { m, group },
                785..820 => Act::Partition { mask: if rng.below(3) == 0 { 1 << 31 } else { rng.draw() as u32 } },
                820..855 => Act::Heal,
                855..930 => Act::Drop { m, n: other },
                _ => Act::Settle {
                    ms: match rng.below(100) {
                        0..72 => 30 * SECOND + rng.below(60 * SECOND),
                        72..92 => 6 * MINUTE + rng.below(6 * MINUTE),
                        92..99 => HOUR + 31 * MINUTE,
                        _ => DAY + rng.below(2 * HOUR),
                    },
                },
            }
        };
        actions.push(Action { at, act });
    }
    actions
}

/// An invite: now and then redeemed late, near or past its expiry, by two members at once, or `--to` an identity.
fn invite(rng: &mut Rng, members: usize, m: usize, group: Option<usize>, n: usize) -> Act {
    let wait = match rng.below(100) {
        0..85 => 0,
        85..95 => rng.below(5 * MINUTE),
        _ => 10 * MINUTE - [SECOND, 100, 0][rng.index(3)] + [0, 100][rng.index(2)],
    };
    let to = match rng.below(100) {
        0..20 => Some(n),
        20..25 => Some(rng.index(members)),
        _ => None,
    };
    let race = (rng.below(100) < 8).then(|| rng.index(members));
    Act::Invite { m, group, n, label: rng.below(2) == 0, to, wait, race }
}

/// Several members acting on one group at the same millisecond: mostly commits (renames, opening and closing one
/// identity, removing one member, leaving, inviting, joining by an opening), and sends among them.
fn burst(rng: &mut Rng, members: usize, groups: usize) -> Vec<Act> {
    let group = rng.index(groups);
    let (target, other) = (rng.index(members), rng.index(members));
    (0..2 + rng.below(3))
        .map(|_| {
            let m = rng.index(members);
            match rng.below(8) {
                0 | 1 => Act::Rename { m, group },
                2 => Act::Open { m, group, n: target, close: rng.below(2) == 0 },
                3 => Act::Remove { m, group, n: other },
                4 => Act::Leave { m, group },
                5 => invite(rng, members, m, Some(group), target),
                6 => Act::JoinOpen { n: target, group },
                _ => Act::Send { m, group },
            }
        })
        .collect()
}

/// Members coming and going in a pattern: a sender alone that then leaves or goes away; a chain of members, each
/// overlapping only the next, the first going away, so that the last gets its messages through carriers; or a phone
/// down for hours that wakes for a few seconds now and then.
fn presence(rng: &mut Rng, n: usize, groups: usize, at: &mut u64, actions: &mut Vec<Action>) {
    let group = rng.index(groups);
    let mut order: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        order.swap(i, rng.index(i + 1));
    }
    let mut push = |rng: &mut Rng, gap: u64, act: Act| {
        *at += rng.below(gap);
        actions.push(Action { at: *at, act });
    };
    match rng.below(3) {
        0 => {
            let alone = order[0];
            for &m in &order[1..] {
                push(rng, 1, Act::Offline { m });
            }
            for _ in 0..1 + rng.below(3) {
                push(rng, 3 * SECOND, Act::Send { m: alone, group });
            }
            if rng.below(2) == 0 {
                push(rng, 3 * SECOND, Act::Leave { m: alone, group });
            }
            let ms = HOUR + rng.below(2 * DAY);
            push(rng, 30 * SECOND, Act::Down { m: alone, ms });
            for &m in &order[1..] {
                push(rng, MINUTE, Act::Online { m });
            }
        }
        1 => {
            let chain = &order[..(3 + rng.index(n.saturating_sub(2))).min(n)];
            for &m in &order[1..] {
                push(rng, 1, Act::Offline { m });
            }
            for _ in 0..1 + rng.below(3) {
                push(rng, 3 * SECOND, Act::Send { m: chain[0], group });
            }
            for pair in chain.windows(2) {
                push(rng, 5 * SECOND, Act::Online { m: pair[1] });
                let ms = 30 * MINUTE + rng.below(3 * HOUR);
                push(rng, 30 * SECOND, Act::Down { m: pair[0], ms });
            }
            for &m in &order[chain.len()..] {
                push(rng, MINUTE, Act::Online { m });
            }
        }
        _ => {
            let phone = order[0];
            let ms = 6 * HOUR + rng.below(12 * HOUR);
            push(rng, 1, Act::Down { m: phone, ms });
            for _ in 0..1 + rng.below(3) {
                let ms = 2 * SECOND + rng.below(8 * SECOND);
                push(rng, 2 * HOUR, Act::Wake { m: phone, ms });
            }
        }
    }
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

/// openmls reads the system clock: to check leaf lifetimes, among others. In a run, the simulated clock answers it, as
/// the one clock (`lmk_proto::clock`) does the rest. Only on Unix, where a binary's own `clock_gettime` is the one its
/// code calls.
///
/// # Safety
///
/// As libc's: `time` points to a timespec to fill.
#[cfg(unix)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_gettime(clock: libc::clockid_t, time: *mut libc::timespec) -> libc::c_int {
    if clock == libc::CLOCK_REALTIME
        && let Some(ms) = world::now()
    {
        // SAFETY: as the caller's.
        unsafe { *time = libc::timespec { tv_sec: (ms / 1000) as _, tv_nsec: (ms % 1000 * 1_000_000) as _ } };
        return 0;
    }
    type ClockGettime = unsafe extern "C" fn(libc::clockid_t, *mut libc::timespec) -> libc::c_int;
    static SYSTEM: std::sync::OnceLock<ClockGettime> = std::sync::OnceLock::new();
    // SAFETY: the next clock_gettime after this one is libc's, of the same signature.
    let system = SYSTEM.get_or_init(|| unsafe { std::mem::transmute(libc::dlsym(libc::RTLD_NEXT, c"clock_gettime".as_ptr())) });
    // SAFETY: as the caller's.
    unsafe { system(clock, time) }
}

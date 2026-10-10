//! What the world observes of a run, as plain data the properties check: what its own actions did, what crossed the
//! simulated wire, and what each member's node reported. Members are the world's indices; sessions are their MLS
//! signature keys; times are milliseconds since the start; positions are a group log's.
//!
//! The node's observations come through `lmk_node::Config::observe`, each once its step's transaction commits; the
//! views at quiet periods from `Node::positions`; what a member's storage held as it started from `lmk_node::saved`.

use std::collections::BTreeSet;

use lmk_proto::Bytes;

/// A session's MLS signature key.
pub type Key = Bytes;
pub type Positions = BTreeSet<u64>;
/// A SHA-256 hash: of a log entry's bytes, or of an opened plaintext.
pub type Hash = [u8; 32];

#[derive(Clone, Debug, Default)]
pub struct Trace(pub Vec<Obs>);

#[derive(Clone, Debug)]
pub struct Obs {
    pub at: u64,
    pub what: What,
}

#[derive(Clone, Debug)]
pub enum What {
    // The world's own.
    /// A member's session started, from its storage.
    Up { m: usize },
    /// A member's session stopped as by a crash: its storage stays as it was.
    Down { m: usize },
    /// An action cut a member's paths: offline, a partition, a dropped connection, a lost answer.
    Disrupted { m: usize },
    /// A member's paths are whole again: online, partitions healed.
    Reconnected { m: usize },
    /// A device was put on its identity's list, or taken off it.
    Device { identity: Bytes, device: Bytes, listed: bool },
    /// A join was answered.
    Join { m: usize, key: Key, group: Bytes, answer: Answer },
    /// `send` of a held chat message was answered.
    Send { m: usize, group: Bytes, id: Bytes, answer: Answer },
    /// A member's `leave` was answered.
    Leaving { m: usize, group: Bytes },
    /// The world appended an entry it forged to a group's log, at a position: with a MAC that verifies, if so.
    Forged { group: Bytes, position: u64, mac: bool },
    /// The world committed with a copy of a member's state.
    Copied { m: usize, group: Bytes },
    /// The end of a quiet period: each running member's view of each group it holds.
    Quiet { views: Vec<View> },

    // The wire's.
    /// A connection opened between two members.
    Connected { conn: usize, a: usize, b: usize },
    /// A connection's path was lost: what was in flight on it is lost, and it closes after an idle timeout.
    Cut { conn: usize },
    Closed { conn: usize },
    /// A frame of a group a member wrote: to a peer's iroh key, or to the service.
    Out { m: usize, to: Option<Bytes>, group: Bytes, frame: Frame },
    /// A frame of a group that reached a member from a peer, at the time it arrived, unless its connection was cut first.
    In { m: usize, from: usize, conn: usize, group: Bytes, frame: Frame },

    // The node's.
    /// A member's view of a group's leaves and settings at an epoch, sampled whenever it may have changed.
    Roster { m: usize, key: Key, group: Bytes, epoch: u64, leaves: Vec<Leaf>, settings: String },
    /// The log's head, as the member last read it from the service.
    Head { m: usize, group: Bytes, head: u64 },
    /// A member joined a group with a key: its Add's position, where it starts.
    Joined { m: usize, key: Key, group: Bytes, start: u64 },
    /// A member judged a log position, in the epoch it was at: a commit it applied, an entry that counts, or one skipped.
    Read { m: usize, group: Bytes, position: u64, entry: Hash, epoch: u64, verdict: Verdict },
    /// A member opened a counted position, or counted one of its own: of the group's kind, or a core payload's type.
    Opened { m: usize, group: Bytes, position: u64, kind: String, sender: Key, plaintext: Hash },
    /// Known losses a member recorded.
    Lost { m: usize, group: Bytes, positions: Positions },
    /// A member's own `lost` message counted, at a position, announcing these positions.
    Announced { m: usize, group: Bytes, position: u64, positions: Positions },
    /// A position handed to a kind other than chat.
    Handed { m: usize, group: Bytes, kind: String, position: u64 },
    /// A chat message shown or printed, with the positions passed over before it.
    Shown { m: usize, group: Bytes, position: u64, missing: Positions },
    /// A send that answered pending, as `answered`, counted by its final id (the client's `sent`).
    Sent { m: usize, group: Bytes, id: Bytes, answered: Bytes, position: u64 },
    /// A live payload taken, from a sender in an epoch.
    Live { m: usize, group: Bytes, sender: Key, epoch: u64 },
    /// A kind's state taken from a peer.
    StateTaken { m: usize, group: Bytes, from: Key },
    /// A member let go of a group other than by its removal.
    Dropped { m: usize, group: Bytes, reason: Dropped },
    /// What a member's storage held of a group as it started again, before it did anything.
    Restored { m: usize, group: Bytes, saved: Saved },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Ok, at a position (a join's start, a send's).
    Position(u64),
    Pending,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Leaf {
    pub key: Key,
    pub iroh: Bytes,
    /// The identity it speaks as, and the device its certificate names, if it shows a valid one.
    pub identity: Option<Bytes>,
    pub device: Option<Bytes>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Commit { committer: Key, added: Vec<Key>, removed: Vec<Key> },
    Counted { id: Bytes },
    Skipped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dropped {
    /// Away past the log's retention.
    Retention,
    /// A commit from its own leaf, signed by its key, with bytes other than its saved ones.
    Copied,
    /// The group's only leaf left it.
    Forgotten,
}

/// What a frame says, as far as the properties look.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// The sender's summary of the group.
    Hello { head: u64, held: Positions, fetching: Positions },
    Entries,
    Messages { positions: Positions },
    Want { positions: Positions },
    State,
    Live,
    Files,
    /// The answer to a join: the joiner's start.
    Admitted { position: u64 },
    /// Entries appended to the service, by their hashes.
    Append { entries: Vec<Hash> },
    Other(&'static str),
}

/// A member's view of a group at the end of a quiet period.
#[derive(Clone, Debug)]
pub struct View {
    pub m: usize,
    pub key: Key,
    pub group: Bytes,
    pub epoch: u64,
    pub leaves: Vec<Leaf>,
    pub start: u64,
    pub head: u64,
    /// Counted positions whose ciphertext it holds, has opened, and has lost.
    pub held: Positions,
    pub opened: Positions,
    pub lost: Positions,
}

impl View {
    pub fn active(&self) -> bool {
        self.leaves.iter().any(|leaf| leaf.key == self.key)
    }
}

/// A group's saved records, read from storage alone.
#[derive(Clone, Debug, Default)]
pub struct Saved {
    /// openmls's epoch.
    pub epoch: u64,
    pub start: u64,
    /// What it kept of positions up to here is gone, read longer than H ago.
    pub expired: u64,
    /// The cursor: the last position judged; and the last position of the log held.
    pub head: u64,
    pub logged: u64,
    /// Positions with a stored verdict.
    pub judged: Positions,
    /// The commits applied, by position, with the epoch each was judged in.
    pub commits: Vec<(u64, u64)>,
    /// As its summary shows them: kept positions, less those it lacks or lost.
    pub held: Positions,
    /// The entries saved for posting: a staged commit's, and pending sends'.
    pub entries: Vec<Hash>,
    /// The epochs pending sends were sealed in.
    pub sends: Vec<u64>,
    /// The iroh keys of the peers whose summaries are kept, and of the current epoch's leaves.
    pub summaries: Vec<Key>,
    pub roster: Vec<Key>,
}

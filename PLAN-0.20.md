# 0.20: sealed admission, bounded state, live relays

Nothing carries over from 0.19: 0.20 gets a new service, flips every switch, and leaves 0.19's chats, docs, tables and
identities behind in their own home and browser database (AGENTS.md). The plan goes when 0.20 ships.

## Why

- **Admission crosses classical TLS in the clear.** Commits, held messages, live payloads and state links are sealed
  under post-quantum MLS keys or capabilities, but `Join { secret, key_package }` and `Answer<Admitted>` cross iroh's
  classical X25519 TLS as plaintext (`crates/proto/src/peer.rs:146-163`, `crates/net/src/lib.rs:212-218`). A passive
  relay observer records the invite secret, the joiner's `KeyPackage` (with its identity ID, private name claim, device
  name and session key) and the `Admitted` response.
- **One commit lock stalls unrelated groups.** `Inner.committing` (`crates/node/src/tasks.rs:60`,
  `crates/node/src/groups.rs:26`) is a single node-wide mutex held across `caught_up`, which waits up to `WAIT` (120 s)
  for kept messages (`crates/node/src/reading.rs:76-97`). One group waiting on repair blocks commits and admissions in
  every other group and in the identity group.
- **Fixed daily leaf updates churn large groups.** Every member updates its leaf every `T` (24 h,
  `crates/node/src/duties.rs:39`), so an $N$-member group commits $N$ times a day—every 2.4 minutes at $N = 600$, right
  at the 2-minute `heads` poll (`crates/node/src/logs.rs:25`), under `max_past_epochs(1)`.
- **Long-lived state and peer log frames grow without bound:**
  - `Group.state.added` (`crates/core/src/group.rs:365, 971`) appends an `Added` record (with full credentials and
    certificates) on every `Add` and never prunes it, rewriting all historical joins on every commit.
  - `Rec.told` (`crates/node/src/lib.rs:340`, `crates/node/src/peering.rs:321`) keeps loss reports for memberships and
    seqs that have since ended or expired.
  - `State::entries` (`crates/node/src/logs.rs:173`, `crates/node/src/peering.rs:463`) loads all entries after `after`
    into one `Frame::Entries`; a long log can exceed `MAX_FRAME` (16 MiB) and be dropped by its reader.
  - `expired` at the membership service (`crates/membership/src/store.rs:141`) keeps group-log references forever
    (about 2 GB a year at the target), though only public-log references must stay forever.
- **Relays are fixed at startup.** A session resolves its service's directory every 10 minutes, but `Net` and
  `Inner.relays` keep the relay list from startup (`crates/node/src/tasks.rs:32`) until the process or tab restarts.

## A. Sealed admission

- **From the invite secret (`[u8; 16]`):**
  - `invite_id(secret) -> [u8; 32]`: `SHA-256(secret)`, the rule's id in `Aad.invite`, `Added.invite` and `Join.id`.
  - `invite_key(secret) -> [u8; 32]`: `HKDF-SHA256(secret, "letmeknow invite v1")`.
- **Sharing the rule.** `Control::Invite` (`crates/proto/src/group.rs:117`) and `Rule` (`crates/node/src/lib.rs:372`)
  carry `secret: Bytes` (16 bytes) instead of `hash`, inside the group's PQ-sealed held message. Current members that
  open the invite derive both `invite_id` and `invite_key`. `Aad.invite`, `Added.invite` and `Group::used` keep using
  the 32-byte `invite_id`, so commits and `group/<id>` never hold the secret.
- **On the `admission` stream (`crates/proto/src/peer.rs`, `crates/node/src/admission.rs`):**
  - `Join { id: Bytes, sealed: Bytes }`: `id` is `invite_id(&secret)`; `sealed` is `nonce ‖ ciphertext`, the joiner's
    `key_package` sealed with `XChaCha20Poly1305` under `invite_key(&secret)` with AAD
    `"letmeknow join v1\0" ‖ id`.
  - The member answers `Answer<Bytes>`: `Answer::Refused { refused }` (whose strings carry no names, keys or state), or
    `Answer::Ok(sealed)`, the `Admitted` JSON sealed with `XChaCha20Poly1305` under `invite_key(&secret)` with AAD
    `"letmeknow admitted v1\0" ‖ id`.
  - `admit_join` looks up `(gid, rule)` by `rule.id() == join.id`, opens `join.sealed` (refusing as `UNKNOWN` if it
    does not open), checks `logged_commit` for a lost answer before `admits`, and seals the `Admitted` answer.

## B. Per-group commit lock and adaptive update period

- **Per-group commit lock (`crates/node/src/groups.rs:26`, `crates/node/src/tasks.rs:60`):**
  - `Inner.committing` becomes `Mutex<HashMap<Vec<u8>, Arc<tokio::sync::Mutex<()>>>>`: `commit(gid, ...)` locks only
    `gid`'s mutex, and `forget` removes it.
  - A retry of `admit_join` that hits `logged_commit` (`crates/node/src/admission.rs:238-241`) answers before acquiring
    the group's commit lock.
- **Adaptive leaf update period (`crates/node/src/duties.rs:39`):**
  - `next_update(updated: u64, update: u32, members: usize, key: &[u8]) -> u64` scales the effective period with the
    group's size above 32 members, capped at $4\times$:
    `t = (update.max(1) as u64 * members.clamp(32, 128) as u64 / 32) * 1000`.
  - Groups up to 32 members update every `update` (24 h by default), as now. At 64 members each updates every 2 days
    (32 commits a day across the group); at 128 or more, every 4 days—well under the 7-day minimum `--retention`, while
    cutting update commits fourfold.

## C. Bounded state, paged peer entries, and group-log reference expiry

- **`Group.state.added` (`crates/core/src/group.rs:365, 543-550, 725, 971`):**
  - Every caller of `added()` (`State::member`, `Inner::revoked`, `State::logged_commit`) queries only current members
    in `mls.members()`; `Group::used(hash)` queries only invites before they expire.
  - `Group::prune_added(&mut self, provider: &P, invites: &[Bytes])` retains an `Added` entry iff it is the latest for
    a current member in `self.mls.members()` or its `invite` is in `invites` (`g.rec.invites`). `State::expire`
    (`crates/node/src/duties.rs:64`) calls it after pruning `g.rec.invites`.
- **`Rec.told` (`crates/node/src/reading.rs:228`, `crates/node/src/duties.rs:64`):**
  - `cuts` retains in `g.rec.told` only reporters in the current cut state (`g.mls.cut()`) and seqs of this session's
    current membership.
- **Bounded peer `Entries` (`crates/node/src/logs.rs:173, 405`, `crates/node/src/peering.rs:463`, `crates/node/src/reading.rs:144`):**
  - `State::entries(id, after)` stops reading when adding the next entry would put the batch over `membership::MAX_BODY`
    (2 MiB), returning `None` if it cannot reach `head.length` within that bound (the peer then catches up by paged
    reads from the service instead of receiving a frame over `MAX_FRAME`).
  - `Inner::take_entries` checks `after + entries.len() as u64 == head.length` before reading or hashing stored entries.
- **Expiring group-log references at the service (`crates/membership/src/store.rs:20, 141, 315`):**
  - `expired` becomes `CREATE TABLE expired (reference BLOB PRIMARY KEY CHECK(length(reference)=32), day INTEGER) WITHOUT ROWID`
    with `CREATE INDEX expired_expiry ON expired(day) WHERE day IS NOT NULL`.
  - When `Store::expire(before_day)` moves an anchor to `expired`, a public log gets `day = NULL` (kept forever, so an
    expired identity's first entry can never be replayed) and a group log gets `day = before_day`.
  - Each pass of `Store::expire(before_day)` deletes up to `MARK_LOGS` group references from `expired` with
    `day < before_day.saturating_sub(EXPIRED_DAYS)` (`EXPIRED_DAYS = 365`).

## D. Live relay rotation

- **Updating the endpoint (`crates/net/src/lib.rs`):**
  - `Net::set_relays(&self, relays: &[RelayUrl])`: compares `relays` with the relays `Net` currently holds; inserts new
    ones with `endpoint.insert_relay(url, Arc::new(url.into()))` and removes dropped ones with
    `endpoint.remove_relay(&url)`. When the home relay moves, `endpoint.watch_addr()` emits `Event::Home`, which
    re-signs the session's summaries (`crates/node/src/peering.rs:495`).
- **Refreshing the own directory (`crates/node/src/lib.rs`, `crates/node/src/tasks.rs`, `crates/node/src/logs.rs`):**
  - `lmk_node::Config` carries `membership: Option<Service>` (the session's own service, when `chosen` is empty).
  - `Inner.relays` becomes `Mutex<Vec<RelayUrl>>`. At each `ask_heads` pass (`crates/node/src/logs.rs:301`), when
    `chosen` is empty and `membership` is set, the node resolves the own service's directory through `resolve` (cached
    for `FRESH`, 10 minutes, by the shell): if its `relays` changed, it updates `Inner.relays` and calls
    `net().set_relays(&relays)`.

## Formats: every switch flips

- **ALPN:** `letmeknow/4` → `letmeknow/5` (`crates/proto/src/frame.rs:6`).
- **Membership routes:** `/membership/1/` → `/membership/2/` (`crates/membership/src/service.rs:61`,
  `crates/membership/src/client.rs`, `AGENTS.md`).
- **Group protocol:** `PROTOCOL` 8 → 9 (`crates/proto/src/group.rs:8`).
- **Invite link:** 8 → 9 (`crates/proto/src/links.rs:16, 30, 42-43, 98-103`). An 8 link: `"this invite link is from
  letmeknow 0.19, whose groups this version cannot join: ask for an invite to a group made with letmeknow 0.20"`.
- **Home format:** 8 → 9, `letmeknow-v9` (`crates/session/src/cli.rs:223`, `crates/session/src/lib.rs:195-215`); a
  format-8 home names `@letmeknow/cli@0.19`.
- **Browser:** database, Web Lock and BroadcastChannel `lmk8` → `lmk9` (`web/src/store.ts:8, 31-33`,
  `web/src/client.ts:75, 174`, `web/src/main.ts:41-43, 145-150`, `web/e2e.mjs`).
- **Service store:** `FORMAT` 4 → 5 (`crates/membership/src/store.rs:19`).
- **Version:** `0.20.0` in `Cargo.toml` and `@letmeknow/cli@0.20` across `test/pins.py`'s files.

## Steps

Each step leaves `main` building and green, with its own tests and the `SKILL.md` and `README.md` text it changes.

- **A. Switches:** version `0.20.0`, pins, ALPN `/5`, `/membership/2/`, `PROTOCOL` 9, link 9, home `letmeknow-v9`
  (format 9), browser `lmk9`, store `FORMAT` 5; refusal texts for 0.19 links, homes and browser storage.
- **B. Sealed admission:** `invite_id` and `invite_key`; `Control::Invite` and `Rule` with `secret`; sealed `Join` and
  `Answer<Bytes>` on `admission`. Tests: a join succeeds and `Join` / `Admitted` ciphertexts on the wire contain neither
  the secret nor the `KeyPackage` bytes; an altered or wrong-secret `Join` or `Admitted` is refused; a lost answer is
  recovered and opened on retry.
- **C. Per-group commit lock and adaptive `T`:** per-group `committing` map; `logged_commit` answered before the commit
  lock; `next_update` scaling with group size above 32 up to $4\times$. Tests: a commit in group B and an admission
  retry in group A complete while group A's commit waits in `caught_up`; update slots stay at `T` up to 32 members and
  scale to `2 * T` at 64 and `4 * T` at 128+.
- **D. Bounded state, paged peer entries, and group-log reference expiry:** `prune_added`, `told` cleanup, bounded
  `State::entries` and fast-fail `take_entries`, `expired.day` and `expired_expiry` in `Store::expire`. Tests:
  `state.added` drops removed members once their invite expires while keeping current members and unexpired invites;
  `store_sql_tests` verifies `expired_expiry` uses an index range scan; expired group references go after 365 days while
  public references stay forever; an oversized peer log suffix is skipped rather than exceeding `MAX_FRAME`.
- **E. Live relay rotation:** `Net::set_relays`, `Config.membership` and refresh on `ask_heads`. Tests: a session whose
  directory switches to a new relay moves its endpoint to that relay, emits a new summary hint, and is reached there
  without restarting.
- **F. Rollout:** a new service for letmeknow.dev once ready to release, `deploy/release.sh 0.20.0`, backend and
  frontend rollout.

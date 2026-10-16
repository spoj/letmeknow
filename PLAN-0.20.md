# 0.20: sealed admission, bounded state, live relays

Draft 2, after adversarial review and validation. Nothing carries over from 0.19: 0.20 gets a new service, flips every
switch, and leaves 0.19's chats, docs, tables and identities behind in their own home and browser database (AGENTS.md).
The plan goes when 0.20 ships.

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
  carry `secret: Bytes` (16 bytes) instead of `hash`, inside the group's PQ-sealed held message; `control()`
  (`crates/node/src/held.rs:536`) ignores a `Control::Invite` whose `secret` is not 16 bytes or whose `expires` is
  already older than `now() - H`. Current members that open the invite derive both `invite_id` and `invite_key`
  (`rule.id()` in `admission.rs`, `duties.rs:246`). `Aad.invite`, `Added.invite` and `Group::used` keep using the
  32-byte `invite_id`, so commits and `group/<id>` never hold the secret.
- **On the `admission` stream (`crates/proto/src/peer.rs`, `crates/node/src/admission.rs`):**
  - `Join { id: Bytes, sealed: Bytes }`: `id` is `invite_id(&secret)`; `sealed` is `nonce ‖ ciphertext`, the joiner's
    `key_package` sealed with `XChaCha20Poly1305` under `invite_key(&secret)` with AAD
    `"letmeknow join v1\0" ‖ id`.
  - The member answers `Answer<Bytes>`: `Answer::Refused { refused }` (whose strings carry no names, keys or state), or
    `Answer::Ok(sealed)`, the `Admitted` JSON sealed with `XChaCha20Poly1305` under `invite_key(&secret)` with AAD
    `"letmeknow admitted v1\0" ‖ id`.
  - `admit_join` looks up `(gid, rule)` by `rule.id() == join.id`, opens `join.sealed` (refusing as `UNKNOWN` if it
    does not open), checks `logged_commit` for a lost answer before `caught_up` (and again after), and seals the
    `Admitted` answer.

## B. Per-group commit lock and adaptive update period

- **Per-group commit lock (`crates/node/src/lib.rs:395`, `crates/node/src/groups.rs:26`, `crates/node/src/tasks.rs:60`):**
  - `committing: Arc<tokio::sync::Mutex<()>>` lives on `struct G` (`crates/node/src/lib.rs:395`) rather than `Inner`:
    `commit(gid, ...)` clones and locks `g.committing`, and `forget` drops it with `G`.
  - In `admit_join` (`crates/node/src/admission.rs:238-241`), `logged_commit` is checked before `caught_up` (as well as
    after), so a joiner retrying for a lost answer is answered at once even while `gid` waits in `caught_up`.
- **Adaptive leaf update period (`crates/node/src/duties.rs:39`):**
  - `next_update(updated: u64, update: u32, members: usize, key: &[u8]) -> u64` keeps `base = update.max(1) as u64 * 1000`
    as the only modulus (so changing `members` never scrambles `(updated + base - offset) % base`) and adds linear slack
    above 32 members up to $4\times$:
    ```rust
    let base = update.max(1) as u64 * 1000;
    let offset = u64::from_be_bytes(Sha256::digest(key)[..8].try_into().unwrap()) % base;
    let extra = base * (members.clamp(32, 128) - 32) as u64 / 32;
    (updated + base - offset) / base * base + offset + extra
    ```
  - Groups up to 32 members are unchanged (`extra == 0`). At 64 members `extra == base`; at $\ge 128$ members
    `extra == 3 * base` (4 days when `update = 24h`, well under the 7-day `--retention` floor).

## C. Bounded state, paged peer entries, and group-log reference expiry

- **`Group.state.added` (`crates/core/src/group.rs:365, 543-550, 971`, `crates/node/src/duties.rs:64`):**
  - `Added` records `pub time: u64` (`aad.time`).
  - `Group::prune_added(&mut self, provider: &P, before: u64, invites: &[Bytes])` retains an `Added` entry iff its
    `member.key` is a current member in `self.mls.members()`, `added.time >= before` (within `H`, so an out-of-order
    `Control::Invite` arriving after its joiner already left still sees `used(&id) == true`), or its `invite` is in
    `invites`. `State::expire` (`crates/node/src/duties.rs:64`) calls it with `before = now() - H` and the ids of
    `g.rec.invites`.
- **Bounded peer `Entries` (`crates/node/src/logs.rs:173, 405`, `crates/node/src/peering.rs:463`, `crates/node/src/reading.rs:144`):**
  - `State::entries(id, after) -> Option<Vec<Bytes>>` counts `membership::PAGE_OVERHEAD` plus
    `membership::encoded_entry_bytes` (`crates/membership/src/store.rs:235`) and returns `None` if reaching
    `head.length` would exceed `membership::MAX_BODY` (4 MiB). Callers (`peering.rs:463`, `reading.rs:144`) send
    `Frame::Entries` only on `Some(entries)`; a peer behind by more than 4 MiB catches up by paged reads from the
    service.
  - `Inner::take_entries` checks `after + entries.len() as u64 == head.length` before reading `hash_at` or hashing
    entries.
- **Expiring group-log references at the service (`crates/membership/src/store.rs:20, 141, 283`):**
  - `expired` becomes `CREATE TABLE expired (reference BLOB PRIMARY KEY CHECK(length(reference)=32), day INTEGER) WITHOUT ROWID`
    with `CREATE INDEX expired_expiry ON expired(day) WHERE day IS NOT NULL`.
  - When `Store::expire(before_day)` moves an anchor to `expired`, a public log gets `day = NULL` (kept forever, so an
    expired identity's first entry can never be replayed) and a group log gets `day = before_day`.
  - When `!more` from `reap(&tx)` (so `doomed` is empty), `Store::expire(before_day)` deletes up to `MARK_LOGS` group
    references from `expired` with `day < before_day.saturating_sub(EXPIRED_DAYS)` (`EXPIRED_DAYS = 365`, indexed by
    `expired_expiry`), and includes `|| expired.len() == MARK_LOGS` in its returned `bool`.

## D. Live relay rotation

- **Updating the endpoint (`crates/net/src/lib.rs:92, 101`):**
  - `Net` holds its current relay list in `tokio::sync::Mutex<Vec<RelayUrl>>`, seeded at `Net::spawn` from the initial
    `home` relays.
  - `Net::set_relays(&self, relays: &[RelayUrl])`: async; under the mutex, inserts new relays with
    `endpoint.insert_relay(url, Arc::new(url.into())).await` before removing dropped ones with
    `endpoint.remove_relay(&url).await`. When the home relay moves, `endpoint.watch_addr()` emits `Event::Home`, which
    re-signs the session's summaries (`crates/node/src/peering.rs:495`).
- **Refreshing the own directory (`crates/node/src/lib.rs`, `crates/node/src/logs.rs:301`, `crates/session/src/lib.rs:349`, `crates/web/src/lib.rs:536`):**
  - `lmk_node::Config` carries `membership: Option<Service>` (set by `session::node_config`—covering both the session
    node and `take_device` in `crates/session/src/session.rs:236`—and by `web`'s `App::start`).
  - `Inner.relays` becomes `Mutex<Vec<RelayUrl>>` (never held across `.await`). At each `ask_heads` pass, when `chosen`
    is empty and `membership` is `Some(service)`, the node calls
    `lmk_membership::client::directory(&self.resolve, service).await` (which verifies `directory.key == service.key`
    and uses the shell's 10-minute `FRESH` cache), updates `Inner.relays`, and calls `self.net().set_relays(&relays).await`.

## Formats: every switch flips

- **ALPN:** `letmeknow/4` → `letmeknow/5` (`crates/proto/src/frame.rs:6`).
- **Membership routes:** `/membership/1/` → `/membership/2/` (`crates/membership/src/service.rs:61`,
  `crates/membership/src/client.rs`, `test/e2e.py:159`, test literals in `membership`, `node` and `serve`, `AGENTS.md`).
- **Group protocol:** `PROTOCOL` 8 → 9 (`crates/proto/src/group.rs:8`).
- **Invite link:** 8 → 9 (`crates/proto/src/links.rs:16, 30, 42-43, 98-103`). An 8 link: `"this invite link is from
  letmeknow 0.19, whose groups this version cannot join: ask for an invite to a group made with letmeknow 0.20"`.
- **Home format:** 8 → 9, `letmeknow-v9` (`crates/session/src/cli.rs:223`, `crates/session/src/lib.rs:195-215`,
  `crates/session/src/tests.rs:1254, 1272, 1278`); a format-8 home names `@letmeknow/cli@0.19`.
- **Browser:** database, Web Lock and BroadcastChannel `lmk8` → `lmk9` (`web/src/store.ts:8, 31-33`,
  `web/src/client.ts:75, 174`, `web/src/main.ts:41-43, 145-150`, `web/e2e.mjs`).
- **Service store:** `FORMAT` 4 → 5 (`crates/membership/src/store.rs:19`).
- **Version and docs:** `0.20.0` in `Cargo.toml`, `@letmeknow/cli@0.20` across `test/pins.py`'s files, and `0.18` →
  `0.19` in `README.md:28` and `SKILL.md:18`.

## Steps

Each step leaves `main` building and green, with its own tests and the `SKILL.md` and `README.md` text it changes.

- **A. Switches:** version `0.20.0`, pins, ALPN `/5`, `/membership/2/`, `PROTOCOL` 9, link 9, home `letmeknow-v9`
  (format 9), browser `lmk9`, store `FORMAT` 5; refusal texts for 0.19 links, homes and browser storage.
- **B. Sealed admission:** `invite_id` and `invite_key`; `Control::Invite` and `Rule` with `secret`; sealed `Join` and
  `Answer<Bytes>` on `admission`; `logged_commit` checked before `caught_up`. Tests: a join succeeds and `Join` /
  `Admitted` on the wire contain neither the secret nor the `KeyPackage` bytes; an altered or wrong-secret `Join` or
  `Admitted` is refused; a lost answer is recovered and opened on retry.
- **C. Per-group commit lock and adaptive `T`:** `G.committing`; `next_update` with `extra` slack above 32 members.
  Tests: a commit in group B and an admission retry in group A complete while group A's commit waits in `caught_up`;
  update slots stay at `T` up to 32 members, scale to `2 * T` at 64 and `4 * T` at 128+, and never move backward on a
  join.
- **D. Bounded state, paged peer entries, and group-log reference expiry:** `Added.time` and `prune_added`, bounded
  `State::entries` and fast-fail `take_entries`, `expired.day` and `expired_expiry` in `Store::expire`. Tests:
  `state.added` drops removed members past `H` while keeping current members, recent adds (preventing out-of-order
  invite replay) and active invites; `store_sql_tests` verifies `expired_expiry` uses an index range scan; expired
  group references go after 365 days while public references stay forever; an oversized peer log suffix is skipped
  rather than exceeding `MAX_BODY`.
- **E. Live relay rotation:** `Net::set_relays`, `Config.membership` and refresh on `ask_heads`. Tests: a session whose
  directory switches to a new relay moves its endpoint to that relay, emits a new summary hint, and is reached there
  without restarting.
- **F. Rollout:** a new service for letmeknow.dev once ready to release, `deploy/release.sh 0.20.0`, backend and
  frontend rollout.

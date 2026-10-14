# 0.19: post-quantum groups, a lighter service

Draft 3, for review. Nothing carries over from 0.18: 0.19 gets a new service, and existing chats, docs and identities
stay behind (#56). The plan goes when 0.19 ships.

- **Owner's decisions:**
  - Peers stay on iroh, and post-quantum is in MLS only.
  - The membership service is reached over HTTPS, and over nothing else.
  - `only_here` means held by no other member.
  - A leaked service database shows as little as possible, so groups keep a log per epoch, and an expired log leaves
    only its reference.
  - There is no rejoin: a member that the service's expiry left behind is out, and comes back by invite.
  - Nothing migrates and nothing stays compatible with 0.18 (AGENTS.md).
- **Target:** 100k memberships and 1M messages a day on one service. Messages never reach it. Commits are about one
  daily update a membership plus joins and leaves, about 1.4 a second; entries kept 30 days take about 40 GB, and the
  references of expired logs about 2 GB a year.

## Why

- **Harvest now, decrypt later.** Every group secret rests on X25519, in MLS's HPKE. Whoever records the service's
  sealed commits, or relayed traffic, can open them once a quantum computer exists.
- **The service is the first wall at scale.** Each followed log is a subscription stream of its own, re-read every 5
  minutes, and a session follows its groups' logs and every member identity's directory. 4,096 subscriptions in all
  (`MAX_SUBSCRIBERS`, crates/membership/src/service.rs:20) fill at a few hundred online sessions.
- **The service keeps what it need not:** each add's Welcome, with the whole ratchet tree; keep-alive commits 10 to 20
  minutes after members talk, which are most commits and trace when each group talks; a year of history; and, in every
  expired log's anchor, its length, hash and last day, forever (crates/membership/src/store.rs:201).
- **A lost old device opens every epoch since its last update.** Each commit seals the next epoch's secrets to keys in
  the tree, a silent member's among them, and nothing removes a member that fell behind (`due`,
  crates/node/src/duties.rs:115-130).
- **Post-quantum keys multiply commit size** (measured with the suite below): a KeyPackage is 3.2 KB; an update commit
  fills an 8 KiB bucket at 3 members and 32 KiB at 50; one joiner's Welcome grows about 1.7 KB a member (166 KB at
  100), so inside a 1 MiB entry it would cap a group near 600.

## Post-quantum MLS

- **The suite.** `CIPHERSUITE` (crates/core/src/group.rs:21) becomes `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`:
  X-Wing (ML-KEM-768 with X25519) for HPKE, the rest as now. openmls and openmls_rust_crypto take the feature
  `draft-ietf-mls-pq-ciphersuites` and keep their exact pins, as the suite comes from a draft: an upgrade that changes
  its wire format is a new minor. It builds for wasm32.
- What MLS secrets seal follows: held messages, commit envelopes, live payloads, the file keys in messages.
- **State links are sealed.** `Admitted.doc` and `Frame::State`'s link carry the key of a doc's or table's state, and
  cross only iroh's classical TLS today. Each becomes `sealed`: the link under `MLS-Exporter("letmeknow state", group ‖
  epoch)`, as live payloads are (group.rs:814-850).
  - An `Admitted`'s is of the epoch the Add moves into: the committer derives it from the staged commit as it makes it
    (`StagedCommit::export_secret`) and keeps it with its answer; the joiner opens it from its staged Welcome.
  - A `State` frame names its epoch, as live payloads do. A receiver in another epoch drops it, and once in the
    sender's epoch asks again with `State { link: None }`, the request the frame already defines
    (crates/proto/src/peer.rs:46), which nothing sends or answers today; members answer it with a fresh link.
- **Not post-quantum:**
  - Ed25519 signatures, since authentication matters only once attacks run live.
  - iroh's transport: summaries, claims, hints, 10-minute invite secrets, and the certificate in a `Join`'s
    KeyPackage, with the member's name and device name (crates/node/src/admission.rs:109-117).
  - HTTPS to the service: rustls with ring has no hybrid key exchange (crates/serve/src/lib.rs:117,
    crates/session/src/lib.rs:73), so capabilities, log references and addresses cross it classically.

## The log

- **One log per epoch, as now.** A log's capability is an exporter of its epoch (group.rs:540-548), so a leaked
  database does not link a group's logs, beyond their days and sizes.
- **An entry is a commit and its signature:** `1 ‖ u32 length ‖ commit ‖ signature`, the committer's over
  `letmeknow commit v2\0 ‖ commit` (crates/proto/src/entry.rs). No Welcome.
- **The Welcome goes to the joiner alone.** `Admitted { commit, welcome, sig, doc }`: the log entry, the Welcome, and
  the committer's signature over `letmeknow welcome v1\0 ‖ SHA-256(commit) ‖ welcome`, which `Group::join` checks
  against the Welcome's sender as it checks the entry's today (group.rs:405-455). Members no longer keep Welcomes from
  the log (crates/node/src/reading.rs:112-114). A joiner whose answer was lost asks again, and only its committer,
  which keeps the answer for H (`logged_commit`, admission.rs:349), can answer it.
- **No keep-alive commits.** `KEEP_ALIVE`, `keep_alive` and `Rec.unkept` go (duties.rs:4, 31-48, 128, 180; held.rs:487;
  sending.rs:85; reading.rs:211; lib.rs:347-348). A member commits for its update each T, and for removals, adds,
  settings and names, as now; each cut keeps what its committer holds.
- **A pass first fetches** the messages past the cut that online members' summaries show held and it lacks, waiting
  as it waits for what the last cut kept (`blocked`, duties.rs:181-184; `HEAR`, 15 s), so a message another member
  holds is kept by the next commit while a holder is online. The commit itself, under the node's one commit lock
  (crates/node/src/groups.rs:25), never waits, and admissions do not fetch.
- **Holders count at the current epoch only.** `holders_of` (crates/node/src/sending.rs:18-24) and the pass's fetch
  count a member's summary only if it names the current epoch (`Summary.epoch`).
- **`only_here`** lists this session's messages that no other member's summary shows held, beside the files no other
  member holds yet, as now. It answers in seconds, for agents and for the browser's leave prompt (web/src/main.ts:106)
  alike. Where the status warning (crates/client/src/lib.rs:743), the browser's texts (main.ts:103, 893, 941;
  client.ts:37), crates/web/src/lib.rs:745-746, 818 and 870, crates/node/src/peering.rs:668, SKILL.md and README.md
  say "no commit keeps it yet", they say "no other member holds it yet", note that another member's copy counts only
  if that member is online at the next commit, and drop "commits within minutes".

## The service over HTTPS

- `serve` answers on its HTTPS listener, beside the directory (`Site`, crates/serve/src/lib.rs:290-334):
  `POST /membership/append`, `/membership/read` and `/membership/heads`, with `Access-Control-Allow-Origin: *`, and
  `OPTIONS` preflights answered with an `Access-Control-Max-Age`. Bodies are lmk-proto's membership JSON as now,
  answered with `Reply`: the value, or a refusal.
- It replaces the iroh membership protocol, which goes, with `Head`, `Subscribe`, the subscribers (`MAX_SUBSCRIBERS`),
  the membership port (serve/lib.rs:57, 75, 187-193; crates/session/src/cli.rs:95) and the directory's `addrs`.
- **Refusals are signed** with the service's key, over `letmeknow refusal v1\0 ‖ code ‖ SHA-256(request)`. Only such
  a refusal cancels a pending commit, as only a `Refused` does now (groups.rs:47-55); any other failure leaves it
  pending, posted again.
- **`heads`:** `{"logs": [[capability, length], …]}`, at most 256, answered with the signed heads of those whose length
  differs, and `expired` for those gone.
- Capabilities stay in bodies, never in URLs.
- **Limits**, per client address: IPv4 as itself, also when mapped into IPv6 (the listener is dual-stack,
  serve/lib.rs:236-245); IPv6 by its /48.
  - Appends: 600 and 16 MiB a minute. Reads and heads: 600 requests and 64 MiB a minute. At most 8 membership
    requests at once.
  - A TLS handshake timeout, and hyper's header timeout, which needs its timer (off now, serve/lib.rs:227): it also
    ends idle connections, and stops at an upgrade, so the relay's WebSockets (serve/lib.rs:308) keep their own limits.
  - Public log entries are at most 16 KiB; an address starts at most 10 public logs a day; public logs take at most a
    tenth of `--disk`. Anyone who knows an identity's id can append to its log.
  - Bodies, database work and memory as now. Per-address state lives in memory only; nothing about requests is
    written to disk.
  - A flood from many addresses can still fill the disk: appends are then refused as `quota` until expiry frees space,
    while members go on talking over peers.
- **The shells post,** as they fetch directories: the node is handed
  `Post = Arc<dyn Fn(String, &'static str, Vec<u8>) -> BoxFuture<Result<Vec<u8>>> + Send + Sync>` (domain, path,
  body), as it is handed `Resolve` (crates/membership/src/client.rs:33).
  - Natively: reqwest, with `LETMEKNOW_CA`, proxies, and the membership client's 30 s timeout (client.rs:85).
  - In the browser: fetch, with `credentials: "omit"` and `redirect: "error"`, through the resolver's channel
    (crates/web/src/lib.rs:314-331).
  - Replies are capped at `MAX_BODY`. A head signed by another key than the group's service warns, as `WrongDirectory`
    does now (crates/node/src/logs.rs:267-270).
  - lmk-testing serves membership over HTTPS (crates/testing/src/lib.rs:121-128).

## Following logs

- No subscriptions and no 5-minute re-read (`follow`, logs.rs:240-280; `REREAD`, crates/node/src/lib.rs:68). Per
  service, every 2 minutes with jitter, a session asks `heads` for its groups' current logs and the public logs it
  follows there, 256 to a request, and reads those that moved; hourly, also for the logs it keeps for its members'
  expiry (below). Earlier epochs' logs, kept for H, are not asked about (lib.rs:447). It reads at once a log it
  appended to.
- Peers' heads come sooner: `hello` carries them and `entries` brings what a peer lacks (`hellos`,
  crates/net/src/peers.rs:483).
- So a commit reaches a member with no peer online within 2 minutes.

## Expiry

- **Retention.** `serve --retention <days>`, default 30, at least 7 (`Policy`, service.rs:40; 365 now, for both kinds
  of log): a group log goes once its first entry is older. A public log goes a year after its last append, as now;
  devices restate unchanged keys every 182 days (crates/node/src/api.rs:365-382).
- **A log that goes leaves only its reference,** which answers reads, appends and `heads` with `expired`, so a member
  that fell behind learns it, and no one can start the log again: a deleted public log restarted from its first entry
  would bring back its revoked devices. The store sets `secure_delete` and truncates its WAL after each expiry pass,
  so a leaked file holds nothing expired.
- **What a leak shows:** each entry's day and padded size, whose bucket grows with its group; each live log's length;
  the references of expired logs; daily totals. Not which logs are one group's, times, addresses or capabilities.
- **A member that fell behind is out.** When the service answers `expired` for the log a session is in, and no peer
  brings its entries within `WAIT` (peers.rs:40), a commit the session never read is gone. It forgets the group, as on
  removal, and reports `removed`. A quiet group's log is empty, not expired, so a group survives any pause in which no
  one commits.
- **Members remove those who fell behind.**
  - For each other member, a session knows the latest epoch that member is surely at or past: its join epoch, the
    epoch after its latest commit, or its latest summary's (`Summary.epoch`). For a member silent since before this
    session joined, it uses its own join epoch.
  - It keeps each such epoch's log capability (32 bytes; exporters are of the current epoch only) and asks `heads`
    about those logs hourly.
  - A pass removes a member whose log answers `expired`, as it removes leavers (`due`).
  - In an identity group, that removal drops the device from its directory, which revokes its sessions everywhere. The
    device comes back through a device link (`identity invite`). A single-device identity never falls behind its own
    commits.
- **Forgetting a group deletes its keys,** including the key pairs openmls leaves after a removal (`EpochKeyPairs`;
  openmls's `MlsGroup::delete` removes only the current epoch's), so a later compromise of the device opens none of
  its last epochs.
- **Limits:**
  - A group ends if every member stayed away longer than the retention right after a commit that none of them read.
  - A joiner whose answer was lost, and whose committer is gone, is refused new invites as `MEMBER_ALREADY`
    (admission.rs:252) until its unused leaf is removed.
  - Retention must stay well above T, or active members fall behind between updates: hence the floor.
- Members keep earlier logs for H and serve them, as now.

## Formats: every switch flips

- **ALPN:** `letmeknow/3` → `letmeknow/4` (crates/proto/src/frame.rs:6).
- **Group protocol:** `PROTOCOL` 7 → 8 (crates/proto/src/group.rs:8): the suite, the entry, `Admitted`, sealed state
  links.
- **Invite link:** 7 → 8 (crates/proto/src/links.rs:16, 30, 42-43, 98-103, 108). A 7 link: "this invite link is from
  letmeknow 0.18, whose groups this version cannot join: ask for an invite to a group made with letmeknow 0.19".
- **Home format:** 7 → 8, `letmeknow-v8` (cli.rs:228, crates/session/src/lib.rs:217-236, tests.rs:1252); a format-7
  home gets the 0.18 command.
- **Browser:** database, Web Lock and BroadcastChannel `lmk7` → `lmk8` (web/src/store.ts:8, client.ts:75, 174;
  web/e2e.mjs:113, 123, 196, 237-262, 592, 606, 939), and `older()` looks for `lmk7` (store.ts:31-33).
- **Service store:** format 3 → 4 (`FORMAT`, store.rs:15), on a new service.
- **Version:** 0.19.0 and the `@letmeknow/cli@0.19` pins, with those in main.ts:41-43 and 145-150 and client.ts:2,
  which neither release.sh nor pins.py rewrites.

## Steps

Each leaves `main` building and green, with its own tests and the SKILL.md and README.md text it changes.

- **A. Switches and the suite:** the version, pins and every switch, with their refusal texts; the feature, the
  constant, new numbers for the size tests (crates/core/src/group_epoch_tests.rs:220). Tests: create, join, commit and
  messages under the suite, natively and in wasm; a 0.18 link, home and database are refused with their texts.
- **B. Sealed state links.** Tests: a link opens only in its epoch; a joiner opens its `Admitted` state, also after
  another commit landed first; a `State` frame of another epoch leads to a request, which is answered; a removed
  member's does not open.
- **C. Entry and Welcome.** Tests: a log entry holds no Welcome; a joiner joins from `Admitted`; a forged Welcome
  signature is refused; a lost answer is answered again by the committer.
- **D. No keep-alive.** Tests: a chatting group commits only when an update or change is due; a message another member
  holds leaves `only_here`, and comes back when that member's summary falls an epoch behind; the next commit keeps a
  message held only by an online member that is not the committer; an Add does not wait for holders. Tests that count
  on keep-alive commits change: crates/client/tests/client.rs:480-494, crates/node/tests/node.rs:2171-2205; the
  wording of crates/session/src/tests.rs:575-600 and 629-645 and web/e2e.mjs:963-976.
- **E. The service over HTTPS:** the routes, `heads`, signed refusals, limits and CORS; `Post` in both shells;
  lmk-testing over HTTPS; the iroh membership protocol deleted, with its test doubles (crates/node/tests/node.rs's `Gated`,
  crates/node/src/identity_tests.rs's `Authority`, the membership tests' `Probe` and `PrivateClose`), `addrs` and the
  membership port, also in web/backend.json, `Directory::builtin` and deploy/README.md. Tests: append, read and heads
  over HTTPS; refusals, and a forged one ignored; budgets per IPv4 address, mapped or not, and per IPv6 /48; a slow
  handshake or header times out; a browser joins and commits through it (e2e).
- **F. Following by heads:** the poll; no subscriptions. Tests: a commit reaches a member with no peer online within the
  poll; one request per service and 256 logs per poll; a directory's change reaches its follower.
- **G. Expiry:** the retention, logs left as references, `secure_delete`, a member that fell behind leaving, members
  removing it, keys deleted on forgetting. Tests: an expired log answers `expired` on every route, keeps no length or
  day, and cannot be appended again; a leaked store file holds no expired bytes; a member behind past the retention
  leaves and reports `removed`, and the others remove it; a group survives a pause longer than the retention; a
  device that missed its identity's commits past the retention is revoked; a single-device identity survives.
  SKILL.md's paragraph on expired history (SKILL.md:38) and README.md:40 say a session that the service's expiry left
  behind leaves the group.
- **H. Rollout:** a new service for letmeknow.dev, as deploy/README.md's "A new minor" says, and a `--disk` in
  deploy/letmeknow.service that holds the target (4 GiB by default, store.rs:16).

## Open

- The update period could grow with the group, so a big group does not start an epoch every minute or two.
- Entries could also be read by reference, over GET, for a CDN.
- A `Join` could be sealed under its invite's secret, so names never cross classical TLS.
- The references of expired group logs could go after a year; a member left behind longer would commit alone into a
  dead epoch, and its log would show another history.

## Not in 0.19

letmetalk; rejoin; a post-quantum transport; post-quantum signatures; a shorter cut, which post-quantum keys dwarf;
hiding from a live operator which logs are one group's, which each session's polls show.

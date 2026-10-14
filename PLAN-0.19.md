# 0.19: post-quantum groups, a lighter service

Draft 4, after three reviews. Nothing carries over from 0.18: 0.19 gets a new service, and existing chats, docs and
identities stay behind (#56). The plan goes when 0.19 ships.

- **Owner's decisions:**
  - Peers stay on iroh, and post-quantum is in MLS only.
  - The membership service is reached over HTTPS, and over nothing else.
  - `only_here` means held by no other member.
  - A leaked service database shows as little as possible: groups keep a log per epoch, and past the retention the
    service keeps only the bare references of expired logs.
  - There is no rejoin: a member that the service's expiry left behind is out, and comes back by invite. That holds
    in identity groups too, where it revokes the device.
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
  minutes after members talk, which are most commits and trace when each group talks; a year of history; daily totals
  and, in every expired log's anchor, its length, hash and last day, forever (crates/membership/src/store.rs:201).
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
  - iroh's transport: summaries, claims, hints, `hello`'s `At { group, epoch, log }` (peer.rs:54-62), which links a
    group's logs, 10-minute invite secrets, and the certificate in a `Join`'s KeyPackage, with the member's name and
    device name (crates/node/src/admission.rs:109-117).
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
  the log (crates/node/src/reading.rs:112-114).
- **A lost answer:** the joiner asks again, and only its committer, which keeps the answer for H (`logged_commit`,
  admission.rs:349), can answer it. The joiner asks again members that timed out, until 5 minutes have passed, since
  the node's one commit lock (crates/node/src/groups.rs:25) is held across `caught_up`, which can wait up to `WAIT`,
  120 s (crates/net/src/peers.rs:40), past `JOIN_WAIT`, 30 s (admission.rs:33).
- **No keep-alive commits.** `KEEP_ALIVE`, `keep_alive` and `Rec.unkept` go (duties.rs:4, 31-48, 128, 180; held.rs:487;
  sending.rs:85; reading.rs:211; lib.rs:347-348). A member commits for its update each T, and for removals, adds,
  settings and names, as now; each cut keeps what its committer holds.
- **Holders count by current sealings.** A cut keeps only sealings of the epoch it ends (duties.rs:62).
  - A summary lists, beside `held`, per membership, the unkept seqs it holds sealed in the summary's own epoch.
  - `holders_of` (crates/node/src/sending.rs:18-24), the cut's rule for its committer's own messages (duties.rs:64)
    and the pass's fetch count only those.
  - A member that takes a newer sealing of a seq it holds signs a new summary (held.rs:451-461 does not now), and
    wants again, from a member whose summary lists it, a seq it holds sealed in an ended epoch (`wanted`,
    held.rs:79-82, skips it now).
- **Resealing.** A `heads` answer that leaves a log out counts as a read of it, so an author reseals its unkept
  messages within a poll of another member's commit (`Log.at`, which resealing waits for: sending.rs:102). Reseals
  are pushed in frames of at most 1 MiB, as answers are (sending.rs:108-123 sends one frame, which past 16 MiB every
  reader drops).
- **A pass first fetches** the messages past the cut that connected members list held and it lacks: the set as it is
  when the pass first waits, for at most `HEAR`, 15 s. A pass that removes does not wait. Other commits keep only what
  their committer holds.
- **Catching up,** a member does not wait for what a commit older than H kept (`cleared`, reading.rs:66-86): no member
  carries it any more. A commit's authenticated data carries when it was made, by its committer's corrected clock.
- **`only_here`** lists this session's messages that no other member's summary lists as held in its epoch, beside the
  files no other member holds yet, as now. It answers in seconds, for agents and for the browser's leave prompt
  (web/src/main.ts:106) alike. Where the status warning (crates/client/src/lib.rs:743), the browser's texts
  (main.ts:103, 893, 941; client.ts:37), crates/web/src/lib.rs:745-746, 818 and 870, crates/node/src/peering.rs:668,
  SKILL.md and README.md say "no commit keeps it yet", they say "no other member holds it yet", note that another
  member's copy counts only if that member is online at the next commit, or holds it when it commits, and drop
  "commits within minutes".

## The service over HTTPS

- `serve` answers on its HTTPS listener, beside the directory (`Site`, crates/serve/src/lib.rs:290-334):
  `POST /membership/1/append`, `/membership/1/read` and `/membership/1/heads`. Their `1` is a switch, which AGENTS.md
  lists from then on. A client that gets 404 there stops and says that the service runs another minor.
- **Origins:** `Access-Control-Allow-Origin` names only the app's origins, letmeknow.dev and those `serve --origin`
  adds, so no other page can make its visitors append; `OPTIONS` preflights are answered with an
  `Access-Control-Max-Age`. The directory stays open to all origins.
- Bodies are lmk-proto's membership JSON as now, answered with `Reply`: the value, or a refusal.
- It replaces the iroh membership protocol, which goes, with `Head`, `Subscribe`, the subscribers (`MAX_SUBSCRIBERS`),
  the membership port (serve/lib.rs:57, 75, 187-193; crates/session/src/cli.rs:95) and the directory's `addrs`.
- **Signed answers.** The service signs each refusal over `letmeknow refusal v1\0 ‖ code ‖ SHA-256(request)`, and each
  expiry over `letmeknow expired v1\0 ‖ reference`, wherever it answers one: reads, appends and `heads` alike. Clients
  act on nothing else. Only a signed refusal cancels a pending commit, as only a `Refused` does now
  (groups.rs:47-55); any other failure leaves it pending, posted again.
- **`heads`:** `{"logs": [[capability, length], …]}`, at most 256, answered with the signed heads of those whose length
  differs, and the signed expiries of those gone.
- Capabilities stay in bodies, never in URLs.
- **Limits**, per client address: IPv4 as itself, also when mapped into IPv6 (the listener is dual-stack,
  serve/lib.rs:236-245); IPv6 by its /64, within a /48 budget 16 times as large.
  - Appends: 600 a minute and 256 MiB a day; new logs: 2,000 a day. Reads and heads: 600 requests and 64 MiB a
    minute. At most 8 membership requests at once from each address (a /48 at 16 times as many).
  - In all, at most 250,000 new logs a day, twice the target's.
  - A TLS handshake timeout, and hyper's header timeout, which needs its timer (off now, serve/lib.rs:227): it also
    ends idle connections, and stops at an upgrade, so the relay's WebSockets (serve/lib.rs:308) keep their own limits.
  - Public logs: entries of at most 16 KiB; at most 10 new public logs a day per address, and 10 stored entries a day
    per log; at most a tenth of `--disk`.
  - Bodies, database work and memory as now. Per-address state lives in memory only; nothing about requests is
    written to disk.
  - Floods from many addresses can still fill the disk: appends are then refused as `quota` until expiry frees space,
    while members go on talking over peers. Anyone who knows an identity's id can lengthen its directory by its
    daily appends.
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
- Peers' heads come sooner: `hello` carries them and `entries` brings what a peer lacks (`hellos`, peers.rs:483).
- So a commit reaches a member with no peer online within 2 minutes.

## Expiry

- **Retention.** `serve --retention <days>`, default 30, at least 7 (`Policy`, service.rs:40; 365 now). A group log
  goes once its first entry is older. A public log goes once its last append is older. Daily totals go after 7 days,
  all `/stats` shows (`STATS_DAYS`, store.rs:14).
- **A log that goes leaves only its reference,** which answers reads, appends and `heads` with a signed expiry, so a
  member that fell behind learns it, and no one can start the log again: a deleted public log started again from its
  first entry would bring back its revoked devices. The references are all the service keeps past the retention. The
  store sets `secure_delete` and truncates its WAL after each expiry pass, so a leaked file holds nothing expired.
- **Directories are touched, not restated.** At each commit of its identity group, a device appends its directory's
  last entry again, byte for byte; the service takes that as a touch: it moves the log's day and stores nothing. The
  182-day restate goes (crates/node/src/api.rs:365-382).
- **What a leak shows:** each entry's day and padded size, whose bucket grows with its group; each live log's length;
  the references of expired logs; 7 days of totals. Not which logs are one group's, times, addresses or capabilities.
- **A member that fell behind is out.** When the service answers a signed expiry for the log a session is in, and no
  peer brings its entries within `WAIT`, a commit the session never read is gone. It forgets the group, as on
  removal, and reports `removed`. A quiet group's log is empty, not expired, so a group survives any pause in which no
  one commits.
- **Members remove those who fell behind.**
  - For each other member, the group's record keeps the latest epoch that member is surely at or past: its join
    epoch, the epoch after its latest commit, or its latest summary's (`Summary.epoch`). For a member silent since
    before this session joined, it is this session's own join epoch.
  - For each such epoch, the record keeps its log's capability and service (32 bytes and the group's settings then;
    exporters are of the current epoch only), until no member's epoch is that one.
  - It asks `heads` about those logs hourly, and a pass removes a member whose log answers a signed expiry, as it
    removes leavers (`due`).
  - An admission of a key still in the tree first removes it, in a commit of its own, if its log has expired.
  - A member that read later commits without committing or being heard can be removed up to T early.
- **An expired directory ends its identity.** Members treat it as dropping all its devices, and remove their sessions
  as they remove a dropped device's (duties.rs:121-124). Its own devices forget it and report it. So an identity whose
  devices all stay off past the retention ends, with every certified membership it has. A quiet group of certified
  members ends once their identities do; only anonymous members outlast a long pause.
- **In an identity group,** removing a device that fell behind drops it from its directory, which revokes its
  sessions everywhere. So does a device left unused past the retention while another of the identity's devices is in
  use. The device is told: the identity kind reports its own removal, which it swallows now (identity.rs:349-351),
  with a warning that it needs a device link from another device (`identity invite`), then `add` into each group again.
  A single-device identity never falls behind its own commits.
- **Forgetting a group deletes its keys,** including the key pairs openmls leaves after a removal (`EpochKeyPairs`;
  openmls's `MlsGroup::delete` removes only the current epoch's), so a later compromise of a native session opens none
  of its last epochs. Browsers cannot promise it: IndexedDB keeps deleted records until it compacts.
- **Limits:**
  - A group ends if every member stayed away longer than the retention right after an entry none of them applied.
  - A joiner whose answer was lost, and whose committer is gone, gets in again only once its unused leaf is removed.
  - Retention must stay well above T, or active members fall behind between updates: hence the floor.
- Members keep earlier logs for H and serve them, as now.

## Formats: every switch flips

- **ALPN:** `letmeknow/3` → `letmeknow/4` (crates/proto/src/frame.rs:6).
- **Group protocol:** `PROTOCOL` 7 → 8 (crates/proto/src/group.rs:8): the suite, the entry, `Admitted`, sealed state
  links, summaries' current holdings, commits' times.
- **Invite link:** 7 → 8 (crates/proto/src/links.rs:16, 30, 42-43, 98-103, 108). A 7 link: "this invite link is from
  letmeknow 0.18, whose groups this version cannot join: ask for an invite to a group made with letmeknow 0.19".
- **Home format:** 7 → 8, `letmeknow-v8` (cli.rs:228, crates/session/src/lib.rs:217-236, tests.rs:1252); a format-7
  home gets the 0.18 command.
- **Browser:** database, Web Lock and BroadcastChannel `lmk7` → `lmk8` (web/src/store.ts:8, client.ts:75, 174;
  web/e2e.mjs:113, 123, 196, 237-262, 592, 606, 939), and `older()` looks for `lmk7` (store.ts:31-33).
- **Service store:** format 3 → 4 (`FORMAT`, store.rs:15), on a new service.
- **Membership routes:** new, at `/membership/1/`.
- **Version:** 0.19.0 and the `@letmeknow/cli@0.19` pins, with those in main.ts:41-43 and 145-150 and client.ts:2,
  which neither release.sh nor pins.py rewrites.

## Steps

Each leaves `main` building and green, with its own tests and the SKILL.md and README.md text it changes.

- **A. Switches and the suite:** the version, pins and every switch, with their refusal texts; the feature, the
  constant, new numbers for the size tests (crates/core/src/group_epoch_tests.rs:220). README.md:28 and SKILL.md:18 name
  0.18 as the previous minor, whose groups end with its service. Tests: create, join, commit and messages under the
  suite, natively and in wasm; a 0.18 link, home and database are refused with their texts.
- **B. Sealed state links.** Tests: a link opens only in its epoch; a joiner opens its `Admitted` state, also after
  another commit landed first; a `State` frame of another epoch leads to a request, which is answered; a removed
  member's does not open.
- **C. Entry and Welcome.** Tests: a log entry holds no Welcome; a joiner joins from `Admitted`; a forged Welcome
  signature is refused; a lost answer is answered again by the committer, also when it was busy past `JOIN_WAIT`.
  SKILL.md:72 says only the committer can answer a join again.
- **D. Keeping without keep-alive:** no keep-alive, current holdings, resealing, the pass's fetch, catching up. Tests:
  a chatting group commits only when an update or change is due; a message another member holds leaves `only_here`,
  and comes back when that member's copy is of an ended epoch, until it holds the new sealing; the next commit keeps a
  message held only by an online member that is not the committer; after another member's commit, the author reseals
  within one poll, in frames of at most 1 MiB; a pass that removes, and an Add, do not wait for holders. Tests that
  count on keep-alive commits change: crates/client/tests/client.rs:480-494, crates/node/tests/node.rs:2171-2205; the
  wording of crates/session/src/tests.rs:575-600 and 629-645 and web/e2e.mjs:963-976.
- **E. The service over HTTPS, and following by heads:**
  - The routes, `heads`, signed refusals and expiries, origins, limits; `Post` in both shells; lmk-testing over HTTPS;
    the poll, with no subscriptions.
  - The iroh membership protocol deleted, with its test doubles, which become `Post` wrappers per node: node.rs's
    `Gated` (crates/node/tests/node.rs:719-749, used at 831, 1247, 1433, 1833, 2400 and
    crates/node/tests/identity/claims.rs:216) and `Authority` (crates/node/src/identity_tests.rs:26-90), and the
    membership tests' `Probe` and `PrivateClose`. crates/membership/examples/probe.rs posts too.
  - `addrs` and the membership port go, also from web/backend.json, `Directory::builtin`, web/build-test.mjs:8,
    deploy/README.md (UDP 7843) and README.md:67.
  - Tests: append, read and heads over HTTPS; refusals and expiries, and a forged one of each ignored; a 404 stops the
    client with its text; a page of another origin cannot append; budgets per IPv4 address, mapped or not, per IPv6 /64
    and /48, for new logs, and in all; a slow handshake or header times out; a commit reaches a member with no peer
    online within the poll; one request per service and 256 logs per poll; a directory's change reaches its follower; a
    browser joins and commits through it (e2e).
- **F. Expiry:** the retention, logs left as references, touches, `secure_delete`, totals, a member that fell behind
  leaving, members removing it, expired directories, keys deleted on forgetting. Tests:
  - An expired log answers a signed expiry on every route, keeps no length or day, and cannot be appended again. A
    leaked store file holds no expired bytes. A run's journal holds no addresses, keys or capabilities, the relay's
    included.
  - A member behind past the retention leaves and reports `removed`, and the others remove it. A group survives a pause
    longer than the retention.
  - A touched directory outlives the retention, and an untouched one ends its identity and its sessions' memberships.
  - A device that missed its identity's commits past the retention is revoked and told; a single-device identity
    survives.
  - The store answers `heads` at the target's rate with a cold cache.
  - node.rs:1479-1499, which asserts that expired history keeps groups, changes. SKILL.md:22, 33 and 38 and
    README.md:40 say a session that the service's expiry left behind leaves the group, and that `not_kept` may then list
    messages a later cut kept.
- **G. Rollout:** a new service for letmeknow.dev, as deploy/README.md's "A new minor" says, and a `--disk` in
  deploy/letmeknow.service that holds the target (4 GiB by default, store.rs:16). README.md's "Your own server" names
  `--retention` and `--origin`.

## Open

- The update period could grow with the group, so a big group does not start an epoch every minute or two.
- Entries could also be read by reference, over GET, for a CDN.
- A `Join` could be sealed under its invite's secret, so names never cross classical TLS.
- The references of expired group logs could go after a year; a member left behind longer would commit alone into a
  dead epoch, and its log would show another history.
- H (`--carry`) can be longer than the retention, so members can hold messages longer than the service keeps commits.

## Not in 0.19

letmetalk; rejoin; a post-quantum transport; post-quantum signatures; a shorter cut, which post-quantum keys dwarf;
hiding from a live operator which logs are one group's, which each session's polls and `hello` show.

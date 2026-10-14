# 0.19: post-quantum groups, a lighter service

Draft 2, for review. Existing chats, docs and identities do not carry over (#56). The plan goes when 0.19 ships.

- **Owner's decisions:** peers stay on iroh; post-quantum in MLS only; the membership service over HTTPS; `only_here`
  means held by no other member; rejoin in 0.19; a leaked service database shows as little as possible, so groups keep
  a log per epoch, and an expired log leaves only its reference.
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
  expired log's anchor, its length, hash and last day, forever (store.rs:201).
- **A lost old device opens every epoch since its last update.** Each commit seals the next epoch's secrets to keys in
  the tree, a silent member's among them, and nothing removes a member for silence (`due`, duties.rs:115-130).
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
  - A `State` frame names its epoch, as live payloads do; a receiver in another epoch asks again. `sends` and `takes`
    check only their own end (crates/net/src/peers.rs:722-737).
- **Not post-quantum:**
  - Ed25519 signatures, since authentication matters only once attacks run live.
  - iroh's transport: summaries, claims, hints, 10-minute invite secrets, and the certificate in a `Join`'s or
    `Rejoin`'s KeyPackage, with the member's name and device name (crates/node/src/admission.rs:109-117).
  - HTTPS to the service: rustls with ring has no hybrid key exchange (crates/serve/src/lib.rs:117,
    crates/session/src/lib.rs:73), so capabilities, log references and addresses cross it classically.

## The log

- **One log per epoch, as now.** A log's capability is an exporter of its epoch (group.rs:540-548), so a leaked
  database does not link a group's logs, beyond their days and sizes.
- **An entry is a commit and its signature:** `1 ‖ u32 length ‖ commit ‖ signature`, the committer's over
  `letmeknow commit v2\0 ‖ commit` (crates/proto/src/entry.rs). No Welcome.
- **The Welcome goes to the joiner alone.** `Admitted { commit, welcome, sig, doc }`: the log entry, the Welcome, and
  the committer's signature over `letmeknow welcome v1\0 ‖ SHA-256(commit) ‖ welcome`, which `Group::join` checks
  against the Welcome's sender as it checks the entry's today (group.rs:405-455). The committer keeps its answer for H
  (`logged_commit`, admission.rs:349); members no longer keep Welcomes from the log (crates/node/src/reading.rs:112-114).
- **A lost answer is answered again.** The joiner asks again with the same KeyPackage, as now. The committer answers
  from what it kept. Any other member re-admits it: a Remove of its leaf, still as its KeyPackage made it (`unchanged`,
  group.rs:507), and an Add of the same KeyPackage, `how: rejoin`.
- **Memberships, not keys, carry the cut state.**
  - A commit may remove and add one key only as that pair alone, of the same identity and device, `how: rejoin`
    (`rules`, group.rs:949).
  - `merged` drops removed members' refs, rather than keeping those whose key is still in the tree (group.rs:762).
  - `Group::join` gives the joiner's own key a fresh ref (group.rs:439-442).
  - So the old membership ends at its final cut and the new one starts at seq 0 of the new epoch. Members report
    `joined` with `how: rejoin`, and no `left` for the old leaf (crates/node/src/groups.rs:174-178).
- **No keep-alive commits.** `KEEP_ALIVE`, `keep_alive` and `Rec.unkept` go (duties.rs:4, 31-48, 128, 180; held.rs:487;
  sending.rs:85; reading.rs:211; lib.rs:347-348). A member commits for its update each T, and for removals, adds,
  settings and names, as now; each cut keeps what its committer holds.
- **The committer first fetches** the messages past the cut that online members' summaries show held, waiting as for
  what the last cut kept (`HEAR`, 15 s), so a message another member holds is kept by the next commit while a holder is
  online. A commit that adds does not wait: its joiner gives up after `JOIN_WAIT`, 30 s (admission.rs:33).
- **Holders count at the current epoch only.** A cut keeps only sealings of the epoch it ends (duties.rs:62), so `cuts`
  drops from `servable` the sealings of ended epochs (reading.rs:184-189), which summaries then stop showing held.
- **`only_here`** lists this session's messages that no other member's summary shows held (`holders_of`,
  crates/node/src/sending.rs:18), beside the files no other member holds yet, as now. It answers in seconds, for agents
  and for the browser's leave prompt (web/src/main.ts:106) alike. Where the status warning (crates/client/src/lib.rs:743),
  the browser's texts (main.ts:103, 893, 941; client.ts:37), crates/web/src/lib.rs:745-746, 818 and 870, peering.rs:668,
  SKILL.md and README.md say "no commit keeps it yet", they say "no other member holds it yet", note that another
  member's copy counts only if that member is online at the next commit, and drop "commits within minutes".

## The service over HTTPS

- `serve` answers on its HTTPS listener, beside the directory (`Site`, crates/serve/src/lib.rs:290-334):
  `POST /membership/append`, `/membership/read` and `/membership/heads`, with `Access-Control-Allow-Origin: *`, and
  `OPTIONS` preflights answered with an `Access-Control-Max-Age`. Bodies are lmk-proto's membership JSON as now,
  answered with `Reply`: the value, or a refusal.
- **Refusals are signed** with the service's key, over the code and the request's hash. Only such a refusal cancels a
  pending commit, as only a `Refused` does now (groups.rs:47-55); any other failure leaves it pending, posted again.
- **`heads`:** `{"logs": [[capability, length], …]}`, at most 256, answered with the signed heads of those whose length
  differs, and `expired` for those gone. `Head` and `Subscribe` leave 0.19's API.
- Capabilities stay in bodies, never in URLs.
- **Limits** per client address: IPv4 as itself, also when mapped into IPv6 (the listener is dual-stack,
  serve/lib.rs:236-245); IPv6 by its /64.
  - Appends: 600 and 16 MiB a minute. Reads and heads: 600 requests and 64 MiB a minute.
  - A connection cap, and header, body and idle timeouts: hyper's timer, off now (serve/lib.rs:227).
  - Bodies, database work and memory as now.
  - Per-address state lives in memory only; nothing about requests is written to disk.
- **Public log entries** are at most 16 KiB, since anyone who knows an identity's id can append to its log.
- **The shells post,** as they fetch directories: the node is handed
  `Post = Arc<dyn Fn(String, &'static str, Vec<u8>) -> BoxFuture<Result<Vec<u8>>> + Send + Sync>` (domain, path,
  body), as it is handed `Resolve` (crates/membership/src/client.rs:33).
  - Natively: reqwest, with `LETMEKNOW_CA`, proxies, and the membership client's 30 s timeout (client.rs:85).
  - In the browser: fetch, with `credentials: "omit"` and `redirect: "error"`, through the resolver's channel
    (crates/web/src/lib.rs:314-331).
  - Replies are capped at `MAX_BODY`. A head signed by another key than the group's service warns, as `WrongDirectory`
    does now (crates/node/src/logs.rs:267-270).
  - lmk-testing serves membership over HTTPS (crates/testing/src/lib.rs:121-128).
- The iroh membership protocol stays in `serve` for 0.18 sessions until they are gone; 0.19 sessions never dial it.
  The directory keeps `addrs` for them.

## Following logs

- No subscriptions and no 5-minute re-read (`follow`, logs.rs:240-285; `REREAD`, crates/node/src/lib.rs:68). Per
  service, every 2 minutes with jitter, a session asks `heads` for its groups' current logs and the public logs it
  follows there, 256 to a request, and reads those that moved. Earlier epochs' logs, kept for H, are not asked about
  (lib.rs:447). It reads at once a log it appended to.
- Peers' heads come sooner: `hello` carries them and `entries` brings what a peer lacks (`hellos`, peers.rs:483).
- So a commit reaches a member with no peer online within 2 minutes.

## Silence and rejoin

A member that cannot catch up joins again through any member, keeping its key.
- **Silent members are removed.** Each commit sets its committer's leaf's `updated`, a day. A pass removes the members
  whose `updated` is more than 30 days old, or 2 T if longer, and records each in the settings' `silenced`: its key,
  identity and device, the SHA-256 of its leaf's encryption key, and the day. A record goes after a year. `rules` lets
  a commit add to `silenced` only keys it removes whose leaf is that old, give or take a day, and drop only keys it
  adds back by rejoin, or records a year old. So a lost old device opens at most the epochs of 30 days after its last
  update.
- **When:** the service answers `expired` for the log a member is in and no peer serves its entries within the wait;
  or the member reads its own removal for silence.
- **The ask,** on the admission stream, whose first frame becomes `Join` or `Rejoin { group, epoch, key_package, leaf,
  sig }`: the epoch the rejoiner is in, a new KeyPackage of the same session key, and, if it was removed for silence,
  its leaf's encryption key then, signed by the session key over `letmeknow rejoin v1\0 ‖ group ‖ epoch ‖
  SHA-256(key_package)`. It asks the members its tree names, dialed as now (leaves' keys, hints, the service's relay).
- **The member checks** that the key is a current member's or recorded in `silenced`; that the KeyPackage names the
  same key, a certificate of the same identity and device, still on its identity's list read afresh (as `invite --to`
  checks, admission.rs:271-279), and the group's kind; and that within H it heard no summary from that membership at
  an epoch past the Rejoin's (`Summary.epoch`), as another live copy of the session would sign.
- **Then it challenges:** it sends a nonce sealed by HPKE to the rejoiner's leaf encryption key, the tree's or the one
  `silenced` hashes, and commits only once the nonce comes back. A copy from before the owner's last update cannot
  open it.
- **The commit** removes the old leaf, if it is still there, adds the new KeyPackage, `how: rejoin`, drops the key from
  `silenced`, and is answered as an admission.
- **Not a member:** a member whose tree lacks the key and whose `silenced` does not record it refuses so; when every
  member reached does, the session reports `removed`. A member that left, or whose device was dropped, cannot rejoin.
- **The rejoiner** restarts the group's records from the Welcome, as a joiner does: openmls replaces the old group
  (`replace_old_group`), and `welcomed` (admission.rs:213) takes a Welcome for a group it holds when it answers its
  Rejoin. What its client was shown stays with the client. Its sends past its final cut are reported in `not_kept`, as
  on removal.

## Retention and what the service keeps

- **Group logs' entries** expire after `serve --retention <days>`, default 30 (`Policy`, service.rs:40; 365 now, one
  knob for both kinds of log).
- **Public logs** go whole a year after their last append, as now, under their own rule; devices restate unchanged
  keys every 182 days (crates/node/src/api.rs:365-382).
- **An expired log leaves only its reference.** Once its last record goes, the store drops its length, hash, day and
  counts, and the reference answers reads, appends and `heads` with `expired`. A format-3 store migrates in place at
  start, one way (`FORMAT`, store.rs:15).
- **What a leak shows:** each entry's day and padded size, whose bucket grows with its group; each live log's length;
  the references of expired logs; daily totals. Not which logs are one group's, times, addresses or capabilities.
- Members keep earlier logs for H and serve them, as now.
- letmeknow.dev runs `--retention 365` until 0.18 sessions are gone, since they cannot rejoin: deploy/letmeknow.service
  passes it, and a `--disk` that holds it (4 GiB by default, store.rs:16).
- **Rollout** follows deploy/README.md's order for a new minor, which brings the service up before pi-letmeknow's
  `MINOR` and Pages. Its note that the membership API is unchanged becomes: the service adds the HTTPS API and keeps the
  iroh one. A session started at `@0.19` between npm and the service reaches no service until it is up.

## Formats: the switches 0.19 flips

- **Group protocol:** `PROTOCOL` 7 → 8 (crates/proto/src/group.rs:8): the suite, the entry, `Admitted`, sealed state
  links, `Rejoin`, `How::Rejoin`, `Leaf.updated`, `Settings.silenced`.
- **Invite link:** 7 → 8 (crates/proto/src/links.rs:30, 42, 98-103). A 7 link: "this invite link is from letmeknow
  0.18, whose groups this version cannot join: ask for an invite to a group made with letmeknow 0.19".
- **Home format:** 7 → 8, `letmeknow-v8` (crates/session/src/cli.rs:228, lib.rs:217-236, tests.rs:1252); a format-7
  home gets the 0.18 command.
- **Browser:** database, Web Lock and BroadcastChannel `lmk7` → `lmk8` (web/src/store.ts:8, client.ts:75, 174;
  web/e2e.mjs:113, 196, 592, 606, 939), and `older()` looks for `lmk7` (store.ts:31-33).
- **Version:** 0.19.0 and the `@letmeknow/cli@0.19` pins, with those in main.ts:41-43 and 145-150 and client.ts:2,
  which neither release.sh nor pins.py rewrites.
- **Service store:** format 3 → 4, migrated in place.
- **Not flipped:** the ALPN `letmeknow/3`. One service serves 0.18 and 0.19, whose groups never meet; compat.py runs the
  released 0.18 against the new `serve`.

## Steps

Each leaves `main` building and green, with its own tests and the SKILL.md and README.md text it changes.

- **A. Switches and the suite:** the version, pins, protocol, link, home and database, with their refusal texts;
  compat.py tests 0.18, its `SERVICE` mapping writing 0.18's service form (compat.py:10, 130); the feature, the
  constant, new numbers for the size tests (group_epoch_tests.rs:220). Tests: create, join, commit and messages under
  the suite, natively and in wasm; a 0.18 link, home and database are refused with their texts.
- **B. Sealed state links.** Tests: a link opens only in its epoch; a joiner opens its `Admitted` state, also after
  another commit landed first; a `State` frame of another epoch is asked for again; a removed member's does not open.
- **C. Entry, Welcome and re-admission.** Tests: a log entry holds no Welcome; a joiner joins from `Admitted`; a forged
  Welcome signature is refused; a lost answer is answered again by the committer, and by another member through a
  re-admission; after it, members open the new membership's messages, the next commit applies everywhere, and a later
  joiner joins.
- **D. No keep-alive.** Tests: a chatting group commits only when an update or change is due; a message another member
  holds leaves `only_here`, and comes back when that member missed the next commit; the next commit keeps a message
  held only by an online member that is not the committer; an Add does not wait for holders.
- **E. HTTPS service:** the routes, `heads`, signed refusals, limits and CORS; `Post` in both shells; lmk-testing over
  HTTPS. Tests: append, read and heads over HTTPS; refusals, and a forged one ignored; budgets per IPv4 address,
  mapped or not, and per IPv6 /64; a slow header times out; a browser joins and commits through it (e2e).
- **F. Following by heads:** the poll; no subscriptions. Tests: a commit reaches a member with no peer online within the
  poll; one request per service and 256 logs per poll; a directory's change reaches its follower.
- **G. Silence and rejoin.** Tests: a member silent past the bound is removed and rejoins; a member whose log expired
  rejoins; a commit that records a recent member as silent is refused; a removed member's rejoin is refused and it
  reports `removed`; a copy from before the owner's last update fails the challenge; a copy live at a later epoch is
  refused.
- **H. Retention and rollout:** `--retention`, public logs' rule, expired logs left as references and the store's
  migration, the unit file, deploy/README.md; compat with 0.18. Tests: an expired log answers `expired` on every route
  and keeps no length or day; a public log outlives the retention; a format-3 store migrates.

## Open

- The update period could grow with the group, so a big group does not start an epoch every minute or two.
- Entries could also be read by reference, over GET, for a CDN.
- A `Join` could be sealed under its invite's secret, and a `Rejoin`'s KeyPackage under its challenge, so names never
  cross classical TLS.
- The references of expired logs could go after some years; a member left behind before then would commit alone into
  a dead epoch instead of rejoining.

## Not in 0.19

letmetalk; a post-quantum transport; post-quantum signatures; a shorter cut, which post-quantum keys dwarf; hiding from
a live operator which logs are one group's, which each session's polls show.

# 0.19: post-quantum groups, a lighter service

Draft 1, for review. Existing chats, docs and identities do not carry over (#56). The plan goes when 0.19 ships.

- **Owner's decisions:** peers stay on iroh; post-quantum in MLS only; the membership service over HTTPS; `only_here`
  means held by no other member; rejoin in 0.19.
- **Target:** 100k memberships and 1M messages a day on one service. Messages never reach it. Commits are about one
  daily update a membership plus joins and leaves, about 1.4 a second; entries kept 30 days take about 40 GB.

## Why

- **Harvest now, decrypt later.** Every group secret rests on X25519, in MLS's HPKE. Whoever records the service's
  sealed commits, or relayed traffic, can open them once a quantum computer exists.
- **The service is the first wall at scale.** Each followed log is a subscription stream of its own, re-read every 5
  minutes, and a session follows its groups' logs and every member identity's directory. 4,096 subscriptions in all
  (`MAX_SUBSCRIBERS`, crates/membership/src/service.rs:20) fill at a few hundred online sessions.
- **The log holds what members could hold:** each add's Welcome, with the whole ratchet tree; keep-alive commits 10 to
  20 minutes after members talk, which are most commits and trace when each group talks; a year of history.
- **Post-quantum keys multiply commit size** (measured with the suite below): a KeyPackage is 3.2 KB; an update commit
  fills 8 KiB at 2 members (2 KiB now) and 16 KiB at 10 (4 KiB now); a Welcome takes about 3.2 KB a member, so inside
  an entry it would cap a group near 300.

## Post-quantum MLS

- **The suite.** `CIPHERSUITE` (crates/core/src/group.rs:21) becomes `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`:
  X-Wing (ML-KEM-768 with X25519) for HPKE, the rest as now. openmls and openmls_rust_crypto take the feature
  `draft-ietf-mls-pq-ciphersuites` and keep their exact pins, as the suite comes from a draft: an upgrade that changes
  its wire format is a new minor. It builds for wasm32.
- What MLS secrets seal follows: held messages, commit envelopes, live payloads, the file keys in messages.
- **State links are sealed.** `Admitted.doc` and `Frame::State`'s link carry the key of a doc's or table's state, and
  cross only iroh's classical TLS today. Each becomes `sealed`: the link under `MLS-Exporter("letmeknow state", group ‖
  epoch)`, as live payloads are (group.rs:814-850). A `State` frame's under the current epoch, which both ends are at
  (`sends`, crates/net/src/peers.rs); an `Admitted`'s under the epoch the Add moves into.
- **Not post-quantum:** Ed25519 signatures, since authentication matters only once attacks run live; and iroh's
  transport, which then exposes metadata only: summaries, claims, hints and 10-minute invite secrets.

## The log

- **An entry is a commit and its signature:** `1 ‖ u32 length ‖ commit ‖ signature`, the committer's over
  `letmeknow commit v2\0 ‖ commit` (crates/proto/src/entry.rs). No Welcome.
- **The Welcome goes to the joiner alone.** `Admitted { commit, welcome, sig, state }`: the log entry, the Welcome, and
  the committer's signature over `letmeknow welcome v1\0 ‖ SHA-256(commit) ‖ welcome`, which `Group::join` checks
  against the Welcome's sender as it checks the entry's today (group.rs:405-455). The committer keeps its answer for H,
  for a joiner whose answer was lost (`logged_commit`, crates/node/src/admission.rs:349); members no longer keep
  Welcomes from the log (crates/node/src/reading.rs:102-114). Any other member answers such a joiner by rejoin.
- **No keep-alive commits.** `KEEP_ALIVE`, `keep_alive` and `Rec.unkept` go (crates/node/src/duties.rs:31-48, 128;
  held.rs:487; sending.rs:85; reading.rs:211). A member commits for its update each T, and for removals, adds,
  settings and names, as now; each cut keeps what its committer holds.
- **The committer first fetches** the messages past the cut that online members' summaries show held, waiting as for
  what the last cut kept (`HEAR`, 15 s), so a message another member holds is kept by the next commit while a holder is
  online.
- **`only_here`** lists this session's messages that no other member's summary shows held (`holders_of`,
  crates/node/src/sending.rs:18), beside the files no other member holds yet, as now. It answers in seconds, for agents
  and for the browser's leave prompt (web/src/main.ts:106) alike. The status warning (crates/client/src/lib.rs:743), the
  browser's texts (main.ts:893, 941), SKILL.md and README.md say "no other member holds it yet" where they say "no
  commit keeps it yet", and drop "commits within minutes".

## The service over HTTPS

- `serve` answers on its HTTPS listener, beside the directory (`Site`, crates/serve/src/lib.rs:290-334):
  `POST /membership/append`, `/membership/read` and `/membership/heads`, with `Access-Control-Allow-Origin: *`. Bodies
  are lmk-proto's membership JSON as now, answered with `Reply`: the value or a refusal code. A status other than 200
  means the request never reached the service.
- **`heads`:** `{"logs": [[capability, length], …]}`, at most 256, answered with the signed heads of those whose
  length differs. `Head` and `Subscribe` leave 0.19's API.
- Capabilities stay in bodies, never in URLs.
- Limits as now (bodies, database work, memory); appends per client IP, IPv6 by its /64, 600 a minute.
- **The shells post,** as they fetch directories: the node is handed
  `Post = Arc<dyn Fn(String, &'static str, Vec<u8>) -> BoxFuture<Result<Vec<u8>>> + Send + Sync>` (domain, path,
  body), as it is handed `Resolve` (crates/membership/src/client.rs:33). Natively reqwest, with `LETMEKNOW_CA` and
  proxies; in the browser fetch, with `credentials: "omit"`.
- The iroh membership protocol stays in `serve` for 0.18 sessions until they are gone; 0.19 sessions never dial it.
  The directory keeps `addrs` for them.

## Following logs

- No subscriptions and no 5-minute re-read (`follow`, crates/node/src/logs.rs:240-285; `REREAD`, lib.rs:68). Per
  service, every 2 minutes with jitter, a session asks `heads` for every log it follows there, group and public alike,
  and reads those that moved. It reads at once a log it appended to.
- Peers' heads come sooner: `hello` carries them and `entries` brings what a peer lacks (`hellos`, peers.rs:483).
- So a commit reaches a member with no peer online within 2 minutes.

## Rejoin

A member that cannot catch up joins again through any member, keeping its key.
- **When:** the service answers `expired` for the log a member is in and no peer serves its entries within the wait;
  or a joiner asks again with its kept KeyPackage, and the member it asks holds no answer for it.
- **The ask,** on the admission stream, whose one frame becomes `Join` or `Rejoin { group, key_package, sig }`: a new
  KeyPackage of the same session key, signed by that key over `letmeknow rejoin v1\0 ‖ group ‖ SHA-256(key_package)`. It
  asks the members its tree names, dialed as now (leaves' keys, hints, the service's relay).
- **The member checks** that the key is a current member's; that it heard no summary from that membership within H, so
  a stolen copy of an active session is refused; and that the KeyPackage names the same key, a certificate of the same
  identity and device, and the group's kind. It then commits `Remove` of the old leaf and `Add` of the new, `how:
  rejoin`, and answers as an admission. `rules` lets a rejoin add the key it removes (group.rs:949): the old membership
  ends at its final cut, and the new one starts in the new epoch.
- **Not a member:** a member whose tree lacks the key refuses so; when every member reached does, the session reports
  `removed`.
- **The rejoiner** restarts the group's records from the Welcome, as a joiner does; what its client was shown stays with
  the client. Its sends past its final cut are reported in `not_kept`, as on removal. Every member reports `joined`
  with `how: rejoin`.

## Retention

- `serve --retention <days>`, default 30 (`Policy`, service.rs:40; 365 now). The directory names it: `"retention": 30`.
  Anchors stay.
- letmeknow.dev runs `--retention 365` until 0.18 sessions are gone, since they cannot rejoin.
- Members keep earlier logs for H and serve them, as now.

## Formats: the switches 0.19 flips

- **Group protocol:** `PROTOCOL` 7 → 8 (crates/proto/src/group.rs:8): the suite, the entry, `Admitted`, sealed state
  links, `Rejoin`, `How::Rejoin`.
- **Invite link:** 7 → 8 (crates/proto/src/links.rs:42). A 7 link: "this invite link is from letmeknow 0.18, whose
  groups this version cannot join: ask for an invite to a group made with letmeknow 0.19".
- **Home format:** 7 → 8, `letmeknow-v8` (crates/session/src/cli.rs:228); a format-7 home gets the 0.18 command.
- **Browser:** database, Web Lock and BroadcastChannel `lmk7` → `lmk8` (web/src/store.ts:8, client.ts:75, 174,
  web/e2e.mjs:113).
- **Version:** 0.19.0 and the `@letmeknow/cli@0.19` pins.
- **Not flipped:** the ALPN `letmeknow/3`. One service serves 0.18 and 0.19, whose groups never meet; compat.py runs the
  released 0.18 against the new `serve`.

## Steps

Each leaves `main` building and green, with its own tests.

- **A. The suite:** the feature, the constant, new numbers for the size tests (group_epoch_tests.rs:220). Tests:
  create, join, commit and messages under it, natively and in wasm.
- **B. Sealed state links.** Tests: a link opens only in its epoch; a joiner opens its `Admitted` state; a removed
  member's frame does not open.
- **C. Entry and Welcome.** Tests: a log entry holds no Welcome; a joiner joins from `Admitted`; a forged Welcome
  signature is refused; a lost answer is answered again by the committer.
- **D. No keep-alive.** Tests: a chatting group commits only when an update or change is due; a message another
  member holds leaves `only_here`; the next commit keeps a message held only by an online member that is not the
  committer.
- **E. HTTPS service:** the routes, `heads`, limits and CORS; `Post` in both shells. Tests: append, read and heads over
  HTTPS; refusals; a browser joins and commits through it (e2e).
- **F. Following by heads:** the poll; no subscriptions. Tests: a commit reaches a member with no peer online within the
  poll; one request per service per poll; a directory's change reaches its follower.
- **G. Rejoin.** Tests: a member away past retention rejoins; a removed member's rejoin is refused and it reports
  `removed`; a stolen copy of an active session is refused; a joiner whose committer vanished after the Add rejoins
  through another member.
- **H. Retention, switches, docs, version and pins;** compat with 0.18.

## Open

- The update period could grow with the group, so a big group does not start an epoch every minute or two.
- Entries could also be read by reference, over GET, for a CDN.

## Not in 0.19

letmetalk; a post-quantum transport; post-quantum signatures; a shorter cut, which post-quantum keys dwarf; expiring
anchors.

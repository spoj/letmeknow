# Plan: 0.20, for agents

Draft 6. Each step makes a line of CHARACTERISTICS.md true, or cheaper to keep true. All of it is 0.20, a new minor on a new service where nothing carries over: step 1 flips the switches, so that `main` carries 0.20 from the start, and steps 1 to 9 make 0.20.0. Step 10 can follow as a 0.20 patch. The plan goes when its last step ships.

## 1. 0.20: every switch flips

- Version 0.20.0, and `@letmeknow/cli@0.20` wherever `test/pins.py` looks; ALPN `letmeknow/5`; membership routes `/membership/2/`; group `PROTOCOL` 9 at `REVISION` 0; invite links version 9, refusing 8's as 0.19's, with `test/e2e.py`'s expected link; home `letmeknow-v9`, whose `format` file says 9 and refuses 8's as 0.19's; the service store's `FORMAT` 5, with the column step 9 adds.
- A new service with a new key, in `crates/proto/src/links.rs` and the backend's configuration, as deploy/README's "A new minor" says.
- README and SKILL say that 0.19's groups and identities do not carry over.
- Tests: a 0.19 link and a 0.19 home are refused, each with its text.

## 2. One commit lock per group

For: a link makes a member within 10 seconds while the inviter is online.

Today one node-wide lock (`Inner.committing`, `crates/node/src/lib.rs`) is held across `caught_up` (`crates/node/src/groups.rs`), which waits up to `WAIT` (120 seconds) for kept messages, so a group waiting on repair stalls commits and admissions in every other group, the identity's included.

- Each group has its own commit lock.
- An admission answers a joiner retrying after a lost answer (`logged_commit`) before it waits on `caught_up`.
- Accepted for now: an admission into a group that is itself waiting for kept messages still waits for them, up to `WAIT`, so links into such a group miss the 10 seconds.
- Test: while group A's commit waits in `caught_up`, a commit in group B and an admission retry in A complete.

## 3. History forgotten

For: a session's state grows with its current groups, never with its history.

Today a group's state keeps an `Added` record, with credentials and certificates, for every join it saw, and rewrites them all at each commit: a group that 100 sessions join a day gathers 36,000 a year. The session's `taken` and `attachments` tables (`crates/session/src/store.rs`) keep a row for every message and attachment taken in, until the group is left.

- An `Added` record stays while its member is in the group, while its invite can still be used, or for H after the join, so that a `Control::Invite` arriving late still finds its invite used. Records gain the time of their join.
- `taken` rows and `attachments` rows go H after their message; an attachment's private copy goes with its row. SKILL says how long copies last.
- Tests: removed members' records go after H, while current members', recent ones and those of usable invites stay; a group's saved state and the session's tables after K messages, joins and leaves do not grow with K.

## 4. Messages stay with the members they were sent to

For: "Who will read this?" has an exact answer: the group's members when it was sent.

Today `reseal` (`crates/node/src/sending.rs`) seals a sender's messages past its cut again in the new epoch and broadcasts them to every member, a member that the epoch's commit added included; answers to `Want` are sealed for the asker's epoch too. So a message sent while an Add is in flight reaches the joiner.

- No member sends a joiner, as a reseal or as an answer, a message sent before it joined. A joiner that a later message names such a message to sees it as `missing`, as any message it cannot get.
- Test: a message sent while an Add is in flight never reaches the joiner.

## 5. Polls on kept connections

For: the service's egress, within 1 TB a month.

A poll on a new TLS connection takes about 3.3 KB of egress, and on a kept one about 0.4 KB: with about 10,000 sessions online at once in the reference load, 27 GB a day against 3, of a 33 GB budget. Today the client drops idle connections after 90 seconds (reqwest's default) while it polls every 90 to 120; the server's `header_read_timeout` of 10 seconds (`crates/serve/src/lib.rs`) may close idle ones sooner; and the server's rustls keeps its default cache of 256 sessions, with no ticketer, so few clients resume.

- A running session's polls reuse one connection to its service; the server keeps an idle connection longer than `POLL`.
- Test: a session polling through several `POLL`s makes one TLS handshake at the service.
- Measure egress per poll at letmeknow.dev, on 0.19's service before and on 0.20's after, and with it the delivery time between online members at p99, which no test measures yet.

## 6. No browser

For: portability, now Linux, macOS, Windows and Android (Termux); one client; one fewer party that can replace the code people run.

- Goes: `crates/web`; `web/`, with its build and test scripts; the browser half of `test/e2e.py`; the release's `frontend` job and asset; pages.yml's app build and its gate on the backend's health; the membership service's `--origin` and CORS answers, `serve`'s `APP` and its hidden `--public-logs`; the wasm32 builds of the node, core, net, membership and client crates, with their wasm gates, getrandom's `wasm_js`, `[profile.wasm]`, CI jobs and AGENTS.md checks; and the seams only the page needed: `Config.durable` and `Durable`, `MemoryProvider`'s save tracking, the wasm `spawn`.
- `lmk-client`, now with one user, folds into the session, its seams for the page and for plugins gone.
- `web/backend.json` and its reader move to `deploy/`, which `deploy/deploy.sh`, the release workflow and `deploy/check-backend.py` read; the pin lists (`test/pins.py`, `deploy/release.sh`, `test/deploy.py`) drop web files.
- letmeknow.dev, where invite links point (`https://letmeknow.dev/i#…`), serves a static page from `site/`, published by pages.yml: what the link is, and the command that joins with it. The page's service worker clears the app's caches and unregisters, so that an installed 0.19 app gives way to it.
- Docs: README's browser and trusted-frontend parts; SKILL's browser mentions; AGENTS.md's frontend and browser-database lines and its checks; deploy/README's frontend rollout.
- Test: `test/e2e.py` runs its command-line path alone.

## 7. No docs or tables

For: "Who will read this?" exact, with step 4: today a doc or table hands every joiner its whole state, written before it joined.

- Goes: `crates/kinds`, with its yrs dependency, its binaries in the release and its CI check; kinds' plugins and their hosting (`crates/session/src/kinds.rs`, `kinds::discover`, the client's `Plugins`); `Leaf.kinds` and the admission's check of it; the kind state handed to a joiner and to a member found behind (`crates/node/src/kind.rs`, `Frame::State`, state links, `STATE_LABEL`, `Admitted.doc`); `invite --kind`, `join <link> [file]`, `doc attach`, `edited`, the `letmeknow <kind>` commands, and `test/e2e.py`'s doc path.
- `logged_commit` knows its own Adds by `commit_key`, not by the state's `admitted_key`.
- Stay: chat, attachments and `fetch`, live payloads, and the identity kind, built in. Agents share files as attachments and code as git bundles (SKILL's "Sharing code").
- Docs: SKILL's description, its Docs and Tables sections and its plugins paragraph; README; `npm/cli/package.json`'s description.
- Test: a joiner gets nothing from before it joined but its Welcome.

## 8. A week's retention

For: a session resumes within seven days, and nothing in use lapses.

- `serve --retention` and `Policy`'s `retention_days` default to 7 days, today's floor, instead of 30. Group logs and directories keep sharing it, so each lives seven to eight days past its clock, counted in whole UTC days. A service may still choose longer.
- T stays 24 hours, far inside it, and H stays 7 days: as long as a member can surely be away. One away longer that is still a member finds its gaps told, as `not_kept`.
- Tests, on a shifted clock: a member away six days resumes; one whose group commits just after it leaves, and that stays away past the retention, is removed; a device away past the retention while another goes on leaves its identity.
- Docs: README's `--retention` default and its storage figure; SKILL's resume window.

## 9. Quiet groups and idle identities end

For: a group with nobody online for about seven days ends, and so does an identity with no device online; a session away up to seven days resumes, in a quiet group too.

Today the service records a group log at its first entry and lets it go a retention after that entry's day (`opened`). An epoch's log stays empty until the commit that ends the epoch, so a group nobody commits to never goes (`a_group_quiet_past_the_retention_survives`). A directory's day moves only at its identity's commits, up to T apart, so an identity's clock can start a day before its last device went offline.

- The service opens a group log on an empty append, which it refuses today: an open records an empty log with today as its `opened` day, or moves an empty log's `opened` to today. It changes nothing once the log has an entry, and is refused for a directory and for a log that went.
- A log's first entry sets `opened` to its day, so an absent member keeps a full retention from the commit it missed.
- While online, a member opens its current epoch's log as it enters the epoch and every hour after, and a device touches its directory every hour, in one request per service. A log's clock thus starts at most an hour before its last member or device went offline. These touches replace the touch at each identity commit.
- Members need nothing new: one whose current log went leaves after `WAIT`, as one that missed commits does (`lapse` in `crates/node/src/logs.rs`); a device whose directory went leaves its identity, as today.
- The retention counts only time the service runs. Each expiry pass records its day; at a start, before its first pass, live logs' days move on by the days since that record, plus one, as days are whole.
- Tests: the last member goes offline 23 hours after its group's last commit and comes back six and a half days later to the group; a group nobody is online in for longer than the retention ends for each member as it comes back, replacing the test above; a device last online 23 hours after its identity's last commit keeps its identity six and a half days later; in the store, an open creates or moves only an empty log and is refused for a directory and for a log that went, and a first entry sets `opened`; a service stopped for longer than the retention lets no log go at its start that was live when it stopped.

## 10. Freshness passed between peers (0.20 patch, after step 5's measurement)

For: members serve one another, and the service is asked only for what needs its authority, when no member can vouch for it.

Today every online session asks its service about every log it follows each 90 to 120 seconds. Peers already pass each other entries with heads the service signed, but not that nothing changed: the service signs heads only for logs that moved, so an unchanged log's freshness comes only from asking.

- The service signs, for each chunk of up to `HEAD_LOGS` (256) logs asked, its time and the root of a Merkle tree over the logs that did not move, at their lengths and hashes, padded to `HEAD_LOGS` leaves so that a proof shows neither how many logs its prover follows nor which.
- After each answer, a session passes its peers the proofs for the logs they share. It counts a valid proof as its own read while it is younger than `POLL` by its estimate of the service's clock, and asks the service only about logs no peer vouched for, or not at all when none is left.
- A revocation or a commit reaches an online member within `POLL` and a peer's hop, the 2 minutes of today. A peer can withhold a proof but not forge one; the service's answer grows by one signature a chunk.
- Tests: three online members of a group make about one request per `POLL` between them for its logs; a member cut off from the others still learns of a revocation within 2 minutes; a stale or forged proof is ignored, and one that contradicts a held head is reported.
- Older 0.20 releases skip the new frame (`read_known`) and keep polling.

## Held without a step

- Used keys and shown text cannot be recovered: `a_forgotten_group_leaves_no_epoch_keys` (`crates/core/src/group_tests.rs`), `text_shown_or_left_behind_stays_in_no_file` (`crates/session/src/tests.rs`).
- Identities stay as 0.19 has them, but for step 9's touches: an identity is its group of devices, and its directory is that group's public roster, written by its members (`Identity::duties`). A device that lapses from the group is revoked.
- T, at 24 hours.

## Dropped from draft 2

- Sealed admission: CHARACTERISTICS.md lets a later quantum attacker learn names, file hashes and joins.
- The adaptive update period: groups stay at 128 members or fewer.
- Bounded peer `Entries`: a group log holds one epoch's commits, and a directory only its device changes; neither nears 16 MiB.
- Expiring group-log references: a service lives one minor, and at the reference load they grow by under 10 GB a year.
- Live relays: nothing above needs them, and a relay change reaches sessions as they restart.

# Plan: 0.20, for agents

Draft 4. Each step makes a line of CHARACTERISTICS.md true, or cheaper to keep true. Steps 1 to 3 change no format and ship as 0.19 patches. Step 4 makes `main` 0.20, a new minor on a new service, where nothing carries over; steps 5 to 8 need it, as they take away what 0.19's users rely on, or set the service's rules from its start. Step 9 waits for step 3's measurement and can follow as a 0.20 patch. The plan goes when its last step ships.

## 1. One commit lock per group (0.19 patch)

For: a link makes a member within 10 seconds while the inviter is online.

Today one node-wide lock (`Inner.committing`) is held across `caught_up`, which waits up to `WAIT` (120 seconds) for kept messages, so a group waiting on repair stalls commits and admissions in every other group, the identity's included.

- Each group has its own commit lock.
- An admission answers a joiner retrying after a lost answer (`logged_commit`) before it waits on `caught_up`.
- Test: while group A's commit waits in `caught_up`, a commit in group B and an admission retry in A complete.

## 2. Joins forgotten (0.19 patch)

For: a session's state grows with its current groups, never with its history.

Today a group's state keeps an `Added` record, with credentials and certificates, for every join it saw, and rewrites them all at each commit: a group that 100 sessions join a day gathers 36,000 a year.

- A record stays while its member is in the group, while its invite can still be used, or for H after the join, so that a `Control::Invite` arriving late still finds its invite used.
- Tests: removed members' records go after H; current members', recent ones and those of usable invites stay; a group's saved state after K joins and leaves does not grow with K.

## 3. Polls on kept connections (0.19 patch)

For: the service's egress, within 1 TB a month.

A poll on a new TLS connection takes about 3.3 KB of egress, and on a kept one about 0.4 KB: at the reference load, 27 GB a day against 3, of a 33 GB budget. Today the client drops idle connections after 90 seconds (reqwest's default) while it polls every 90 to 120, the server's 10-second header timeout may close them sooner, and rustls resumes only 256 TLS sessions.

- A running session's polls reuse one connection to its service.
- Test: a session polling through several `POLL`s makes one TLS handshake at the service. Measure egress per poll at letmeknow.dev before and after.

## 4. 0.20: every switch flips

- Version 0.20.0, and `@letmeknow/cli@0.20` wherever `test/pins.py` looks; ALPN `letmeknow/5`; membership routes `/membership/2/`; group `PROTOCOL` 9 at `REVISION` 0; invite links version 9, refusing 8's as 0.19's; home `letmeknow-v9`; the service store's `FORMAT` 5.
- README and SKILL say that 0.19's groups and identities do not carry over.
- Tests: a 0.19 link and a 0.19 home are refused, each with its text.

## 5. No browser

For: portability, now Linux, macOS, Windows and Android (Termux); one client; and one fewer party that can replace the code people run.

- Goes: `crates/web`; `web/` with its build and test scripts; the browser half of `test/e2e.py`; the release's `frontend` job and asset; the membership service's `--origin` and its CORS answers; the wasm32 builds of the node, core, net, membership and client crates, with their wasm-only code, CI jobs and AGENTS.md checks; and whatever in the client core only the page used.
- letmeknow.dev, where invite links point (`https://letmeknow.dev/i#…`), serves a static page instead of the app: what the link is, and the command that joins with it.
- Docs: README's browser and trusted-frontend parts; SKILL's browser mentions; AGENTS.md's frontend and browser-database lines; deploy/README's frontend rollout.
- Test: `test/e2e.py` runs its command-line path alone.

## 6. No docs or tables

For: "Who will read this?" exact without exception. Today a doc or table hands every joiner its whole state, written before it joined.

- Goes: `crates/kinds`, with its yrs dependency; kinds' plugins and their hosting (`crates/session/src/kinds.rs`, the client's `Plugins`); the kind state handed to a joiner and to a member found behind (`crates/node/src/kind.rs`, `Frame::State`, state links); `invite --kind`, `join <link> [file]`, `doc attach`, `edited`, and `letmeknow <kind>` commands.
- Stay: chat, attachments and `fetch`, live payloads, and the identity kind, built in. Agents share files as attachments and code as git bundles (SKILL's "Sharing code").
- Docs: SKILL's description, its Docs and Tables sections and its plugins paragraph; README.
- Test: a joiner gets nothing from before it joined but its Welcome.

## 7. Two days' retention

For: a session resumes within two days, and nothing in use lapses.

- `serve --retention` defaults to 2 days, at least 2 (today 30, at least 7). Group logs and directories keep sharing it, so each lives 48 to 72 hours past its clock, counted in whole UTC days.
- T stays 24 hours. An online member its peers cannot hear is judged by the epoch of its last commit, and updates at least a day before that epoch's log can go: the margin the 7-day floor kept.
- New groups carry messages for 3 days (`--carry`, H), not 7: past the two days a member can surely be away. One away longer that is still a member finds its gaps told, as `not_kept`.
- Tests, on a shifted clock: a member away 47 hours resumes, and one away past the retention while its group went on is removed; a member online but unheard stays one across a week of daily updates; a device away past the retention leaves its identity.
- Docs: README's `--retention` and its storage figure; SKILL's resume window and `--carry` default.

## 8. Quiet groups end

For: a group with nobody online for about two days ends.

Today the service records a group log at its first entry and lets it go a retention after that entry. An epoch's log stays empty until the commit that ends the epoch, so a group nobody commits to never goes (`a_group_quiet_past_the_retention_survives`).

- The service opens a group log on an empty append, which it refuses today: it records the log, empty, with today as its day. Opening is idempotent, and a directory cannot be opened empty.
- An open, empty log goes a retention after it was opened. Its first entry restarts its clock, so an absent member keeps a full retention from the commit it missed.
- The member whose commit the service took opens the next epoch's log; a group's creator opens its first. If it stops in between, that epoch's log is unclocked until its commit, as every log is today.
- Members need nothing new: one whose current log went leaves after `WAIT`, as one that missed commits does (`lapse` in `crates/node/src/logs.rs`).
- The retention counts only time the service runs: at a start, live logs' days move on by the whole days it was down, so an outage ends no group.
- Tests: a group nobody commits to for longer than the retention ends for each member as it comes back, replacing the test above; a member away less than the retention since the commit it missed resumes, though its epoch opened earlier; in the store, an open is idempotent and refused for a directory, the first entry restarts the clock, and expiry takes open, empty logs past the cutoff; a service stopped for longer than the retention lets no log go at its start that was live when it stopped.

## 9. Freshness passed between peers (0.20 patch, once 3 is measured)

For: the service as a backstop, asked only what no peer can vouch for.

Today every online session asks its service about every log it follows each 90 to 120 seconds. Peers already pass each other entries with heads the service signed, but not that nothing changed: the service signs heads only for logs that moved, so an unchanged log's freshness comes only from asking.

- Each answer to `heads` carries one signature over its time and every log asked that did not move, at its length and hash: a Merkle root, so that a session can show a peer only the logs they share.
- After each answer, a session passes its peers the proofs for the logs they share. It counts a valid proof no older than `POLL` as its own read, and asks the service only about logs no peer vouched for, or not at all when none is left.
- Revocations and commits still reach every online member within `POLL`. A peer can withhold a proof but not forge one; a proof shows no log its receiver does not follow; the service's answer grows by one signature.
- Tests: three online members of a group make about one request per `POLL` between them for its logs; a member cut off from the others still learns of a revocation within 2 minutes; a stale or forged proof is ignored, and one that contradicts a held head is reported.
- Older 0.20 releases skip the new frame (`read_known`) and keep polling.

## Kept

- Identities: an identity is its group of devices, and its directory is that group's public roster, written by its members (`Identity::duties`). A device that lapses from the group is revoked.
- T, at 24 hours.

## Dropped from draft 2

- Sealed admission: CHARACTERISTICS.md lets a later quantum attacker learn names, file hashes and joins.
- The adaptive update period: groups stay at 128 members or fewer.
- Bounded peer `Entries`: a group log holds one epoch's commits, and a directory only its device changes; neither nears 16 MiB.
- Expiring group-log references: a service lives one minor, and at the reference load they grow by under 10 GB a year.
- Live relays: nothing above needs them, and a relay change reaches sessions as they restart.

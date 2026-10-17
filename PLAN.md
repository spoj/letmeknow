# Plan: toward the characteristics

Draft 3. Each step makes a line of CHARACTERISTICS.md true, or cheaper to keep true, and ships as a 0.19 patch: none changes a format, and where a step needs both sides, an older release on either side keeps today's behaviour. A new minor would end every group and identity at once; these patches end only what idles past two days. The plan goes when its last step ships.

## 1. Two days' retention

For: a session resumes within two days, and nothing in use lapses.

- `serve --retention` defaults to 2 days, at least 2 (today 30, at least 7). Group logs and directories keep sharing it, so each lives 48 to 72 hours past its clock, counted in whole UTC days.
- T stays 24 hours. An online member its peers cannot hear is judged by the epoch of its last commit, and updates at least a day before that epoch's log can go: the margin the 7-day floor kept.
- New groups carry messages for 3 days (`--carry`, H), not 7: past the two days a member can surely be away. One away longer that is still a member finds its gaps told, as `not_kept`.
- Tests, on a shifted clock: a member away 47 hours resumes, and one away past the retention while its group went on is removed; a member online but unheard stays one across a week of daily updates; a device away past the retention leaves its identity.
- Docs: README's `--retention` and its storage figure; SKILL's resume window and `--carry` default.
- Rollout: letmeknow.dev's service takes it at its next deploy. The release notes say that identities and memberships idle for more than two days end then.

## 2. Quiet groups end

For: a group with nobody online for about two days ends.

Today the service records a group log at its first entry and lets it go a retention after that entry. An epoch's log stays empty until the commit that ends the epoch, so a group nobody commits to never goes (`a_group_quiet_past_the_retention_survives`).

- The service opens a group log on an empty append, which it refuses today: it records the log, empty, with today as its day. Opening is idempotent, and a directory cannot be opened empty.
- An open, empty log goes a retention after it was opened. Its first entry restarts its clock, so an absent member keeps a full retention from the commit it missed.
- The member whose commit the service took opens the next epoch's log; a group's creator opens its first. If it stops in between, that epoch keeps today's behaviour.
- Members need nothing new: one whose current log went leaves after `WAIT`, as one that missed commits does (`lapse` in `crates/node/src/logs.rs`).
- The retention counts only time the service runs: at a start, live logs' days move on by the whole days it was down, so an outage ends no group.
- Tests: a group nobody commits to for longer than the retention ends for each member as it comes back, replacing the test above; a member away less than the retention since the commit it missed resumes, though its epoch opened earlier; in the store, an open is idempotent and refused for a directory, the first entry restarts the clock, and expiry takes open, empty logs past the cutoff; a service stopped for longer than the retention lets no log go at its start that was live when it stopped.
- Older releases: an older committer does not open, and an older service refuses the open; either way that epoch keeps today's behaviour.

## 3. One commit lock per group

For: a link makes a member within 10 seconds while the inviter is online.

Today one node-wide lock (`Inner.committing`) is held across `caught_up`, which waits up to `WAIT` (120 seconds) for kept messages, so a group waiting on repair stalls commits and admissions in every other group, the identity's included.

- Each group has its own commit lock.
- An admission answers a joiner retrying after a lost answer (`logged_commit`) before it waits on `caught_up`.
- Test: while group A's commit waits in `caught_up`, a commit in group B and an admission retry in A complete.

## 4. Joins forgotten

For: a session's state grows with its current groups, never with its history.

Today a group's state keeps an `Added` record, with credentials and certificates, for every join it saw, and rewrites them all at each commit: a group that 100 sessions join a day gathers 36,000 a year.

- A record stays while its member is in the group, while its invite can still be used, or for H after the join, so that a `Control::Invite` arriving late still finds its invite used.
- Tests: removed members' records go after H; current members', recent ones and those of usable invites stay; a group's saved state after K joins and leaves does not grow with K.

## 5. Polls on kept connections

For: the service's egress, within 1 TB a month.

A poll on a new TLS connection takes about 3.3 KB of egress, and on a kept one about 0.4 KB: at the reference load, 27 GB a day against 3, of a 33 GB budget. Today the client drops idle connections after 90 seconds (reqwest's default) while it polls every 90 to 120, the server's 10-second header timeout may close them sooner, and rustls resumes only 256 TLS sessions.

- A running session's polls reuse one connection to its service.
- Test: a session polling through several `POLL`s makes one TLS handshake at the service. Measure egress per poll at letmeknow.dev before and after.

## 6. Freshness passed between peers

For: the service as a backstop, asked only what no peer can vouch for. Take it once 5 is measured.

Today every online session asks its service about every log it follows each 90 to 120 seconds. Peers already pass each other entries with heads the service signed, but not that nothing changed: the service signs heads only for logs that moved, so an unchanged log's freshness comes only from asking.

- Each answer to `heads` carries one signature over its time and every log asked that did not move, at its length and hash: a Merkle root, so that a session can show a peer only the logs they share.
- After each answer, a session passes its peers the proofs for the logs they share. It counts a valid proof no older than `POLL` as its own read, and asks the service only about logs no peer vouched for, or not at all when none is left.
- Revocations and commits still reach every online member within `POLL`. A peer can withhold a proof but not forge one; a proof shows no log its receiver does not follow; the service's answer grows by one signature.
- Tests: three online members of a group make about one request per `POLL` between them for its logs; a member cut off from the others still learns of a revocation within 2 minutes; a stale or forged proof is ignored, and one that contradicts a held head is reported.
- Older releases skip the new frame (`read_known`) and keep polling; an older service sends no signature, and its sessions keep polling.

## Kept

- Identities: an identity is its group of devices, and its directory is that group's public roster, written by its members (`Identity::duties`). A device that lapses from the group is revoked.
- T, at 24 hours.

## Dropped from draft 2

- Sealed admission: CHARACTERISTICS.md lets a later quantum attacker learn names, file hashes and joins.
- The adaptive update period: groups stay at 128 members or fewer.
- Bounded peer `Entries`: a group log holds one epoch's commits, and a directory only its device changes; neither nears 16 MiB.
- Expiring group-log references: a service lives one minor, and at the reference load they grow by under 10 GB a year.
- Live relays: nothing above needs them, and a relay change reaches sessions as they restart.
- Flipping every switch: no step changes a format.

# What letmeknow is built to be

A draft to settle before planning 0.20, drawn from the decision records (#66, #79, #80), README.md, SKILL.md, AGENTS.md
and the 0.19 and 0.20 plans. **Decide** marks what is still open. Once settled, the ranking and its rule go into
AGENTS.md, the guarantees and non-goals into README.md, each target into a test, and this file goes.

## Purpose

AI agents and the people they work with share small end-to-end encrypted groups (chats, docs, tables), joined by a
link, with no accounts. Agent-first (#79): each session is a member and a mind of its own; sessions share what they know
only through groups.

The reference load, which sets every number below:
- A group: 2 to 10 members, mostly agents and one or two people; at most 128.
- A session: up to 128 groups. Agents run `listen` for days and take patches when they restart; people's browsers come
  and go.
- A service: 100,000 to 1,000,000 memberships, churning fast: a device makes up to 100 sessions a day, each a member of
  its groups, and few are active at once. Groups and identities stay warm for 30 days. **Decide** whether the
  1,000,000 are held at once or made each day: the budgets below take them as held at once, and made each day they are
  30 times tighter.
- Its hardware: a modest cloud deployment, with 1 TB of storage, 1 TB a month of egress and 256 GB of memory.

The budgets this sets, at 1,000,000 memberships: about 33 KB of stored commits and 33 KB of egress per membership a
day. A post-quantum commit fills an 8 KiB bucket at 3 members and 32 KiB at 50 (measured for 0.19).

## What the load implies

- **Ended sessions leave within hours.** A session that stops without leaving stays a member until the log of its epoch
  expires, 30 days after the group moves on. A group that every new session joins would fill its 128 places with dead
  sessions within a day, each named in every commit's cut and carried in every Welcome (about 1.7 KB a member). That
  collides with characteristic 3's resume within the retention. **Decide**: sessions that say they are ephemeral leave
  as they stop, or their groups remove them after hours of silence, while persistent ones keep the 30 days.
- **Polls may spend the egress.** Each online native session asks for heads every 90 to 120 s. reqwest drops a
  connection idle for 90 s, and the server's 256-entry TLS session cache resumes few of thousands of clients, so most
  polls likely pay a full handshake, about 3 KB from the server: about 15,000 sessions online would spend the 1 TB a
  month on polls alone. Measure; then reuse connections, push, or poll less while peers carry commits.
- **Commits reach online members from peers.** Read from the service by every member, a 5-member group's daily updates
  alone cost 40 KiB a membership-day. Peers carry commits today; the budget makes it a requirement, and the service
  serves those who were away.
- **Expired references** grow by about 1.5 GB a month at a million epochs a day; their expiry (0.20's C) is due once a
  service outlives its minor (Decide: continuity).
- **The relay** carries all of a browser's traffic, files included (#78). **Decide** whether it shares the 1 TB of
  egress, or relays scale apart.

## Characteristics, ranked

When two conflict, the higher one wins, unless a target says otherwise.

1. **Exact, forward-secret confidentiality.** "Who will read this?" has an exact answer: the members of the epoch it is
   sealed in (#66). Used keys and shown text cannot be recovered (#80, SKILL.md). Content resists a later quantum
   attack on what is recorded now.
   - Targets: a copy of a member's state reads new messages for at most T (24 h) after it was taken; natively, used
     keys and shown text leave no bytes on disk after a scrub.
   - Guard: a removed member opens nothing of later epochs; storage scans, as `a_forgotten_group_leaves_no_epoch_keys`.
2. **Infrastructure that learns little and impersonates no one.** The service orders commits and keeps directories,
   relays forward ciphertext, and none holds accounts. The service can withhold, delay and refuse, and a contradiction
   is reported; it cannot read, add members or forge an identity. Identities are self-certifying and belong to their
   devices (#66).
   - Targets: the table below.
   - Guard: `a_contradiction_is_reported_once` and the forgery tests; a scan that what crosses classical channels holds
     no name, identity ID or KeyPackage (its scope: Decide, quantum observer).
3. **Agent-first, without friction.** From nothing to a member with `npx` and a link; a session resumes after any
   restart within the retention; it wakes its agent only for what concerns it.
   - Targets (**Decide**): a link to membership in 10 s with the inviter online, whatever its other groups are doing;
     online-to-online delivery in 5 s at p99, also right after a tab handoff (#77).
   - Guard: e2e.py's joins and deliveries, timed.
4. **Works without the service.** Chat goes on among online members while the service is down; membership waits for it
   (#80). Delivery is causal and every gap is told (`missing`, `late`, `lost`, `not_kept`): nothing is lost silently,
   and nothing a step produces leaves before it is durable. A group that must stay reachable keeps an always-on member.
   - Targets: membership changes reach online members at once, others within 2 minutes.
   - Guard: `chat_works_while_the_service_is_down`, `lost_seqs_are_told_once_across_restarts`.
5. **Small and cheap to run.** One `serve` binary, self-hostable. Every structure in a session or the service is
   bounded by current members, H and the retention, never by history, and no frame exceeds what its reader takes.
   - Targets: the reference load within the storage and egress budgets; a session's state after K joins and leaves
     independent of K. The service's expired references grow with history until continuity, as each minor starts a new
     service.
6. **Simple enough for one maintainer and agents.** Minimum code (AGENTS.md), I/O-free cores, and tests rather than
   review to hold each characteristic.

Constraints:
- **Portability:** Linux, macOS, Windows, Android (Termux) and browsers (wasm), on the same node code. What the node
  depends on builds for wasm32, and everything native builds for Windows.
- **Evolution:** while pre-alpha, speed over continuity: nothing crosses a minor version, and within one, members run
  side by side (AGENTS.md). **Decide** what ends this (identities carried over, #56).

## Who learns and can do what

| Party | Learns | Can | Cannot |
|---|---|---|---|
| Member | its epochs' content, every member's leaf | add and remove anyone | read a chat from before it joined |
| Removed member, revoked device | what it had | | read later epochs, or use an invite made before it left |
| Link holder | the invite's secret | join once, while it is valid | |
| Service | each log's length, sizes and timing; who polls which logs; capabilities | withhold, delay, refuse, expire, contradict itself (reported) | read, add members, forge identities |
| Relay | endpoint IDs, addresses, traffic timing | drop, delay | read |
| Releases, Pages and DNS | | replace the code everyone runs (README.md) | |
| Observer that breaks X25519 later | **Decide**: today `hello`, summaries, file hashes, joins and service requests | | content, commits, state links |

## Not goals, for now

Groups past 128 members; the service holding messages for absent members, as a group that must stay reachable keeps an
always-on member; hiding the group graph from a live service or network observer; post-quantum signatures; history for
a chat's joiners; shared state across one person's devices (#79); one group across services; continuity across minor
versions, until its trigger.

## Decide

1. **Memberships:** 1,000,000 held at once, or made each day.
2. **Ephemeral sessions:** how a session that stops for good leaves its groups within hours.
3. **The relay's egress:** inside the 1 TB a month, or apart.
4. **What a later quantum observer may learn:** which of names, the group graph and file hashes must stay hidden; at the
   transport (a hybrid key exchange through iroh's `crypto_provider`, if it builds for wasm) or frame by frame.
5. **Continuity:** when minor versions stop resetting everyone, what carries over, and whether the service's state,
   whose loss freezes every group and identity on it, is backed up.
6. **The targets** in 3.
7. **Where this lives:** as above, or a file of its own.

## For 0.20, if this holds

- As 0.19.x patches: the per-group commit lock (3: a join waits on no other group), bounded `Entries` frames and
  `Added` pruning (5).
- Dropped: the adaptive T, as groups stay at 128 members or fewer.
- Waiting on Decide 4: sealed admission, whose invites must stay unusable to removed members. On 5: tombstone expiry. On
  a relay list that changes: live relays.
- New, from the load: ephemeral sessions that leave (Decide 2), and the cost of polls, measured first.

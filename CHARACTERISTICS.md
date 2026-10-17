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
- A service: 100,000 active users, each starting about 10 sessions a day, one of which makes a membership: about
  100,000 new memberships a day, most of which go stale or are seldom online. Groups and identities stay warm for 30
  days.
- Its hardware: a modest cloud deployment for the membership service alone, with 1 TB of storage, 1 TB a month of
  egress and 256 GB of memory. Relays scale apart.

## What the load implies

Worked for a day, with a post-quantum commit at 8 KiB for 3 members and 32 KiB for 50 (measured for 0.19); the other
assumptions are rough:

| A day's | Assuming | Comes to |
|---|---|---|
| Commits | 100,000 Adds, up to as many Removes, and an update for each membership online that day (3 per user) | 400,000 to 500,000 |
| Storage, kept 30 days | 8 to 16 KiB a commit | 120 to 240 GB of 1 TB |
| Egress for polls | 10,000 sessions online at once, 823 polls each: 3.3 KB with a fresh TLS handshake, 0.4 KB on a kept connection | 27 GB, or 3 GB |
| Egress for commits | 2 readers at the service for each 8 KiB commit; 20 GB if each of 5 members reads | 8 GB |
| Egress for directories | 10 reads of about 3 KB for each join | 3 GB |
| Egress, of 33 GB | | 38 GB with fresh handshakes; 14 GB on kept connections |

- **Storage and memory are comfortable:** 30 days of commits fit in memory, as "warm" asks.
- **Egress binds.** It fits only if polls keep their connections, which reqwest drops after 90 s idle against a poll
  every 90 to 120 s and the server's TLS cache resumes only 256 clients, or the service pushes; and if peers carry
  most commits, leaving the service those who were away. Measure both.
- **Memberships held at once** are the new ones times the days until each is removed, the lease below: about 3,000,000
  at today's 30 days, 700,000 at 7 and 100,000 at one. A group gathers stale members at the rate sessions join it,
  each named in every commit's cut and carried in every Welcome (about 1.7 KB a member): one that 100 sessions a day
  join holds about 100 stale members even at a one-day lease, and fills its 128 places at any longer one, unless they
  leave as they stop.
- **Expired references** grow by under 1 GB a month; their expiry (0.20's C) is due once a service outlives its minor
  (Decide: continuity).

**Quiet, absent and gone.** An online session commits a leaf update every T (24 h) even when it says nothing, and the
log shows that to every member alike, so a quiet member and an absent one already differ. Only the session knows
whether an absent one is gone for good, and harnesses are disposable, so the lease is central: the service's retention
of group logs, by 0.19's lapse rule. A member away past it cannot read the commit it missed; it leaves, and the others
remove it, with nothing in a leaf or a harness. **Decide** its length, a promise to people more than a budget: at 7
days the service already stores 30 to 50 GB and holds about 700,000 memberships. At 24 hours, as the code stands:
- Directories share the retention, so an identity whose devices are all off for a day ends, with its memberships:
  directories need their own, 30 days.
- Identity groups' logs are group logs, so a device unused for a day while another is in use is revoked everywhere,
  and the service cannot tell those logs apart.
- The 7-day floor is there because retention must stay well above T: an unheard member is judged by its last commit,
  and would be removed while online.
- Resume shrinks to a day: an agent resumed after a weekend, or a person back on Monday, needs new invites.

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
- **Thin harnesses:** a harness (pi-letmeknow, a Claude Code plugin) starts `listen` and passes its output on; no
  characteristic depends on what it does.
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

1. **The lease:** the group logs' retention, a day, a weekend or a week, with directories split off at 30 days.
2. **What a later quantum observer may learn:** which of names, the group graph and file hashes must stay hidden; at the
   transport (a hybrid key exchange through iroh's `crypto_provider`, if it builds for wasm) or frame by frame.
3. **Continuity:** when minor versions stop resetting everyone, what carries over, and whether the service's state,
   whose loss freezes every group and identity on it, is backed up.
4. **The targets** in 3.
5. **Where this lives:** as above, or a file of its own.

## For 0.20, if this holds

- As 0.19.x patches: the per-group commit lock (3: a join waits on no other group), bounded `Entries` frames and
  `Added` pruning (5).
- Dropped: the adaptive T, as groups stay at 128 members or fewer.
- Waiting on Decide 2: sealed admission, whose invites must stay unusable to removed members. On 3: tombstone expiry. On
  a relay list that changes: live relays.
- New, from the load: `serve`'s retention split into group logs' (the lease, Decide 1) and directories', a patch;
  polls on kept connections, a patch once measured.

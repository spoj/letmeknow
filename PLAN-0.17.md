# 0.17: causal chat over gossip

Spec draft 3 of #80, the implementation contract until 0.17 ships; then it goes, as PLAN-0.16.md went. It settles
draft 2's open items (numbered as there, under "Settled"), keeps its decisions, and answers the draft-1 review where it
still applies. Existing chats, docs and identities do not carry over.

## Model

Every member keeps, per group:

- **memberships**: a member's MLS signature key and `joined`, the epoch its Add moved into (0 for the creator). A key
  admitted again is a new membership, with a new sequence.
- **cut state**: per current membership, `(seq, id)`: how far its held messages are kept by the group. It changes only
  when a commit applies, and every member derives it alike from the commits it applied.
- **held messages**: by id, and by `(membership, seq)`.
- **delivery state**: per membership, the seqs delivered, given up (missing past the wait, lost, or not kept), and the
  seqs its client marked shown.

A held message is in one of these states for a member: *pending* (opened, waiting on requirements), *delivered* (handed
to the client and kind; the client may then show it), *kept* (at or below its author's cut: every member holds it, or
knows it lost it), *not kept* (its author's membership ended with a cut below it). Delivered and kept are independent: a
member may deliver a message no cut ever keeps.

**Guarantees.** Every held message of a membership that stays is eventually kept, once its author is online in an epoch
and some committer holds it. All members agree on the kept set of each epoch. A member that held the keys of every
epoch since it joined delivers every kept message, or reports it lost by `(author, seq)`. A removed or departed
member's messages after its final cut may reach only some members; members that delivered them keep them, and
messages that depend on them are delivered without them. Control effects (`leave`, invites, identity adds) act on
delivery, as now, independent of later cuts: a leave or an invite from a member later removed is judged against the
membership current when it acts, as `admits` does now.

## Held messages

The plaintext of the MLS application message is `body ‖ sig`: `body` is the header's JSON, `sig` (the last 64 bytes)
the author's Ed25519 signature, by its leaf's signature key, over `"letmeknow held v1\0" ‖ body`.

```json
{"group": "<16-byte group id>", "author": "<key>", "joined": 3, "seq": 7, "prev": "<id of seq 6>",
 "deps": [["<key>", 2, 41, "<id>"]], "reply_to": "<id>", "payload": {"type": "message", "content": "…"}}
```

- `id = SHA-256(plaintext)`: the same in every epoch the author seals it in, as the author keeps and reseals the exact
  bytes. The body names the group, so ids are group-scoped; storage keys them by `(group, id)`.
- `prev` is absent for seq 1. `deps` holds at most one entry per membership, none the author's own; `reply_to` and
  `deps` are absent when empty.
- A receiver checks, after MLS opens it: `group` is the group; `author` is the MLS sender's signature key; `joined` is
  the sender's current membership's (from the cut state; a membership the receiver never saw is taken as claimed, as
  it predates the receiver); the signature; `seq ≥ 1` and `prev` present iff `seq > 1`; `deps` well formed; `payload`
  has a `type`. A message failing any check is dropped. `prev` is checked against the held `seq - 1`, and a dep's id
  against the held message it names: a mismatch, or two bodies under one `(membership, seq)`, is equivocation: the
  member keeps the first and warns once per membership.
- The node assigns `seq` and `prev`; the client supplies `deps` (the shown frontier, below) and `reply_to`.

**Delivery.** A message's requirements are its `prev` and its deps. A requirement is satisfied once it is delivered, at
or below the member's baseline for its membership (below), or given up. A message is delivered once all its
requirements are satisfied, and gets the group's next local index (delivery order, which local cursors use). An
unsatisfied requirement holds up its dependents while it may still come: for at least `HOLD_OFF` (2 s) after a
dependent was opened, and while some member's summary shows it held and that holder has not been struck for it, up to
`GIVE_UP` (30 s). Then it is given up, and the next message delivered that needed it, directly or through its
author's earlier seqs, names in `missing` every seq of that membership up to the requirement not delivered or reported
yet. A given-up message that arrives later is delivered when its own requirements are satisfied, marked `late`. A dep
on a membership the member never knew is satisfied: that membership ended before the member joined.

**Shown frontier.** The client marks messages shown as it prints or displays them (`mark_shown(ids)`). `deps` is the
frontier of the shown set: for each membership, its highest shown seq, less those in another such message's causal
past. The node keeps each delivered message's causal past as a vector (membership → seq), the pointwise maximum of its
requirements' vectors and itself. `reply_to` must name a message in the shown past: the sending client refuses
otherwise, and a receiver that holds the replied-to message and finds it outside the message's vector marks the
message `reply_outside: true`. Messages the node delivered but the client has not shown are concurrent with what the
client sends.

**Opening.** A member opens a held ciphertext when it arrives, if it holds its epoch's keys; one of the next epoch waits
in `early` (4 MiB per peer, as now). Live messages no longer use the MLS ratchet, so a sender's generations count only
its held messages and reseals. Authors seal in seq order, pushes go out in that order and repair asks each membership's
seqs in ascending order, so the out-of-order distance stays at the messages in flight, far below openmls's 1,000; a
member catching up asks in ascending order, far below 100,000 ahead. A message a member cannot open because the ratchet
moved more than 1,000 past it is, if kept, lost to that member (known by `(author, seq)`); if not kept, its author
reseals it later. Item 4 below has the tests.

**The outbox.** `send` signs the header, seals it in the current epoch, and saves the plaintext, its seq and prev, the
ciphertext and its epoch in one step, then answers `{id}` once that step is durable, and pushes it. The author keeps
the plaintext until its cut reaches the seq; after each commit it applies, it reseals every message past its cut in the
new epoch, in seq order, and pushes those. Nothing of `send` involves the service.

**Flood control** is local: per `(group, membership)` a token bucket (100, refilled at 1 per second) for pushes and
repair. A message over it is not taken now (no MLS work, no storage); its author's summary still shows it, so it is
pulled when tokens return. The wait before a commit ignores the bucket for what the ending cut names. Nothing over the
bucket is ever counted lost.

## Cuts

A commit's authenticated data (inside the sealed, padded commit envelope, as now) is JSON
`{"how", "invite", "cut": [[index, joined, seq, id], …]}`: one entry per member of the epoch the commit ends, in leaf
index order, `id` empty for seq 0. It is cumulative: the cut state after the commit is its entries, less the members it
removes, plus the members it adds at `(joined = new epoch, seq 0)`.

**Meaning.** The committer of the commit ending epoch E asserts it holds, each sealed in E, every message of each
membership from that membership's previous cut seq to the cut's, and that the cut's id is the message at that seq.
Messages at or below a membership's cut are kept; the commit ending E keeps those between the previous cut and its own.
Since the committer seals and holds only sealings of E, members that lack a kept message can fetch an E sealing while
they still hold E's keys, until the next commit.

**Validity**, checked in `rules` from the group state alone, never from what a reader holds: exactly one entry per
member of the ending epoch, by index; `joined` as in the cut state; `seq` not below the cut state's, and the same `id`
when equal; `id` 32 bytes iff `seq > 0`. An invalid cut makes the commit invalid, like any rule. The encoding costs
about 70 bytes per member beside the Welcome's ~1 KiB per added tree member, within the 1 MiB entry for the group sizes
supported (below).

**Building.** The node computes the cut as it builds the commit: for each membership, from its cut state seq, while it
holds the next seq sealed in E with a `prev` that chains, take it. Its own seq is its last, as it reseals its outbox in
each epoch. The pending commit keeps its authenticated data, so posting it again after a crash or a lost answer posts
the same cut; a commit that loses its epoch is built again on the next one, with a new cut. Messages that arrive after
the build are past the cut and resealed after it.

**Applying.** Before applying the commit ending E+1, which deletes E's keys, a member must hold every message the
commit ending E kept. It waits for them as now (`Peers::wait`), asking any member whose summary shows them held, and
dialing a holder that is not a neighbour; then it applies, and whatever it still lacks of them is lost to it, by
`(author, seq)`, and given up. After applying, a member drops the pending messages of memberships the commit removed
that lie past their final cuts (not kept), gives up requirements on them, reseals its own outbox, and opens its early
ciphertexts of the new epoch. A member catches up commit by commit: holders keep, for H, each kept message's sealing in
the epoch whose cut kept it, and each unkept message's latest sealing.

**Joining.** An admitter answers `Admitted { commit, doc }`: `commit` is the encoded commit entry (commit, Welcome and
signature) that added the joiner. The joiner joins by the Welcome inside it, checks the entry's signature against a
member of the tree it joined, and reads the cut from the commit's authenticated data: its baseline. Requirements at or
below the baseline are satisfied, as they came before the joiner. Messages sealed before the Add but kept only after it
reach the joiner too: a joiner gets every message kept after its baseline. A member asked again for a lost answer
answers with the commit entry it kept for H, by the epoch the Add moved into.

## Live messages

Doc and table edits, typing, presence: the wire form is `epoch ‖ nonce ‖ XChaCha20-Poly1305(key, nonce, aad, plaintext)`
with `key = MLS-Exporter("letmeknow live", group ‖ epoch, 32)`, `aad = "letmeknow live v1\0" ‖ group ‖ epoch`, and
plaintext `body ‖ sig`: body the JSON `{"author", "payload"}`, sig the author's over `"letmeknow live v1\0" ‖ group ‖
epoch ‖ body`. A member takes one sealed in its current epoch from a current member, verified. Its id is the hash of the
wire bytes. `Live { group, hops, item }` goes once to each neighbour but the one it came from, with `hops` (at most 6)
less one; a member keeps the ids it saw in the last 2 minutes, at most 4,096, and forwards nothing it saw. A live
message to one member goes to it alone, with no hops. Live messages in flight across a commit are dropped.

Docs and tables keep syncing by state. `Synced` fires for a neighbour whose `hello` shows the same current log reference
(the same epoch secret): on connecting, after each commit, and with every periodic `hello` (5 minutes), so neighbours
compare state hashes on a schedule and a repair reaches others through the next comparison, with no further edits.

## Peers

**Neighbours.** Per group, a member's targets are every other member when the group has at most K + 1 = 7, else the K = 6
members ranked best by `SHA-256("letmeknow neighbours v1\0" ‖ MLS-Exporter("letmeknow neighbours", "", 32) ‖ min(a, b) ‖
max(a, b))` over iroh keys, among those not backing off. The rank is symmetric, so pairs tend to choose each other, and
changes with each epoch's secret, which no key can be ground against. A member dials targets it is not connected to every
10 s; a failed dial backs off from 30 s, doubling to 10 minutes. Every minute it also dials one random member it is
not connected to, so an overlay split during an outage heals without a commit. One connection serves every group a pair
shares. A member accepts at most 128 connections; a dialer closes a connection none of its groups targets, after 5
idle minutes. Directed connections, outside the targets: admission, repair from a holder that is not a neighbour, a
file only one member holds, a joiner's state.

**Frames** (`letmeknow/3`, as 0.16 and 0.17 share no groups):

- `Hello { groups: [{group, epoch, log, head}], heads }`: on connecting, on change (1 s debounce), and every 5 minutes.
  Commits and public-log entries travel as now: `Entries { log, entries, head }` to a peer whose `hello` shows less.
- `Summaries { group, items: [signed summary] }`.
- `Held { group, items: [ciphertext] }`: a push, forwarded once to each other neighbour (dedup by ciphertext hash), or
  an answer to `Want`.
- `Want { group, epoch, wants: [[key, joined, seqs]] }`: the asker's epoch, so the holder answers with the sealings it
  can open (that epoch's, or the one before); it answers with what it has, ~1 MiB at most, and an empty answer strikes it
  for those seqs until its next summary.
- `Live { group, hops, item }`, `WantFiles`, `Have`, `State` as now.

Every frame of a group is checked against the group's membership as it is written, as now.

**Summaries.** Each member signs its own per group: `"letmeknow summary v1\0" ‖ body`, body the JSON
`{group, member, joined, version, time, epoch, held, shown, lost}`, each of the last three `[[key, joined, seqs]]`.
`version` grows with each new summary and is saved; `time` is the member's clock. A member re-signs at most once a
second while it changes, and at least hourly. A receiver keeps the highest version of each current membership's
summary that verifies, drops those of removed memberships, and passes on new ones to neighbours that have not shown
them (each connection remembers the versions it carried); on connecting, peers send each other all they hold for their
shared groups. Receipts (`held_by`, `read_by` = shown), `only_here`, `leave_held`, losses (the `lost` event to the
author) and `away` (no summary with a `time` within H, and not connected) come from them; `online` is the members
connected now. `Control::Lost` goes: losses travel in summaries.

**Repair.** A member wants, per membership, the seqs it knows exist (deps, prev gaps, cuts, summaries) that it neither
holds nor gave up, and asks the best holder for them in ascending order: a connected neighbour whose summary shows them,
else any member whose summary shows them, dialed directly. One request per group at a time, as now, with the same
timeout and strikes.

## The membership service

Epoch logs hold only commit entries (with each add's Welcome and the cut). `Entry::Message`, its MAC, the node's
message pages and batches, and sends' appends go. The request API stays, so one service serves 0.16 and 0.17 during the
move. Limits (from #78): one budget of bytes in flight per connection and overall that covers decoding requests and
building replies; a disk budget on the database's pages in use plus its WAL, refused as `quota`; `MAX_LOGS`,
`MAX_ROWS`, `MAX_STORED_BYTES`, `MAX_LOG_LENGTH` and `MAX_LOG_BYTES` go. Store format 3 stays.

## Client, CLI, browser

- `send` answers `{id}`; `pos`, `pending` and the `sent` event go.
- `message` events show `id`, `from`, `seq`, `sent_at`, and `missing: [{from, seqs}]`; a late one `late: true`. Events
  come in delivery order.
- `lost`: `{member, messages: [{from, seqs, ids}]}`, from summaries; told to authors as now.
- `read <id> --ancestors N`: the N most recent shown messages in its causal past.
- `status.only_here`: `{what, id, seq}` of own messages no other member's summary holds; `leave` is pending until
  another member's summary holds the `leave`.
- `ChatMessage.read` goes (deps carry causality); receipts come from summaries.
- Local cursors replace positions: the identity kind follows delivery indices and takes adds by id; the session
  reprints unshown messages in delivery order after a restart; the browser stores records by id in delivery order.
- SKILL.md and README.md describe causal order, `missing`, `late`, `lost`, and that chat works while the service is
  down.

## Switches

Group `PROTOCOL` 6; invite links `6.`; home `letmeknow-v6` (format 6); browser database, Web Lock and channel `lmk6`;
ALPN stays `letmeknow/3`. Pins move to `@letmeknow/cli@0.17` by hand. Rollout: the service first (its API is
unchanged), then npm, then Pages. Links of 0.16 are refused as another version's. A browser profile with `lmk5` and
`lmk6` tabs runs both apart, as their names differ.

## Settled

1. **Shown, then not kept**: the states and guarantees above (Model). No event retracts a delivered message.
2. **The cut**: cumulative, one entry per member, JSON in the sealed commit's authenticated data, ~70 bytes per member;
   competing commits: only the winner's counts, the loser is rebuilt; crash and retry post the same pending entry.
3. **When no commit comes**: requirements are given up after `HOLD_OFF`, or while holders are known up to `GIVE_UP`;
   late arrivals are delivered `late`. Nothing is lost without a commit.
4. **Ratchet bounds**: live messages leave the ratchet; held messages open on arrival, in ascending order under repair.
   Real-openmls tests: a gap of up to 1,000 later held messages opens late; one more makes it unopenable, and if kept it
   is reported lost; a member catching up 5,000 messages of one epoch in ascending order opens them all.
5. **Overlay**: symmetric epoch-keyed ranking, K = 6, full mesh to 7, 10 s redial with backoff, a random probe a minute,
   128 connections, idle close by the dialer. Admission and repair dial outside the targets.
6. **Summaries**: signed per membership, versioned, highest kept, forwarded once per connection, re-signed at most once
   a second and at least hourly. Supported group size: 200 members (summaries are O(members × authors) per member).
7. **Live**: at most 6 hops; ids kept 2 minutes, at most 4,096; author checked against the current epoch; dropped across
   commits.
8. **Budgets**: pending (opened, undelivered) messages 64 MiB per group, beyond which the oldest pending wait for repair
   again; early ciphertexts 4 MiB per peer; answers ~1 MiB; frames 16 MiB; dials 4 at once per group.
9. **Client inventory**: as listed above; every position use goes (kind cursors, adds, receipts, `only_here`,
   `leave_held`, the browser timeline).
10. **Rollout**: as under Switches.
11. **ALPN**: stays `letmeknow/3`.
12. **Sealing again by holders**: no. Only an author seals its messages: holders delete text once shown (decision 8), and
    a holder's sealing would need a membership check of the original author per epoch. A message a member lost stays
    lost; an author's unkept message waits for its author.

## Tests

Real openmls and storage, as examples: causal delivery with holes and late arrivals; the shown frontier, `reply_to`
checks; more than 8 concurrent heads; a cut, and resealing past it; competing commits with different cuts; a removal
after a member delivered the removed member's last message; joining and rejoining with the same key; catch-up over many
epochs; the ratchet bounds of item 4; equivocation; a sole holder that is not a neighbour; a split overlay healing
without commits; doc repair through a neighbour with no further edits; chat while the service is unreachable; #76's
reproducer. The peer core stays I/O-free, with randomized schedules of loss, reordering and reconnection.

## Work, in order

1. Proto and core: headers, ids, cuts in commits, the joiner's baseline, live sealing; message entries go.
2. Net: the I/O-free peer core (neighbours, summaries, repair, flooding); the service's limits; #76.
3. Node: delivery, the outbox, cuts and catch-up, admission, summaries.
4. Client, CLI, browser and kinds.
5. Release tooling (#69, #71, #64), docs and switches; then the release.

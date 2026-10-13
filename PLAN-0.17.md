# 0.17: causal chat over gossip

Spec draft 4 of #80, the implementation contract until 0.17 ships; then it goes, as PLAN-0.16.md went. Draft 3 settled
#80's open items; an adversarial review of it (five lenses: cuts, MLS, delivery, overlay, client) led to this draft. It
keeps #80's decisions, but: held headers are not signed (MLS authenticates their author), cuts are keyed by member key,
and summaries never decide what is safe to drop. Existing chats, docs and identities do not carry over.

## Model

Every member keeps, per group:

- **memberships**: a member's MLS signature key and `joined`, the epoch its Add moved into (0 for the creator). A key
  admitted again is a new membership, with a new sequence. A commit may not add a key it removes.
- **cut state**: per current membership, `(seq, id)`: how far its held messages are kept. It changes only when a commit
  applies; every member derives it alike. A removed membership's final cut is kept while its epochs' keys are.
- **held messages**: by id, and by `(membership, seq)`.
- **delivery state**: per membership, the seqs delivered, given up, lost, and shown by the client; kept for the
  membership's lifetime.

States of a held message for a member: *unopened* (a ciphertext it holds), *pending* (opened, waiting on
requirements), *delivered*, and, by the cuts, *kept* (at or below its author's cut) or *not kept* (past the final cut of
an ended membership). Delivered and kept are independent.

**Guarantees.** All members agree on each epoch's kept `(membership, seq, id)`. Every message of a membership that stays
is kept once its author is online at the head of the log and some member holds it: the author reseals it in each epoch
until a cut keeps it, and a member that holds unkept messages commits within minutes (Cuts). A member that held the
keys of every epoch since it joined delivers every kept message, or reports it lost by `(author, seq)`. An ended
membership's messages past its final cut may reach only some members. Control payloads (`leave`, `invite`, identity
adds) act when opened, as 0.16's acted when counted, judged against the membership current then. Only being kept makes
a message safe without its author: `only_here`, leave completion and `sessions remove` key on it, never on summaries.

## Held messages

The MLS application message's plaintext is its header's JSON; its id is `SHA-256(plaintext)`, the same in every epoch
its author seals it in, as the author keeps and reseals the exact bytes. The body names the group, so ids are
group-scoped. Its MLS authenticated data, clear on the wire and authenticated once opened, is `[key, joined, seq]`.

```json
{"group": "<16-byte group id>", "author": "<key>", "joined": 3, "seq": 7, "prev": "<id of seq 6>",
 "deps": [["<key>", 2, 41, "<id>"]], "reply_to": "<id>", "payload": {"type": "message", "content": "…"}}
```

- `prev` is absent at seq 1. `deps` holds at most one entry per membership, none the author's own; control payloads and
  identity adds have none. `reply_to` and `deps` are absent when empty.
- A receiver checks, after MLS opens it: the group; the author is the MLS sender; `joined` is the author's membership in
  the epoch it was sealed in (core keeps the cut states of the current and previous epochs); the authenticated data
  matches; `seq ≥ 1` and `prev` present iff `seq > 1`; `payload` has a `type`. A message failing a check is dropped.
- Tuples (`deps`, cuts, `Seqs`) ignore trailing elements, so a later 0.17.x can extend them; the checks here and the
  cut's validity are frozen for 0.17.x.

**Opening.** Openmls refuses a generation more than 1,000 behind the newest it opened (999 still open). A member opens a
membership's ciphertext only while its seq is within 500 of that membership's lowest wanted seq; others wait unopened,
up to 4 MiB per membership, beyond which they are not taken and come again by repair. It saves the plaintext in the
same step as the ratchet advance, and never evicts an opened message. A ciphertext it opened is never opened again (the
message record lists its sealings' hashes). One that fails as too distant is, if kept, lost to it.

**Delivery.** A message's requirements are its `prev` and deps. A requirement `(N, t)` is satisfied once every seq of
`N` up to `t` is resolved: at or below the member's baseline for `N`, delivered, given up, lost, or past `N`'s final
cut. A message is delivered once its requirements are; it then gets the group's next local index (delivery order). Only
at the head of its log (not while catching up commit by commit) does a member give up: an unsatisfied requirement whose
seqs it does not hold holds up dependents for `HOLD_OFF` (2 s) after they opened, and while a holder is untried, up to
`GIVE_UP` (30 s); after `GIVE_UP`, seqs it holds but has not delivered are given up too, as two pending messages may
require each other. It gives up only seqs it knows were sent (its author's own messages it holds, or a cut): a dep
past those is met, after `GIVE_UP`, once all it knows was sent is, so no dep can name a range that poisons later
messages. Giving up releases dependents only: the seqs stay wanted. The next message shown whose requirements reach
them names them in `missing`, per membership; one delivered later is `late`. A requirement held back by the local
flood bucket is never given up. A dep on a membership the member never knew is satisfied: it ended
before the member joined.

**Shown frontier.** The client marks what it shows (prints, displays, or replies to). `deps` is the frontier of the
shown set: per membership its highest shown seq, less those in another's causal past, found by walking deps (cached),
and less memberships that ended over H ago. `reply_to` must name a delivered message; a receiver whose walk of the
message's past completes without finding it marks the message `reply_outside`. Once shown, a record keeps no payload
text (as 0.16's redaction); the plaintext of a reseal of a shown message is dropped after its id is checked.

**Sending.** `send` signs nothing: it builds the header (the node assigns `seq` and `prev`, the client gives `deps` by
showing and `reply_to`), seals it in the current epoch, saves plaintext, seq, prev and sealing in one step, delivers it
to itself (own messages are never opened), answers `{id}` once that step is durable, and pushes it. Errors: `size`, and
`rate` past the sender's bucket (100 messages and 4 MiB, refilled at 1 per second and 64 KiB per second). Nothing of
`send` involves the service. The author keeps the plaintext until its cut reaches the seq. In the step that applies a
commit and leaves it at the head of its log, before any new seal, it reseals every own message past its cut, in seq
order, and pushes them. When a commit removes it, `removed` names its messages past its final cut as `not_kept`.

**Flood control** is local. Receivers allow each membership twice the sender's bucket, charged when opening, and a
membership over it waits unopened (then not taken), so honest senders are never throttled. Live payloads have a bucket
of their own per membership, ten times the held one (1,000 and 40 MiB, refilled at 10 per second and 640 KiB per
second), charged after dedup, and are forwarded at most `HOPS` (6) hops. The wait before a commit ignores buckets.

## Cuts

A commit's authenticated data (inside the sealed, padded commit envelope, as now) is JSON `{"how", "invite", "cut"}`,
`cut` being `[[key, joined, seq, id], …]`: one entry per member of the epoch the commit ends, sorted by key, `id` empty
at seq 0. It is cumulative: after the commit the cut state is its entries less the members it removes, plus those it
adds at `(joined = new epoch, 0)`; a removed member's entry is its final cut.

**Validity**, checked in `rules` from the group state alone: exactly the members of the cut state, by key, in order, at
their `joined`; each `seq` at least the state's and at most 100,000 more, with the same `id` when equal; `id` 32 bytes
iff `seq > 0`. An invalid cut makes the commit invalid.

**Meaning and building.** The committer of the commit ending E asserts it holds, each sealed in E, every message of each
membership from its previous cut seq to the cut's, chained by `prev` down from the cut's `id`. It builds the cut so: per
membership, extend while it holds the next seq sealed in E with a chaining `prev`; its own entry too, and only as far as
another member's summary shows held, so every kept message has two holders. A member builds a commit only once it holds,
or has lost, everything the previous cut kept, which makes it another holder of those. The pending commit keeps its
authenticated data, so a retry posts the same cut; a commit that loses its epoch is built again on the next.
Equivocation: a member keeps the first body it holds under a `(membership, seq)` and warns of another. Deciding by the
chain down from the cut's id (marking another body not kept, asking for the kept one by id) is left for after 0.17.0:
until then, members an author equivocated to may keep different bodies under one kept seq.

**Keep-alive.** A member that holds messages unkept for 10 minutes commits an update at its slot (a hash of its key
within the next 10 minutes), if its cut would keep any, unless a commit comes first; so active groups get about one commit per 10 minutes, and
authors can stop soon after they send.

**Applying.** Before applying the commit ending E+1, which deletes E's keys, a member must hold every message the
commit ending E kept above its baseline. It waits while a holder (by summaries) is untried: connected, or with a dial in
flight; and for 15 s after it read the commit or came online even with none, as a member back online hears the others'
summaries by then; it dials holders past their backoff; an empty answer or a failed dial strikes a holder for the epoch; only a
lacking message arriving is progress; the wait ends 2 minutes online after the commit was read at the latest. Then it
applies, and what it lacks of them is lost to it, by `(author, seq)`. After applying, it drops pending messages of
removed memberships past their final cuts and takes no more of them, reseals its own (Sending), and opens the unopened
ciphertexts of the new epoch. Catching up goes commit by commit.

**Joining.** An admitter answers `Admitted { commit, doc }`: `commit` is the encoded commit entry (commit, Welcome and
signature) that added the joiner. The joiner joins by the Welcome inside it, checks the entry's signature against the
Welcome's sender (the GroupInfo signer, which is the committer), and that the commit is a commit of the group's previous
epoch; it trusts the committer's cut, which it cannot judge: its baseline. Tree members named in the cut take their
entries, the others `(new epoch, 0)`. Messages sealed before the Add but kept only after it reach the joiner too. A
member asked again for a lost answer answers with the commit entry it kept for H.

## Live messages

Doc and table edits, typing, presence: `epoch ‖ nonce ‖ XChaCha20-Poly1305(key, nonce, aad, body ‖ sig)` with
`key = MLS-Exporter("letmeknow live", aad, 32)`, `aad = "letmeknow live v1\0" ‖ group ‖ epoch`, body the JSON
`{"author", "payload"}`, sig the author's over `aad ‖ body`. A member takes one sealed in its current epoch from a
current member, verified; its id is `SHA-256(sig)`, checked after opening. `Live { group, hops, item }` goes to each
neighbour but its source, once verified, with `hops` (at most 6) less one; ids are kept FIFO, 2 minutes and at most
4,096. In a full mesh nothing is forwarded. A live payload to one member goes to it alone. Live payloads in flight
across a commit are dropped.

Docs and tables sync by state. `Synced` fires for a neighbour whose `hello` shows the same current log reference (the
same epoch secret): on connecting, after each commit, and with each periodic `hello` (5 minutes), so neighbours compare
state hashes on a schedule and a repair reaches others through the next comparison.

## Peers

**Overlay.** A neighbour is any connected member the gate admits. Per group, a member's targets are every other member
when the group has at most 7, else the 6 ranked best by `SHA-256("letmeknow neighbours v1\0" ‖ group ‖ min(a, b) ‖ max(a,
b))` over iroh keys, among members connected or whose summary `time` is under 2 hours old and not backing off. The rank
is symmetric and stable: a commit changes only the added and removed members' edges. A member dials targets every 10 s;
a failed dial backs off from 30 s, doubling to 10 minutes, cleared when the peer connects to it. Once a minute per
session it dials one random recently seen member it is not connected to, so a split heals without a commit. One
connection serves every group a pair shares. A connection a group targets is always accepted; others are capped at 128,
evicting the longest-idle one nothing targets; a non-member's closes after its admission exchange, or 30 s. A dialer
closes a connection idle 5 minutes: no target of it, and no request, answer, admission or file transfer.

**Frames** (`letmeknow/3`, as 0.16 and 0.17 share no groups). A frame of a group is taken only from a peer the gate
admits, but `hello` and `entries`, which check themselves; every frame is checked against the membership as written.

- `Hello { groups: [{group, epoch, log, head}], heads }`: on connecting, on change (1 s debounce), and every 5 minutes.
  Commits and public-log entries travel as now: `Entries { log, entries, head }` to a peer whose `hello` shows less.
- `Versions { group, versions: [[key, joined, version]] }` on connecting, then `Summaries { group, items }` with only
  what the other lacks; new summaries go to neighbours that have not shown them.
- `Held { group, items }`: ciphertexts, pushed and forwarded once each after opening (nothing forwarded in a full mesh),
  or answering `Want`.
- `Want { group, epoch, wants: [[key, joined, seqs]], ids }`: the holder answers with sealings openable in the asker's
  epoch or the one before and not before the asker's `joined`, about 1 MiB at most, and `answers`, what it covered.
- `Live { group, hops, item }`, `WantFiles`, `Have`, `State` as now.

**Summaries.** Each member signs its own per group with its leaf key: `"letmeknow summary v1\0" ‖ body`, body the JSON
`{group, member, joined, version, time, epoch, held, shown, lost}`, the last three `[[key, joined, seqs]]`, listing
only memberships with any (most members of a large group never post). `held` lists seqs whose sealing it holds openable at its epoch, or sealed
in the epoch whose cut kept them; holders keep every sealing they open. `version` is `max(saved + 1, time)`, saved
before it is sent; a member re-signs at most every `max(1 s, members / 4 s)` while it changes, and at least hourly. A
receiver keeps the highest valid version per current membership, drops removed ones', keeps up to 32 it cannot verify
yet (a joiner's before its Add) until the next commit, and takes `time` as at most when it received it. Summaries serve
receipts (`held_by`, `read_by` = shown), repair, the wait before a commit, `lost` (told to the author once per seq,
persisted), and `away` (no summary within H, not connected). `Control::Lost` goes.

**Repair.** A member wants each membership's seqs it knows of (deps, prev gaps, cuts, summaries) that it neither holds
nor lost, given up or not, and asks one holder per group at a time, in ascending seq order: a connected neighbour whose
summary shows them, else any such member, dialed directly. A request times out 10 s after it was made; an answer
short of its size (about 1 MiB) strikes its holder for all that was asked, a full one for what it covered; a want
refused, or of a group the holder no longer has, is answered empty. Strikes last for
the epoch.

## The membership service

Epoch logs hold only commit entries (with each add's Welcome and the cut). `Entry::Message`, its MAC, the node's
message pages and batches, and sends' appends go. The request API stays, so one service serves 0.16 and 0.17 during the
move. Limits (from #78): a byte budget per connection and overall covering request decoding and replies; a disk budget
on the database's pages in use plus its WAL (`serve --disk`), refused as `quota`; `MAX_LOGS`, `MAX_ROWS`,
`MAX_STORED_BYTES`, `MAX_LOG_LENGTH` and `MAX_LOG_BYTES` go. Store format 3 stays.

## Client, CLI, browser

- `send` answers `{id}`; `pos`, `pending`, `unavailable` and the `sent` event go; `rate` and `size` stay.
- `message` events show `id`, `from`, `seq`, `sent_at`, `missing: [{from, seqs}]`, `late`, `reply_outside`; they come
  in delivery order. `read <id> --ancestors N`: the latest N chat messages in its causal past that this member
  delivered, by delivery index. A restart reprints what was delivered after the last shown message.
- `lost`: `{member, messages: [{from, seqs, ids}]}`, from summaries, once per seq.
- `status.only_here`: own messages not kept yet (`{what, id}`); `leave` is pending until the Remove applies
  (`removed`), and `leave_held` goes; `sessions remove` waits for that; `removed` lists `not_kept` own messages.
- `online`: members connected to this session (in groups over 7, its neighbours); `away` as above.
- `ChatMessage.read` and `reply_to` leave the payload: deps carry causality, `reply_to` the header.
- Positions go everywhere: the kind cursor (`follow_log`, `entries`, `Logged`) goes; the identity kind scans delivered
  adds and persists the ids taken; the browser keeps its timeline by delivery time, late ones where they were delivered.
- The browser, finding an `lmk5` database, says once that 0.16's chats stay with 0.16; a `5.` link is explained as made
  by letmeknow 0.16, whose maker must restart with `@letmeknow/cli@0.17`.
- SKILL.md and README.md describe causal order, `missing`, `late`, `lost`, `not_kept`, keeping, and that chat works
  while the service is down.

## Switches and rollout

Group `PROTOCOL` 6; invite links `6.`; home `letmeknow-v6` (format 6); browser database, Web Lock and channel `lmk6`;
ALPN stays `letmeknow/3`; commit entries are signed over `"letmeknow commit v1\0"`. The release goes npm, then the
service (its API is unchanged), then pi-letmeknow's pin, then Pages. Pins move to `@letmeknow/cli@0.17`.

## Budgets and size

Supported group size: 100 members, with the peer core's tests asserting bytes per message and per hour there. Per
membership: 4 MiB unopened; per group: early (next-epoch) ciphertexts 4 MiB per peer; answers ~1 MiB; frames 16 MiB;
4 dials at once per group; live ids 4,096.

## Tests

Real openmls and storage, as examples: causal delivery with holes, `missing` and `late`; the shown frontier and
`reply_outside`; more than 8 concurrent heads; a cut, and resealing past it; competing commits; a removal after a member
delivered the removed member's last message, and a removed member sealing on in its last epoch; joining and rejoining
with the same key; a forged baseline refused; catch-up over many epochs with a dependency kept one epoch later; the
ratchet bounds (999 and 1,000 later messages; catch-up then a push; bucket overflow then a late push); equivocation
with a cut through either body; a sole holder that is not a neighbour; a split overlay healing without commits;
keep-alive making a message kept; doc repair through a neighbour with no further edits; chat while the service is
unreachable; `lost` told once across a restart; a send after being removed offline; the 0.16 and 0.17 CLIs on one
service; the frontend over an `lmk5` database with a `5.` link; #76's reproducer. The peer core stays I/O-free, with
randomized schedules of loss, reordering and reconnection.

## Work, in order

1. Proto and core: headers, AAD claims, cuts, the joiner's baseline, live sealing.
2. Net: the I/O-free peer core; the service's limits; #76.
3. Node: opening, delivery, the outbox, cuts, keep-alive and catch-up, admission, summaries.
4. Client, CLI, browser and kinds.
5. Release tooling (#69, #71, #64), docs and switches; then the release.

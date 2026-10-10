# letmeknow design

A person asks their agent to work with a coworker's agent, or with a person. One of them shares an invite link; the other joins. People join the same groups from a browser. A group has a kind: a chat, where members talk and send files; a doc, one markdown text that people and agents edit at once; a git repository, which agents push to and fetch from with plain git, and talk in; or another kind a plugin brings. Groups are small and task-scoped, and last hours to days.

Everything in a group is end-to-end encrypted with MLS (RFC 9420). Members send to each other directly, or through a relay; no server holds what they say. PROTOCOL.md gives the exact formats.

## Goals

- Groups have a kind, fixed when made: chat, built in, or one a plugin brings, such as doc or git. Everything in them is end-to-end encrypted.
- Forward secrecy, post-compromise security, and strict membership: one agreed order of membership changes, which every member applies the same way.
- Chat useful in the real world: messages in one order, gaps known, and every member knowing who holds, who read and who lost what.
- Convergence: members that overlap, directly or through others, end with the same readable messages since their start, except known losses.
- No content on any server. One central authority per group orders its commits and held messages without reading either.
- Membership changes that cannot half-happen: duties derived from durable state, rules decided inside the commit, few timers.
- Agents work through a session process: JSON events, a delivery policy, docs as files, attachments as private files.
- One Rust codebase: a client core every client shares, the CLI and session process, kinds' plugins, the browser client (WebAssembly), and the server.

Not goals: availability (a message moves only while a member holding it and one lacking it are online together, and nothing else holds it), and delivery guarantees beyond that.

## Roles

- **Session**: an MLS member, either an agent's session process or a browser profile. Each agent session is its own member, with its own key. Its name is an unverified claim. It sees the IP address of members it connects to directly.
- **Device**: a machine's `LETMEKNOW_HOME`, or a browser profile. It is a member of its identities' devices groups, with a key of its own in each, and certifies its sessions with that key.
- **Identity**: a person, team or agent ("Matthew": laptop, phone), as a key log that lists its devices. It makes a member's "Matthew" verifiable and is as strong as its weakest device. No nesting, no admins.
- **Membership service**: keeps groups' logs and identities' key logs, and is a member of nothing. It sees log ids, each entry's size and time, and which endpoints connect. It can stall, withhold or split a log, all detectably; it cannot read, forge, or add anyone.
- **Relay**: an iroh relay. It forwards packets when no direct path exists; browsers always use one. It sees who connects to whom and when, and cannot read.
- **Page server**: letmeknow.dev, or one's own `letmeknow serve`, serves the browser client, so it could take over every browser member it serves. Accepted for now.

## Membership service

A membership service keeps append-only logs. For each log it promises that:

1. every entry gets exactly one position;
2. every reader sees the same entries at the same positions;
3. entries neither change nor vanish before its retention ends.

Anything with create-if-absent can keep these promises. Two kinds exist:

- `letmeknow serve`, reached over iroh; letmeknow.dev runs one.
- A local folder, where an exclusive file create is atomic: for sessions on one machine, and for tests.

It holds two kinds of log and nothing else:

- **A group's log**, under the group id: its commits and its held messages' entries, in one order (see The group log).
- **An identity's key log** (see Identity). In a key log, the first entry that extends the latest one, signed by its key, wins.

A client appends several entries in one request, counted once against the rate limit. It subscribes to the logs it follows, and an append wakes only that log's subscribers. Members hash-chain every log as they read it, so two readers can compare what they saw by one hash, and catch it up from peers. `letmeknow serve` signs each answer with its key: the log's id, length, latest hash, and the time. This is a signed head.

A member's copy of entries counts only with a signed head that covers them, checked against its own chain. Members show each other the heads of their shared groups' logs and of the key logs those groups' members speak as (see Peer protocol). Two incompatible heads prove that the service showed different members different logs; the member drops the frame that showed it and reports both heads in a `warning`, once while it runs. A member behind takes the entries it lacks from the peer that is ahead, so a commit, and with it a removal, spreads in network time. A local folder signs nothing, but its sessions all read the folder directly.

Policy belongs to each service: who may create logs, how long it keeps entries, and size and rate limits. letmeknow.dev lets anyone create a log, keeps entries a year, and takes entries up to 1 MiB and 60 appends a minute per connection. A member away longer than the retention cannot replay the commits it missed: once the service refuses its read as `expired`, it reports itself removed and forgets the group, and must be added again.

## The group log

One log per group, at the membership service its settings name, holds the commits and the held messages' entries, in one order.

- An entry is one of:
  - a commit entry: the MLS commit, its Welcome if it adds members, and the committer's signature with its leaf key over both;
  - a message entry: `id ‖ HMAC-SHA256(MLS-Exporter("letmeknow entry", "", 32), id)`, where `id` is SHA-256 of the message's ciphertext.
- A member reads the log strictly in order, and records each position's epoch and verdict in the step that applies it:
  - the first commit for the member's epoch that MLS accepts, that keeps the rules below, and whose signature verifies under its sender's leaf key wins and is applied when reached, the member's own included; every other is skipped;
  - a message entry counts if its MAC verifies under the member's current epoch and no earlier entry of that epoch named its id.
- So every member judges every entry alike, from the log alone: a removed member can add nothing after its removal, junk is skipped, and a replayed or retried entry counts once.
- A committer saves its whole entry in the step that stages the commit, and posts exactly that until the log shows it or a rival wins; only the service's refusal drops it. It finds its entry by its bytes, as a sender finds its message entry by id. If another commit won the epoch, it applies that one and builds its change again on the new epoch; after 5 tries in all, the request fails and says so.
- Every change goes through one call, `commit(|group| -> Result<Option<Change>, Refusal>)`, rebuilt on each lost epoch, and every rule that reads group state runs inside it: invites and openings, expiry, "already a member", the inviter's departure. `Ok(None)` is moot: answered ok, nothing committed (the member already removed, the name already set).
- A joiner starts at its Add: it cannot judge earlier entries, lacking their epochs' secrets, and MLS hides earlier history from it.
- Commit rules, which bind the committer too and read only MLS state, so members never disagree about which commit won:
  - every change is inline: a commit referring to a proposal is invalid;
  - an Add's authenticated data says how its members came in, `{how, invite}`;
  - a credential's key is its leaf's signature key, and an update may change a credential's `name`, nothing else of it;
  - the settings keep the group's protocol and kind.
- openmls cannot open a commit from one's own leaf. Such a commit whose signature verifies under one's own leaf key, with bytes other than one's saved ones, means this session's state was copied: the session stops using the group and says so; the user rejoins, or revokes the device if it may be stolen. Any other entry from one's own leaf is junk, skipped.
- Held messages, like commits, need the group's service: while it is unreachable, held sends wait or fail and only live payloads flow. A group that needs otherwise uses a service of its own (`letmeknow serve`).

## Groups

- Settings live in the MLS group context and change only by commit: kind (fixed; see Kinds), name, the identities the group is open to, H, T, the membership service's address, and the protocol version.
- Each member's leaf names its iroh key and relay, so every member can dial every other, the kinds its session supports, and its protocol revision (see Compatibility). The roster is the address book.
- **T** (a group setting, default daily): each member updates its own leaf every T, at an offset of its own by a hash of its key, so members update apart; any commit of its own counts. Leaf updates give post-compromise security. A member also updates when its leaf differs from what it would write now (relay, kinds, revision) or its device was renamed.
- **H** (a group setting, default 7 days): how long members carry messages, and the files they link, for others (see Messages).
- Keys of the current and prior epoch only (openmls `max_past_epochs(1)`). openmls rewrites every kept epoch on each send and receive, so a longer window costs writes on every message.
- **Duties**, each derived from durable state and idempotent, run in a pass per group at the log's head: after each advance, at start, every 10 minutes, and at the member's update slot; a pass also lets go of what the member carried past H, and in a devices group runs the devices kind's duties (see Identity). A pass commits at most once, with every Remove due and the member's own update if due; the log picks the winner among members that commit the same Remove.
  - a counted `leave` from a current member, sealed since its latest Add: Remove it;
  - a member whose device an earlier key log entry listed and the current one does not: Remove it, and report the members its sessions added or let in by their invites, who stay until removed by hand;
  - one's own leaf due an update (above);
  - while one leaves: send `leave` again unless one of one's own counts in the current or prior epoch; forget the group once one's own leaf is its only leaf;
  - one's own known losses not in a counted or pending `lost` of one's own: send one.
- Removal: a member commits a Remove. A leaving session asks the others, in a held `leave`, to commit its removal (MLS lets no member commit its own), and keeps the group until the Remove. A session alone in a group just forgets it.
- No idle removal: a member that goes quiet is shown away (no summary heard for H), and its summaries no longer count as holding; removing it is an explicit action.
- A group past its log's retention, or whose state was copied, is dropped and reported.

## Messages

- A message is an MLS application message. Its id is SHA-256 of its ciphertext, so a reference names exactly one content.
- Held payloads are a kind's choice, plus the core's `leave`, `invite`, `introduce` and `lost`. They are ordered by the group log. Live payloads go to the connected members, unordered, unlogged and unheld: the channel kinds use for edits (the doc). A live payload is marked so in its clear authenticated data. There are no held-but-unordered messages.
- Sending a held payload; the node owns it until its entry counts, across lost answers, re-seals and restarts:
  1. check its size: a payload with 1 KiB for MLS's framing must fit in 1 MiB, or `send` fails with `size` and nothing goes out; more goes as an attachment;
  2. wait until the member has applied the log to its head as last read;
  3. seal it in the current epoch, and save the plaintext and the ciphertext in the step that writes openmls's state;
  4. append the entry, batched with the group's other sends; after a lost answer, append the same bytes again, 5 seconds later, until answered (a second copy is skipped as a repeated id);
  5. read the log to the entry: if it counts, push the ciphertext to connected members, and the saved plaintext becomes that position's (a member never opens its own messages); if a commit came first, seal it again in the new epoch and go back to 4.

  `send` answers `{id, position}`, or `{id, pending: true}` after 5 seconds without the entry counting; the node finishes a pending send while it runs, after a restart too, and reports `sent {id, answered, position}`: `id` is the message's final id, which members know it by, and `answered` the one `send` gave, which differs once a commit made it seal again. It fails only when the service certainly did not take it: `unavailable` (nothing reached it), `rate`, `size`.
- **Carrying**: a member holds, for H after reading its entry, the ciphertext of every counted position at or after its start, its own included, and serves it to members who ask (see Peer protocol). A ciphertext fills a counted position only if its MLS epoch, in its clear header, is the position's epoch. One that arrives before its entry is read, from an admitted peer, is kept if it is for the current epoch or the next, up to 4 MiB per peer per group; anything else is dropped, and repair brings it back.
- **Opening**: a member opens each epoch's counted ciphertexts in position order. A missing position holds up the later ones of its epoch while it is being fetched, or for 2 seconds after its entry was read, as its push is likely on the way; then they open past it, and it still opens if it arrives while its epoch's keys are kept. openmls opens a sender's message only within 1,000 of that sender's newest opened one; live payloads use the same window, so a held message more than 1,000 of its sender's messages behind, live ones included, is lost.
- **Keys and catch-up**: a member applies each commit as it reads it, unless the commit would delete the keys of an epoch with counted positions it lacks. Then it first fetches them, without the 2-second hold-off. It waits while a connected member's summary from the current connection holds or is fetching one of them (an admitted member's, or one whose identity's key log it has not read yet, which the gate may admit once it has), but at least 3 seconds after it came online or joined the group, whichever is later (so dials can land), and at most until 10 seconds pass without progress (a changed summary, a new connection, a gate opening, or a missing ciphertext arriving). A member with no connection has not come online, so it waits until 10 seconds pass without progress. What it still lacks then is a known loss. A member coming back dials its roster and applies the log by that rule; there is no other catch-up wait, so it gets what the members online in its first seconds carry. Before applying the commit that removes it, a member opens what it holds of its current and prior epochs.
- **Losses**: a known loss is a counted position a member can no longer open: its keys went before its ciphertext came, or it did not open. One's own counted positions are never lost. A duty announces losses in a held `lost {positions}`, carried like any message, so every member learns who lost what: kinds get `lost`; a client reports its own losses once its `lost` counts, and which of its messages another member lost, so a person or agent may send them again as new messages. A member that loses a `lost` announces that too; this ends, since only real losses are announced.
- **Taking**: a live payload is taken only once the member has applied its log to its head as last read, and only if its sender (leaf index and signature key) is in the member's current epoch, so a removed member's edits stop at its removal.
- **Hand-off**: openmls opens a message only once, so the node writes the plaintext in the step that writes openmls's state, and keeps each opened message for H. A client that keeps or shows a chat message deletes the node's copy of its text: the browser once its timeline stores it, `listen` once printed (see Agent interface). The core's own payloads become records, kept until moot (the Remove committed, the invite expired past H).
- **Chat**: a chat message carries its text, the positions its sender had read (`read`, as ranges), optional addressees (`to`), the message it answers (`reply_to`), an `urgent` flag and an attachment. `to` directs attention, not visibility: every member reads every message. Messages show in position order; chat passes a gap once it no longer holds up later positions, and the next message names the positions passed over (`missing`); one that fills later is shown, or printed, when it arrives, with its position. A member's read positions travel in its summaries and in each of its chat messages; there is no live read mark. One-to-one is a two-member group.
- **Presentation**: a message's `content` is shown and printed. An attachment arrives as its name, size, type and a `path` to a private copy, and never enters anyone's context or preview, so sensitive material (an API key) goes as an attachment.

## Peer protocol

- Two members sharing a group keep one `peer` stream. Admission (`join` and its answer) gets a stream of its own.
- **Gate**: a side serves a group to a peer whose iroh key is in a leaf of its current epoch and, if its credential speaks as an identity, whose device is on the identity's current list (see Identity). It takes from any peer what checks itself: summaries, log entries checked against a signed head, and ciphertexts matching counted entries. It acts on every other frame of a group only from a peer the gate admits, and checks the gate again as each frame is written, since a later step may have removed the peer. Until a member has applied its log to its head as last read, it neither takes nor sends `state` or live payloads in that group.
- Frames:
  - `hello`: per group, a summary: its log's head (the last position read from the service) and, within H, its held, read (chat) and fetching positions as ranges ("1-10, 13-50"). Ranges count positions with no message (commits, skipped entries) as covered, so they stay short. Also the heads of the key logs those groups' members speak as. On connect, and every 5 minutes, it carries every group served to the peer; on change, a second after the first unsent change, only the groups that changed. A gate opening sends the group's summary to the newly admitted peer at once, and a peer's first summary of a group on a connection is answered with ours, as a joiner drops those that came before its Welcome.
  - `entries`: log entries the peer lacks, judged by the head it showed, with the head they end at.
  - `messages`: ciphertexts with their positions, pushed at send once the entry counts, and in answer to `want`.
  - `want`: message positions asked of one holder; answered by `messages` with what it holds, up to about 1 MiB of ciphertext, naming the asked positions it went through. A holder answers every `want`, with nothing if the gate refuses it.
  - `live`: live payloads.
  - `state`: a link to a state of the group's kind; without one, a request for one.
  - files' `want_files` and `have`.
- **Summaries**: each side keeps each peer's latest summary per group, and when it was heard, as one durable record, whatever the gate; it is overwritten by the next, used only while the gate admits the peer, and deleted when the peer's Remove is applied. Saved summaries serve display and Away (who holds, who read, `only_here`); repair and the wait before a commit use only summaries heard on the current connection.
- **Repair by pull**: a member lacking counted positions since its start, within H, asks for them in position order, of one holder per group at a time (the lowest iroh key among those holding the first position it lacks), with one request outstanding. An answer settles its request: positions it went through and omitted are not asked of that holder again until its next summary, and the next holder is asked. A request times out 10 seconds after the holder's last frame; that holder is skipped until it sends any frame. A position whose entry was read under 2 seconds ago is not asked for yet, except before a commit. Holders push only at send. "Fetching" means a connected, admitted holder's summary holds the position and it has not omitted it.
- `synced`: a connected member's `hello` shows the same head of the group's log as one's own; it fires on each such `hello`, and kinds use it to compare state.
- The protocol's core has no I/O: per member, (state, frame or tick) → (state, frames).

## Files

- A file is a blob of any size, sealed under a random key in the STREAM construction (as in age: ChaCha20-Poly1305 over 65,520-byte chunks, so each sealed chunk is 64 KiB), and linked with its hash, size and key inside a message or a kind's content. The hash is BLAKE3 over the ciphertext, so a receiver verifies each chunk before decrypting it, and resumes from any holder where it stopped. Files are not tied to epochs: whoever reads the link can open the file; a holder of only the ciphertext cannot.
- Files follow their messages. A member holds a file for H from when a held message linked it, the kind added it, or a state hand-off (sent or taken, beside a Welcome or in `state`) carried it; and while the kind's current state links it (a doc's links). It fetches without being asked the files up to its size limit (a client setting: 100 MiB for agents, 25 MiB for browsers), larger ones only when asked (`fetch`, or opening it in the browser). It asks a connected member for the files it lacks when their logs show the same head, and on each new link.
- A member fetches each file from whoever holds it, from several holders at once. Transfer is iroh-blobs (pinned, and kept inside one module of ours; links are plain BLAKE3, so replacing it later keeps every link valid). A holder serves a file only to current members of a group that holds it, checked per connection, per request and per 16 KiB sent, so a member removed mid-transfer is cut off.
- No one is responsible for a file. The sender has one duty: `send --attach` returns once another member holds a copy, or warns after a few seconds that the file is available only while the sender is online.
- A browser keeps the ciphertext of files it holds in its own storage, since iroh-blobs gives browsers only a store in memory, and loads a file into memory only when it is needed. A larger one it fetched when asked stays in memory only, and it serves that to no one.

## Kinds

The core is a stable substrate, and kinds are extensions that compete: they need not share one model. The core is MLS groups, the group log, identities' key logs, invites, peers, messages, files, and its own payloads (`leave`, `invite`, `introduce`, `lost`). It never reads a kind's content.

- A kind is a plain string, the group's `kind`. Chat and devices (an identity's devices group, see Identity) are built in; every other kind is a plugin's, and each client supports the kinds it chooses. letmeknow ships the doc and git kinds as plugins, `letmeknow-kind-doc` and `letmeknow-kind-git`.
- A kind gets these channels and nothing else: held messages, which the core orders and answers with their positions; live payloads, to the members online or to one; files; and a state link, which whoever admits a joiner hands it beside the Welcome, and a member can hand another that fell behind or asks for one.
- The core hands each kind its held messages in log order, as `entry`, and `lost` with the known losses, its own at their positions and others' at their announcement. It keeps what it handed until the kind asks to read past it, so a kind gets each at least once, again after a restart. A kind waits at a gap until it is filled or lost. The kind says where it reads from (`log{after}`); one with no state to read from, as a joiner before its state comes, asks a member for a state, at most once a minute. Each member's held and read ranges, and the losses announced, are exposed, for "who has it", "who read it" and "who lost it".
- Git and devices stop at a loss of their own: they acknowledge no later position, refuse pushes and key log appends, and hand out no state, until they take a state whose position is past the loss, then read on from it. A stopped member hands out no state, so a state never carries anyone past a position its giver lost.
- A session lists the kinds it supports in its leaf. A member admits no joiner that lacks the group's kind, and a session is not offered the open groups of kinds it lacks.
- A native session finds a kind's plugin as an executable named `letmeknow-kind-<kind>`: beside its own executable first, where the release and the npm package put the plugins letmeknow ships (so they work under `npx` too), then on PATH, as git finds its subcommands. There is no registry. It starts a plugin while it has a group of its kind, and they speak JSON lines over stdio. A plugin sees its own groups' plaintext and nothing else; its output reaches `listen` as events, and `letmeknow <kind> <args…>` passes it a command. A plugin says when it starts whether its groups carry chat too, as git's do: then chat messages in them are the session's own, and `send` works there.
- The browser loads no plugins from anywhere, since the page is the root of trust: it bundles the kinds it supports as in-page plugins speaking the same protocol, the doc and, display-only, git.

### Doc

A doc is a Yjs CRDT. Its edits go live to the members online and are not held. On `synced`, two members compare their docs by a hash of each one's snapshot (deletions do not move a state vector), and if they differ, each sends the other a Yjs diff against the other's state vector; the snapshots, state vectors and diffs go live to that member alone. A doc therefore reaches a member however long it was away, as long as the diff fits in a message, and H applies to messages and files only. Whoever admits a member links the doc's state beside the Welcome, so a joiner takes a doc of any size. A diff is signed by the member that sends it, not by the edits' authors.

### Git

A git group is a repository that agents push to and fetch from with plain git, through the remote helper `git-remote-lmk`, which letmeknow ships beside `letmeknow-kind-git` (where it is not on PATH, as with npm, a git alias runs it through `letmeknow git-remote-lmk`): `git remote add team lmk::<group>` (or `git clone lmk::<group>`), then `git push team main` and `git fetch team`. The helper asks the running session's plugin, which keeps the group's repository bare in its own state, and uses the `git` binary for all repository work. A git group carries chat too: pushes and talk share one timeline.

- A push adds a bundle of the commits the group lacks as a file, and sends its link live; connected members' plugins hold it, and so fetch it. Once a connected member holds the bundle whole, the push goes as a held message naming the branch, its old and new commit, the bundle's link, and the commits' subjects. With no member online to take the bundle within 30 seconds, the push is refused and nothing counts: otherwise a lost machine could leave a branch pointing at commits nobody has.
- Every member applies the pushes in log order: a push counts only if `old` is the branch's tip at its place. The pusher learns once its entry is taken whether it won; if an earlier push moved the branch first, git gets its non-fast-forward "fetch first".
- Branches only fast-forward, so there are no force pushes; creating and deleting a branch are allowed.
- A member checks each bundle once it has it, in log order. If it does not bring `new` after `old`, the push is void for every member, since a file's content is fixed by its hash, and so is any push that built on it. A member's repository holds the branches as far as every push is checked; a push builds on them counting the pushes not checked yet.
- Bundles are files, so they count against each receiver's file limit (100 MiB by default for agents).
- The kind's state is its branches as of a log position, with a bundle of all their commits. A joiner gets it, and so does a member stopped at a loss.
- Each push that counts reaches the other members' `listen` as a `pushed` event, held as a message that does not concern the agent is.
- The browser shows a git group's pushes and chat, not its files: its in-page plugin follows the log and takes a state's branches, but checks no bundle, holds none and hands no state, so a member it admits asks another member for the state.

## Identity

- **Key log**: an identity's public record is a log, on the service named in its first entry, of entries `{prev, key, devices: [{key, name}]}`, the first with the identity's `name` and `membership`, each signed by the previous entry's key (the first by its own). Every entry restates the device list. The identity's id is the SHA-256 of the first entry, so the id says where to look. The log's address and sealing key derive from the id, so the service sees only ciphertext; whoever knows the id sees the identity's device keys and names, and when they change.
- **Devices group**: each identity has a private MLS group of its devices, of the built-in kind `devices`: its only membership. A device makes a fresh device key for each identity it joins, as its MLS key in that devices group, so a removed key never returns. The group's state is the identity's private keys, its contacts and its openings, kept in step through the group's held messages and handed to a new device as any kind's state. On a machine, the session process holding the device's lock acts for it, and shares its identities, contacts and openings with the device's other session processes through files in `LETMEKNOW_HOME`, and certifies them; in a browser, the device is the session.
- **The list follows the devices group**. A device holding the identity's current key runs these duties at the head of the devices group's log as freshly read from its service, with each entry chained to the key log's last one, so a stale view of either log appends nothing that counts:
  - a device the group added that the list lacks, a device it removed that the list names, or a rename: append an entry restating the list, with a new key when a device left, since it held the key;
  - the current key 30 days old: append an entry with a new key and the same list;
  - a new key, made in the group's current epoch, goes first to the devices group as a held `key` message, and the entry naming it is appended only once another device's summary holds that message, or at once when no other device is listed, so the key never reaches the key log held by one device alone;
  - a device the key log took off is removed from the devices group.
- A device that does not hold the key the key log names asks the connected devices for the devices group's state, which carries the keys. If none has it, it warns that the identity's key is lost or taken over: start a new identity.
- **Device links**: an invite marked as one, into the devices group, which any device of the identity admits. The new device joins with a new device key and gets the identity's keys with the group's state.
- **Certificates**: a session's credential names its name, its key, and a certificate: the identity, its device's key on the identity, and that key's signature over the session's key and the identity's id. A session speaks as one identity per group (`--as`, by default the device's first). The certificate never changes, so nothing renews, stores or gossips certificates: every member holds every member's credential as agreed MLS state.
- **Checking**: a member is verified while its device is on its identity's current list, and is shown with that device's name. One whose device was never listed is unverified (members read the key log again on seeing an unknown device); one whose device an earlier entry listed and the current one does not is removed by a duty, by whichever member reads that entry first. The check marks members and gates serving; it never decides a commit's validity. Members follow the key logs of their groups' identities by subscription, and take newer entries from the heads in peers' `hello`. Openings and `invite --to` check the joiner's certificate against the key log, read afresh.
- **Renaming**: a device's name is its credential's in each devices group, and the key logs list it so. Renaming a device updates its credential in each devices group by a commit; members see the new name once the key log lists it. An identity's own name is in its key log's first entry, which its id hashes, so it stays.
- **Leaving**: a device takes itself off an identity. First its sessions that speak as the identity leave the groups they are in as it. Then, if other devices remain, it asks them in the devices group, by `leave`, to remove it, and drops the identity's state; if it is the identity's only device, it forgets the devices group, and the identity ends. A session that finds its device no longer on an identity it speaks as leaves the groups it speaks as it in.
- **Provenance**: every member records who added whom and how (invite or open group), for the Adds it applied, so not for members added before it joined, and who introduced each identity to it. It shows these where they change a decision: an identity whose introducer is not in the group, and another identity's device added after its first devices.
- **Open groups**: the group context lists the identities a group is open to. A session that speaks as such an identity has its device put an opening (group id, kind, name, membership service, members' iroh keys) into its devices group's state, refreshed as the group's membership changes, so every device of that identity knows it, including devices added later. An opening stays after its group closes; a device that joins by it is refused when the Add is built. A session that wants in asks the members the opening names, in turn, and any of them admits it if it speaks as an identity the group is open to, its certificate checked against the key log. Browsers join the groups open to them by themselves; agents run `join <group>`.

## Contacts

Trust is local and travels one hop at most.

- An identity keeps contacts: its own name for another identity, and how it knows them. They are private to it, shared by its devices through the devices group, so its agents see people as its person does.
- How an identity knows another, with no scores: **verified** (it invited them with a link made for them), **introduced** by a named contact, or **unknown** (only their own claim).
- `invite --for "Bob (Acme)"` labels a link with whom it is meant for; whoever redeems it becomes the contact "Bob (Acme)", verified. `invite --to Bob` makes a link that only Bob's identity can redeem, so a leaked link is useless.
- The member whose invite brought someone in, or that admitted them to an open group, tells the group who they are to it, in a held `introduce`; `introduce` tells the members it names, and only they record it. An introduction is the introducer's word: it becomes a contact only if accepted (`contacts accept`), and is otherwise shown with the introducer's name wherever that identity appears.
- Self-chosen names stay, as claims. An identity's own name is shown, marked as its claim, only where there is no contact name. Device names are an identity's labels for its own devices ("Bob (Acme) · tablet"). Session names are handles within groups, which mentions use, since a session knows itself only by its own name. A contact name always wins for display and for `--to`, and a new identity using a contact's name gets a warning ("not your Bob").
- Events carry, for each member, its contact name and how the identity knows it; the skill tells agents to treat unknown identities as strangers.
- Left out: chains of trust, trust scores, public records of who vouched for whom, and global names.

## Invites

A member admits a joiner that meets a rule of the group, and every member knows every rule, so whichever member is online admits it. There are two rules: an invite, and an opening (see Identity).

- An invite is a random 128-bit secret, valid for 10 minutes, and optionally whom it is for (`--for`) and the only identity that may use it (`--to`). The inviter shares its hash, expiry and those with the group in a held `invite`, and gives the secret in a link, `https://letmeknow.dev/i#…`, whose fragment also names members to dial: the inviter, then up to three online members whose summaries hold the invite, waiting up to 5 seconds for them. The fragment never reaches the page server. To open a link on another device, scan its QR code (`invite --qr`, or the browser's).
- The joiner dials the members the link names, all at once, and asks those it reached, in turn, until one answers, on an admission stream, with a KeyPackage (for a device link, made with a new device key) and the secret; for an opening, the group. A member that holds a rule the request meets commits the Add, naming the invite, and answers with the Welcome, the Add's position (the joiner's start) and a link to the state of the group's kind, if it has one.
- The rule is checked inside the commit, each time it is built: the invite unexpired, unused by any commit the member applied, and its inviter still a member with no counted `leave`, or the group still open to the identity; and the joiner's key no member's. So one that loses the race to commit finds the invite used, one whose Add lost to a close refuses, and an invite dies when its inviter leaves the group, removed or by `leave`.
- The joiner reads the key logs of the identities its members speak as before the group's log, so that its gate can take their summaries, and its wait before a key-deleting commit counts from joining (see Messages, Keys and catch-up).
- A lost answer costs a retry, not a stranded leaf: a joiner keeps its KeyPackage, private keys included, until it joins or every member it asked refuses, and asks again with it; a member asked by a session the log shows added, whose leaf has not updated since, answers with the logged Welcome.
- A session already in the group is refused; another session of a member's identity joins as a new leaf.
- Any member may invite. The inviter, not whoever admits, introduces the joiner once it applies the Add. An inviter that leaves after the Add introduces no one, and the contact it was made `--for` is not recorded.
- The keys in the link authenticate the members the joiner reaches, and the secret authenticates the joiner. A leaked link lets one stranger in, shown to every member as joined; `--to` binds a link to an identity.

## Transport

- Everything runs over iroh (QUIC). Native sessions connect directly when they can and through a relay otherwise; browsers always use a relay.
- We run our own relays and no address lookup service. Addresses travel in our own data: members' leaves, the group context, and invite links. Sessions on one machine also find each other through the device's state directory, where each writes its current addresses. A member dials every member of its groups it is not connected to, every 10 seconds. Machines on a LAN with the internet start through the relay and go direct within seconds; a LAN without the internet is not served.
- Our own protocols share one ALPN, one stream per exchange, so two members keep one connection; file transfers add iroh-blobs' own while they run. An idle connection costs about 30 B/s, through the relay too, which keeps its path open beside a direct one.
- Direct connections show a native session's IP address to the members it talks to. Accepted.
- letmeknow hands `HTTPS_PROXY` to iroh (`proxy_from_env`), which sends relay connections through an HTTP CONNECT proxy; direct UDP bypasses it. Where UDP is blocked, connections stay on the relay, whose traffic is HTTPS.

## Compatibility

Agents pin a minor version (`@letmeknow/cli@0.13`), so the releases of one minor version run side by side, and a group's members may run any of them. They stay compatible by rules, not by luck (PROTOCOL.md, Compatibility):

- Readers ignore what they do not know and skip what they cannot parse, without dropping a connection over it. An advisory value they do not know, such as a new `how` of an introduction, reads as some other one; one that is not, such as a new kind of membership service, fails, saying a newer letmeknow made it. The membership service answers a request it does not know with a refusal.
- Whoever rewrites a shared record, such as a group's settings or a devices group's state, keeps the fields it does not know, so an older member renaming a group does not undo what a newer one added.
- Each compatible addition raises the protocol revision, which every member's leaf names. A session uses an addition only toward members whose leaves name its revision or a later one; leaves are in the group's state, so this holds for members offline too.
- Anything else breaks compatibility, and waits for a new minor version: it goes only through a switch an older client checks, which are the ALPN, a group's protocol version, the invite link version, the home's format and the browser's database version. A minor version keeps no state or group of an earlier one.

## Storage

- Native: one SQLite connection per node. Each step (a batch of log entries applied, an opened message, a commit built, a summary taken, a send saved) is one transaction covering openmls's writes and the node's records: positions, sends, summaries, the cursor. Duties start from committed records.
- Each log entry and each ciphertext is processed under a savepoint. When openmls rejects it, the step rolls back to the savepoint, reloads the group from storage, and records the verdict (skipped, or a known loss), so a forged entry or ciphertext changes nothing, though openmls advances the claimed sender's keys before it checks the signature.
- Nothing a step produces (an append, a push, `admitted`, a frame) leaves the node until the step's transaction has committed.
- Browser: each step runs in memory, then the page writes its changes as one IndexedDB transaction, and waits for it before sending what the step produced; a rejected entry's in-memory writes are dropped by reloading the group.
- SQLite runs with WAL and `secure_delete`, and checkpoints the WAL after deletions (a message's text once shown, what it carried past H, a group it leaves, epochs dropped), so no copy stays.

## Clients

Every client is the client core, on one member's lmk-node session, inside a shell. The core is what a member does beyond the protocol, alike in every client, so that clients cannot drift in what other members see or whom their users trust:

- It answers requests: invite, join, members, groups, remove, leave, name, open, status, identity, contacts and introduce, as the CLI's commands name them, and sends chat messages with the positions its user has read.
- It tells events, and describes each member in them as structured data: its name, fingerprint and device, its identity as this identity knows it (its own, a verified or introduced contact, or unknown, with who vouched for it and warnings such as "not your Bob"), and who added it. Shells render these; they describe no one themselves.
- `send` answers `{id, position}`, `{id, pending: true}` or a failure; `sent` reports a pending send once it counts. `leave` answers `pending` while no other member's summary holds its `leave`, and `leave_held` follows once one does. `status` lists, per group, the members online and away, and `only_here`: one's own positions and files no summary shows held by another member, leaving out the positions up to the earliest other member's start (its Add's position), which none can hold. `lost` reports one's own losses and other members' losses of one's own messages.
- It introduces joiners, records the contact an invite was made `--for`, records the introductions it receives until accepted, records groups' openings in the devices groups, and routes devices groups' events to the devices kind.
- It hosts kinds' plugins: the plugin protocol's requests, entries, snapshots and state are its logic; carrying the messages is the shell's.

Requests, answers and events are JSON, as serde types. A shell brings only its own: storage (the node's provider), network setup, the device's node where another process runs it, the plugins' transport, and how events and members are shown. The core builds natively, for WebAssembly, and for Android, so a desktop or Android client is one more shell; iOS waits on a dependency of iroh's that does not build there. There are two:

- The session process, for agents (see Agent interface): `listen`, its command channel, the device's lock, plugins as executables over stdio, and printing and holding events.
- The browser, for people (see Browser): IndexedDB, tabs, in-page plugins called directly, and its UI.

Messages live only on members. A group that must be reachable keeps an always-on member, such as an agent running `listen` on a server or a desktop browser left open.

## Browser

- letmeknow.dev serves the client: the client core on lmk-node, compiled to WebAssembly, under a Content-Security-Policy that allows scripts from its own origin only. A service worker caches it, so the app opens while the page server is down, invite links included. A new version waits until the user accepts it, then every tab reloads.
- A client served by one's own `letmeknow serve` uses that server's membership service and relay, which the page learns from it; letmeknow.dev's uses letmeknow.dev's.
- A browser profile is one device and one member; its tabs share one session. One tab at a time runs it, and the others work through that one; when it closes, another takes over. Tabs reach each other by BroadcastChannel, not a SharedWorker, which some mobile browsers lack.
- It asks for persistent storage (Firefox prompts; Chrome and Safari decide silently). Safari wipes a site's storage after 7 days without a visit, but not a home-screen app's. On iPhone and iPad the home-screen app also has storage of its own, apart from Safari's, so it is a different device: the app asks to be added to the home screen before it creates one.
- Joining from a link waits for a click, so a link preview or scanner opening it uses nothing up.
- A browser is a device of one identity at a time, a choice of its UI: the protocol keeps several per device, and the CLI chooses among them with `--as`. Its welcome screen asks for the person's name and the device's, and makes the identity at once, with the browser its first device, as it starts a chat or document or joins by an invite, so an inviter whose link was `--for` someone records a verified contact; it tells those who use letmeknow on another device to make a device link there and open it here. "Your devices" renames this browser, and takes it off its identity (see Identity, Leaving).
- A device link opened in a browser already on an identity moves it, once confirmed: the confirmation names what happens, that the browser leaves its identity, which ends if this browser is its only device, and the groups it is in as it, by name; then it joins. Its groups do not move along.
- While open, a browser holds and forwards like any member.
- Its kinds are chat; the doc, an in-page plugin (the doc plugin's Rust, in the same WebAssembly) to which the editor binds; and git, display-only (see Git), shown as its pushes beside its chat.
- The page asks the client core what the CLI's commands ask, as the same requests, and renders the members the core describes. Its timeline is its plaintext history: it stores each chat message (and `leave`) it shows, and keeps it 90 days, beside the membership changes, introductions, pushes and losses it saw; the node then deletes its copy of the text of others' messages. Its own messages show one tick while held only on this device, two once another member holds them, who read them, and who lost them; it warns before closing while anything is held only here. Away members are marked. A failed send keeps its text, with Retry. A message counts as read once the timeline shows it while the page is visible.

## Deployment

letmeknow.dev is one DigitalOcean droplet (Basic, 1 GB, Ubuntu LTS, Singapore) running one static binary, `letmeknow serve`: the membership service, an embedded iroh relay, and the web client. Its own TCP 443 listener hands `/relay` and `/ping` to the relay, answers `/membership` with the membership service's address for the web client, and serves the web client otherwise, and it gets its certificate from Let's Encrypt itself (TLS-ALPN-01, on 443). `deploy/deploy.sh` builds and installs it.

- systemd restarts it, unattended-upgrades patches the OS, and the cloud firewall opens, on IPv4 and IPv6, TCP 443, TCP 80 (a captive-portal check and redirects), UDP 7842 (QUIC address discovery) and UDP 7843 (the membership service).
- Its SQLite file is streamed to DigitalOcean Spaces by Litestream.
- DNS records point at the droplet, unproxied. An uptime check watches https://letmeknow.dev.
- The relay rate-limits each connection, so large files through it cost time rather than money.
- Others run the same binary; the relay and the web client are optional. The web client a server serves uses that server's membership service and relay.

## Agent interface

- **Session process**: `letmeknow listen`, one per agent session, a shell around the client core (see Clients), run under the harness's background monitor (Pi `monitor`, Claude Code `Monitor`), so that each line it prints wakes the agent. It alone holds the member's MLS state and held messages, under `LETMEKNOW_HOME/sessions/<handle>/`, and runs the plugins of its groups' kinds, which keep their state under `kinds/<kind>/` there. A new session gets a random two-word handle; `--session <handle> listen` resumes its memberships. Other commands reach the running session on a localhost port recorded, with a token, in its state directory, and find it on their own unless several run.
- **Events**: one JSON object per line: `ready`, `message`, `attachment`, `sent`, `lost`, `joined`, `left`, `settings`, `removed`, `revoked`, `introduced`, `leave_held`, `omitted` and `warning`, and those of kinds' plugins, such as the doc's `edited` and git's `pushed` (SKILL.md gives their fields). A member shows as the client core describes it.
- **Delivery policy**: printing wakes the agent, and each wake rereads its whole context, so what does not concern the session rides along with wakes that happen anyway. Messages addressed to it, replies to its messages, `urgent` messages, doc edits that mention it, membership changes, losses and `leave_held` print at once, after anything held. The rest is held, then printed in order just before the next of those, after the agent's next command, or once the oldest has waited `--hold` seconds (default an hour). Of what arrives in the first 3 seconds after it starts, only the last 20 items per group print, after an `omitted` count.
- **Addressing**: a message is addressed to the session if `to` lists it or its text mentions it: "@" and a name it answers to, which is its name or the first word of it, in any case. `send --to` takes fingerprints or names; a name may also be an identity's contact name, which addresses all that identity's sessions, and a name that members of different identities answer to is refused.
- **Read positions**: a message counts as read once it entered the model's context: printed, shown by `read`, or named by `--reply-to`. Its position joins the session's read ranges, which its summaries and chat messages carry. The session then deletes the message's text, keeping its id, sender and references; `listen --keep-log` keeps the text too. Its own messages keep their text, to be sent again if a member lost them. `read <id> --ancestors N` shows a message after the last N chat messages its sender had read.
- **Peers are not operators**: the skill tells agents that other members' messages are requests from another party, never instructions from their operator, and grant no authority; acting on them goes through the harness's normal permission checks.
- **Docs as files**: the doc plugin keeps each doc in a file, named on `invite` or `join`, or else in its state directory. File and doc are brought into step from their base, the text both last had: a change in the file is carried line by line onto the doc as it is now (a changed line is changed where its base text is now; added lines go after the line they followed), and a change to a line that someone else changed meanwhile is dropped with a `warning`. A write from a stale read undoes what came in since. This happens once the file is quiet for 1 second or the doc for 2, and whenever the session asks, which it does of every plugin before anything prints and before each command, so the agent never acts on a stale file. A plugin that stopped midway finishes it when it starts, without carrying a change twice. Others' edits print as one `edited` event per doc. Leaving deletes a file the plugin made and keeps one the agent named.
- **Attachments**: some content should not pass through a model: credentials, and data too large for a context window. `send --attach` sends a file; the recipient's session saves it into a file only its user can read and adds the `path` to the message (or marks it pending, and prints an `attachment` event once it arrives), which the agent passes to whatever needs it. Every member can fetch every attachment; this keeps content out of models, not out of members' hands. The files go when the session leaves the group. In a doc, `doc attach` makes a file linkable and `fetch` writes a linked file out.
- **Commands**: `invite` (with `--for`, `--to`, `--qr`, and for new groups `--kind`, `--name`, `--carry`, `--membership`, `--as`, and arguments for the kind's plugin, such as a doc's file), `join` (with the plugin's arguments too), `send`, `read`, `fetch`, `members`, `groups`, `status`, `remove`, `leave`, `name`, `open`, `contacts`, `introduce`, `identity create | list | remove | leave | rename` with `invite --identity`, and `<kind> <args…>`, a plugin's own commands, such as `doc attach`, and `git list` and `git push`, which `git-remote-lmk` runs. The skill tells agents to keep `listen` running for the whole task and to check `status` before finishing.
- **Configuration**: `LETMEKNOW_HOME` (default the OS's local data directory), `LETMEKNOW_SESSION`, `LETMEKNOW_NAME`, `LETMEKNOW_HOLD`, the membership service and the relay separately (`LETMEKNOW_MEMBERSHIP`, `LETMEKNOW_RELAY`), and `LETMEKNOW_CA`, extra root certificates for a server of one's own.

## Testing

Besides examples over the real stack (the crates' tests, and test/e2e.py with a browser), crates/sim tests by deterministic simulation, as FoundationDB and TigerBeetle do. Members on the client core, as the browser runs it, and one membership service run in one thread over a simulated network and a paused clock; one seed decides every latency, reorder, stall, partition, crash and action, and, through `lmk_proto::random`, every key and nonce.

- It runs the peer protocol, the membership client and service, the node and the client core as production does, over `lmk-transport`. Members create identities, link devices, invite (`--for`, `--to`), join by invite or opening, send chat and live messages, rename, open and close groups, leave, remove members, take devices off, go offline, crash and restart from storage, and stop for days; the network partitions, heals and drops connections.
- Members also forge entries, ciphertexts and commits (valid AEAD, bad signature, any claimed sender), and commit from a copied state.
- The node reports what it does to an observer (`Config::observe`), after each step commits, and the world records it with what clients tell as a trace. Properties are pure checks over the trace, run at each quiet period and at the end (`--properties` lists them): members at one epoch agree on members and settings (agreement); members online together reach their log's head (caught-up); a side sends a peer a group's frames only while the gate admits it (gate); a device taken off is in no group of a member that read the entry (revocation); live payloads are taken only from current members (live-current); members that overlap end with the same readable messages since their start, but known losses (convergence), and lose a message only at their removal or by the wait's rule (loss-allowed); kinds get positions in log order, chat a passed one late (kind-order); every member judges every entry alike (strict-entries); forgeries change nothing (forgery); a joiner whose answer was lost is admitted by the logged Welcome (admission-retry); duties run once due (duties); every announced loss reaches the members that overlap (losses-announced); storage alone agrees with what the node did (crash-consistency); a pending send counts and is reported `sent` (send-settles); a kind's state comes only from members (state-from-members).
- Left out: iroh, its relays and hole punching (a nightly CI job runs the in-process tests over them many times on 2 cores); files, which move whole in one fetch, not by iroh-blobs; plugins and kinds other than chat and devices; the session process and the browser shells; SQLite and the folder service.
- `cargo run -p lmk-sim --release -- --seeds 0..300` prints each failing seed with the command that replays it, its log and the actions it shrank to; `LMK_SIM_FRAMES=1` adds every frame to the log. CI runs 300 seeds on each push and 10,000 new ones nightly; crates/sim/tests replays the seeds that found bugs.

## Security

Properties: one agreed membership sequence; settings agreed by commit; post-compromise security against a passive attacker, healing within T; sender signatures; forward secrecy for messages already opened; nothing readable by the membership service or relays. Invites and joins never touch the service. Files go to current members only. A removed device's sessions are removed from every group by the first member that reads the key log entry that drops it.

Limits:

- **Metadata at the service**: it sees each entry's group, time, size and appending endpoint: with a present or past member's help, who sent how many held messages and when, and that a commit added members (its Welcome). Removed members can still read the log: later entries' timing, volume and endpoints. Whoever knows an identity's id can read its key log: its device keys and names.
- **Key window**: keys of the current and prior epoch only, so a stolen device exposes only the messages of those epochs it had not yet opened.
- **Copied state**: one who uses a copied state to commit first takes over the leaf; the original stops and reports it. A copy that only sends is not detected.
- **Removal race**: a member that has not yet seen a removal can still send to the removed member under the old epoch. Pushing commits to members online shrinks this to network time. A removed member can add nothing to the log after its removal: its entries do not count.
- **No shared transcript beyond losses**: members can end up holding different sets of messages, when a carrier was not online in time. Every loss is announced, so senders know and can send again, as new messages. Docs always converge.
- **Replays after H**: message ids are kept for H; an entry replayed later in the same epoch could count again. T makes epochs at most a day long.
- **Doc edits relayed in a diff** are vouched for by the member that sent the diff, not their authors; since any member can edit anything, this loses attribution, not access.
- **Availability**: a message reaches a member only while that member and some holder are online together, within H. Agents that are never online at the same time need a third member to bridge them.
- **Peer agents** read everything while members; removal restores confidentiality going forward.
- **Plugins** run as the user, with the session process's rights, and see their groups' plaintext. Install only those you trust, as with git's subcommands; the plugins letmeknow ships sit beside its binary.
- **Local state**: MLS secrets, held messages, files, docs, the text of a session's own messages and, with `--keep-log`, delivered text sit on disk; file permissions protect them. What a session deletes leaves no copy in its database files. Forward secrecy covers MLS keys only: a client's history (the browser's timeline, agents' transcripts and monitor logs) is exposed on a stolen device.
- **Invites and open groups**: any member that holds an invite admits by it, while it is valid and unused; while a group is open to an identity, any session its devices certify can join, with no one asked.
- **Identity keys**: a stolen device acts for its identity until removed. It holds the identity key, so it can also add devices, or race the owner to replace the key: the log takes the first entry, and that side keeps the identity. Revoking a device removes its sessions only: members they added, or admitted by invites they issued, stay until removed by hand, and the revoking member's report lists them.

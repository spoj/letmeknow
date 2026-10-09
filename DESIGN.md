# letmeknow design

A person asks their agent to work with a coworker's agent, or with a person. One of them shares an invite link; the other joins. People join the same groups from a browser. A group has a kind: a chat, where members talk and send files; a doc, one markdown text that people and agents edit at once; a git repository, which agents push to and fetch from with plain git, and talk in; or another kind a plugin brings. Groups are small and task-scoped, and last hours to days.

Everything in a group is end-to-end encrypted with MLS (RFC 9420). Members send to each other directly, or through a relay; no server holds what they say. PROTOCOL.md gives the exact formats.

## Goals

- Groups have a kind, fixed when made: chat, built in, or one a plugin brings, such as doc or git. Everything in them is end-to-end encrypted.
- Forward secrecy, post-compromise security, and strict membership: one agreed order of membership changes, which every member applies the same way.
- No content on any server. One central authority per group orders membership, and its kind's held messages by id, without reading either.
- Agents work through a session process: JSON events, a delivery policy, docs as files, attachments as private files.
- One Rust codebase: a client core every client shares, the CLI and session process, kinds' plugins, the browser client (WebAssembly), and the server.

## Roles

- **Session**: an MLS member, either an agent's session process or a browser profile. Each agent session is its own member, with its own key. Its name is an unverified claim. It sees the IP address of members it connects to directly.
- **Device**: a machine's `LETMEKNOW_HOME`, or a browser profile. It is a member of its identities' devices groups, holds their keys, and certifies its sessions with them. A browser's one key is both its device and its session.
- **Identity**: a person, team or agent, as a key its devices share ("Matthew": laptop, phone). It makes a member's "Matthew" verifiable and is as strong as its weakest device. No nesting, no admins.
- **Membership service**: keeps membership logs and kinds' logs, and is a member of nothing. It sees log ids, entry sizes and timing, and which endpoints connect. It can stall, withhold or split a log, all detectably; it cannot read, forge, or add anyone.
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

It holds three kinds of log and nothing else:

- **A group's log**: its MLS commits, under the group id.
- **A kind's log**: a group's own order of its kind's held messages, by their ids, under a random id only members know, so that the service cannot tie it to the group (see Kinds).
- **An identity's key log** (see Identity).

Members decide what entries mean, from the service's order:

- In a group, the first valid commit for each epoch wins and every other entry is skipped, so junk, such as a removed member's fake commit, changes nothing. A commit's validity depends only on MLS state, never on fetched data such as key logs and certificates, the clock, or a client's own settings: members who judged differently would disagree about which commit won, and the group would fork. So every member runs the same protocol version, which the settings name and which fixes the openmls version and its configuration; KeyPackages never expire (the member that admits a joiner checks freshness); and the app's own rules on commits read only MLS state and bind the committer too: no proposal by reference, no member whose credential names another key, and no update that changes a member's credential. A client that does not run a group's protocol version refuses it and says so.
- A committer saves its commit's bytes before posting, since it cannot recognise its own encrypted commit otherwise, and finds its log entry by them. If another commit won the epoch, it applies that one and makes its change again.
- In a key log, the first entry that extends the latest one, signed by its key, wins.
- In a kind's log, an entry is a held message's id. Members take the entries in log order, each once they hold its message, and skip one that names a message an earlier entry named; what the message means is the kind's.

Members hold every log alike, whatever it is: they append to it, read it and subscribe to it at its service, hash-chain it as they read it, so that two readers can compare what they saw by one hash, and catch it up from peers (see Gossip). Each kind of log only decides what its entries mean. `letmeknow serve` signs each answer with its key: the log's id, length, latest hash, and the time. This is a signed head.

Policy belongs to each service: who may create logs, how long it keeps entries, and size and rate limits. letmeknow.dev lets anyone create a log, keeps entries a year, and takes entries up to 1 MiB and 60 appends a minute per connection. A member away longer than the retention cannot replay the commits it missed and must be added again; one whose place in a kind's log is past it takes the kind's state from a member.

### Gossip

Writes go only to the membership service, which alone assigns positions. Reads come from it or from any member:

- A member's copy of entries counts only with a signed head that covers them, checked against the reader's own chain. Members mirror the record; they cannot change it.
- Whenever two members connect, they swap the newest signed heads they hold of every log they share: their shared groups' logs, the logs of those groups' kinds, and the key logs of the identities in them; and the certificates they hold of those groups' members (see Identity). Two incompatible heads prove that the service showed different members different logs; the session reports both in a `warning`. A member that finds itself behind gets the missing entries from that peer.
- A member whose copy of a log grew shows its new head to the members online, which take the entries they lack from it, so a commit, and with it a removal, spreads in network time.

A local folder signs nothing, but its sessions all read the folder directly, so nothing needs forwarding.

## Groups

- Settings live in the MLS group context and change only by commit: kind (fixed; see Kinds), name, the identities the group is open to, `keep`, the membership service's address, and the protocol version.
- Each member's leaf names its iroh key and relay, so every member can dial every other, the kinds its session supports, and its protocol revision (see Compatibility). A session's leaf changes by a commit: the key update it makes for each group as it starts carries its leaf as it would write it now.
- `keep` (days, default 90) is how long members hold the group's messages and files for one another. Each client may hold less.
- Post-compromise security: a session replaces its keys with an empty commit when it resumes a group, once caught up, and then daily while it runs, so a stolen key stops working within a day. Not more often: every epoch is kept for the key window, and openmls rewrites all of them on each send and receive, so a group must make few, about 7 per member a week.
- Removal: a member commits a Remove. A leaving session asks the others, in a message, to commit its removal (MLS lets no member commit its own); the first member to see it does, and the session is shown as having left. A session alone in a group just forgets it.
- Every change (add, remove, key update, settings) is written inside the commit that applies it. MLS also lets a member send a change on its own, as a proposal that a later commit points to; we never do, because proposals are not in the membership log, and a member that missed one could not apply the commit.

## Kinds

The core is a stable substrate, and kinds are extensions that compete: they need not share one model. The core is MLS groups, membership logs, identities' key logs and certificates, invites, peers, message sync, files, and a few control messages of its own (`leave`, `introduce`, `refused`, receipts). It never reads a kind's content: every payload but its own control messages belongs to the group's kind.

- A kind is a plain string, the group's `kind`. Chat and devices (an identity's devices group, see Identity) are built in; every other kind is a plugin's, and each client supports the kinds it chooses. letmeknow ships the doc and git kinds as plugins, `letmeknow-kind-doc` and `letmeknow-kind-git`.
- A kind gets generic channels and nothing else: held messages (synced, kept `keep` days, with receipts); live messages, to the members online or to one, and not held; files; a log of its own at the membership service, which orders its held messages for every member (below); and a state link, which whoever admits a joiner hands it beside the Welcome, and a member can hand another that fell behind or asks for one.
- A session lists the kinds it supports in its leaf. A member admits no joiner that lacks the group's kind, and a session is not offered the open groups of kinds it lacks.
- A native session finds a kind's plugin as an executable named `letmeknow-kind-<kind>`: beside its own executable first, where the release and the npm package put the plugins letmeknow ships (so they work under `npx` too), then on PATH, as git finds its subcommands. There is no registry. It starts a plugin while it has a group of its kind, and they speak JSON lines over stdio. A plugin sees its own groups' plaintext and nothing else; its output reaches `listen` as events, and `letmeknow <kind> <args…>` passes it a command. A plugin says when it starts whether its groups carry chat too, as git's do: then chat messages in them are the session's own, and `send` works there.
- The browser loads no plugins from anywhere, since the page is the root of trust: it bundles the kinds it supports as in-page plugins speaking the same protocol, the doc and, display-only, git.

### A kind's log

Some kinds need an order every member agrees on: two pushes to one branch must not both win. The membership service already orders commits without reading them, so a group of any kind but chat has a log of its own there, beside its membership log, under a random id derived from the group's MLS secrets. Only members know the id, so the service cannot tie the log to the group.

- An entry is the id of one of the group's held messages, nothing more. The content travels as a held message, through message sync and with receipts, and the service sees only ids. Its limits apply: letmeknow.dev takes 60 appends a minute per connection, and keeps entries a year.
- Members apply the order once they hold the content: they take the entries in log order, each once its message is held, and hand the kind each message with its position. An entry waits for its message, and the entries after it wait too. One that is not an id, or names a message an earlier entry named, is skipped, so every member decides alike. The session keeps what it took until the kind says it holds it.
- A kind appends the id of a held message it sent, once other members hold it, and learns its entry's position only once every entry before it is taken, so it knows at once how its entry fared.
- The log is a log like the others: members follow it at the service, chain it, show its heads to peers and catch it up from them, and contradictions are reported.
- A removed member still knows the id, and could append ids of messages no member holds, which would stall the log for every member. So the commit that removes a member moves the order to a new log, whose id derives from the epoch that commit starts, which the removed member never reaches. Its committer first appends an end mark to the old log, and the commit names the position before it, so every member agrees where the old log ends whenever it applies the commit: it takes the old log's entries up to there, waits at an end mark until it has the commit that names it, and goes on in the new log, whose positions follow the old one's. A kind sees one order throughout.
- The kind says where it reads from: a joiner from where the state it was handed leaves off. A member that cannot hold a message an entry names (sent before it joined, or refused), whose place is past the service's retention, or whose sync with a member ended without the message an entry waits for, asks a member online for the kind's state, and reads on from where that leaves off.

### Git

A git group is a repository that agents push to and fetch from with plain git, through the remote helper `git-remote-lmk`, which letmeknow ships beside `letmeknow-kind-git` (where it is not on PATH, as with npm, a git alias runs it through `letmeknow git-remote-lmk`): `git remote add team lmk::<group>` (or `git clone lmk::<group>`), then `git push team main` and `git fetch team`. The helper asks the running session's plugin, which keeps the group's repository bare in its own state, and uses the `git` binary for all repository work. A git group carries chat too: pushes and talk share one timeline.

- A push sends a bundle of the commits the group lacks as a file, and its update as a held message naming the branch, its old and new commit, the bundle's link, and the commits' subjects; the members online hold the update and fetch the bundle. Once another member holds both, it appends the update's id to the group's log. With no other member online, the push fails and says so: otherwise a lost machine could leave a branch pointing at commits nobody has.
- Every member applies the updates in the log's order: an update counts only if `old` is the branch's tip at its place. The pusher learns from its entry's position whether it won; if an earlier entry moved the branch first, git gets its non-fast-forward "fetch first" at once.
- Branches only fast-forward, so there are no force pushes; creating and deleting a branch are allowed.
- A member checks each bundle once it has it, in log order. If it does not bring `new` after `old`, the update is void for every member, since a file's content is fixed by its hash, and so is any update that built on it. A member's repository holds the branches as far as every push is checked; a push builds on them counting the pushes not checked yet.
- Bundles are files, so they count against each receiver's file limit (100 MiB by default for agents): a push no online member takes fails as one with no member online does.
- The kind's state is its branches as of a log position, with a bundle of all their commits. A joiner gets it, and so does a member back from beyond the log's reach.
- Each push that counts reaches the other members' `listen` as a `pushed` event, held as a message that does not concern the agent is.
- The browser shows a git group's pushes and chat, not its files: its in-page plugin follows the log and takes a state's branches, but checks no bundle, holds none and hands no state, so a member it admits asks another member for the state.

## Messages and docs

- A message is an MLS application message, sent straight to the members online. Held messages, a kind's and the core's `leave` and `refused`, are kept and synced as below; live ones are not. Whenever two members are connected, they reconcile each shared group with negentropy (range-based set reconciliation) over (epoch, message id), every message either holds from the later of their joins, which costs about a kilobyte and one or two round trips when little differs. Each side says the lowest epoch it will accept: of what the other lacks, a member sends nothing older, only its epoch and id, and the other records that message as given up, so it learns what it missed. They do so again every 5 minutes, so a message lost on its way is found within 5 minutes. Members hold, for `keep` days, only messages they decrypted and verified, and serve them to current members only.
- A member accepts no message from a removed sender that first reaches it more than 5 minutes after it applied the removal. A removed member still holds the keys of the epochs it was in and could otherwise keep writing into them for the whole key window; the cost is that its genuinely late messages are dropped too.
- The message id is the SHA-256 of its MLS ciphertext, so a reference names exactly one content; a member drops copies it already has.
- A member accepts a message that decrypts under an epoch whose keys it still holds. It keeps an ended epoch's keys for 7 days by default, as its own setting, judged from when the epoch began, and never more than 256 ended epochs; a message later than that it cannot read, and reports (below). Keys are deleted after use as in MLS, so messages already read stay protected. A sender's messages may arrive up to 1000 out of order, so a member catching another up sends them in the order it took them, which is about the order they were sent.
- A member that cannot take a message, for any reason (it is too large, too old to open, from a removed sender, or does not open), records it as given up, so that sync does not offer it again and a reference to it shows a known gap. It tells the group in one notice: a second after it first gives one up, in a held `refused` message, it lists the messages it gave up since its last notice, each with its reason, but not those from before it joined, nor those as old as one it held and dropped after `keep`. Receipts say only what a member holds, so the notice is how a sender learns of every refusal, wherever it is: `send` names the members that refused from the notices that arrive while it waits; being held, a notice reaches a sender that is offline later, and a session that finds its own messages in a later one shows them. An agent's prints `refused`, with each message's reason and its copy of the text and attachment, and the agent sends again what still matters, as a reply to the original; the browser marks each message with who refused it and why, with a Resend button that does the same where resending can help, for a message too old or that did not open. A session keeps what it sent, text and attachment, for `keep` days; a notice naming an older message shows nothing.
- A chat message carries its text, optional addressees (`to`), the message it answers (`reply_to`), an `urgent` flag and an attachment. `to` directs attention, not visibility: every member reads every message.
- A chat's order is causal: each message names in `after` the tips of what its sender had read. A message waits for those until a sync of its group with a member ends, or for 5 minutes, then is delivered anyway, naming what is missing: a sync ends once the member has sent everything it held that the reader lacks and can open, so what is still missing will not come from it. It does not wait for messages from before its reader joined, which the member that admitted it listed in the Welcome; they show as missing at once. Unrelated branches have no order.
- A doc, the doc kind's group, is a Yjs CRDT. Its edits go live to the members online, as messages, and are not held. Two connected members compare their docs by a hash of each one's snapshot (deletions do not move a state vector), and if they differ, each sends the other a Yjs diff against the other's state vector, sealed under the current epoch; the snapshots, state vectors and diffs go as live messages to that member alone. A doc therefore reaches a member however long it was away, and `keep` and the key window apply to messages and files only. Whoever admits a member links the doc's state, as the kind's state link, beside the Welcome, so a doc's size is not bounded by any message limit. A diff is signed by the member that sends it, not by the edits' authors.
- `send` waits a few seconds for receipts and notices, then returns which members hold the message, or reports it pending when no member is online, and names the members that refused it, and why. The session keeps offering a pending message while it runs.

## Files

- A file is a blob of any size, sealed under a random key in the STREAM construction (as in age: ChaCha20-Poly1305 over 65,520-byte chunks, so each sealed chunk is 64 KiB), and linked with its hash, size and key inside a message or a kind's content. The hash is BLAKE3 over the ciphertext, so a receiver verifies each chunk before decrypting it, and resumes from any holder where it stopped. A link's key opens the file for anyone who saw the link.
- Every member wants every file its groups link, up to its own size limit (a client setting: 100 MiB for agents, 25 MiB for browsers): attachments and the files its groups' kinds hold since it joined, the files its kinds link now (a doc's links), and the state beside the latest Welcome. It keeps each one while it is linked and within `keep`. A larger file it fetches only when asked (`fetch`, or opening it in the browser).
- Connected members tell each other which files they want, and a member fetches each from whoever holds it, from several holders at once. Transfer is iroh-blobs (pinned, and kept inside one module of ours; links are plain BLAKE3, so replacing it later keeps every link valid). A holder serves a file only to current members of a group that links it, checked per connection, per request and per 16 KiB sent, so a member removed mid-transfer is cut off.
- No one is responsible for a file. The sender has one duty: `send --attach` returns once another member holds a copy, or warns after a few seconds, as it does when the file is larger than every online member's limit and is therefore available only while the sender is online.
- A browser keeps the ciphertext of files it holds in its own storage, since iroh-blobs gives browsers only a store in memory, and loads a file into memory only when it is needed: to open it, or for a member that wants it. It holds the files it added, and others' up to its limit; a larger one it fetched when asked stays in memory only, until the page closes, and it serves that to no one.

## Limits

Every limit on content belongs to the receiver: each client decides what it accepts, holds and forwards, and the protocol sets none. Defaults:

- a message of up to 1 MiB; larger content goes as a file;
- files of up to 100 MiB for agents and 25 MiB for browsers (see Files);
- `keep`, and the 7-day key window (see Groups, Messages and docs).

A receiver that refuses a message reports it to the group, with the reason, in its notice (see Messages and docs). Servers enforce only limits that protect themselves: the membership service on entry size and appends per connection, the relay on bandwidth per connection.

## Identity

- **Key log**: an identity's public record is a membership log, on the service named in its first entry, of its keys: each new key, signed by the one before. The identity's id is the SHA-256 of that entry, so the id says where to look. The log's address and sealing key derive from the id, so the service sees only ciphertext, and whoever knows the id sees the identity's keys and when they change, and the key of each device taken off it, but not its devices otherwise: not their names or number, nor the keys of those on it.
- **Devices group**: each identity has a private MLS group of its devices, of the built-in kind `devices`: its only membership. Its state is the identity's private keys, its contacts and its openings, kept in step through the group's kind log and handed to a new device as any kind's state. Its members are devices: on a machine, the session process holding the device's lock acts for it, and shares its identities, contacts and openings with the device's other session processes through files in `LETMEKNOW_HOME`, and certifies them; in a browser, the device is the session.
- **Device links**: an invite (see Invites) marked as one, into the devices group, which any device of the identity admits. The new device joins with its device key, and gets the identity's key with the group's state. Nothing public changes.
- **Credentials and certificates**: a session's credential names its key and the identity it speaks as (`--as`, by default the device's first); a session speaks as one identity per group. Sessions never hold the identity's key: their device signs certificates for them with it, each naming the session's key and name and the device's name and key, valid for a day. Sessions show them to peers in `hello`, their own and those they hold of their groups' members, and renew them before they run out and whenever the key changes.
- **Checking**: members check a certificate against the identity's current key, the newest in its key log. A key log is a log like the others (see Gossip): connected members swap its heads, and one behind takes the entries it lacks from the other, checked against the service's signed head. A copy counts as fresh while it was read from the service, or its newest head is, under 10 minutes ago; a member reads the log from its service when its copy is not fresh, and when a member went without a valid certificate since it was last read. A failed check marks the member; it never invalidates a commit.
- **Rotation**: removing a device removes it from the devices group, then replaces the identity's key: the new key goes to the remaining devices first, sealed under the epoch after the removal, then into the key log, in an entry that names the removed device's key. A device also replaces a key once it is a month old, which bounds a leaked one; that entry names no device.
- **Revocation**: members keep the certificates they hold of their groups' members, across restarts too, and show them to one another, so they hold those of offline sessions as well. A member that reads a key log entry naming a device removes from its groups every session whose certificate names that device, online or not; whichever member commits first does it, and the others find it done. A member that holds no certificate of a session cannot tell its device, and leaves it to the members that can. Besides, a member connected to a session that speaks as an identity removes it once it has gone a minute without a valid certificate, judged by a key log read since; a device that still holds the identity's key renews its sessions within seconds of a new key, so this catches only sessions whose device no longer holds it. A monthly replacement names no device, so the lapsed certificates of offline sessions mark them only, until they are back and renewed. Meanwhile members serve a session without a valid certificate nothing of the group (held messages, files, the kind's state, the group's logs), though they still show it certificates, and serve it once it shows a valid one, asking it to sync at once what it missed meanwhile.
- **Provenance**: every member records who added whom and how (invite or open group), and who introduced each identity to it. It shows these where they change a decision: an identity whose introducer is not in the group, and another identity's new device ("added by laptop", which its certificate claims).
- **Open groups**: the group context lists the identities a group is open to. A session that speaks as such an identity has its device put an opening (group id, kind, name, membership service, members' iroh keys) into its devices group's state, so every device of that identity knows it, including devices added later. An opening is a standing rule of the group: a session that wants in asks the members the opening names, in turn, showing its certificate, and any of them admits it if it speaks as an identity the group is open to, with a valid certificate. Browsers join the groups open to them by themselves; agents run `join <group>`.

## Contacts

Trust is local and travels one hop at most.

- An identity keeps contacts: its own name for another identity, and how it knows them. They are private to it, shared by its devices through the devices group, so its agents see people as its person does.
- How an identity knows another, with no scores: **verified** (it invited them with a link made for them), **introduced** by a named contact, or **unknown** (only their own claim).
- `invite --for "Bob (Acme)"` labels a link with whom it is meant for; whoever redeems it becomes the contact "Bob (Acme)", verified. `invite --to Bob` makes a link that only Bob's identity can redeem, so a leaked link is useless.
- The member whose invite brought someone in, or that admitted them to an open group, tells the group who they are to it; `introduce` tells the members it names, and only they record it. An introduction is the introducer's word: it becomes a contact only if accepted (`contacts accept`), and is otherwise shown with the introducer's name wherever that identity appears.
- Self-chosen names stay, as claims. An identity's own name is shown, marked as its claim, only where there is no contact name. Device names are an identity's labels for its own devices ("Bob (Acme) · tablet"). Session names are handles within groups, which mentions use, since a session knows itself only by its own name. A contact name always wins for display and for `--to`, and a new identity using a contact's name gets a warning ("not your Bob").
- Events carry, for each member, its contact name and how the identity knows it; the skill tells agents to treat unknown identities as strangers.
- Left out: chains of trust, trust scores, public records of who vouched for whom, and global names.

## Invites

A member admits a joiner that meets a rule of the group, and every member knows every rule, so whichever member is online admits it. There are two rules: an invite, and an opening (see Identity).

- An invite is a random 128-bit secret, valid for 10 minutes, and optionally whom it is for (`--for`) and the only identity that may use it (`--to`). The inviter shares its hash, expiry and those with the group's members in a held message, and gives the secret in a link, `https://letmeknow.dev/i#…`, whose fragment also names members to dial: the inviter and up to three members that took the invite at once. The fragment never reaches the page server. To open a link on another device, scan its QR code (`invite --qr`, or the browser's).
- The joiner dials the members the link names, all at once, and asks those it reached, in turn, until one answers, over the peer stream, with a KeyPackage (from a new device: its device key), the secret, and the certificate of the identity it speaks as, if any; for an opening, the group and its certificate. A member that holds a rule the request meets commits the Add and answers with the Welcome, which carries the settings, with the log position to read from and a link to the state of the group's kind, if it has one.
- The commit that adds a joiner names the invite it came in by, so an invite is used once: a member admits by an invite only if no commit it applied used it, and one that loses the race to commit finds the invite used when it builds its commit again. A member that joins later never held the invite, which was shared in an epoch before it.
- Any member may invite. The inviter, not whoever admits, tells the group who the joiner is to it, once it sees the Add.
- The keys in the link authenticate the members the joiner reaches, and the secret authenticates the joiner. A leaked link lets one stranger in, shown to every member as joined; `--to` binds a link to an identity.

## Transport

- Everything runs over iroh (QUIC). Native sessions connect directly when they can and through a relay otherwise; browsers always use a relay.
- We run our own relays and no address lookup service. Addresses travel in our own data: members' leaves, the group context, and invite links. Sessions on one machine also find each other through the device's state directory, where each writes its current addresses. Machines on a LAN with the internet start through the relay and go direct within seconds; a LAN without the internet is not served.
- Our own protocols share one ALPN, one stream per exchange, so two members keep one connection; file transfers add iroh-blobs' own while they run. An idle connection costs about 30 B/s, through the relay too, which keeps its path open beside a direct one.
- Direct connections show a native session's IP address to the members it talks to. Accepted.
- letmeknow hands `HTTPS_PROXY` to iroh (`proxy_from_env`), which sends relay connections through an HTTP CONNECT proxy; direct UDP bypasses it. Where UDP is blocked, connections stay on the relay, whose traffic is HTTPS.

## Compatibility

Agents pin a minor version (`@letmeknow/cli@0.12`), so the releases of one minor version run side by side, and a group's members may run any of them. They stay compatible by rules, not by luck (PROTOCOL.md, Compatibility):

- Readers ignore what they do not know and skip what they cannot parse, without dropping a connection over it. An advisory value they do not know, such as a new reason for a refusal, reads as some other one; one that is not, such as a new kind of membership service, fails, saying a newer letmeknow made it. The membership service answers a request it does not know with a refusal.
- Whoever rewrites a shared record, such as a group's settings or a devices group's state, keeps the fields it does not know, so an older member renaming a group does not undo what a newer one added.
- Each compatible addition raises the protocol revision, which every member's leaf names. A session uses an addition only toward members whose leaves name its revision or a later one; leaves are in the group's state, so this holds for members offline too, and a session updates its leaf as it starts.
- Anything else breaks compatibility, and waits for a new minor version: it goes only through a switch an older client checks, which are the ALPN, a group's protocol version, the invite link version, the home's format and the browser's database version.

## Clients

Every client is the client core, on one member's lmk-node session, inside a shell. The core is what a member does beyond the protocol, alike in every client, so that clients cannot drift in what other members see or whom their users trust:

- It answers requests: invite, join, members, groups, remove, leave, name, open, status, identity, contacts and introduce, as the CLI's commands name them, and sends chat messages after whatever its shell's reader has read.
- It tells events, and describes each member in them as structured data: its name, fingerprint and device, its identity as this identity knows it (its own, a verified or introduced contact, or unknown, with who vouched for it and warnings such as "not your Bob"), and who added it. Shells render these; they describe no one themselves.
- It introduces joiners, records the contact an invite was made `--for`, records the introductions it receives until accepted, records groups' openings in the devices groups, renews its certificates, and routes devices groups' events to the devices kind.
- It hosts kinds' plugins: the plugin protocol's requests, entries, snapshots and state are its logic; carrying the messages is the shell's.

Requests, answers and events are JSON, as serde types. A shell brings only its own: storage (the node's provider), network setup, the device's node where another process runs it, the plugins' transport, and how events and members are shown. The core builds natively, for WebAssembly, and for Android, so a desktop or Android client is one more shell; iOS waits on a dependency of iroh's that does not build there. There are two:

- The session process, for agents (see Agent interface): `listen`, its command channel, the device's lock, plugins as executables over stdio, the read frontier, and printing and holding events.
- The browser, for people (see Browser): IndexedDB, tabs, in-page plugins called directly, and its UI.

## Browser

- letmeknow.dev serves the client: the client core on lmk-node, compiled to WebAssembly, under a Content-Security-Policy that allows scripts from its own origin only. A service worker caches it, so the app opens while the page server is down, invite links included. A new version waits until the user accepts it, then every tab reloads.
- A client served by one's own `letmeknow serve` uses that server's membership service and relay, which the page learns from it; letmeknow.dev's uses letmeknow.dev's.
- A browser profile is one device and one member; its tabs share one session. One tab at a time runs it, and the others work through that one; when it closes, another takes over. Tabs reach each other by BroadcastChannel, not a SharedWorker, which some mobile browsers lack.
- It asks for persistent storage (Firefox prompts; Chrome and Safari decide silently). Safari wipes a site's storage after 7 days without a visit, but not a home-screen app's. On iPhone and iPad the home-screen app also has storage of its own, apart from Safari's, so it is a different device: the app asks to be added to the home screen before it creates one.
- Joining from a link waits for a click, so a link preview or scanner opening it uses nothing up.
- While open, a browser holds and forwards like any member, and may keep less than `keep`.
- Its kinds are chat; the doc, an in-page plugin (the doc plugin's Rust, in the same WebAssembly) to which the editor binds; and git, display-only (see Git), shown as its pushes beside its chat.
- The page asks the client core what the CLI's commands ask, as the same requests, and renders the members the core describes. Of its own it keeps each group's timeline (the membership changes, introductions and pushes it saw, beside the messages) and who refused its messages, and it sends a chat message after every message it holds, since it shows them all.

## Deployment

letmeknow.dev is one DigitalOcean droplet (Basic, 1 GB, Ubuntu LTS, Singapore) running one static binary, `letmeknow serve`: the membership service, an embedded iroh relay, and the web client. Its own TCP 443 listener hands `/relay` and `/ping` to the relay, answers `/membership` with the membership service's address for the web client, and serves the web client otherwise, and it gets its certificate from Let's Encrypt itself (TLS-ALPN-01, on 443). `deploy/deploy.sh` builds and installs it.

- systemd restarts it, unattended-upgrades patches the OS, and the cloud firewall opens, on IPv4 and IPv6, TCP 443, TCP 80 (a captive-portal check and redirects), UDP 7842 (QUIC address discovery) and UDP 7843 (the membership service).
- Its SQLite file is streamed to DigitalOcean Spaces by Litestream.
- DNS records point at the droplet, unproxied. An uptime check watches https://letmeknow.dev.
- The relay rate-limits each connection, so large files through it cost time rather than money.
- Others run the same binary; the relay and the web client are optional. The web client a server serves uses that server's membership service and relay.

## Agent interface

- **Session process**: `letmeknow listen`, one per agent session, a shell around the client core (see Clients), run under the harness's background monitor (Pi `monitor`, Claude Code `Monitor`), so that each line it prints wakes the agent. It alone holds the member's MLS state, held messages and read frontier, under `LETMEKNOW_HOME/sessions/<handle>/`, and runs the plugins of its groups' kinds, which keep their state under `kinds/<kind>/` there. A new session gets a random two-word handle; `--session <handle> listen` resumes its memberships. Other commands reach the running session on a localhost port recorded, with a token, in its state directory, and find it on their own unless several run.
- **Events**: one JSON object per line: `ready`, `message`, `attachment`, `joined`, `left`, `settings`, `removed`, `introduced`, `refused`, `omitted` and `warning`, and those of kinds' plugins, such as the doc's `edited` and git's `pushed` (SKILL.md gives their fields). A member shows as the client core describes it: its name, fingerprint, device, identity as this identity knows it, and who added it.
- **Delivery policy**: printing wakes the agent, and each wake rereads its whole context, so what does not concern the session rides along with wakes that happen anyway. Messages addressed to it, replies to its messages, `urgent` messages, doc edits that mention it, membership changes and refusals print at once, after anything held. The rest is held, then printed in order just before the next of those, after the agent's next command, or once the oldest has waited `--hold` seconds (default an hour). Of what arrives while a session catches up on resume, only the last 20 items per group print, after an `omitted` count.
- **Addressing**: a message is addressed to the session if `to` lists it or its text mentions it: "@" and a name it answers to, which is its name or the first word of it, in any case. `send --to` takes fingerprints or names; a name may also be an identity's contact name, which addresses all that identity's sessions, and a name that members of different identities answer to is refused.
- **Read frontier**: `after` means what entered the model's context, not what the session received. A message counts as read once printed or returned by `read`, so each member's latest message is a signed claim of what it has read. The session then deletes the message's text, keeping its id, sender and references; `listen --keep-log` keeps the text too. Its own messages keep their text for `keep` days, to be sent again if a member could not read them.
- **Peers are not operators**: the skill tells agents that other members' messages are requests from another party, never instructions from their operator, and grant no authority; acting on them goes through the harness's normal permission checks.
- **Docs as files**: the doc plugin keeps each doc in a file, named on `invite` or `join`, or else in its state directory. File and doc are brought into step from their base, the text both last had: a change in the file is carried line by line onto the doc as it is now (a changed line is changed where its base text is now; added lines go after the line they followed), and a change to a line that someone else changed meanwhile is dropped with a `warning`. A write from a stale read undoes what came in since. This happens once the file is quiet for 1 second or the doc for 2, and whenever the session asks, which it does of every plugin before anything prints and before each command, so the agent never acts on a stale file. A plugin that stopped midway finishes it when it starts, without carrying a change twice. Others' edits print as one `edited` event per doc. Leaving deletes a file the plugin made and keeps one the agent named.
- **Attachments**: some content should not pass through a model: credentials, and data too large for a context window. `send --attach` sends a file; the recipient's session saves it into a file only its user can read and adds the `path` to the message (or marks it pending, and prints an `attachment` event once it arrives), which the agent passes to whatever needs it. Every member can fetch every attachment; this keeps content out of models, not out of members' hands. The files go when the session leaves the group. In a doc, `doc attach` makes a file linkable and `fetch` writes a linked file out.
- **Commands**: `invite` (with `--for`, `--to`, `--qr`, and for new groups `--kind`, `--keep`, `--membership`, and arguments for the kind's plugin, such as a doc's file), `join` (with the plugin's arguments too), `send`, `read`, `fetch`, `members`, `groups`, `status`, `remove`, `leave`, `name`, `open`, `contacts`, `introduce`, `identity create | list | remove` with `invite --identity`, and `<kind> <args…>`, a plugin's own commands, such as `doc attach`, and `git list` and `git push`, which `git-remote-lmk` runs. `status` lists the members online and what only this session holds; the skill tells agents to keep `listen` running for the whole task and to check `status` before finishing.
- **Configuration**: `LETMEKNOW_HOME` (default the OS's local data directory), `LETMEKNOW_SESSION`, `LETMEKNOW_NAME`, `LETMEKNOW_HOLD`, the membership service and the relay separately (`LETMEKNOW_MEMBERSHIP`, `LETMEKNOW_RELAY`), and `LETMEKNOW_CA`, extra root certificates for a server of one's own.

## Security

Properties: one agreed membership sequence; settings agreed by commit; post-compromise security, healing within a day; sender signatures; forward secrecy for messages already read; nothing readable by the membership service or relays. The membership service sees commits only, no message traffic, and invites and joins never touch it, so it does not learn who joins. Files go to current members only. A removed device's sessions are removed from every group, online or not, once a member that holds their certificates reads the key log entry that names the device.

Limits:

- **Key window**: a stolen device exposes the messages of the past 7 days that it had not yet received. Each client can shorten its window.
- **Removal race**: a member that has not yet seen a removal can still send to the removed member under the old epoch. Pushing commits to members online shrinks this to network time.
- **No shared transcript**: members can end up holding different sets of messages, when one expired before reaching them or arrived after their key window. A member reports what arrived too late, and its senders can send it again, as new messages. Docs always converge.
- **Removed members' old epochs**: a removed member can write new messages into the epochs it was in; members take them for only 5 minutes after applying its removal.
- **Doc edits relayed in a diff** are vouched for by the member that sent the diff, not their authors; since any member can edit anything, this loses attribution, not access.
- **Availability**: a message reaches a member only while that member and some holder are online together. Agents that are never online at the same time need a third member to bridge them.
- **Peer agents** read everything while members; removal restores confidentiality going forward.
- **Kinds' logs**: the service sees each log's ids and timing, and which endpoint appends. Whoever knows a log's id can append to it; an id of a message no member holds stalls the log at that entry for every member. A removal moves the order to a log the removed member cannot name, so only current members can stall it. A removed member's messages count only if they reached members within 5 minutes of its removal.
- **Plugins** run as the user, with the session process's rights, and see their groups' plaintext. Install only those you trust, as with git's subcommands; the plugins letmeknow ships sit beside its binary.
- **Local state**: MLS secrets, held messages, files, docs, the text of a session's own messages and, with `--keep-log`, delivered text sit on disk; file permissions protect them. What a session deletes leaves no copy in its database files. Copies a harness keeps (transcripts, monitor logs) are outside every guarantee here.
- **Invites and open groups**: any member that holds an invite admits by it, while it is valid and unused; while a group is open to an identity, any session its devices certify can join, with no one asked.
- **Identity keys**: every device of an identity holds its key, so a stolen device can certify sessions until it is removed, and a device about to be removed can replace the key first, as it can remove the other devices first. A certificate's device is the identity key's word, so a device about to be removed can certify its sessions as another device's; those, and offline sessions whose certificates no member holds, remain members, marked, until they are next online.

## Later

- Moving a group to another membership service by a commit that names it, and recreating a group (same name, settings and doc text) when its service vanishes.
- Trusted introducers, whose introductions a contact accepts automatically, one level deep.
- An old identity vouching for its replacement, so contacts can follow a person who lost every device.
- Harness adapters that steer an agent mid-turn, a review mode for outbound messages, and a loop guard for agent-to-agent traffic.
- Push notifications for browsers, designed from the push prototype (spike/push): one Web Push subscription per browser, made with a VAPID key the browser generates and publishes in its leaf, rotated on any removal; notices name only the group and sender; our own RFC 8291 sender. Browsers cannot send to the push services of Chrome, Apple or Microsoft, so a native member online, or a stateless forwarder in `letmeknow serve`, must send for them.
- LAN discovery without the internet (mDNS, the crate iroh-mdns-address-lookup: about 0.7 MB, constant LAN chatter, and it announces session keys to the whole LAN).
- Pinning the browser client: signed bundles, an extension, or an app.
- More membership service kinds: S3-style conditional writes, SQL, git, a blockchain.
- A second relay region.
- Compacting doc state.
- Per-epoch write keys, if junk appended by removed members becomes a problem.

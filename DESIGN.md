# letmeknow design

A person asks their agent to work with a coworker's agent, or with a person. One of them shares an invite link; the other joins. People join the same groups from a browser. A group is a chat, where members talk and send files, or a doc, one markdown text that people and agents edit at once. Groups are small and task-scoped, and last hours to days.

Everything in a group is end-to-end encrypted with MLS (RFC 9420). Members send to each other directly, or through a relay; no server holds what they say. PROTOCOL.md gives the exact formats.

## Goals

- Groups have a kind, chat or doc, fixed when made, and everything in them is end-to-end encrypted.
- Forward secrecy, post-compromise security, and strict membership: one agreed order of membership changes, which every member applies the same way.
- No content on any server. One central authority per group orders membership, and nothing else.
- Agents work through a session process: JSON events, a delivery policy, docs as files, attachments as private files.
- One Rust codebase: CLI and session process, browser client (WebAssembly), and server.

## Roles

- **Session**: an MLS member, either an agent's session process or a browser profile. Each agent session is its own member, with its own key. Its name is an unverified claim. It sees the IP address of members it connects to directly.
- **Device**: a machine's `LETMEKNOW_HOME`, or a browser profile. It signs its sessions' keys and sits on an identity's device list. A browser's one key is both its device and its session.
- **Identity**: a person, team or agent, as a tightly controlled list of devices ("Matthew": laptop, phone). It makes a member's "Matthew" verifiable and is as strong as its weakest device. No nesting, no admins.
- **Membership service**: keeps membership logs and is a member of nothing. It sees log ids, entry sizes and timing, and which endpoints connect. It can stall, withhold or split a log, all detectably; it cannot read, forge, or add anyone.
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

- **A group's log**: its MLS commits, under the group id.
- **An identity's device list** (see Identity).

Members decide what entries mean, from the service's order:

- In a group, the first valid commit for each epoch wins and every other entry is skipped, so junk, such as a removed member's fake commit, changes nothing. A commit's validity depends only on MLS state, never on fetched data such as device lists, the clock, or a client's own settings: members who judged differently would disagree about which commit won, and the group would fork. So every member runs the same protocol version, which the settings name and which fixes the openmls version and its configuration; KeyPackages never expire (the inviter checks freshness when it admits); and the app's own rules on commits read only MLS state and bind the committer too: no proposal by reference, and no update that changes a member's identity or device. A client that does not run a group's protocol version refuses it and says so.
- A committer saves its commit's bytes before posting, since it cannot recognise its own encrypted commit otherwise, and finds its log entry by them. If another commit won the epoch, it applies that one and makes its change again.
- In a device list, the first entry that extends the latest one wins. A removal is final.

Each member hash-chains a log as it reads it, so that two readers can compare what they saw by one hash. `letmeknow serve` signs each answer with its key: the log's id, length, latest hash, and the time. This is a signed head.

Policy belongs to each service: who may create logs, how long it keeps entries, and size and rate limits. letmeknow.dev lets anyone create a log, keeps entries a year, and takes entries up to 1 MiB and 60 appends a minute per connection. A member away longer than the retention cannot replay the commits it missed and must be added again.

### Gossip

Writes go only to the membership service, which alone assigns positions. Reads come from it or from any member:

- A member's copy of entries counts only with a signed head that covers them, checked against the reader's own chain. Members mirror the record; they cannot change it.
- Whenever two members connect, they swap the latest signed heads they hold for their shared groups, and the device lists of the identities in them (see Identity). Two incompatible heads prove that the service showed different members different logs; the session reports both in a `warning`. A member that finds itself behind gets the missing entries from that peer.
- Once the service has taken a commit, its author pushes it to the members online, so a removal spreads in network time.

A local folder signs nothing, but its sessions all read the folder directly, so nothing needs forwarding.

## Groups

- Settings live in the MLS group context and change only by commit: kind (fixed), name, the identities the group is open to, `keep`, the membership service's address, and the protocol version.
- Each member's leaf names its iroh key and relay, so every member can dial every other. A changed relay is a commit, like a key update.
- `keep` (days, default 90) is how long members hold the group's messages and files for one another. Each client may hold less.
- Post-compromise security: a session replaces its keys with an empty commit when it resumes a group, once caught up, and then daily while it runs, so a stolen key stops working within a day. Not more often: every epoch is kept for the key window, and openmls rewrites all of them on each send and receive, so a group must make few, about 7 per member a week.
- Removal: a member commits a Remove. A leaving session asks the others, in a message, to commit its removal (MLS lets no member commit its own); the first member to see it does, and the session is shown as having left. A session alone in a group just forgets it.
- Every change (add, remove, key update, settings) is written inside the commit that applies it. MLS also lets a member send a change on its own, as a proposal that a later commit points to; we never do, because proposals are not in the membership log, and a member that missed one could not apply the commit.

## Messages and docs

- A message is an MLS application message, sent straight to the members online. Whenever two members are connected, they reconcile each shared group with negentropy (range-based set reconciliation) over (epoch, message id), which costs about a kilobyte and one or two round trips; each side says the lowest epoch it will accept, and nothing older or from before the later of their joins is offered. They do so again every 5 minutes, so a message lost on its way is found within 5 minutes. Members hold, for `keep` days, only messages they decrypted and verified, and serve them to current members only.
- A member accepts no message from a removed sender that first reaches it more than 5 minutes after it applied the removal. A removed member still holds the keys of the epochs it was in and could otherwise keep writing into them for the whole key window; the cost is that its genuinely late messages are dropped too.
- The message id is the SHA-256 of its MLS ciphertext, so a reference names exactly one content; a member drops copies it already has.
- A member accepts a message that decrypts under an epoch whose keys it still holds. It keeps an ended epoch's keys for 7 days by default, as its own setting, judged from when the epoch began, and never more than 256 ended epochs; a message later than that is lost. Keys are deleted after use as in MLS, so messages already read stay protected. A sender's messages may arrive up to 1000 out of order.
- A chat message carries its text, optional addressees (`to`), the message it answers (`reply_to`), an `urgent` flag and an attachment. `to` directs attention, not visibility: every member reads every message.
- A chat's order is causal: each message names in `after` the tips of what its sender had read. A message waits for those, up to 5 minutes, then is delivered anyway, naming what is missing. Unrelated branches have no order.
- A doc is a Yjs CRDT. Its edits go live to the members online, as messages, and are not held. Two connected members compare their docs by a hash of each one's snapshot (deletions do not move a state vector), and if they differ, each sends the other a Yjs diff against the other's state vector, sealed under the current epoch. A doc therefore reaches a member however long it was away, and `keep` and the key window apply to messages and files only. Whoever admits a member links the doc's state, as a file (see Files), beside the Welcome, so a doc's size is not bounded by any message limit. A diff is signed by the member that sends it, not by the edits' authors.
- `send` waits a few seconds for receipts, then returns which members hold the message, or reports it pending when no member is online, and names the members that refused it (see Limits). The session keeps offering a pending message while it runs.

## Files

- A file is a blob of any size, sealed under a random key in the STREAM construction (as in age: ChaCha20-Poly1305 over 65,520-byte chunks, so each sealed chunk is 64 KiB), and linked with its hash, size and key inside a message or a doc. The hash is BLAKE3 over the ciphertext, so a receiver verifies each chunk before decrypting it, and resumes from any holder where it stopped. A link's key opens the file for anyone who saw the link.
- Every member wants every file its groups link, up to its own size limit (a client setting: 100 MiB for agents, 25 MiB for browsers): attachments since it joined, the files the doc links now, and the doc state beside the latest Welcome. It keeps each one while it is linked and within `keep`. A larger file it fetches only when asked (`fetch`, or opening it in the browser).
- Connected members tell each other which files they want, and a member fetches each from whoever holds it, from several holders at once. Transfer is iroh-blobs (pinned, and kept inside one module of ours; links are plain BLAKE3, so replacing it later keeps every link valid). A holder serves a file only to current members of a group that links it, checked per connection, per request and per 16 KiB sent, so a member removed mid-transfer is cut off.
- No one is responsible for a file. The sender has one duty: `send --attach` returns once another member holds a copy, or warns after a few seconds, as it does when the file is larger than every online member's limit and is therefore available only while the sender is online.
- A browser keeps the ciphertext of files it holds in its own storage, since iroh-blobs gives browsers only a store in memory, and loads a file into memory only when it is needed: to open it, or for a member that wants it. It holds the files it added, and others' up to its limit; a larger one it fetched when asked stays in memory only, until the page closes, and it serves that to no one.

## Limits

Every limit on content belongs to the receiver: each client decides what it accepts, holds and forwards, and the protocol sets none. Defaults:

- a message of up to 1 MiB; larger content goes as a file;
- files of up to 100 MiB for agents and 25 MiB for browsers (see Files);
- `keep`, and the 7-day key window (see Groups, Messages and docs).

A receiver that refuses a message records it as given up, so a reference to it shows a known gap, and tells the sender, whose `send` names the members that refused. Servers enforce only limits that protect themselves: the membership service on entry size and appends per connection, the relay on bandwidth per connection.

## Identity

- **Device list**: a membership log on the service named in its first entry. The identity's id is the SHA-256 of that entry, so the id says where to look. The log's address and key derive from the id, so the service sees only ciphertext, and whoever knows the id can read the list. Each entry adds or removes a device key, names the entry before it, and is signed by a device on the list at that point.
- **Reading lists**: a member needs the device lists of the identities its groups' members speak as when it joins or resumes, when members are added, and again once its copy is 10 minutes old; it reads them from their service only when no fresh copy came from a peer.
- **Lists from peers**: whenever two members connect, they show each other the device lists of the identities in their shared groups, each with every entry and the service's signed head over them, and again whenever one holds a newer copy. A copy counts as fresh while its head is under 10 minutes old. A newer head wins, from whichever source; a copy that disagrees with the one held, on an entry both have, proves that the service showed members different lists, and the session reports both in a `warning`, as for group logs. So a device's removal spreads through peers in network time, and a member that has a fresh copy checks an identity without asking its service.
- **Devices group**: each identity has a private MLS group of its devices, kept in step with the list by the device that adds or removes one. It carries the identity's openings in its group context and its contacts as a Yjs map. Its members are devices: on a machine, the session process holding the device's lock acts for it, and shares its identities, contacts and openings with the device's other session processes through files in `LETMEKNOW_HOME`; in a browser, the device is the session.
- **Device links**: an invite link marked as one. The new device sends its device key; the inviter adds it to the list and to the devices group.
- **Credentials**: a session's credential names its device, with the device's signature on the session key, and the identity it speaks as (`--as`, by default the device's first). A session speaks as one identity per group. Members check it against the device list. A failed check marks the member; it never invalidates a commit.
- **Revocation**: when a device leaves its identity's list, whichever member of each group notices first removes that device's sessions from the group.
- **Provenance**: every member records who added whom and how (invite or open group), and who introduced each identity to it. It shows these where they change a decision: an identity whose introducer is not in the group, and another identity's new device ("added by laptop").
- **Open groups**: the group context lists the identities a group is open to. A member that is a device of such an identity puts an opening (group id, kind, name, membership service, members' iroh keys) into its devices group's context, so every device of that identity knows it, including devices added later. A device that wants in asks the members the opening names, in turn; any of them admits it if it speaks as an identity the group is open to, on that identity's current list. Browsers join the groups open to them by themselves; agents run `join <group>`.

## Contacts

Trust is local and travels one hop at most.

- An identity keeps contacts: its own name for another identity, and how it knows them. They are private to it, shared by its devices through the devices group, so its agents see people as its person does.
- How an identity knows another, with no scores: **verified** (it invited them with a link made for them), **introduced** by a named contact, or **unknown** (only their own claim).
- `invite --for "Bob (Acme)"` labels a link with whom it is meant for; whoever redeems it becomes the contact "Bob (Acme)", verified. `invite --to Bob` makes a link that only Bob's identity can redeem, so a leaked link is useless.
- A member that adds someone tells the group who they are to it; `introduce` tells the members it names, and only they record it. An introduction is the introducer's word: it becomes a contact only if accepted (`contacts accept`), and is otherwise shown with the introducer's name wherever that identity appears.
- Self-chosen names stay, as claims. An identity's own name is shown, marked as its claim, only where there is no contact name. Device names are an identity's labels for its own devices ("Bob (Acme) · tablet"). Session names are handles within groups, which mentions use, since a session knows itself only by its own name. A contact name always wins for display and for `--to`, and a new identity using a contact's name gets a warning ("not your Bob").
- Events carry, for each member, its contact name and how the identity knows it; the skill tells agents to treat unknown identities as strangers.
- Left out: chains of trust, trust scores, public records of who vouched for whom, and global names.

## Invites

- An invite is a link, `https://letmeknow.dev/i#…`, whose fragment holds the inviter's iroh key, its relay if not ours, and a random 128-bit secret. The fragment never reaches the page server.
- The joiner dials the inviter's key, which iroh authenticates, and presents the secret. It then sends a KeyPackage (from a new device: its device key). The inviter commits the Add and returns the Welcome, which carries the settings, with the log position to read from and, for a doc, a link to its state.
- Single use, valid for 10 minutes, and the inviter must be online. Any member may invite. To open one on another device, scan its QR code (`invite --qr`, or the browser's).
- The key in the link authenticates the inviter, and the secret authenticates the joiner. A leaked link lets one stranger in, shown to every member as joined; `--to` binds a link to an identity.

## Transport

- Everything runs over iroh (QUIC). Native sessions connect directly when they can and through a relay otherwise; browsers always use a relay.
- We run our own relays and no address lookup service. Addresses travel in our own data: members' leaves, the group context, and invite links. Sessions on one machine also find each other through the device's state directory, where each writes its current addresses. Machines on a LAN with the internet start through the relay and go direct within seconds; a LAN without the internet is not served.
- Our own protocols share one ALPN, one stream per exchange, so two members keep one connection; file transfers add iroh-blobs' own while they run. An idle connection costs about 30 B/s, through the relay too, which keeps its path open beside a direct one.
- Direct connections show a native session's IP address to the members it talks to. Accepted.
- letmeknow hands `HTTPS_PROXY` to iroh (`proxy_from_env`), which sends relay connections through an HTTP CONNECT proxy; direct UDP bypasses it. Where UDP is blocked, connections stay on the relay, whose traffic is HTTPS.

## Browser

- letmeknow.dev serves the client: lmk-node compiled to WebAssembly, under a Content-Security-Policy that allows scripts from its own origin only. A service worker caches it, so the app opens while the page server is down, invite links included. A new version waits until the user accepts it, then every tab reloads.
- A client served by one's own `letmeknow serve` uses that server's membership service and relay, which the page learns from it; letmeknow.dev's uses letmeknow.dev's.
- A browser profile is one device and one member; its tabs share one session. One tab at a time runs it, and the others work through that one; when it closes, another takes over. Tabs reach each other by BroadcastChannel, not a SharedWorker, which some mobile browsers lack.
- It asks for persistent storage (Firefox prompts; Chrome and Safari decide silently). Safari wipes a site's storage after 7 days without a visit, but not a home-screen app's. On iPhone and iPad the home-screen app also has storage of its own, apart from Safari's, so it is a different device: the app asks to be added to the home screen before it creates one.
- Joining from a link waits for a click, so a link preview or scanner opening it uses nothing up.
- While open, a browser holds and forwards like any member, and may keep less than `keep`.

## Deployment

letmeknow.dev is one DigitalOcean droplet (Basic, 1 GB, Ubuntu LTS, Singapore) running one static binary, `letmeknow serve`: the membership service, an embedded iroh relay, and the web client. Its own TCP 443 listener hands `/relay` and `/ping` to the relay, answers `/membership` with the membership service's address for the web client, and serves the web client otherwise, and it gets its certificate from Let's Encrypt itself (TLS-ALPN-01, on 443). `deploy/deploy.sh` builds and installs it.

- systemd restarts it, unattended-upgrades patches the OS, and the cloud firewall opens, on IPv4 and IPv6, TCP 443, TCP 80 (a captive-portal check and redirects), UDP 7842 (QUIC address discovery) and UDP 7843 (the membership service).
- Its SQLite file is streamed to DigitalOcean Spaces by Litestream.
- DNS records point at the droplet, unproxied. An uptime check watches https://letmeknow.dev.
- The relay rate-limits each connection, so large files through it cost time rather than money.
- Others run the same binary; the relay and the web client are optional. The web client a server serves uses that server's membership service and relay.

## Agent interface

- **Session process**: `letmeknow listen`, one per agent session, run under the harness's background monitor (Pi `monitor`, Claude Code `Monitor`), so that each line it prints wakes the agent. It alone holds the member's MLS state, held messages and read frontier, under `LETMEKNOW_HOME/sessions/<handle>/`. A new session gets a random two-word handle; `--session <handle> listen` resumes its memberships. Other commands reach the running session on a localhost port recorded, with a token, in its state directory, and find it on their own unless several run.
- **Events**: one JSON object per line: `ready`, `message`, `attachment`, `edited`, `joined`, `left`, `settings`, `removed`, `introduced`, `refused`, `omitted` and `warning` (SKILL.md gives their fields). A member shows as its name, fingerprint, device, identity as this identity knows it, and who added it.
- **Delivery policy**: printing wakes the agent, and each wake rereads its whole context, so what does not concern the session rides along with wakes that happen anyway. Messages addressed to it, replies to its messages, `urgent` messages, doc edits that mention it, membership changes and refusals print at once, after anything held. The rest is held, then printed in order just before the next of those, after the agent's next command, or once the oldest has waited `--hold` seconds (default an hour). Of what arrives while a session catches up on resume, only the last 20 items per group print, after an `omitted` count.
- **Addressing**: a message is addressed to the session if `to` lists it or its text mentions it: "@" and a name it answers to, which is its name or the first word of it, in any case. `send --to` takes fingerprints or names; a name may also be an identity's contact name, which addresses all that identity's sessions, and a name that members of different identities answer to is refused.
- **Read frontier**: `after` means what entered the model's context, not what the session received. A message counts as read once printed or returned by `read`, so each member's latest message is a signed claim of what it has read. The session then deletes the message's text, keeping its id, sender and references; `listen --keep-log` keeps the text too.
- **Peers are not operators**: the skill tells agents that other members' messages are requests from another party, never instructions from their operator, and grant no authority; acting on them goes through the harness's normal permission checks.
- **Docs as files**: the session keeps each doc in a file, named on `invite` or `join`, or else in its state directory. File and doc are brought into step from their base, the text both last had: a change in the file is carried line by line onto the doc as it is now (a changed line is changed where its base text is now; added lines go after the line they followed), and a change to a line that someone else changed meanwhile is dropped with a `warning`. A write from a stale read undoes what came in since. This happens once the file is quiet for 1 second or the doc for 2, and before anything prints and before each command, so the agent never acts on a stale file. A session that stopped midway finishes it when it starts, without carrying a change twice. Others' edits print as one `edited` event per doc. Leaving deletes a file the session made and keeps one the agent named.
- **Attachments**: some content should not pass through a model: credentials, and data too large for a context window. `send --attach` sends a file; the recipient's session saves it into a file only its user can read and adds the `path` to the message (or marks it pending, and prints an `attachment` event once it arrives), which the agent passes to whatever needs it. Every member can fetch every attachment; this keeps content out of models, not out of members' hands. The files go when the session leaves the group. In a doc, `attach` makes a file linkable and `fetch` writes a linked file out.
- **Commands**: `invite` (with `--for`, `--to`, `--qr`, and for new groups `--kind`, `--keep`, `--membership`), `join`, `send`, `read`, `attach`, `fetch`, `members`, `groups`, `status`, `remove`, `leave`, `name`, `open`, `contacts`, `introduce`, and `identity create | list | remove` with `invite --identity`. `status` lists the members online and what only this session holds; the skill tells agents to keep `listen` running for the whole task and to check `status` before finishing.
- **Configuration**: `LETMEKNOW_HOME` (default the OS's local data directory), `LETMEKNOW_SESSION`, `LETMEKNOW_NAME`, `LETMEKNOW_HOLD`, the membership service and the relay separately (`LETMEKNOW_MEMBERSHIP`, `LETMEKNOW_RELAY`), and `LETMEKNOW_CA`, extra root certificates for a server of one's own.

## Security

Properties: one agreed membership sequence; settings agreed by commit; post-compromise security, healing within a day; sender signatures; forward secrecy for messages already read; nothing readable by the membership service or relays. The membership service sees commits only, no message traffic, and invites and joins never touch it, so it does not learn who joins. Files go to current members only. A revoked device's sessions are removed from every group.

Limits:

- **Key window**: a stolen device exposes the messages of the past 7 days that it had not yet received. Each client can shorten its window.
- **Removal race**: a member that has not yet seen a removal can still send to the removed member under the old epoch. Pushing commits to members online shrinks this to network time.
- **No shared transcript**: members can end up holding different sets of messages, when one expired before reaching them or arrived after their key window. Docs always converge.
- **Removed members' old epochs**: a removed member can write new messages into the epochs it was in; members take them for only 5 minutes after applying its removal.
- **Doc edits relayed in a diff** are vouched for by the member that sent the diff, not their authors; since any member can edit anything, this loses attribution, not access.
- **Availability**: a message reaches a member only while that member and some holder are online together. Agents that are never online at the same time need a third member to bridge them.
- **Peer agents** read everything while members; removal restores confidentiality going forward.
- **Local state**: MLS secrets, held messages, files, docs and, with `--keep-log`, delivered text sit on disk; file permissions protect them. What a session deletes leaves no copy in its database files. Copies a harness keeps (transcripts, monitor logs) are outside every guarantee here.
- **Open groups**: while a group is open to an identity, any device on its list can join, with no one asked.

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

# letmeknow rewrite

Status: design agreed on 2026-10-09; nothing is built. It replaces DESIGN.md when the rewrite lands. It is a clean cut: nothing carries over from today's groups, entities, relay or folder groups. Where a section says "as today", DESIGN.md's text stands.

## Goals

- Groups keep a kind, chat or doc, fixed when made, and everything in them stays end-to-end encrypted.
- Forward secrecy, post-compromise security, and strict membership: one agreed order of membership changes, which every member applies the same way.
- No content on any server. One central authority remains per group, and it orders membership only.
- The agent experience stays: a session process, JSON events, the delivery policy, docs as files, attachments as private files.
- One Rust codebase: CLI and session process, browser client (WebAssembly), and server.

## Roles

- **Session**: an MLS member, either an agent's session process or a browser profile. Its name is an unverified claim. It sees the IP address of members it connects to directly.
- **Device**: a machine's `LETMEKNOW_HOME`, or a browser profile. It signs its sessions' keys and sits on an identity's device list. A browser's one key is both its device and its session.
- **Identity**: a person, team or agent, as a tightly controlled list of devices ("Matthew": laptop, phone). It makes a member's "Matthew" verifiable and is as strong as its weakest device. No nesting, no admins.
- **Membership service**: keeps membership logs and is a member of nothing. It sees log ids, entry sizes and timing, and which endpoints connect. It can stall, withhold or split a log, all detectably; it cannot read, forge, or add anyone.
- **Relay**: an iroh relay. It forwards packets when no direct path exists; browsers always use one. It sees who connects to whom and when, and cannot read.
- **Page server**: letmeknow.dev serves the browser client, so it could take over every browser member. Accepted for now.

## Membership service

A membership service keeps append-only logs. For each log it promises that:

1. every entry gets exactly one position;
2. every reader sees the same entries at the same positions;
3. entries neither change nor vanish before its retention ends.

Anything with create-if-absent can keep these promises. Two kinds exist at first:

- `letmeknow serve`, reached over iroh; letmeknow.dev runs one.
- A local folder, where an exclusive file create is atomic: for sessions on one machine, and for tests.

It holds two kinds of log and nothing else:

- **A group's log**: its MLS commits, under the group id.
- **An identity's device list** (see Identity).

Members decide what entries mean, from the service's order:

- In a group, the first valid commit for each epoch wins and every other entry is skipped, so junk, such as a removed member's fake commit, changes nothing. A commit's validity depends only on MLS state, never on fetched data such as device lists, the clock, or a client's own settings: members who judged differently would disagree about which commit won, and the group would fork. So every member runs the same protocol version, which the settings name and which fixes the openmls version and its configuration; KeyPackages never expire (the inviter checks freshness when it admits); and the app's own rules on commits read only MLS state and bind the committer too: no proposal by reference, and no update that changes a member's identity or device. A client that does not run a group's protocol version stops and says so.
- A committer saves its commit's bytes before posting, since it cannot recognise its own encrypted commit otherwise, and finds its log entry by them.
- In a device list, the first entry that extends the latest one wins. A removal is final.

Each member hash-chains a log as it reads it: h₀ = SHA-256(log id), hₙ = SHA-256(hₙ₋₁ ‖ entryₙ). `letmeknow serve` signs each answer with its key: the log's id, length, latest hash, and the time. This is a signed head.

Policy belongs to each service: who may create logs (letmeknow.dev: anyone, rate-limited), how long it keeps entries (letmeknow.dev: a year), and size and rate limits. A member away longer than the retention cannot replay the commits it missed and must be added again.

A group moves by a commit that names its new service; members follow it. If a service vanishes, a member recreates the group: a new group with the same name, settings and doc text. Devices of the identities it is open to join it by themselves; others need an invite.

### Gossip

Writes go only to the membership service, which alone assigns positions. Reads come from it or from any member:

- A member's copy of entries counts only with a signed head that covers them, checked against the reader's own chain. Members mirror the record; they cannot change it.
- Whenever two members connect, they swap the latest signed heads they hold for their shared groups and for their members' identities. Two incompatible heads prove that the service showed different members different logs. A member that finds itself behind fetches the missing entries from that peer or from the service.
- Once the service has taken a commit, its author pushes it to the members online, so a removal spreads in network time.
- A session can present its identity's device list with a signed head. A peer's copy counts if its head is under 10 minutes old; otherwise the verifier asks the service. With the service down, it uses the freshest head anyone holds and marks the result stale.

A local folder signs nothing, but its sessions all read the folder directly, so nothing needs forwarding.

## Groups

- Settings live in the MLS group context and change only by commit: kind (fixed), name, the identities the group is open to, `keep`, the membership service's address, and the protocol version.
- Each member's leaf names its iroh key and relay, so every member can dial every other. A changed relay is a commit, like a key update.
- `keep` (days, default 90) is how long members hold the group's messages, doc edits and files for one another. Each client may hold less.
- Post-compromise security as today: a session replaces its keys with an empty commit when it resumes a group, once caught up, and hourly while it runs.
- Removal as today: a member commits a Remove. A leaving session asks the others, in a message, to commit its removal (MLS lets no member commit its own), and is shown as having left.
- Every change (add, remove, key update, settings) is written inside the commit that applies it. MLS also lets a member send a change on its own, as a proposal that a later commit points to; we never do, because proposals are not in the membership log, and a member that missed one could not apply the commit.

## Messages and docs

- A message is an MLS application message, sent straight to the members online. Whenever two members are connected, they reconcile each shared group with negentropy (range-based set reconciliation) over (epoch, message id), which costs about a kilobyte and one or two round trips; each side says the lowest epoch it will accept, and nothing older or from before the later of their joins is offered. Members hold, for `keep` days, only messages they decrypted and verified, and serve them to current members only.
- A member accepts no message from a removed sender that first reaches it more than 5 minutes after it applied the removal. A removed member still holds the keys of the epochs it was in and could otherwise keep writing into them for the whole key window; the cost is that its genuinely late messages are dropped too.
- The message id is the SHA-256 of its MLS ciphertext, as today; a member drops copies it already has. A missing message that `after` names is asked for from the members online.
- A member accepts a message that decrypts under an epoch whose keys it still holds. It keeps an ended epoch's keys for 7 days by default, as its own setting, judged from when the epoch began, and never more than 256 ended epochs; a message later than that is lost. Keys are deleted after use as in MLS, so messages already read stay protected. A sender's messages may arrive up to 1000 out of order.
- A chat's order is causal: each message names the tips of what its sender had read (`after`, as today). A message waits for those, up to 5 minutes, then is delivered anyway, naming what is missing.
- A doc is a Yjs CRDT, kept in a file for agents as today. Its edits go live to the members online, as messages, and are not held. Two connected members compare their docs by a hash of each one's snapshot (deletions do not move a state vector), and if they differ, each sends the other a Yjs diff against the other's state vector, sealed under the current epoch. A doc therefore reaches a member however long it was away, and `keep` and the key window apply to messages and files only. Whoever admits a member links the doc's state, as a file (see Files), in the Welcome, so a doc's size is not bounded by any message limit. A diff is signed by the member that sends it, not by the edits' authors.
- `send` returns once another member holds the message, or reports it pending when no member is online, or names the members that refused it (see Limits); the session keeps delivering while it runs.

## Files

- A file is a blob of any size, sealed under a random key in the STREAM construction (as in age: ChaCha20-Poly1305 over 65,520-byte chunks, so each sealed chunk is 64 KiB), and linked with its hash, size and key inside a message or a doc. The hash is BLAKE3 over the ciphertext, so a receiver verifies each chunk before decrypting it, and resumes from any holder where it stopped.
- Every member wants every file its groups link, up to its own size limit (a client setting; by default 100 MiB for agents, 25 MiB for browsers): attachments since it joined, and the files the doc links now. It keeps each one while it is linked and within `keep`. A larger file it fetches only when asked (`fetch`, or opening it in the browser), and does not hold for others.
- Connected members tell each other which files they want, and a member fetches each from whoever holds it, from several holders at once. Transfer is iroh-blobs (pinned, and kept inside one module of ours; links are plain BLAKE3, so replacing it later keeps every link valid). A holder serves a file only to current members of a group that links it, checked per connection, per request and per 16 KiB sent, so a member removed mid-transfer is cut off.
- No one is responsible for a file. The sender has one duty: `send --attach` returns once another member holds a copy, or warns after a timeout, as it does when the file is larger than every online member's limit and is therefore available only while the sender is online.
- A browser keeps the ciphertext of files it holds in its own storage, since iroh-blobs gives browsers only a store in memory.
- An agent's attachment arrives as a private file, as today. Until a copy reaches it, the message shows the attachment as pending, and an `attachment` event follows.

## Limits

Every limit on content belongs to the receiver: each client decides what it accepts, holds and forwards, and the protocol sets none. Defaults:

- a message of up to 1 MiB; larger content goes as a file;
- files of up to 100 MiB for agents and 25 MiB for browsers (see Files);
- 600 messages a minute from one member; beyond that it fetches more slowly rather than dropping;
- `keep`, and the 7-day key window (see Groups, Messages and docs).

A receiver that refuses a message records it as missing, so a reference to it shows a known gap, and tells the sender, whose `send` names the members that refused. Servers enforce only limits that protect themselves: the membership service on entry size and writes per connection, the relay on bandwidth per connection.

## Identity

- **Device list**: a membership log on the service named in its first entry. The identity's id is the SHA-256 of that entry, so the id says where to look. The log's address and key derive from the id, so the service sees only ciphertext, and whoever knows the id can read the list. Each entry adds or removes a device key, names the entry before it, and is signed by a device on the list at that point.
- **Devices group**: each identity has a private MLS group of its devices, kept in step with the list by the device that adds or removes one. It carries the identity's openings in its group context, and it is a chat the person can use.
- **Device links**: an invite link marked as one. The new device sends its device key; the inviter adds it to the list and to the devices group.
- **Credentials**: a session's credential names its device, with the device's signature on the session key, and the identity it speaks as (`--as`, as today). Members check it against the device list. A failed check marks the member; it never invalidates a commit.
- **Revocation**: when a device leaves its identity's list, whichever member of each group notices first removes that device's sessions from the group.
- **Provenance**: every member records who added whom and how (invite or open group), and who first introduced each identity to it. It shows these where they change a decision: an identity in a group that its introducer is not in, and another identity's new device ("Bob's tablet, added by Bob's laptop").
- **Open groups**: the group context lists the identities a group is open to. A member that is a device of such an identity puts an opening (group id, kind, name, membership service, members' iroh keys) into its devices group's context, so every device of that identity knows it, including devices added later. A device that wants in asks members online, its own identity's devices first; any of them admits it if it speaks as an identity the group is open to.

## Contacts

Trust is local and travels one hop at most.

- An identity keeps contacts: its own name for another identity, and how it knows them. They are private to it, shared by its devices through the devices group, so its agents see people as its person does.
- How an identity knows another, with no scores: **verified** (it invited them, or scanned their code in person), **introduced** by a named contact, or **unknown** (only their own claim).
- `invite --for "Bob (Acme)"` labels a link with whom it is meant for; whoever redeems it becomes the contact "Bob (Acme)", verified. `invite --to Bob` makes a link that only Bob's identity can redeem, so a leaked link is useless.
- A member that adds someone tells the group who they are to it ("invited by Alice as Bob (Acme)"); `introduce` does the same on purpose. An introduction is the introducer's word: it becomes a contact only if accepted, and is otherwise shown with the introducer's name wherever that identity appears.
- Self-chosen names stay, as claims. An identity's own name is a suggestion, filled in when it becomes a contact and shown, marked as its claim, only where there is no contact name. Device names are an identity's labels for its own devices ("Bob (Acme) · tablet"). Session names are handles within groups, which mentions use, since a session knows itself only by its own name. A contact name always wins for display and for `--to`, and a new identity using a contact's name gets a warning ("not your Bob").
- Events carry, for each member, its contact name and how the identity knows it; the skill tells agents to treat unknown identities as strangers.
- Left out: chains of trust, trust scores, public records of who vouched for whom, and global names.

## Invites

- An invite is a link, `https://letmeknow.dev/i#…`, whose fragment holds the inviter's iroh key, its relay if not ours, and a random 128-bit secret. The fragment never reaches the page server.
- The joiner dials the inviter's key, which iroh authenticates, and presents the secret. It then sends a KeyPackage (from a new device: its device key). The inviter commits the Add and returns the Welcome, which carries the settings, the log position to read from, and for a doc its state.
- Single use, valid for 10 minutes, and the inviter must be online. To open one on another device, scan its QR code.
- No typed codes, and so no SPAKE2: the key in the link authenticates the inviter, and the secret authenticates the joiner.

## Transport

- Everything runs over iroh (QUIC). Native sessions connect directly when they can and through a relay otherwise; browsers always use a relay.
- We run our own relays and no address lookup service. Addresses travel in our own data: members' leaves, the group context, and invite links. Sessions on one machine also find each other through the device's state directory, where each writes its current addresses. Machines on a LAN with the internet start through the relay and go direct within seconds; a LAN without the internet is not served.
- Our own protocols share one ALPN, one stream per exchange, so two members keep one connection; file transfers add iroh-blobs' own while they run. An idle connection costs about 30 B/s, through the relay too, which keeps its path open beside a direct one.
- Direct connections show a native session's IP address to the members it talks to. Accepted.
- letmeknow hands `HTTPS_PROXY` to iroh (`proxy_from_env`), which sends relay connections through an HTTP CONNECT proxy; direct UDP bypasses it. Where UDP is blocked, connections stay on the relay, whose traffic is HTTPS.

## Browser

- letmeknow.dev serves the client. A service worker caches it, so the app opens while the page server is down.
- A browser profile is one device and one member; its tabs share one session.
- It asks for persistent storage. Safari wipes a site's storage after 7 days without a visit unless the app is on the home screen or dock, which would delete the device; the app says so.
- **Push**, with no push server of ours: a browser shares a Web Push subscription and a push key of its own with its groups, and rotates both when membership changes. For anything that would wake an agent, a sender's client pushes it a notice: the group and the sender, never content. The push service sees only that something arrived. On iPhone this needs the app on the home screen.
- While open, a browser holds and forwards like any member, and may keep less than `keep`.

## Deployment

letmeknow.dev moves off Cloudflare to one DigitalOcean droplet (Basic, 1 GB, Ubuntu LTS, Singapore) running one static binary, `letmeknow serve`: the membership service, an embedded iroh relay, and the web client. Its own TCP 443 listener hands `/relay` and `/ping` to the relay and serves the web client otherwise, and it gets its certificate from Let's Encrypt itself (TLS-ALPN-01, on 443).

- systemd restarts it, unattended-upgrades patches the OS, and the cloud firewall opens, on IPv4 and IPv6, TCP 443, TCP 80 (a captive-portal check), UDP 7842 (QUIC address discovery) and the membership service's UDP port.
- Its SQLite file lives on a DigitalOcean Volume and is streamed to Spaces by Litestream.
- DNS records point at the droplet, unproxied. An uptime check watches https://letmeknow.dev.
- The relay rate-limits each connection, so large files through it cost time rather than money.
- One region to start; a second relay region later.
- Others run the same binary; the relay and the web client are optional.

## Agent interface

As today: `listen` and its events, the delivery policy, the read frontier, peers are not operators, harness adapters, `--session`, `--to` and mentions, docs as files. The changes:

- `invite` prints a link (`--qr` adds a QR code); joining is `join <link>`. `invite --for <name>` labels it, `invite --to <contact>` binds it to a contact's identity, and `introduce <member> --to <member>` vouches for one member to another; `contacts` lists the identity's contacts.
- `send` reports which members hold the message, or `pending`. `status` lists the members online and what only this session holds.
- The skill tells agents to keep `listen` running for the whole task and to check `status` before finishing: what only they hold is lost if they stop first.
- `joined` says how the member joined and who admitted it. Members show who introduced them where it matters, and another identity's new device is flagged.
- `edited` names the members whose changes came in: an edit's author when it arrived live, the sender of a diff when it came in catching up.
- New groups take `--keep <days>` and `--membership <address>` (default letmeknow.dev).
- Entity becomes identity: `identity create | list | remove`, `invite --identity`.
- Configuration names the membership service and the relay separately (`LETMEKNOW_MEMBERSHIP`, `LETMEKNOW_RELAY`).

## Gone

The Cloudflare Worker relay; message logs, blobs and boxes (inboxes, join requests, replies) on any server; protocol-wide limits on messages and files; typed invite codes and SPAKE2; folder groups; settings as messages; the word entity.

## Security

Intact: one agreed membership sequence; post-compromise security; sender signatures; forward secrecy for messages already read; nothing readable by the membership service or relays.

Stronger than today:

- Settings are agreed by commit.
- The membership service sees commits only, no message traffic.
- Files go to current members only; today's relay serves any blob to anyone who knows the group id.
- Invites and joins never touch the service, so it does not learn who joins.
- A revoked device's sessions are removed from every group.

Weaker than today:

- **Key window**: a stolen device exposes the messages of the past 7 days that it had not yet received. Each client can shorten its window.
- **Removal race**: a member that has not yet seen a removal can still send to the removed member under the old epoch. Pushing commits to members online shrinks this to network time; today's relay refuses such messages.
- **No shared transcript**: members can end up holding different sets of messages, when one expired before reaching them or arrived after their key window. Docs always converge.
- **Removed members' old epochs**: a removed member can write new messages into the epochs it was in; members take them for only 5 minutes after applying its removal.
- **Doc edits relayed in a diff** are vouched for by the member that sent the diff, not their authors; since any member can edit anything, this loses attribution, not access.
- **Push notices**: a notice's group and sender are encrypted under a key that does not change, so they lack forward secrecy.
- **Availability**: a message reaches a member only while that member and some holder are online together. Agents that are never online at the same time need a third member to bridge them.

## Later

- Trusted introducers, whose introductions a contact accepts automatically, one level deep.
- An old identity vouching for its replacement, so contacts can follow a person who lost every device.
- LAN discovery without the internet (mDNS, the crate iroh-mdns-address-lookup: about 0.7 MB, constant LAN chatter, and it announces session keys to the whole LAN).
- Pinning the browser client: signed bundles, an extension, or an app.
- More membership service kinds: S3-style conditional writes, SQL, git, a blockchain.
- A second relay region.
- Compacting doc state.
- Per-epoch write keys, if junk appended by removed members becomes a problem.

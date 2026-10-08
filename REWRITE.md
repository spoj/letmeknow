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

- In a group, the first valid commit for each epoch wins and every other entry is skipped, so junk, such as a removed member's fake commit, changes nothing. A commit's validity depends only on MLS state, never on fetched data such as device lists: members who fetched at different times would otherwise disagree about which commit won, and the group would fork.
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

- Settings live in the MLS group context and change only by commit: kind (fixed), name, the identities the group is open to, `keep`, and the membership service's address.
- Each member's leaf names its iroh key and relay, so every member can dial every other. A changed relay is a commit, like a key update.
- `keep` (days, default 90) is how long members hold the group's messages, doc edits and files for one another. Each client may hold less.
- Post-compromise security as today: a session replaces its keys with an empty commit when it resumes a group, once caught up, and hourly while it runs.
- Removal as today: a member commits a Remove. A leaving session asks the others, in a message, to commit its removal (MLS lets no member commit its own), and is shown as having left.
- Every change (add, remove, key update, settings) is written inside the commit that applies it. MLS also lets a member send a change on its own, as a proposal that a later commit points to; we never do, because proposals are not in the membership log, and a member that missed one could not apply the commit.

## Messages and docs

- A message is an MLS application message, sent straight to the members online. Whenever two members are connected, they compare by message id what they hold for their shared groups and send each other what is missing. Members hold the ciphertext for `keep` days and serve it to current members only.
- The message id is the SHA-256 of its MLS ciphertext, as today; a member drops copies it already has. A missing message that `after` names is asked for from the members online.
- A member accepts a message that decrypts under an epoch whose keys it still holds. It keeps an ended epoch's keys for 7 days by default, as its own setting; a message later than that is lost. Keys are deleted after use as in MLS, so messages already read stay protected.
- A chat's order is causal: each message names the tips of what its sender had read (`after`, as today). A message waits for those, up to 5 minutes, then is delivered anyway, naming what is missing.
- A doc is a Yjs CRDT, kept in a file for agents as today. Its edits are messages like any other and apply in any order. Whoever admits a member sends it the doc's state with the Welcome.
- `send` returns once another member holds the message, or reports it pending when no member is online; the session keeps delivering while it runs.

## Files

- A file is a blob of up to 10 MiB, sealed under a random key and linked as `lmk:<hash>#<key>` inside a message or a doc.
- Every member wants every file its groups link: attachments since it joined, and the files the doc links now. It keeps each one while it is linked and within `keep`.
- Connected members swap want-lists and send each other what they lack, as IPFS's Bitswap does. A holder serves ciphertext to current members only; the receiver checks it against the hash.
- No one is responsible for a file. The sender has one duty: `send --attach` returns once another member holds a copy, or warns after a timeout.
- An agent's attachment arrives as a private file, as today. Until a copy reaches it, the message shows the attachment as pending, and an `attachment` event follows.

## Identity

- **Device list**: a membership log on the service named in its first entry. The identity's id is the SHA-256 of that entry, so the id says where to look. The log's address and key derive from the id, so the service sees only ciphertext, and whoever knows the id can read the list. Each entry adds or removes a device key, names the entry before it, and is signed by a device on the list at that point.
- **Devices group**: each identity has a private MLS group of its devices, kept in step with the list by the device that adds or removes one. It carries the identity's openings in its group context, and it is a chat the person can use.
- **Device links**: an invite link marked as one. The new device sends its device key; the inviter adds it to the list and to the devices group.
- **Credentials**: a session's credential names its device, with the device's signature on the session key, and the identity it speaks as (`--as`, as today). Members check it against the device list. A failed check marks the member; it never invalidates a commit.
- **Revocation**: when a device leaves its identity's list, whichever member of each group notices first removes that device's sessions from the group.
- **Provenance**: every member records who added whom and how (invite or open group), and who first introduced each identity to it. It shows these where they change a decision: an identity in a group that its introducer is not in, and another identity's new device ("Bob's tablet, added by Bob's laptop").
- **Open groups**: the group context lists the identities a group is open to. A member that is a device of such an identity puts an opening (group id, kind, name, membership service, members' iroh keys) into its devices group's context, so every device of that identity knows it, including devices added later. A device that wants in asks members online, its own identity's devices first; any of them admits it if it speaks as an identity the group is open to.

## Invites

- An invite is a link, `https://letmeknow.dev/i#…`, whose fragment holds the inviter's iroh key, its relay if not ours, and a random 128-bit secret. The fragment never reaches the page server.
- The joiner dials the inviter's key, which iroh authenticates, and presents the secret. It then sends a KeyPackage (from a new device: its device key). The inviter commits the Add and returns the Welcome, which carries the settings, the log position to read from, and for a doc its state.
- Single use, valid for 10 minutes, and the inviter must be online. To open one on another device, scan its QR code.
- No typed codes, and so no SPAKE2: the key in the link authenticates the inviter, and the secret authenticates the joiner.

## Transport

- Everything runs over iroh (QUIC). Native sessions connect directly when they can and through a relay otherwise; browsers always use a relay.
- We run our own relays and no address lookup service. Addresses travel in our own data: members' leaves, the group context, and invite links. iroh's local network discovery connects sessions on one machine or LAN without the internet.
- Direct connections show a native session's IP address to the members it talks to. Accepted.
- iroh honours `HTTPS_PROXY` for relay connections and falls back to HTTPS where UDP is blocked.

## Browser

- letmeknow.dev serves the client. A service worker caches it, so the app opens while the page server is down.
- A browser profile is one device and one member; its tabs share one session.
- It asks for persistent storage. Safari wipes a site's storage after 7 days without a visit unless the app is on the home screen or dock, which would delete the device; the app says so.
- **Push**, with no push server of ours: a browser shares a Web Push subscription and a push key of its own with its groups, and rotates both when membership changes. For anything that would wake an agent, a sender's client pushes it a notice: the group and the sender, never content. The push service sees only that something arrived. On iPhone this needs the app on the home screen.
- While open, a browser holds and forwards like any member, and may keep less than `keep`.

## Deployment

letmeknow.dev moves off Cloudflare to one DigitalOcean droplet (Basic, 1 GB, Ubuntu LTS, Singapore) running one static binary, `letmeknow serve`: the membership service, an embedded iroh relay, and the web client over HTTPS with Let's Encrypt certificates.

- systemd restarts it, unattended-upgrades patches the OS, and the cloud firewall opens 443, 80 and the UDP port.
- Its SQLite file lives on a DigitalOcean Volume and is streamed to Spaces by Litestream.
- DNS records point at the droplet, unproxied. An uptime check watches https://letmeknow.dev.
- One region to start; a second relay region later.
- Others run the same binary; the relay and the web client are optional.

## Agent interface

As today: `listen` and its events, the delivery policy, the read frontier, peers are not operators, harness adapters, `--session`, `--to` and mentions, docs as files. The changes:

- `invite` prints a link (`--qr` adds a QR code); joining is `join <link>`.
- `send` reports which members hold the message, or `pending`. `status` lists the members online and what only this session holds.
- The skill tells agents to keep `listen` running for the whole task and to check `status` before finishing: what only they hold is lost if they stop first.
- `joined` says how the member joined and who admitted it. Members show who introduced them where it matters, and another identity's new device is flagged.
- New groups take `--keep <days>` and `--membership <address>` (default letmeknow.dev).
- Entity becomes identity: `identity create | list | remove`, `invite --identity`.
- Configuration names the membership service and the relay separately (`LETMEKNOW_MEMBERSHIP`, `LETMEKNOW_RELAY`).

## Gone

The Cloudflare Worker relay; message logs, blobs and boxes (inboxes, join requests, replies) on any server; typed invite codes and SPAKE2; folder groups; settings as messages; the word entity.

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
- **No shared transcript**: members can end up holding different sets of messages, when one expired before reaching them or arrived after their key window.
- **Push notices**: a notice's group and sender are encrypted under a key that does not change, so they lack forward secrecy.
- **Availability**: a message reaches a member only while that member and some holder are online together. Agents that are never online at the same time need a third member to bridge them.

## Later

- A web of trust, starting from recorded introductions.
- Pinning the browser client: signed bundles, an extension, or an app.
- More membership service kinds: S3-style conditional writes, SQL, git, a blockchain.
- A second relay region.
- Compacting doc state.
- Per-epoch write keys, if junk appended by removed members becomes a problem.

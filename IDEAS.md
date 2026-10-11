# Ideas

Explorations, kept loose on purpose: ideas, questions and the trade-offs seen so far. Designs come later, once more ideas have accumulated and crossed.

## Where we stand

- Peer to peer first; servers minimal. The membership service blindly orders commits and held messages' entries, and nothing else.
- Trust is chosen and visible: whoever a group relies on is in its settings or its member list.

## Kinds

- Built in 0.11 (DESIGN.md, Kinds): kinds compete on a stable core, which never reads their content. Chat is built in; the doc is a plugin, `letmeknow-kind-doc`, and the browser's in-page plugin. Each client supports the kinds it chooses, and lists them in its leaf.
- What a kind reuses, as built: members and identities, held messages in the group log's order, live messages to the members online or to one, files, and a state link for joiners.
- Built in 0.11: git, as `letmeknow-kind-git` with the remote helper `git-remote-lmk`; pushes ordered by the log with bundles as files, chat in the same group, a full bundle as joiners' state, and a display-only in-page plugin in the browser.
- Candidates: other docs, games, voice, job boards for agent teams, polls, a secrets vault, a ledger, broadcast channels (which need roles), whiteboards and tables.

## Docs and CRDTs

- Agents often rewrite large parts of a file, from reads that may be minutes old. A text CRDT keeps every insert, so overlapping rewrites merge silently into duplicates or fragments.
- Agents may be better served by explicit conflicts. Does the CRDT earn its place? Now that kinds compete, a doc kind with explicit conflicts can be tried beside it.

## Voice

- Group voice usually needs a strong node to mix or forward. Here it could be a special member invited into the group, and clients need voice support.
- MLS negotiates (who is in, keys), the iroh address names each participant, and an outside service carries the audio.
- MLS itself is a poor transport for media: per-frame overhead, state churn, and it gets in the way of the group's chat.
- A member that turns speech into text and back could bring agents into calls.

## Members trusted by choice

- Referee, dealer, mixer, transcriber, vote counter, escrow, arbiter: each is invited like anyone, visible in the member list, and removable. It can see what the players cannot.

## Ordering

- Without ordering, groups can do what is safe under concurrency: CRDTs, and turn-based games where only one player can act at a time.
- Every held message is ordered through the service (built in 0.13): each append is a round trip to the service and counts against its rate limit (appends batch), which suits chat and pushes, but not kinds that act many times a second; those use live messages.
- Beyond that, every option is a trade-off:
  - ordering through the membership service;
  - members running their own consensus;
  - a referee;
  - negotiating in MLS and acting outside letmeknow.
- Ordering through the service is like a blockchain: the append is the confirmation, the signed head the receipt, the rate limit the fee. One sequencer cannot be stopped from lying, only caught.
- Members' own consensus is safe without timing guarantees, but makes progress only while a majority is online. Members that may lie need four to tolerate one liar. Chat messages' `read` ranges already say what each sender had seen.
- A leader per group, chosen through the log, could sequence messages, do one-off chores, and keep clocks. There is at most one per claim, but someone leads only while someone online can take over. It remains an idea for frequent kinds, such as games, which the service's order is too slow for.
- With leaders, the service could order only claims and key logs: a leader would sequence its group's commits and anchor its head at the service now and then, so the service would see far less, and a group could change members while the service is unreachable. The cost is failover: a commit the old leader took that the new one never saw forks the group's keys, and the members that applied it must be added again. Who leads must still come from one place.

## Identity as a key

- Built (DESIGN.md, Identity): the devices group is an identity's only membership, its key log lists its devices, each device certifies its sessions with a key of its own, and the certificate travels in the session's credential.

## Identity as a group

For 0.14 (#39); contacts go in 0.13.2 (#40).

- Today an identity is two things kept in step by duties: a key log, public to whoever knows the id, listing device keys; and a devices group, private, holding the identity's keys and openings. Contacts were one identity's names for others, and introductions a member telling a group its name for someone.
- The idea: an identity is a group whose membership is public and whose content is private. A device speaks for X when X's roster lists it. Device links become ordinary invites into X, certificates become proofs of membership, and the key log's duties and the devices kind's special cases may go.
- Members could be keys or identities: Alice speaks for Acme when Acme's roster lists Alice. Teams and companies fall out (Later: entities), and so does a group open to Acme.
- The identity's private content carries what its devices share: openings, notes between one's own devices (#38), which devices are online (#26).
- Questions:
  - Do identities nest, or do organisations stay plain groups?
  - Does anything replace contacts: names only, or sets that groups open to?
  - Is a roster seen only by whoever knows the id, or can identities be found?
  - How does removal reach every group someone speaks in as X, one level up from today's device duty?
  - How do outsiders check a roster without replaying MLS? A signed roster may stay the public face, written from the group's membership rather than beside it.
  - Nesting is a chain of trust, which DESIGN.md leaves out: where does it stop?

## Delivery and history

- Delivery is peer to peer and transitive: every member carries the ciphertexts of its group's counted messages for H, whether or not it can open them, so a message travels A to B to C even if A and C never overlap. Keys are kept for the current and prior epoch only, so a member that comes back after a commit or two gets what the members online in its first seconds carry, and the rest is a known loss, announced to all.
- So the cost of peer to peer is availability, not history: groups of intermittent members (laptops that sleep, phones) may not overlap in time. An always-on member (an agent on a server, a desktop) closes the gap with no new infrastructure.
- History beyond the key window is gone by design, mailbox or not (forward secrecy, and openmls rewrites every kept epoch on each send). Docs and repositories are not bound by it: their state reaches any member however long it was away, so chat is for live coordination and lasting things go in a doc or a repository.
- A mailbox was considered and deferred: an optional service, named in a group's settings, holding ciphertext under per-epoch addresses derived from the MLS exporter, so only that epoch's members can read or write, a removal revokes by itself, and the service cannot tie epochs to a group. It would carry like a member that opens nothing. It sees addresses, sizes, timing and IPs, its retention only helps within the key window, and it needs revocation of its own, since a stolen device's state can derive later epochs' addresses until its sessions are removed. Revisit if phones make overlap too rare; with push, a member could register a token for a content-free wake-up.
- A new device of an identity starts empty, as MLS joiners do; the identity's other devices hold the plaintext and could hand it over through the devices group, as Signal's transfer does.

## Clients

- Built: one client core, lmk-client, that the CLI and the browser share (introductions, openings, member descriptions, plugin hosting), behind one API of requests, responses and events, so a desktop or mobile client is a thin shell: storage, network setup, UI and OS integration.
- Next for the core: its responses are JSON built ad hoc, and the browser's TypeScript types copy them by hand. Typed responses, with the TypeScript generated from them, would make the agents' and the page's contract checked, before a third shell.
- Which protocol capabilities a client exposes is its choice: the protocol and the CLI keep several identities per device (`--as`), while the browser keeps one, and moves to another identity by leaving its own. If several get used, the browser can expose them too.
- The core is built natively per platform; WASM only where a platform forces it (the browser) or for plugins. Raw UDP for iroh's direct paths, processes, SQLite and iOS's lack of JIT all argue against WASM elsewhere.
- Kinds that run as executables cannot run on phones or in the browser. Portable kinds would be libraries linked into each client, and third-party kinds WASM modules speaking the plugin protocol, sandboxed, in every client.
- The core builds for Android (checked in CI). iOS waits on iroh's network monitor: netdev 0.46.3 uses libc's `in6_ifreq`, which libc defines for macOS only.
- Phones suspend apps, and messages move only between members online at once: a phone needs an always-on member of its own, or a push to wake it.

## Testing

- The hard bugs are orderings no one listed. Example tests run one ordering each, with timing left to the OS, so they find such bugs by luck; the deterministic simulation (DESIGN.md, Testing) runs many.
- Model checks of the duties and of repair, over every interleaving of 3 members and 2 devices with crashes, loss and reconnects. The cores without I/O make them possible.

## Case management

- A corporate case is a group: its members are exactly who may see it, the membership log records who could see what when, and the service's signed heads timestamp each event.
- A `case` kind on the kind's log would be a replicated state machine: operations (open, note, assign, transition from one state to another, approve, close) checked by every member against the case's workflow, so a claim is won once and four-eyes approval holds with no trusted server. A register group would number cases by log position and hold queues, with each case's content in its own group.
- Companies would add an always-on records member in every case group, visible to all, for retention and e-discovery, and certify identities with roles so that groups open to a role.

## Transactions

- All-or-nothing among members that cooperate is a classic problem with classic answers.
- Among members that distrust each other, such as two programs exchanging USD for HKD, it is fair exchange. That needs something trusted outside the parties: a decider that holds the assets, or trusted time (for digital goods only).
- Ordering comes with the decider. As a separate service it matters only when trust is spread, or as an auditable record.
- Without atomicity, signed commitments still make cheating provable.

## Smaller

- Relays stay named in commits, not passed around as hints: a member that only reads the log must still find everyone. Prefer sticky relays.

## Later

- Entities: identities whose key log lists member identities; `open <entity>`; their sessions removed when dropped; a home group for openings.
- Re-share of a lost message by members other than its author.
- Blind relay of files: their hashes in `hello`, so a member can carry files it cannot open.
- Idle removal, as an opt-in group setting.
- MLS targeted messages, for one-to-one within a group.
- Configurable plaintext history: how long each client keeps what it opened.
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

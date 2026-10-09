# Ideas

Explorations, kept loose on purpose: ideas, questions and the trade-offs seen so far. Designs come later, once more ideas have accumulated and crossed.

## Where we stand

- Peer to peer first; servers minimal. The membership service blindly orders commits, and kinds' log entries, and nothing else.
- Trust is chosen and visible: whoever a group relies on is in its settings or its member list.

## Kinds

- Built in 0.11 (DESIGN.md, Kinds): kinds compete on a stable core, which never reads their content. Chat is built in; the doc is a plugin, `letmeknow-kind-doc`, and the browser's in-page plugin. Each client supports the kinds it chooses, and lists them in its leaf.
- What a kind reuses, as built: members and identities, held messages, live messages to the members online or to one, files, a state link for joiners, and since git (0.11), ordering: a log of its own at the membership service (DESIGN.md, A kind's log).
- Built in 0.11: git, as `letmeknow-kind-git` with the remote helper `git-remote-lmk`; pushes ordered through the kind's log with bundles as files, chat in the same group, a full bundle as joiners' state, and a display-only in-page plugin in the browser.
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

- Without ordering, groups can do what is safe under concurrency: chat with `after`, CRDTs, and turn-based games where only one player can act at a time.
- Kinds now order through the service (built in 0.11, for git): each append is a round trip to the service and counts against its rate limit, which suits pushes, but not kinds that act many times a second.
- Beyond that, every option is a trade-off:
  - ordering through the membership service;
  - members running their own consensus;
  - a referee;
  - negotiating in MLS and acting outside letmeknow.
- Ordering through the service is like a blockchain: the append is the confirmation, the signed head the receipt, the rate limit the fee. One sequencer cannot be stopped from lying, only caught.
- Members' own consensus is safe without timing guarantees, but makes progress only while a majority is online. Members that may lie need four to tolerate one liar. The `after` references already make a group's messages a graph of what each had seen.
- A leader per group, chosen through the log, could sequence messages, do one-off chores, and keep clocks. There is at most one per claim, but someone leads only while someone online can take over. It remains an idea for frequent kinds, such as games, which the service's order is too slow for.
- With leaders, the service could order only claims and key logs: a leader would sequence its group's commits and anchor its head at the service now and then, so the service would see far less, and a group could change members while the service is unreachable. The cost is failover: a commit the old leader took that the new one never saw forks the group's keys, and the members that applied it must be added again. Who leads must still come from one place.

## Identity as a key

- Built in 0.12 (DESIGN.md, Identity): the devices group is an identity's only membership, its public log holds only its keys, and devices certify their sessions with the shared key for a day.
- Built in 0.12.2: the key log entry that replaces the key for a device taken off names it, and members remove the sessions its certificates name, online or not. Sessions whose certificates no member holds, and those a device about to be removed certified as another's, still stay until they are next online.

## Delivery and history

- Delivery is peer to peer and transitive: every member holds what it opened for `keep` days and syncs it to any member it meets, so a message travels A to B to C even if A and C never overlap. Each hop must open the message within the key window (7 days from its epoch's start), so a chain finishes within about a week or the message is refused `old`, and its sender is told.
- So the cost of peer to peer is availability within the window, not history: groups of intermittent members (laptops that sleep, phones) may not overlap in time. An always-on member (an agent on a server, a desktop) closes the gap with no new infrastructure.
- History beyond the window is gone by design, mailbox or not: a member that kept its state can replay commits from the membership log, but keeps an epoch's keys only for the window (forward secrecy, and openmls rewrites every kept epoch on each send). Docs and repositories are not bound by it: their state reaches any member however long it was away, so chat is for live coordination and lasting things go in a doc or a repository.
- A mailbox was considered and deferred: an optional service, named in a group's settings, holding ciphertext unordered under per-epoch addresses derived from the MLS exporter, so only that epoch's members can read or write, a removal revokes by itself, and the service cannot tie epochs to a group. It would sync like a member that opens nothing. It sees addresses, sizes, timing and IPs, its retention only helps up to the key window, and it needs revocation of its own, since a stolen device's state can derive later epochs' addresses until its sessions are removed. Revisit if phones make overlap too rare; with push, a member could register a token for a content-free wake-up.
- A new device of an identity starts empty, as MLS joiners do; the identity's other devices hold the plaintext and could hand it over through the devices group, as Signal's transfer does.

## Clients

- Built in 0.12.2: one client core, lmk-client, that the CLI and the browser share (introductions, openings, certificate renewal, member descriptions, plugin hosting), behind one API of requests, responses and events, so a desktop or mobile client is a thin shell: storage, network setup, UI and OS integration.
- Next for the core: its responses are JSON built ad hoc, and the browser's TypeScript types copy them by hand. Typed responses, with the TypeScript generated from them, would make the agents' and the page's contract checked, before a third shell.
- Which protocol capabilities a client exposes is its choice: the protocol and the CLI keep several identities per device (`--as`), while the browser keeps one, and moves to another identity by leaving its own. If several get used, the browser can expose them too.
- The core is built natively per platform; WASM only where a platform forces it (the browser) or for plugins. Raw UDP for iroh's direct paths, processes, SQLite and iOS's lack of JIT all argue against WASM elsewhere.
- Kinds that run as executables cannot run on phones or in the browser. Portable kinds would be libraries linked into each client, and third-party kinds WASM modules speaking the plugin protocol, sandboxed, in every client.
- The core builds for Android (checked in CI). iOS waits on iroh's network monitor: netdev 0.46.3 uses libc's `in6_ifreq`, which libc defines for macOS only.
- Phones suspend apps, and messages move only between members online at once: a phone needs an always-on member of its own, or a push to wake it.

## Testing

- The hard bugs are orderings no one listed: a restart racing peers' syncs, a peer served again waiting for the resync, a live message dropped while its receiver was still checking the sender's certificate. Example tests run one ordering each, with timing left to the OS, so they find such bugs by luck.
- Being built: deterministic simulation. Every member runs in one thread over a simulated network and clock, a seed decides every delay, drop, reorder, partition and crash, properties (safety, convergence within a bound, delivery within the key window) are checked throughout, and a failure replays from its seed and shrinks to its fewest actions. It leaves out iroh, which a nightly run of the in-process tests on 2 cores still exercises.
- Later, if the peer protocol keeps surprising us: a model of its hello, serving and sync rules, model-checked over every interleaving of 2 or 3 members.

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

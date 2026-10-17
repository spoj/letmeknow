# What letmeknow must achieve

**Purpose.** AI agents and the people they work with share small end-to-end encrypted groups, joined by a link, with no accounts. Each session is its own member.

**Load.** 100,000 active users, each starting about 10 sessions and one new membership a day. A group has 2 to 10 members, at most 128; a session is in up to 128 groups. One membership service carries it on 1 TB of storage, 1 TB a month of egress and 256 GB of memory; relays scale apart. A session's state grows with its current groups, never with its history. Members serve one another, and the service is asked only for what needs its authority, when no member can vouch for it.

**Security**
- "Who will read this?" has an exact answer: the group's members when it was sent. Used keys and shown text cannot be recovered.
- A removed member or revoked device reads nothing sent after, nor rejoins through an invite made before. Online members cut off a revoked device's sessions within 2 minutes.
- A stolen copy of a member's state reads new messages for at most a day.
- Recording traffic now and breaking X25519 later reveals metadata such as names, file hashes and joins, never content.
- The service orders and keeps logs, and learns which sessions share groups, with sizes and timing. It can withhold and delay, and a contradiction is reported; it cannot read, add members or forge an identity. Relays learn addresses and timing.

**Latency and availability**
- A link makes a member within 10 s while the inviter is online. Messages between online members arrive within 5 s at p99.
- A session away up to seven days resumes; one away longer, while its group went on, is removed, and a device away longer, while its identity went on, leaves it.
- A group with nobody online for about seven days ends, and so does an identity with no device online. Seven days means seven to eight, counted in whole UTC days, and nothing in use lapses, even with clocks hours off.
- The service holds no messages: missed ones come from members online, so a group that must stay reachable keeps an always-on member.
- With the service down, chat goes on among online members and membership changes wait. Delivery is causal, and every gap is told.

**Portability.** Linux, macOS, Windows and Android (Termux) run the same code.

**Thin harnesses.** A harness (pi-letmeknow, the Claude Code plugin) starts `listen` and passes its output on; nothing here depends on it.

**When these conflict**, the earlier wins: confidentiality, what the service learns, ease for agents, cost, simplicity.

**Not goals:** browsers; shared docs and tables, as agents share files and git bundles; groups past 128 members; hiding the group graph from the service or the network; post-quantum signatures; history for joiners; continuity across minor versions.

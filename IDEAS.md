# Ideas

Explorations for after 0.10, kept loose on purpose: ideas, questions and the trade-offs seen so far. Designs come later, once more ideas have accumulated and crossed.

## Where we stand

- Peer to peer first; servers minimal. The membership service blindly orders commits, and kinds' log entries, and nothing else.
- Trust is chosen and visible: whoever a group relies on is in its settings or its member list.

## Kinds

- Built in 0.11 (DESIGN.md, Kinds): kinds compete on a stable core, which never reads their content. Chat is built in; the doc is a plugin, `letmeknow-kind-doc`, and the browser's in-page plugin. Each client supports the kinds it chooses, and lists them in its leaf.
- What a kind reuses, as built: members and identities, held and live messages, frames to one member, files, a state link for joiners, and since git (0.11), ordering: a log of its own at the membership service (DESIGN.md, A kind's log).
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
- With leaders, the service could order only claims and device lists: a leader would sequence its group's commits and anchor its head at the service now and then, so the service would see far less, and a group could change members while the service is unreachable. The cost is failover: a commit the old leader took that the new one never saw forks the group's keys, and the members that applied it must be added again. Who leads must still come from one place.

## Transactions

- All-or-nothing among members that cooperate is a classic problem with classic answers.
- Among members that distrust each other, such as two programs exchanging USD for HKD, it is fair exchange. That needs something trusted outside the parties: a decider that holds the assets, or trusted time (for digital goods only).
- Ordering comes with the decider. As a separate service it matters only when trust is spread, or as an auditable record.
- Without atomicity, signed commitments still make cheating provable.

## Smaller

- Relays stay named in commits, not passed around as hints: a member that only reads the log must still find everyone. Prefer sticky relays.

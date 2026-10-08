# Ideas

Explorations for after 0.10, kept loose on purpose: ideas, questions and the trade-offs seen so far. Designs come later, once more ideas have accumulated and crossed.

## Where we stand

- Peer to peer first; servers minimal. The membership service blindly orders commits and nothing else.
- Trust is chosen and visible: whoever a group relies on is in its settings or its member list.

## Kinds

- Group kinds need not share one model. They can compete: the doc we have, other docs, git.
- Each client supports the kinds it chooses, some built in and others as plugins or extensions.
- What any kind could reuse from letmeknow: members and identities, keys, messages, files, connections to members by their iroh address, and perhaps ordering.
- Candidates: git (messages are like commits), games, voice, job boards for agent teams, polls, a secrets vault, a ledger, broadcast channels (which need roles), whiteboards and tables.

## Docs and CRDTs

- Agents often rewrite large parts of a file, from reads that may be minutes old. A text CRDT keeps every insert, so overlapping rewrites merge silently into duplicates or fragments.
- Agents may be better served by explicit conflicts. Does the CRDT earn its place? If kinds compete, the question answers itself.

## Voice

- Group voice usually needs a strong node to mix or forward. Here it could be a special member invited into the group, and clients need voice support.
- MLS negotiates (who is in, keys), the iroh address names each participant, and an outside service carries the audio.
- MLS itself is a poor transport for media: per-frame overhead, state churn, and it gets in the way of the group's chat.
- A member that turns speech into text and back could bring agents into calls.

## Members trusted by choice

- Referee, dealer, mixer, transcriber, vote counter, escrow, arbiter: each is invited like anyone, visible in the member list, and removable. It can see what the players cannot.

## Ordering

- Without ordering, groups can do what is safe under concurrency: chat with `after`, CRDTs, git, and turn-based games where only one player can act at a time.
- Beyond that, every option is a trade-off:
  - ordering through the membership service;
  - members running their own consensus;
  - a referee;
  - negotiating in MLS and acting outside letmeknow.
- Ordering through the service is like a blockchain: the append is the confirmation, the signed head the receipt, the rate limit the fee. One sequencer cannot be stopped from lying, only caught.
- Members' own consensus is safe without timing guarantees, but makes progress only while a majority is online. Members that may lie need four to tolerate one liar. The `after` references already make a group's messages a graph of what each had seen.
- A leader per group, chosen through the log, could sequence messages, do one-off chores, and keep clocks. There is at most one per claim, but someone leads only while someone online can take over.

## Transactions

- All-or-nothing among members that cooperate is a classic problem with classic answers.
- Among members that distrust each other, such as two programs exchanging USD for HKD, it is fair exchange. That needs something trusted outside the parties: a decider that holds the assets, or trusted time (for digital goods only).
- Ordering comes with the decider. As a separate service it matters only when trust is spread, or as an auditable record.
- Without atomicity, signed commitments still make cheating provable.

## Smaller

- Relays stay named in commits, not passed around as hints: a member that only reads the log must still find everyone. Prefer sticky relays.

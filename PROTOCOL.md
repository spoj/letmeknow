# letmeknow protocol

The exact formats behind DESIGN.md. The crate `lmk-proto` (`crates/proto`) implements the shared shapes; where the two differ, fix one of them.

## Conventions

- Our own structures are JSON, with bytes as unpadded base64url, except where a section gives a binary layout.
- A signature covers an explicit byte string: a context string ending in a NUL byte, then the exact bytes being vouched for. Signers send the bytes they signed, and verifiers check those bytes, so nothing depends on canonical JSON.
- Hashes are SHA-256, keys and signatures Ed25519, except files, which hash with BLAKE3 (see Files).
- On a QUIC stream, every frame is a 4-byte big-endian length, then that many bytes of JSON.

## Connections

- All of our protocols use one ALPN, `letmeknow/1`, so two endpoints keep one connection. Each exchange is a bidirectional stream whose first frame names it: `{"stream": "membership" | "peer" | "invite"}`. File transfers use iroh-blobs' own ALPN.
- Endpoints use iroh's `presets::Minimal` with a relay map holding our relays, and dial `EndpointAddr::new(key).with_relay_url(url)`, from the addresses that leaves, settings and invite links carry. iroh 1.3.0; the browser build enables only `tls-ring`.
- Sessions of one device write their current direct addresses to `LETMEKNOW_HOME/addresses/<iroh key, hex>.json`, as `{"addrs": ["<ip:port>"]}`, and dial each other from there, with no relay needed.
- An invite link that names no relay is reached through letmeknow.dev's.
- The session process calls `proxy_from_env()`.

## Keys

- **Device key**: Ed25519, in `device.json` (CLI) or IndexedDB (browser). It signs its sessions' keys and its identity's device list entries.
- **Session key**: the MLS signature key of one member.
- **iroh key**: each session's iroh endpoint key, separate from its MLS key and named in its leaf. A membership service's iroh key is also its signing key for heads.
- A session's device signature: Ed25519 by the device key over `"letmeknow session v1\0" ‖ session public key`.

## Membership service

### Logs

A log is named by an id: a group's MLS group id, a kind's log id (see Kinds), or a device list's address (see Identity). Positions start at 1. Each member chains a log as it reads it:

- h₀ = SHA-256(`"letmeknow log v1\0"` ‖ log id)
- hₙ = SHA-256(hₙ₋₁ ‖ SHA-256(entryₙ))

### `letmeknow serve`

A client opens one `membership` stream per request and gets one answer, except `subscribe`, which stays open.

| Request | Answer |
|---|---|
| `{"append": {"log", "entry"}}` | `{"position", "head"}`, or `{"refused": reason}` (size, rate, policy) |
| `{"read": {"log", "after"}}` | `{"entries": [...], "head"}`: entries after position `after`, a page at a time; `head` covers the last one returned |
| `{"head": {"log"}}` | `{"head"}` |
| `{"subscribe": {"logs": [...]}}` | a frame `{"log", "position", "entry", "head"}` per new entry, until the stream closes; sending another `subscribe` on it replaces the set |

The first append to an unknown log creates it, if the service's policy allows.

A head is `{"log", "length", "hash", "time", "sig"}`, where `time` is milliseconds since the Unix epoch and `sig` is the service's Ed25519 signature, by its iroh key, over:

`"letmeknow head v1\0"` ‖ u16 length of log id ‖ log id ‖ u64 length ‖ hash (32 bytes) ‖ u64 time

all integers big-endian.

### Local folder

A log is a directory, `<folder>/<log id, hex>/`, holding one file per entry, `<position>.entry`, whose bytes are the entry. To append, a writer creates the file for the position after the last one with an exclusive create (`O_CREAT | O_EXCL`, Rust's `create_new`), and on a clash moves to the next position and tries again. Readers list the directory and read in order; a file notification or a poll every 2 seconds brings news. Heads are not signed; members still compare chains.

### Gossip

Two connected members exchange the newest signed heads they hold for the logs they share (see Peer protocol). A head that a member's own chain contradicts (same length, other hash; or a shorter head that is not a prefix of its chain) is proof: the session reports both heads in a `warning`. A longer head is kept, the longest from each peer, and judged once the member's own chain reaches its length.

## Groups

### Settings

A group context extension, of the private-use type `0xff01`, whose data is JSON:

```json
{"protocol": 1, "kind": "<kind>", "name": "", "open": [{"id": "<identity id>", "name": "Matthew"}], "keep": 90,
 "membership": {"serve": {"key": "<iroh key>", "relay": "<url>", "addrs": ["<ip:port>"]}} | {"folder": "<path>"},
 "devices_of": "<identity id>", "openings": [<opening>], "log": "<16 random bytes>"}
```

`kind` is a kind id (see Kinds): `chat`, `doc`, `git`, or another plugin's. `devices_of` marks an identity's devices group, a chat, and `openings` appear only there (see Identity). `log` is the id of the kind's log (see Kinds), which its creator draws for a group of a plugin's kind; groups made before 0.11 have none, and a 0.10 member that changes the settings drops it. Members list `0xff01` and `0xff02` in their capabilities.

### Leaf data

A leaf node extension, of type `0xff02`, whose data is JSON:

```json
{"key": "<iroh key>", "relay": "<url>", "kinds": ["chat", "doc"]}
```

`kinds` lists the kinds the session supports, `chat` always among them; a leaf without it (0.10) supports `chat` and `doc`. A changed relay or list of kinds is an update commit.

### Credential

An MLS basic credential whose identity bytes are JSON:

```json
{"name": "Builder, Matthew's agent", "device": "<device public key>", "device_sig": "<sig>", "device_name": "laptop",
 "identity": {"id": "<identity id>", "membership": <as in settings>} | null}
```

A member checks `device_sig` and the identity's device list (see Identity) when it first sees the credential and again when either changes. The result marks the member; it never decides whether a commit is valid.

### Commits

- Protocol version 1 fixes: openmls `=0.9.1`; ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY` (commits are PrivateMessages, so the membership service reads nothing); `SenderRatchetConfiguration::new(1000, 100_000)`; KeyPackages built with `Lifetime::init(0, u64::MAX)`, joins with lifetime validation skipped; `RequiredCapabilities` naming `0xff01` and `0xff02`, resent with every settings change, since a GroupContextExtensions proposal replaces the whole list. Settings carry `"protocol": 1`.
- Ended epochs are kept by `max_past_epochs(256)` and dropped by `delete_past_epoch_secrets(PastEpochDeletion::older_than_duration(7 days))`, which dates an epoch by when it began.
- State is stored in SQLite with WAL, `synchronous = NORMAL` and `secure_delete`, encoded as CBOR (ciborium; openmls cannot be read back by bincode). After it deletes secrets or text (a message's text once shown, messages past `keep`, a group it leaves, epochs dropped when it applies a commit or daily), a session checkpoints with `wal_checkpoint(TRUNCATE)`, so that no copy stays in the WAL. The browser stores openmls state in IndexedDB, one record per key, not as one dump.
- Every change is inline in its commit; standalone proposals are never sent, and a commit that refers to one is invalid. So is an update that changes a member's credential identity or device.
- A commit that adds members carries, as its authenticated data, `{"how": "invite" | "open"}`: how they came in, as its committer vouches. It does not bear on the commit's validity.
- A member reads its group's log in order. For the epoch it is in, the first entry that is a valid commit for that epoch is applied; every other entry is skipped.
- A committer saves its commit's bytes, posts them, and merges (`merge_pending_commit`) only if its entry, found by those bytes, is the first valid commit for its epoch; otherwise it clears it (`clear_pending_commit`), applies the winner (`merge_staged_commit`), and redoes its change on the new epoch.
- Once the log has taken a commit, its author sends it to the members online (see Peer protocol).

## Identity

### Device list

- The address of an identity's log is SHA-256(`"letmeknow device list address\0"` ‖ id), and its entries are sealed with ChaCha20-Poly1305 under HKDF-SHA256(ikm = id, info = `"letmeknow device list key"`), each with a random 12-byte nonce in front. The service sees only ciphertext; whoever knows the id can read the list.
- An entry, before sealing, is `{"body": "<bytes>", "sig": "<sig>"}`. `body` is JSON, `{"prev": "<hash of the previous entry's body>" | null, "op": "create" | "add" | "remove", "device": "<key>", "device_name": "", "by": "<signing device key>"}`, plus `"name"` and `"membership"` on `create`. `sig` is by `by` over `"letmeknow device list v1\0"` ‖ body.
- The identity's id is SHA-256 of the first entry's body. A credential names the id and its service; the first entry proves both.
- Valid entries: `create` first, signed by the device it names; then each `prev` names the latest valid entry, and `by` is on the list at that point. A removal is final. Members apply the first valid entry per `prev`, in log order, and skip the rest.
- A member needs the lists of the identities its groups' members speak as, and of each devices group's identity, when it joins or resumes, when members are added, and again once its copy is 10 minutes old. It reads a list from its service (every entry, and the head of the empty page after them) unless it holds a fresh copy: one read from the service within 10 minutes, or a copy a peer presented whose head's `time` is within 10 minutes. Whenever a list it takes has removed a member's device, it commits that member's removal; a member that finds the removal already done drops its own.
- Peers present lists in `hello` (see Peer protocol). A presented list counts only if its head is the signature of the service its `create` entry names, over the log at the identity's address, and chains exactly its entries, from h₀. Of a held copy and another, from a peer or the service: if they differ in an entry both have, the service showed two lists, and the session reports it in a `warning` and keeps its own; else the longer wins, or, if they are as long, the one with the later head. A member that takes a newer copy checks every group's members against it and presents it to the peers of the groups it concerns. Lists on a local folder are not presented, as their heads are unsigned.

### Contacts

An identity's contacts live in its devices group as a Yjs map, named `contacts`, from identity id (unpadded base64url) to `{"name", "how": "verified" | "introduced", "by", "at"}` (`by`: the introducer's identity id). The core syncs it as the doc kind syncs a doc (see Kinds), with the same payloads (`edit`, `diff`) and frames (`doc`, `doc_sv`), and its state linked in the Welcome. A device on several identities writes contacts to its first.

### Devices group

An identity's devices group is a chat whose settings carry `devices_of`. Its members are devices, not sessions: on a machine, whichever session process holds the lock `LETMEKNOW_HOME/device.lock` acts for the device, as a member whose MLS key is the device key, with its own iroh key and its state in `LETMEKNOW_HOME/device.db`. The device's other session processes try the lock every 10 seconds, so one takes over when the holder stops. In a browser, the device is the session.

On a machine, the holder shares the device with its other session processes through two files in `LETMEKNOW_HOME`:

- `device-state.json`: `{"identities": [[<identity ref>, "<name>"]], "contacts": [["<identity id>", <contact>]], "openings": [<opening>]}`, rewritten whenever it changes and by each session process that takes the lock, by writing `device-state.new` and renaming it over the old. `device.json` too is written through a rename, and a devices group in `device.db` whose identity `device.json` lacks, as when a process stopped between joining and saving, puts the identity back. The others read it whenever they need contacts, identities or openings.
- `device-endpoint`: the holder's second command channel (`{"port", "token"}`, a localhost TCP port taking one JSON line `{"token", "request"}` and answering one line, as each session's own `endpoint`). The others send it the requests only the device's node can answer: `identity`, `invite --identity`, `join` with a device link, and two of their own, `{"cmd": "set_contact", "identity", "contact"}` and `{"cmd": "set_opening", "identity", "opening"}`. The holder rewrites `device-state.json` before it answers.

An opening, in its settings: `{"group", "kind", "name", "membership", "members": ["<iroh key>"]}`. A member that is a device of the identity writes it, and refreshes `members` when the group's membership changes.

## Invites

A link is `https://letmeknow.dev/i#<fragment>`, where the fragment is `1.<g|d>.<inviter's iroh key>.<secret>[.<relay>]`: version 1; `g` for a group, `d` for a device link; then the key, a 16-byte random secret and, only if it is not letmeknow.dev's, the relay URL, each in unpadded base64url.

The joiner opens an `invite` stream to the inviter's key and sends `{"secret", "key_package"}`. The inviter refuses a joiner whose KeyPackage's leaf does not list the group's kind. For a device link, the KeyPackage's credential names the new device's key and name, and no identity: the devices group's `devices_of` names it. The inviter checks the secret (single use, 10 minutes), commits the Add (for a device link: appends to the device list and adds the device to the devices group), and answers `{"welcome", "position", "doc", "before"}`: `position` is the log position of the commit that added the joiner, which reads the entries after it and anchors its chain at the first head it reads; `doc` links, as a file (see Files), the state of the group's kind, if its kind gives one (see Kinds), or a devices group's contacts; and `before` lists the ids of the messages the inviter holds from epochs before the joiner's, which the joiner can never get, so that no message waits for them (see Messages). A wrong or used secret gets `{"refused"}`; with 128 bits there is nothing to guess, so it uses nothing up. Neither does a joiner refused by a link made for another identity. For a device link, the new device's MLS key is its device key.

## Messages

The plaintext of an MLS application message is JSON with a `type`. `leave` and `introduce` are the core's; every other type belongs to the group's kind (see Kinds), except in a devices group, whose `edit` and `diff` are its contacts' (see Identity).

| `type` | Fields |
|---|---|
| `leave` | none: the sender asks to be removed; the first member to see it commits the Remove |
| `introduce` | `identity` (`id`, `membership`), `name`, `how` (`invite`, `open`, `introduce`), and optional `to`: who a member is to the sender; sent after the sender adds someone, and by `introduce` |
| `message` | chat's: `content`, `after`, and optional `to`, `reply_to`, `urgent`, `attachment` (below) |

An `introduce`'s `to` lists the members it is for, as a message's `to` does; only they act on it (record the introduction, offer the contact), and the others ignore it. Without `to`, it is for the whole group. Clients before 0.10.1 ignore `to` and act on every introduction.

A chat `message`'s fields: `content`, its text, which may be empty with an attachment; `after`, the ids of the messages the sender had read that no other message it read lists in `after`; `to`, the members it addresses, each as the first 8 bytes of SHA-256 of its session key, or none for the group; `reply_to`, the id of the message it answers; `urgent`, `true` to wake every member; `attachment`, `{"link", "name", "size", "type"}`: a file link (see Files), its name, its size in bytes, and its media type, which may be empty. A chat holds the file an attachment links.

A message's id is SHA-256 of its MLS ciphertext. A payload is held or live. Held are `message` and `leave`, and any payload whose sender marks it so with the MLS message's authenticated data `{"held": true}`; every other payload is live. An entry of a kind's log is marked `{"log": true}` instead (see Kinds); a member refuses a message so marked, and skips an entry not marked. A member holds a held payload for `keep` days, and only once it has decrypted and verified it; a live one it takes and holds not. It takes no message from a removed sender that first reaches it more than 5 minutes after it applied the removal.

## Peer protocol

A `peer` stream joins two sessions that share a group, one stream per pair, kept open while both are online. Either side may send a frame at any time; every frame names its group, and a side serves a group only to a peer whose iroh key is in a leaf of that group's current epoch. Each side sends `hello` when the stream opens and when its state of a group changes; and every 5 minutes it sends `hello` again and syncs each group anew, even if nothing changed, so a message lost on its way is found within 5 minutes.

| Frame | Meaning |
|---|---|
| `{"hello": {"groups": [{"group", "epoch", "head", "floor", "joined", "log"}], "lists": [{"identity", "entries", "head"}]}}` | For each group both are in: the epoch the sender is at, the newest signed head it holds, the lowest epoch it accepts, the epoch it joined, and if it follows the kind's log, the newest signed head it holds of that. `lists`, if any: the device lists of the identities in those groups, each with all its entries and the service's head over them, that the other side has not yet shown or been shown with that head (see Identity) |
| `{"commits": {"group", "entries", "head"}}` | Log entries the other lacks, judged by its head; also sent by a commit's author once the service has taken it |
| `{"reconcile": {"group", "msg"}}` | A negentropy message (see below) |
| `{"messages": {"group", "items"}}` | MLS ciphertexts the other lacks; also every new message as it is sent, to the members online or to one |
| `{"receipt": {"group", "held": ["<id>"], "refused": [{"id", "reason"}]}}` | The answer to `messages`: the ids of the items the receiver took (held, or taken in if live), and of those it refused; items that wait for a commit are not answered |
| `{"<name>": {"group", ...}}` | A frame of the group's kind, to this member: any name but the core's frames here (see Kinds) |
| `{"state": {"group", "link"}}` | A link to a state of the group's kind (see Files) that the sender's kind hands this member, as an inviter does in `admitted`; without `link`, a request for one |
| `{"want": {"group", "files"}}`, `{"have": {"group", "files"}}` | BLAKE3 hashes (see Files) |
| `{"join": {"group", "key_package"}}` | A request to join an open group, answered by `admitted` or `refused` |
| `{"admitted": {"group", "admitted": {"welcome", "position", "doc", "before"}}}`, `{"refused": {"group", "refused"}}` | The answer to `join`, as an invite's |

Clients before 0.10.1 send no `lists` and ignore them, and clients before 0.11 send no `log` and ignore it. A head of a kind's log is judged as a group's is (see Gossip): one that contradicts the member's chain is reported, and a longer one has the member read the log. A side that holds no head for a group yet sends the empty log's: length 0, hash h₀, `time` 0 and no signature, which needs none.

A sender learns from receipts who holds its message, and who refused it; it keeps its message as its own pending send until a receipt says a member holds it, and offers it in every sync meanwhile. A receiver that refuses or cannot open a message keeps its id among those it gave up, so a message naming it in `after` shows a known gap rather than waiting.

Message sync, per group, starts once both sides have caught up on commits. It is negentropy (crate `negentropy` 0.5) over items whose timestamp is the epoch and whose id is the message id, from epoch max(the later `joined`, the lower `floor`). `reconcile` frames alternate until negentropy is done; then `messages` carries what each lacks, never older than the receiver's `floor`, in the order the sender took them, since MLS opens a sender's messages at most 1000 out of order. Ids a member gave up on (beyond its key window) stay in its set, so they are not offered again.

## Files

- A file's key is 32 random bytes. Its ciphertext is the STREAM construction as in age: the plaintext in chunks of 65,520 bytes (the last shorter, and empty only for an empty file), each sealed with ChaCha20-Poly1305 under the key, with the nonce u88 big-endian chunk counter ‖ `0x01` for the last chunk, else `0x00`. Sealed chunks are 64 KiB.
- Its hash is BLAKE3 over the whole ciphertext. A link is `lmk:<hash, hex>.<plaintext size>#<key, hex>`.
- Transfer is iroh-blobs `=0.103.1` on its own ALPN, kept inside one module. A holder admits a connection only from the iroh key of a current member of a group the two share, a request only for a file one of those groups links, and checks again every 16 KiB it sends.
- A member holds, for a group, the files linked within `keep` (those its kind holds, by when it held them: a chat's attachments, by when the message reached it; files it added; states beside Welcomes and in `state` frames), the files its kind links now, and the latest state it handed or took. It serves and wants only those, and deletes every other file it holds once an hour.
- A member asks connected peers with `want`; each answers `have` with those it holds, and the member fetches from several holders at once, resuming where a transfer stopped. A browser keeps the ciphertext in its own storage (IndexedDB), since iroh-blobs keeps only memory there.

## Kinds

A kind id is a plain string: `chat`, built in, or a plugin's, such as `doc` or `git`. The core reads none of a kind's content.

### Channels

What a kind may do in its groups, and nothing else:

- **Held messages**: payloads marked held (see Messages), synced, kept `keep` days, answered by receipts, and pending until another member holds them.
- **Live messages**: payloads to the members online, or to one, not held.
- **Frames to one member**: `{"<name>": {...}}`, sent as the peer frame `{"<name>": {"group", ...}}` to a current member online. A name of the core's frames is refused. Clients before 0.11 close the stream on a frame they do not know, so a kind sends frames only in its own groups, whose members all support it; 0.10 knows the doc's frames, but not `state`.
- **Files**: files it adds, held `keep` days; files it holds `keep` days from when it says, as those a held message links; and the files it links now, held while it does. A member fetches those within its limit.
- **A log**: the group's kind log (below).
- **A state link**: when a member is admitted, the inviter asks its kind for a state and links it in `admitted`'s `doc`; a kind can also hand a member that fell behind a state, which goes as a `state` frame. A member behind its kind's log asks a member online for one with a `state` frame without `link`, at most once a minute, and whenever it syncs with a member while still behind, unless it was handed one in that minute; the member asked hands one if its kind gives one. The member fetches the file and gives it to its kind.

### Logs

A group of a plugin's kind has a log of its own at the group's membership service, named by the settings' `log`. It is chained and signed as a group's log is (see Membership service), and members swap its heads in `hello` (see Peer protocol), but read its entries from the service only.

- An entry is an MLS application message whose plaintext is a payload of the kind, sealed under the epoch current when it is appended, with the authenticated data `{"log": true}`. Before sealing, the appender reads its group's log to its end.
- A member reads the log in order, from where its kind asks, and for each entry: one whose header names an epoch older than that of the last entry taken is skipped; one that is this session's own (it keeps each payload it appends, by SHA-256 of the ciphertext, until its entry is read) is taken; one whose epoch this session has not reached is skipped once the group's log is read to its end; one that opens and is marked is taken; one under an epoch whose keys this session does not hold leaves it behind; any other is skipped. Entries are opened once; the session keeps those taken until its kind asks to read past them.
- A read the service refuses as `expired` leaves the member behind too. A member behind reads no further until its kind asks to read from a later position, as from a state it was handed.

### Plugins

### Plugins

A native session finds a kind's plugin as the executable `letmeknow-kind-<kind>` (`.exe` on Windows) in the directory of its own executable, then in each directory of `PATH`; the first found wins. Its leaf lists `chat` and every kind it found. It starts a plugin when it has a group of its kind (when it starts, makes one or joins one) or a command for it, with stdin and stdout piped and stderr its own, and stops it with itself; one that stops, it starts again and tells it its groups.

They speak JSON lines: one JSON object per line, each way. Bytes are unpadded base64url, and so are group ids; message ids are hex. A member is described as `listen` events describe it (`name`, `fp`, `device`, `identity`, `added_by`, `you`), and named by its `fp` in `to`. A message with an `id` is a request: the other side answers `{"type": "answer", "id", "answer"}`, or `{"type": "answer", "id", "error"}`. A plugin hears only of its kind's groups, and the session refuses what it asks of others.

The session sends:

| Message | Meaning |
|---|---|
| `{"type": "start", "id", "kind", "dir"}` | The first line, a request. `dir` is the plugin's own state directory, `sessions/<handle>/kinds/<kind>/`. Answered `{}`, or `{"chat": true}` if the kind's groups carry chat too: then their `message` payloads are the session's chat, which `send` sends there, and do not reach the plugin |
| `{"type": "group", "group", "settings", "me"}`, and optionally `id`, `command`, `args`, `cwd`, `import` | The session is in a group of the kind: for each when the plugin starts, and when the session makes one (`command`: `invite`) or joins one (`join`), with the command's arguments for the kind and the directory they are relative to, as a request. `me` is this session as the group's members see it. `import`: a doc 0.10 kept (see Doc). A session whose plugin refuses a group it makes or joins leaves it |
| `{"type": "gone", "group"}` | The session left the group, or was removed |
| `{"type": "message", "group", "from", "payload", "held"}`, and `id` if held | A payload of the kind from a member |
| `{"type": "frame", "group", "from", "frame"}` | A frame from a member, `{"<name>": {...}}` |
| `{"type": "synced", "group", "member"}` | The session and a connected member hold the same log of the group: a time to compare state |
| `{"type": "state", "group", "from", "data"}` | A state `from` handed this session, beside the Welcome that admitted it or in a `state` frame |
| `{"type": "snapshot", "id", "group"}` | A member is being admitted, or asks for a state: answered `{"data"}` to hand it one, or `{}`. The session waits 10 seconds |
| `{"type": "entry", "group", "position", "epoch", "from", "payload"}` | An entry of the kind's log taken, in log order, with the epoch it was sealed under |
| `{"type": "command", "id", "args", "cwd"}` | `letmeknow <kind> <args>...`, run in `cwd`: the answer is what the command prints. The session goes on meanwhile |
| `{"type": "sync", "id"}` | Bring into step what the plugin keeps outside letmeknow, such as a doc's file: asked before the session prints anything and before each command, which wait for the answer |
| `{"type": "printed", "group", "key"}` | The plugin's event with this `key` was printed |

The plugin sends:

| Message | Meaning |
|---|---|
| `{"type": "send", "group", "payload"}`, and optionally `held`, `to`, `id` | Seals and sends a payload of the kind. With `held: true` it is held, and a request is answered `{"id", "held_by", "refused", "pending"}` once the receipts came in, or after 5 seconds; otherwise it is live, to the member `to` or to every member online |
| `{"type": "frame", "group", "to", "frame"}` | A frame to one member |
| `{"type": "add", "id", "group", "data"}` | Seals a file, held for the group: answered `{"link"}` |
| `{"type": "hold", "group", "links"}` | Holds files for `keep` days from now, unless held already, as those a held message links |
| `{"type": "links", "group", "links"}` | The files the kind links now, which replace those it linked before |
| `{"type": "fetch", "id", "group", "link"}` | A file the group holds: answered `{"data"}` once it is here, fetched from the members online, or with an error after a minute |
| `{"type": "state", "group", "to", "data"}` | Hands a member a state |
| `{"type": "log", "group"}`, and optionally `after`, `epoch` | Follows the kind's log after position `after`, whose last entry taken was sealed under `epoch`, as the kind's own state stands: entries come as `entry`, the ones the session keeps after `after` first, and those up to `after` go. Without `after`, the kind has no state yet, and the session asks a member for one. A position before one the kind named earlier leaves the session behind |
| `{"type": "append", "id", "group", "payload"}` | Appends to the kind's log: answered `{"position"}` once every entry up to it was handed as `entry`, its own among them unless it was skipped. Refused while the session is behind, and as the service refuses (`size`, `rate`) |
| `{"type": "spread", "id", "group", "link"}` | Waits until a member online holds a file whole, up to 30 seconds: answered `{"held_by"}`, at once with none if no member is online |
| `{"type": "event", "group", "event"}`, and optionally `wake`, `key` | For `listen`, which prints `event` with the group's id in `group`: by the delivery policy at once with `wake: true`, held otherwise. An event of type `warning` prints at once, as the session's own. With `key`, it replaces a held event of the plugin's for the group with the same key, and is told as `printed` |
| `{"type": "info", "group", "info"}` | Fields `groups` shows for the group |

The browser's in-page plugins speak the same messages, as JSON values, without `start`, `me` and `cwd`, and with no `spread`; the page sends their commands (`Lmk.command(kind, args)`), and gets their events as `{...event, "group", "kind"}`.

### Git

The git kind's plugin is `letmeknow-kind-git`, with git's remote helper `git-remote-lmk` beside it; in the browser, `lmk_kind_git::Page` runs in the page, display-only. Its groups carry chat (`start` answers `{"chat": true}`).

- A push is the log entry `{"type": "push", "ref", "old", "new", "bundle", "subjects"}`: the full ref name, the old and new commit ids (hex), each null for a branch created or deleted, the file link of a git bundle of the new commits, or null if they need none, and their subjects, newest first, at most 50. Ahead of it, the pusher adds the bundle as a file and sends the members online the live payload `{"type": "bundle", "link"}`, which they hold; it appends only once `spread` names a member that holds it.
- A member replays the pushes in log order over its branches: a push counts if `old` is its ref's tip (none, for one created), and then moves the ref to `new` or deletes it. A member checks each push in log order: it unbundles the bundle into its repository (`git bundle unbundle`, which needs the bundle's prerequisites), and the push is void if that fails, or `new` is not a commit there, or `old` is not its ancestor (`git merge-base --is-ancestor`). Void pushes are left out of the replay. The repository's refs are the branches replayed as far as every push is checked; a push must build on the branches replayed counting those not checked yet. A pusher's push won if it counted when its entry was taken.
- Its state, given on `snapshot` and taken on `state`, is JSON, `{"position", "epoch", "refs", "bundle"}`: the log position and epoch as far as every push is checked, the branches there (`{"<ref>": "<commit>"}`), and the file link of a bundle of all their commits (`git bundle create` of every ref), or null if there are none. A member takes a state no older than the last entry it took, fetches its bundle and unbundles it, and follows the log after `position`.
- Its event is `pushed` (`by`, `ref`, `old`, `new`, `subjects`), for a push of another member that counted when its entry was taken, not waking. `info` gives `remote`, `lmk::<group>`, as `group`'s answer does on `invite` and `join`.
- Its commands are git-remote-lmk's: `git list <group> [--push]`, answered `{"refs", "head", "repo"}` (the branches as checked, or with `--push` counting those not checked yet; the ref `HEAD` names, `refs/heads/main` if there is one; the repository's path), and `git push <group> <ref> <old> <new> <bundle> [<subject>...]`, with `-` for none and a bundle's path, answered `{"position"}`, or the error `fetch first` if `old` is not the tip or its entry did not count. `<group>` is a group's id or name.
- `git-remote-lmk` (gitremote-helpers(7)) is git's helper for `lmk::<group>`. It finds `letmeknow` beside its own executable, then on PATH, and runs `letmeknow git list` and `letmeknow git push` against the session `LETMEKNOW_SESSION` names, or the one running. It has the capabilities `fetch`, `push` and `option` (only `force-if-includes`, which git requires and which matters only for force pushes). It fetches from the plugin's repository (`git fetch --no-write-fetch-head`), refuses a force push, and bundles a push as `<src> --not` the group's branches it has.
- The plugin keeps, in `dir`, each group's bare repository, `repos/<group>.git`, and its branches and the pushes not yet checked, `<group>.json`. In the browser, it keeps them in the record `kind/git/<group>`, takes every push as checked, holds no file, answers `snapshot` with `{}`, and has no commands.

### Doc

The doc kind's plugin is `letmeknow-kind-doc`; in the browser, the same Rust (`lmk_kind_doc::Page`) runs in the page.

- A doc is a Yjs document whose text is named `text`. Its payloads are live: `{"type": "edit", "update"}`, an edit to the members online, and `{"type": "diff", "update"}`, a diff to one member; both are Yjs v1 updates.
- On `synced`, it sends the member the frame `{"doc": {"snapshot"}}`, SHA-256 of `txn.snapshot().encode_v1()`. A member whose snapshot differs answers `{"doc_sv": {"sv"}}`, its Yjs state vector, which is answered by a `diff`.
- Its state, given on `snapshot` and taken on `state`, is the whole Yjs document as a v1 update. Its `links` are the `lmk:` links in its text.
- `invite --kind doc [<file>]` and `join <link> [<file>]` pass the doc's file as `args`; a joined doc's file must not exist. `doc attach [--group <doc>] <path>` adds a file and answers `{"link", "markdown"}`. Its event is `edited` (`file`, `by`, `lines`, `direct`; key `edited`, waking when `direct`), and `info` gives `file`.
- The plugin keeps, in `dir`, each doc's state (`<group>.yjs`) and its file's binding (`<group>.json`: `{"path", "base", "made", "carrying"}`, `carrying` the file's text and the edit on their way onto the doc, or null), and the files it makes in `docs/`. In the browser, its commands are `state <group>` (answered `{"state"}`), `diff <group> <state vector>` (`{"diff"}`) and `edit <group> <update>`, and it keeps each doc's state in the record `kind/doc/<group>`.
- 0.10 kept a doc's Yjs state in lmk-node's record `node/doc/<group id>` (raw bytes), and natively its file in `session.db`'s tables `bindings` (`gid`, `path`, `base`) and `carrying` (`gid`, `file`, `edit`; 0.10.0 has none). The session and the page hand such a doc to the plugin as `group`'s `import`, `{"state", "path", "base", "made", "carrying"}` (`made`: the file is in the session's `docs/`), as a request; the plugin takes it unless it keeps the doc already, and once it answers, the old records go, and the tables once empty.

## Browser

- The client is lmk-node compiled to WebAssembly (`crates/web`), with a device key that is also its MLS key, so its credential's `device` is its own key. Its iroh key is separate, as natively, and it reaches every peer and membership service through relays.
- Its records live in an IndexedDB database `lmk`. The store `records` holds the `Provider`'s, one record per key: openmls's own keys, and ours under `lmk/` (lmk-node's `node/…` and `session`, the client's `web/…`: its device, name, and each group's timeline, refusals and settings as last seen, and the in-page plugins' `kind/doc/<group id, base64url>`, each doc's Yjs state, and `kind/git/<group id, base64url>`, each git group's branches). A git group's timeline holds its pushes beside its changes. The page writes the records that changed every second and after each action. The store `files` holds the ciphertext of each file it holds, by BLAKE3 hash (hex): the files it adds, and those it fetches up to 25 MiB, which it takes without being asked. The page reads only their hashes when it opens; the session loads a file into iroh-blobs' memory store when it reads it, or when a member's `want` names it. It answers `have` only for files in this store, so a larger file fetched when asked, which stays in memory only, is served to no one. When the page opens and once an hour, it deletes the files no group links, by the rule in Files.
- Its membership service is the one `letmeknow serve` names at `GET /membership`, as text, `<iroh key, hex>@<relay URL>`, on the server the page came from; its relay is that address's relay URL. `localStorage` can name others, as tests do: `lmk relay` (a URL) and `lmk membership` (the same form). The service worker caches `/membership` with the build's files.
- The page serves `/i` as the app, which reads the invite from the fragment.
- A service worker caches exactly the files of one build, under a name derived from their contents, and serves navigations with its `index.html`. A new build installs beside it and waits; the page offers it, and on acceptance tells it `"skip"`, and every tab the old one served reloads.
- One tab at a time runs the session, holding the Web Lock `letmeknow`; every other tab waits for the lock, and meanwhile calls the session over the BroadcastChannel `letmeknow`. A call is `{"id", "method", "args"}`, a method of the WebAssembly's `Lmk` (or `open`, which starts a new session with a name and a device name), answered by `{"id", "result"}` or `{"id", "error"}`. The running tab posts each event as `{"event"}`, and `{"ready": true}` once the session runs and whenever a tab posts `{"ask": true}`. A tab sends its unanswered calls again on each `ready`, and the running tab answers each call id once. When the running tab closes, the next tab takes the lock and runs the session from IndexedDB.

Push notifications are deferred (see DESIGN.md, Later).

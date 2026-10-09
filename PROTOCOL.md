# letmeknow protocol

The exact formats behind DESIGN.md. The crate `lmk-proto` (`crates/proto`) implements the shared shapes; where the two differ, fix one of them.

## Conventions

- Our own structures are JSON, with bytes as unpadded base64url, except where a section gives a binary layout.
- A signature covers an explicit byte string: a context string ending in a NUL byte, then the exact bytes being vouched for. Signers send the bytes they signed, and verifiers check those bytes, so nothing depends on canonical JSON.
- Hashes are SHA-256, keys and signatures Ed25519, except files, which hash with BLAKE3 (see Files).
- On a QUIC stream, every frame is a 4-byte big-endian length, then that many bytes of JSON.

### Compatibility

Releases of one minor version (0.12.x) run side by side: each adds only what the others can ignore, and a breaking change waits for the next minor version. Every reader and writer follows these rules.

- **Unknown input**: readers ignore fields they do not know, and skip what they cannot parse (a frame, a payload, a log entry, a subscription notice, a plugin's line) without closing a stream over it.
- **Growing enums**: an enum whose values may grow parses an unknown value to a catch-all where the value is advisory: a refusal's `reason`, the `how` of an introduction, of a commit's authenticated data and of a contact. Where it is not, the error says a newer letmeknow made it: a membership service of a kind it does not know is kept as it is, and fails so when used.
- **Shared records**: whoever rewrites a shared record keeps the fields it does not know: a group's settings, with the identities and the service in them, and a devices group's state, with its contacts and openings, which a device hands on and refreshes.
- **Revisions**: a leaf names its session's protocol revision (see Leaf data), a number that grows with each compatible addition; a leaf without one is revision 0. A session uses what a revision added only toward members whose leaves name that revision or a later one; their leaves are in the group's state even while they are offline. A session whose leaf differs from what it would write now (revision, kinds, relay) updates it as it starts (see Leaf data).
- **Unknown requests**: the membership service answers a request it does not know with `{"refused": "unknown request"}`; the session and plugins answer a plugin message with an `id` and a `type` they do not know with an error.
- **Breaking changes** happen only through these switches: the ALPN (`letmeknow/1`), a group's `protocol` (2, see Commits), the invite link version (2, see Invites), the home's `format` (2) and IndexedDB's version (2, see Connections).

| Revision | Release | Added |
|---|---|---|
| 0 | 0.12.1 | (leaves name no revision) |
| 1 | 0.12.2 | leaves' `revision`; `hello`'s `anew`; key log entries' `revoked`; certificates' `device_key`; a joiner's `hello` of the group it joined, and messages held for a peer until its `hello` shows their group; an update that renames its member (see Commits); `introduce` marked held (see Invites) |

## Connections

- All of our protocols use one ALPN, `letmeknow/1`, so two endpoints keep one connection. Each exchange is a bidirectional stream whose first frame names it: `{"stream": "membership" | "peer"}`. File transfers use iroh-blobs' own ALPN.
- Endpoints use iroh's `presets::Minimal` with a relay map holding our relays, and dial `EndpointAddr::new(key).with_relay_url(url)`, from the addresses that leaves, settings and invite links carry. iroh 1.3.0; the browser build enables only `tls-ring`.
- Sessions of one device write their current direct addresses to `LETMEKNOW_HOME/addresses/<iroh key, hex>.json`, as `{"addrs": ["<ip:port>"]}`, and dial each other from there, with no relay needed.
- A member an invite link names without a relay is reached through letmeknow.dev's.
- The session process calls `proxy_from_env()`.
- `LETMEKNOW_HOME/format` holds `2`, the layout of the state kept there; a session refuses a home that holds state without it. The browser keeps its state in IndexedDB `lmk`, version 2.

## Keys

- **Device key**: Ed25519, in `device.json` (CLI) or IndexedDB (browser): the device's MLS key in its identities' devices groups, and nothing else.
- **Session key**: the MLS signature key of one member.
- **Identity key**: Ed25519, an identity's, shared by its devices through its devices group and replaced from time to time. It signs its key log's next entry and its devices' sessions' certificates.
- **iroh key**: each session's iroh endpoint key, separate from its MLS key and named in its leaf. A membership service's iroh key is also its signing key for heads.

## Membership service

### Logs

A log is named by an id: a group's MLS group id, a kind's log id (see Kinds), or a key log's address (see Identity). Positions start at 1. Each member chains a log as it reads it:

- h₀ = SHA-256(`"letmeknow log v1\0"` ‖ log id)
- hₙ = SHA-256(hₙ₋₁ ‖ SHA-256(entryₙ))

A member holds every log alike: it reads it from its service from the position after the last it holds, page by page, follows it by `subscribe` (a group's log and its kind's), reading it again every 5 minutes, since a read sent after a `subscribe` may reach the service first and miss an entry appended in between, or reads it again when it needs it (a key log), holds each entry, and keeps the chain over what it holds, anchored at the first head it reads when it starts past position 0, as a joiner does. Only once an entry is held does the log's type read it: a group's applies commits (see Groups), a kind's takes held messages (see Kinds), a key log's replays the identity's keys (see Identity).

### `letmeknow serve`

A client opens one `membership` stream per request and gets one answer, except `subscribe`, which stays open.

| Request | Answer |
|---|---|
| `{"append": {"log", "entry"}}` | `{"position", "head"}`, or `{"refused": reason}` (size, rate, policy) |
| `{"read": {"log", "after"}}` | `{"entries": [...], "head"}`: entries after position `after`, a page at a time; `head` covers the last one returned |
| `{"head": {"log"}}` | `{"head"}` |
| `{"subscribe": {"logs": [...]}}` | a frame `{"log", "position", "entry", "head"}` per new entry, until the stream closes; sending another `subscribe` on it replaces the set |

The first append to an unknown log creates it, if the service's policy allows. A request the service does not know is answered `{"refused": "unknown request"}`; on a subscription, it is skipped, as a client skips a frame it does not know.

A head is `{"log", "length", "hash", "time", "sig"}`, where `time` is milliseconds since the Unix epoch and `sig` is the service's Ed25519 signature, by its iroh key, over:

`"letmeknow head v1\0"` ‖ u16 length of log id ‖ log id ‖ u64 length ‖ hash (32 bytes) ‖ u64 time

all integers big-endian.

### Local folder

A log is a directory, `<folder>/<log id, hex>/`, holding one file per entry, `<position>.entry`, whose bytes are the entry. To append, a writer creates the file for the position after the last one with an exclusive create (`O_CREAT | O_EXCL`, Rust's `create_new`), and on a clash moves to the next position and tries again. Readers list the directory and read in order; a file notification or a poll every 2 seconds brings news. Heads are not signed; members still compare chains.

### Gossip

Two connected members exchange the newest signed heads they hold of the logs they share: those of the groups both are in, of those groups' kinds, and the key logs of the identities their members speak as, as far as each follows them (see Peer protocol). A head counts only if the log's service signed it; a folder's need not be. A head that a member's own chain contradicts (same length, other hash; or a shorter head that is not a prefix of its chain) is proof: the session reports both heads in a `warning`, as it does when the service's own answer contradicts its chain. A longer head is kept, the longest from each peer, and judged once the member's own chain reaches its length. A member whose head is longer than the one a peer showed sends it the entries it lacks, and a member whose copy of a log grew shows its peers the new head.

## Groups

### Settings

A group context extension, of the private-use type `0xff01`, whose data is JSON:

```json
{"protocol": 2, "kind": "<kind>", "name": "", "open": [{"id": "<identity id>", "name": "Matthew"}], "keep": 90,
 "membership": {"serve": {"key": "<iroh key>", "relay": "<url>", "addrs": ["<ip:port>"]}} | {"folder": "<path>"}}
```

`kind` is a kind id (see Kinds): `chat`, `devices` (an identity's devices group, see Identity), `doc`, `git`, or another plugin's. Members list `0xff01` and `0xff02` in their capabilities.

### Leaf data

A leaf node extension, of type `0xff02`, whose data is JSON:

```json
{"key": "<iroh key>", "relay": "<url>", "kinds": ["chat", "doc"], "revision": 1}
```

`kinds` lists the kinds the session supports, `chat` always among them; `revision` is the session's protocol revision (see Compatibility). A session's leaf changes by an update commit: the key update it commits for each group as it starts carries its leaf as it would write it now.

### Credential

An MLS basic credential whose identity bytes are JSON:

```json
{"name": "Builder, Matthew's agent", "key": "<the member's MLS signature key>",
 "identity": {"id": "<identity id>", "membership": <as in settings>} | null}
```

`key` must be the leaf's own signature key: a KeyPackage or an Add whose credential names another is invalid. The identity a member speaks as is proved by a certificate (see Identity), which a member checks when it first sees the credential and again when the certificate or the identity's key changes. The result marks the member; it never decides whether a commit is valid. A devices group's members are devices, whose credentials name no identity, and the device's name (see Devices group).

### Commits

- Protocol version 2 fixes: openmls `=0.9.1`; ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY` (commits are PrivateMessages, so the membership service reads nothing); `SenderRatchetConfiguration::new(1000, 100_000)`; KeyPackages built with `Lifetime::init(0, u64::MAX)`, joins with lifetime validation skipped; `RequiredCapabilities` naming `0xff01` and `0xff02`, resent with every settings change, since a GroupContextExtensions proposal replaces the whole list. Settings carry `"protocol": 2`.
- Ended epochs are kept by `max_past_epochs(256)` and dropped by `delete_past_epoch_secrets(PastEpochDeletion::older_than_duration(7 days))`, which dates an epoch by when it began at this member: when it applied the commit that started it. A member catching up after a week or more away therefore keeps the keys of the epochs it applies for 7 days from then, however long ago they began for the others, which weakens forward secrecy for it meanwhile.
- State is stored in SQLite with WAL, `synchronous = NORMAL` and `secure_delete`, encoded as CBOR (ciborium; openmls cannot be read back by bincode). After it deletes secrets or text (a message's text once shown, messages past `keep`, a group it leaves, epochs dropped when it applies a commit or daily), a session checkpoints with `wal_checkpoint(TRUNCATE)`, so that no copy stays in the WAL. The browser stores openmls state in IndexedDB, one record per key, not as one dump.
- Every change is inline in its commit; standalone proposals are never sent, and a commit that refers to one is invalid. So is an update that changes a member's credential, but for one that changes only its `name` in a group whose members' leaves, in the epoch it commits in, all name revision 1 or later. A 0.12.1 member refuses every change, so no member makes one while a leaf names an earlier revision.
- A commit carries, as its authenticated data, JSON: one that adds members `{"how": "invite" | "open", "invite": "<SHA-256 of the invite's secret>"}`, how they came in, as its committer vouches, and for an invite which one (see Invites); one that removes members in a group with a kind's log `{"end": <position>}`, where that log ends (see Kinds). It does not bear on the commit's validity.
- A member reads its group's log in order. For the epoch it is in, the first entry that is a valid commit for that epoch is applied; every other entry is skipped.
- A committer saves its commit's bytes, posts them, and merges (`merge_pending_commit`) only if its entry, found by those bytes, is the first valid commit for its epoch; otherwise it clears it (`clear_pending_commit`), applies the winner (`merge_staged_commit`), and redoes its change on the new epoch.
- Once the log has taken a commit, its author shows the members online its new head, and they take the entry from it (see Peer protocol).

## Identity

### Key log

- An identity's public record is its key log: each of its keys in turn, each signed by the one before. The log's address is SHA-256(`"letmeknow identity address\0"` ‖ id), and its entries are sealed with ChaCha20-Poly1305 under HKDF-SHA256(ikm = id, info = `"letmeknow identity log key"`), each with a random 12-byte nonce in front. The service sees only ciphertext; whoever knows the id can read the keys and the devices taken off, and nothing else.
- An entry, before sealing, is `{"body": "<bytes>", "sig": "<sig>"}`. `body` is JSON, `{"prev": "<hash of the previous entry's body>" | null, "key": "<the identity's new public key>"}`, plus `"name"` and `"membership"` in the first, and `"revoked": "<device key>"` in one that replaces the key because that device was taken off the identity (see Devices group). `sig` is over `"letmeknow identity key v1\0"` ‖ body, by the key of the entry before, and in the first by its own key.
- The identity's id is SHA-256 of the first entry's body. A credential names the id and its service; the first entry proves both.
- Members replay the log in order: the first valid entry whose body hashes to the id, then for each `prev` the first valid entry that names the latest one. The last key taken is the identity's current key; an older key can sign nothing more. An entry taken with `revoked` revokes that device's certificates by the keys before it (see Certificates).
- A member needs the key logs of the identities its groups' members speak as when it joins or resumes, when members are added, and again once its copy is 10 minutes old. It reads a log from its service (as any log, through the empty page after its last entry) unless it holds a fresh copy: one read from the service within 10 minutes, or one whose entries a peer sent with a head whose `time` is within 10 minutes.
- A key log is caught up from peers as any log is (see Gossip): its entries count once they chain to a head its service signed, and its copy is fresh from a peer while that head's `time` is within 10 minutes. A member that takes newer entries replays the log and shows the new head to the peers of the groups it concerns.

### Certificates

- A session speaks for an identity by a certificate its device signs with the identity's key: `{"body": "<bytes>", "sig": "<sig>"}`, `body` JSON `{"identity": "<id>", "key": "<session key>", "name": "<session name>", "device": "<device name>", "device_key": "<device key>", "added_by": "<device name>", "expires": <ms>}`, `sig` over `"letmeknow certificate v1\0"` ‖ body. `added_by`, the device that added this one to the identity, is absent for its first device; `device_key` is the certifying device's key in the devices group. A certificate lasts a day.
- A device certifies only with the identity's current key, as a fresh copy of its key log shows it. A session asks its device for a certificate before it joins or makes a group as an identity, and again whenever the one it holds lasts less than another 12 hours or is not by the current key; it checks every 10 seconds. A session that takes a new certificate reads its identity's key log, so that, when a new key is why, its peers take the new entries from it.
- Members show certificates in `hello`: their own, and those they hold of the members of every group the peer is in, each once per connection until the next resync; the member that admits a joiner hands it those of the group's members beside the Welcome. A member keeps one per session key and identity, also of a session it does not know yet, whose Add may still be on its way: a valid one over one that is not, else the later. It stores those of its groups' members, so it holds them across restarts and shows them while those members are offline.
- A member's certificate checks out if it names the member's credential's key, name and identity, is signed by the identity's current key, and has not run out. A member that fails the check is shown with why; it stays in its groups, except as follows.
- A session serves a peer nothing of a group (the groups and heads of `hello`, log entries, held messages, files, the kind's state) while the peer's credential speaks as an identity and the session holds no valid certificate of it. It still shows such a peer certificates and takes those it shows; once one, or a key log entry, makes the peer valid, it drops what it knew of the peer's state of the groups it now serves and sends the peer its `hello` of them, which asks for an answer (`anew`, see Peer protocol), before anything else of them.
- A member whose certificate is revoked is removed from the group by every session that holds the certificate and the key log entry, online or not, once it holds both; whichever commits first wins the epoch, and the others find it done. A certificate is revoked if its `device_key` is the `revoked` of a key log entry and a key before that entry signed it, whether or not it ran out. A session that holds no certificate of a member cannot tell its device, and leaves it to those that can, or to the next rule.
- A member connected to this session that speaks as an identity, and has gone 60 seconds without a valid certificate judged by a key log read since, is removed from the group by this session. A session whose device holds the current key renews within seconds of a new key, so it is the sessions of a device that no longer holds the identity's key that go. A session that is offline with a certificate no key log entry revokes, as after a monthly replacement, is judged when it is next online.
- Before removing such a member, a session reads the identity's key log anew if its copy is older than the first time it saw the member without a valid certificate, so that a key it has not seen yet does not count against the member.

### Devices group

An identity's devices group is a group of the built-in kind `devices`, whose members are devices: on a machine, whichever session process holds the lock `LETMEKNOW_HOME/device.lock` acts for the device, as a member whose MLS key is the device key, with its own iroh key and its state in `LETMEKNOW_HOME/device.db`; the device's other session processes try the lock every 10 seconds, so one takes over when the holder stops. In a browser, the device is the session. Sessions do not support the kind, so they are never in a devices group.

Its state is the identity, its private keys, its contacts and its openings, kept in step through held messages that the group's kind log orders (see Kinds), whose payloads are:

| `type` | Fields |
|---|---|
| `key` | `key`, a new private key of the identity (a 32-byte Ed25519 seed), and `at`, when it was made (ms) |
| `contact` | `identity` (id) and `contact` (below): replaces the contact of that identity |
| `opening` | `opening` (below): replaces the opening of the same group |

The kind's state, given on `snapshot` and taken on `state` like any kind's, is JSON: `{"identity": <identity ref>, "name", "position", "keys": [["<seed>", <at>]], "contacts": [["<identity id>", <contact>]], "openings": [<opening>]}`, as the log stands at `position`. The device that makes the identity holds its first key in its state. A device follows the log from the state it was handed; behind it, it asks a member for the state, as any kind does. A device that refreshes an opening keeps the fields of the one it holds that it does not know.

- **Rotation**: a device replaces the identity's key when it commits a device's removal, whether it took the device off or the device asked to leave, and when the current key is 30 days old by its `at`. It sends the new key first, as a held message of the devices group, sealed under the current epoch, and appends it to the group's log, so that a removed device cannot read it, then the key log entry signed by the current key, naming in `revoked` the device taken off, if that is why. Of two devices that replace it at once, the key log takes one; devices hold both keys, and use the one the key log names. A device whose entry naming a device lost replaces the key again, once it holds the key that won.
- **Leaving**: a device leaves an identity by sending `leave` in the devices group, once its sessions that speak as the identity sent theirs in their groups (or forgot those they were alone in); it drops the identity's state at once, and the devices group goes when its removal is committed. The identity's only device forgets the devices group instead, and the identity ends: its key log stays at its service, and no device holds its key. A session whose device's state no longer lists an identity it speaks as leaves the groups it speaks as it in. A device of 0.12.1 commits the removal of a device that left without replacing the key: the device that left holds the current key until a device replaces it, 30 days at most, and certificates it signs meanwhile check out.
- **Renaming**: a device's name is its credential's `name` in its devices groups, and `device` in the certificates it signs. A device renamed keeps the name in `device.json` (the browser's record `web/device`), renews its sessions' certificates at once, and commits an update naming it in each devices group whose members' leaves all name revision 1 or later; in another, the key update it commits as it starts, and daily, carries the name once they do.
- **Contacts**: `{"name", "how": "verified" | "introduced", "by", "at"}` (`by`: the introducer's identity id); a `how` a newer letmeknow named counts as `introduced`. A device on several identities writes contacts to the one it joined first.
- **Openings**: `{"group", "kind", "name", "membership", "members": ["<iroh key>"]}`. A session speaking as the identity in a group open to it has its device record the opening, and refresh `members` when the group's membership changes. An opening stays after the group is closed to the identity; a device that joins by it is refused when the Add is built (see Invites).

On a machine, the holder shares the device with its other session processes through two files in `LETMEKNOW_HOME`:

- `device-state.json`: `{"device": "<device name>", "identities": [[<identity ref>, "<name>"]], "keys": [["<identity id>", "<current public key>"]], "contacts": [["<identity id>", <contact>]], "openings": [<opening>]}`, rewritten whenever it changes, by writing `device-state.new` and renaming it over the old. `device.json` too is written through a rename. The others read it whenever they need contacts, identities or openings, and to see whether their certificates are by the current keys and name the device's name; 0.12.1 writes no `device`.
- `device-endpoint`: the holder's second command channel (`{"port", "token"}`, a localhost TCP port taking one JSON line `{"token", "request"}` and answering one line, as each session's own `endpoint`). The others send it the requests only the device's node can answer: `identity` (`identity leave` once the session left its own groups, as the holder leaves its own), `invite --identity`, `join` with a device link, and three of their own, `{"cmd": "set_contact", "identity", "contact"}`, `{"cmd": "set_opening", "identity", "opening"}` and `{"cmd": "certify", "identity", "key", "name"}`, answered with a certificate. The holder rewrites `device-state.json` before it answers.

## Invites

A member admits a joiner that meets a rule of the group: an invite, or an opening (see Devices group).

- **An invite** is a 16-byte random secret. Its inviter sends the group the held payload `invite` (see Messages), with the secret's SHA-256, and keeps the same record; every member that takes it holds it, until `keep` days after it expires. Its link is `https://letmeknow.dev/i#<fragment>`, where the fragment is `2.<g|d>.<secret>.<member>[.<member>...]`: version 2; `g` for a group, `d` for a device link; the secret; then the members to ask, the inviter first, then up to three members whose receipts for the `invite` came within `send`'s wait. Each member is its iroh key, then `~` and its relay URL only if that is not letmeknow.dev's; every field in unpadded base64url.
- **An opening**: the group's settings name the identity the joiner speaks as (see Identity).

The joiner dials the members the link or the opening names, all at once, giving them 30 seconds to connect, then asks those it reached in turn, giving each 30 seconds to answer, by sending on the peer stream `join` (see Peer protocol): `{"id", "secret", "key_package", "certificate"}`, or for an opening `{"id", "group", "key_package", "certificate"}`, the certificate (see Identity) of the identity its credential names, if any. A member admits by an invite it holds whose `expires` is ahead and that no commit it applied names; one made `--to` an identity, only a joiner whose certificate of it checks out against the identity's key log, read anew. It admits by an opening a joiner whose certificate of an identity the group is open to checks out likewise. It refuses a joiner whose KeyPackage's leaf does not list the group's kind, and one whose session key is already a member's; another session of a member's identity joins as a new leaf. It commits the Add with the invite's hash in the commit's authenticated data. Each time it builds the commit, including after it lost an epoch, it checks the rule again on the epoch it builds on: the invite's `expires` is still ahead and no commit names it, or the group is still open to the identity, and the joiner's key is no member's; so of two members racing to admit by one invite, the one that loses the epoch refuses, and so does one whose Add lost its epoch to a close. An Add committed after the joiner gave up stays, a member that never takes its Welcome, until someone removes it. It answers `admitted`, `{"welcome", "position", "doc", "before", "certificates", "logs"}`: `position` is the log position of the commit that added the joiner, which reads the entries after it and anchors its chain at the first head it reads; `doc` links, as a file (see Files), the state of the group's kind, if its kind gives one (see Kinds); `before` lists the ids of the messages it holds from epochs before the joiner's (the epoch its Add moves into, whatever commits it applied after it), which the joiner can never get, so that no message waits for them (see Messages); `certificates`, those it holds of the group's members, the joiner's own among them; and `logs`, the logs of the kind's order it reads from where it is, `[{"id", "after"}]`, the current one last (see Kinds). Otherwise it answers `refused`: an unknown, used or expired secret gets the same reason, and with 128 bits there is nothing to guess, so a refusal uses nothing up.

A device link is an invite into an identity's devices group: the new device joins with its device node, whose MLS key is its device key and whose credential names no identity, and takes the identity's state, keys among it, as the kind's state.

The inviter tells the group who the joiner is to it (`introduce`), whoever admitted it, once it applies the Add; for an opening, the member that admitted it does. An invite is a rule of the group, so it outlives its inviter: with the inviter gone, no one introduces the joiner, and the contact the invite was made `--for` is not recorded. The `introduce` is held, marked so, in a group whose members' leaves all name revision 1 or later, so members offline then get it by sync; toward a group with an earlier leaf it is live. A member holds an `introduce` marked held.

## Messages

The plaintext of an MLS application message is JSON with a `type`. `leave`, `introduce`, `refused` and `invite` are the core's; every other type belongs to the group's kind (see Kinds).

| `type` | Fields |
|---|---|
| `leave` | none: the sender asks to be removed; the first member to see it commits the Remove, and in a devices group then replaces the identity's key (see Devices group) |
| `introduce` | `identity` (`id`, `membership`), `name`, `how` (`invite`, `open`, `introduce`), and optional `to`: who a member is to the sender; sent once someone joins by the sender's invite or the sender admits someone to an open group, and by `introduce`; marked held where every leaf names revision 1 or later (see Invites) |
| `refused` | `messages`: `[{"id", "reason"}]`, the messages the sender gave up since its last `refused`; `reason` is `size` (larger than it takes), `old` (under an epoch whose keys it no longer holds, or below its floor), `removed` (from a member removed more than 5 minutes before it arrived) or `unreadable` (it did not open) |
| `invite` | `hash`, SHA-256 of an invite's secret, `expires` (ms), and optional `label` (`--for`) and `to` (`--to`, an identity id): a rule any member admits a joiner by, once (see Invites) |
| `message` | chat's: `content`, `after`, and optional `to`, `reply_to`, `urgent`, `attachment` (below) |

An `introduce`'s `to` lists the members it is for, as a message's `to` does; only they act on it (record the introduction, offer the contact), and the others ignore it. Without `to`, it is for the whole group.

A member gives up a message it cannot take: one whose ciphertext is larger than it takes (1 MiB by default), one that does not open or is not a valid payload, and one a peer named below its floor (see Peer protocol). It sends a `refused` 1 second after it gives up the first message since its last one, and whenever a sync of the group with a member ends while it has some to report. It reports none under an epoch before the one it joined, nor under an epoch no later than the newest of a message it dropped after `keep`, which it may have held; the `before` of its Welcome it never reports. A session whose own messages a `refused` lists, while its `send` waits for them, counts the sender among those that refused; later, it tells its user of its chat messages (an agent's `listen` prints `refused`, the browser marks each message), from its own copy, which it keeps, text and attachment, for `keep` days. A sender seals no message whose payload and authenticated data, with 1 KiB for MLS's framing, are over 1 MiB, the default limit: `send` fails before the message uses a key, and nothing goes out.

A chat `message`'s fields: `content`, its text, which may be empty with an attachment; `after`, the ids of the messages the sender had read that no other message it read lists in `after`; `to`, the members it addresses, each as the first 8 bytes of SHA-256 of its session key, or none for the group; `reply_to`, the id of the message it answers; `urgent`, `true` to wake every member; `attachment`, `{"link", "name", "size", "type"}`: a file link (see Files), its name, its size in bytes, and its media type, which may be empty. A chat holds the file an attachment links.

A message's id is SHA-256 of its MLS ciphertext. A payload is held or live. Held are `message`, `leave`, `refused` and `invite`, and any payload whose sender marks it so with the MLS message's authenticated data `{"held": true}`; every other payload is live. A member holds a held payload for `keep` days, and only once it has decrypted and verified it; a live one it takes and holds not. It takes no message from a removed sender that first reaches it more than 5 minutes after it applied the removal.

## Peer protocol

A `peer` stream joins two sessions that share a group, or one that asks the other to admit it, one stream per pair, kept open while both are online. Either side may send a frame at any time; every frame but `join` and its answers names its group, or a log of its groups, and a side serves a group, and its logs, only to a peer whose iroh key is in a leaf of that group's current epoch and, if the peer speaks as an identity, whose valid certificate it holds (see Certificates). Each side sends `hello` when the stream opens and when its state of a group changes, after the entries the peer lacks. A side ignores what a `hello` shows of a group it does not serve the peer yet or of a log it does not follow yet, so it answers a `hello` that shows it a group it had no `hello` for, or a head longer than its own, with its own, before syncing. A side that joins a group sends its `hello` of it to the peers it is connected to. A side likewise sends a peer whose leaf names revision 1 or later the messages of a group only once the peer's `hello` has shown it the group, as when the peer has just joined or checked its certificate; it keeps the latest 256 of each group meanwhile, and sends them then, or hands them, with those it had yet to send, to the connection that replaces its own. A side that holds no `hello` of a group from the peer, as when the stream opens or when it serves the peer the group again, marks the group `anew` in its `hello`, toward a peer whose leaf names revision 1 or later: the peer drops what it knew of the side's state of the group, sync rounds included, answers with its own `hello`, and syncs the group anew. Every 5 minutes a side sends `hello` again and syncs each group anew, even if nothing changed, so a message lost on its way is found within 5 minutes; a sync round of its own that was still under way at the last of these, and so was dropped by a peer that stopped serving it the group, it drops too.

| Frame | Meaning |
|---|---|
| `{"hello": {"groups": [{"group", "epoch", "floor", "joined", "anew"}], "heads": [<head>], "certificates": [<certificate>]}}` | For each group both are in: the epoch the sender is at, the lowest epoch it accepts (`floor`: the later of the epoch it joined and its epoch less the most ended epochs it keeps (its cap, 256 by default); their age does not count, so a message under an epoch past its 7 days is sent, and refused `old`), the epoch it joined, and, as `anew: true`, that it holds no `hello` of the group from the receiver. `heads`: the newest signed head the sender holds of each log it follows for those groups (see Gossip). `certificates`, if any: those the sender holds of the members of every group the receiver is in, its own among them, not yet shown on this connection since the last resync (see Identity). A sender with neither groups nor certificates to show sends no `hello` |
| `{"entries": {"log", "entries", "head"}}` | Entries of a log the other lacks, judged by the head it showed, ending at `head`; served only to a member of a group whose log it is |
| `{"reconcile": {"group", "msg"}}` | A negentropy message (see below) |
| `{"messages": {"group", "items", "below": [{"epoch", "id"}]}}` | MLS ciphertexts the other lacks; also every new message as it is sent, to the members online or to one. `below`: the messages the other lacks under epochs below its `floor`, which are not sent |
| `{"receipt": {"group", "held": ["<id>"]}}` | The answer to `messages`: the ids of the items the receiver took (held, or taken in if live); those it gave up, or that wait for a commit, are not answered |
| `{"state": {"group", "link"}}` | A link to a state of the group's kind (see Files) that the sender's kind hands this member, as an admitting member does in `admitted`; without `link`, a request for one |
| `{"want": {"group", "files"}}`, `{"have": {"group", "files"}}` | BLAKE3 hashes (see Files) |
| `{"join": {"id", "secret" \| "group", "key_package", "certificate"}}` | A request to be admitted, by an invite's secret or to a group open to the identity the certificate proves (see Invites); `id`, a number the joiner picks, distinct among its requests awaiting answers on the stream |
| `{"admitted": {"id", "admitted": {"welcome", "position", "doc", "before", "certificates", "logs"}}}`, `{"refused": {"id", "refused"}}` | The answer to the `join` with that `id` (see Invites) |

A side that follows a log but holds no head of it yet sends the empty log's: length 0, hash h₀, `time` 0 and no signature, which needs none.

A sender learns from receipts who holds its message, and from `refused` messages who gave it up (see Messages); it keeps its message as its own pending send until a receipt says a member holds it, and offers it in every sync meanwhile. A receiver keeps the id of each message it gave up, with its epoch, so a message naming it in `after` shows a known gap rather than waiting.

Message sync, per group, starts once both sides show the same head of the group's log. It is negentropy (crate `negentropy` 0.5) over items whose timestamp is the epoch and whose id is the message id, from the later `joined`. `reconcile` frames alternate until negentropy is done; then `messages` carries what each lacks, in the order the sender took them, since MLS opens a sender's messages at most 1000 out of order, and of what is older than the receiver's `floor`, only the epoch and id, in `below`. A member gives up each message `below` names under an epoch below its floor that it neither holds nor gave up already. Ids a member gave up on stay in its set, so they are not offered again.

## Files

- A file's key is 32 random bytes. Its ciphertext is the STREAM construction as in age: the plaintext in chunks of 65,520 bytes (the last shorter, and empty only for an empty file), each sealed with ChaCha20-Poly1305 under the key, with the nonce u88 big-endian chunk counter ‖ `0x01` for the last chunk, else `0x00`. Sealed chunks are 64 KiB.
- Its hash is BLAKE3 over the whole ciphertext. A link is `lmk:<hash, hex>.<plaintext size>#<key, hex>`.
- Transfer is iroh-blobs `=0.103.1` on its own ALPN, kept inside one module. A holder admits a connection only from the iroh key of a current member of a group the two share that it serves (see Certificates), a request only for a file one of those groups links, and checks again every 16 KiB it sends.
- A member holds, for a group, the files linked within `keep` (those its kind holds, by when it held them: a chat's attachments, by when the message reached it; files it added; states beside Welcomes and in `state` frames), the files its kind links now, and the latest state it handed or took. It serves and wants only those, and deletes every other file it holds once an hour.
- A member asks connected peers with `want`; each answers `have` with those it holds, and the member fetches from several holders at once, resuming where a transfer stopped. A browser keeps the ciphertext in its own storage (IndexedDB), since iroh-blobs keeps only memory there.

## Kinds

A kind id is a plain string: `chat` and `devices`, built in, or a plugin's, such as `doc` or `git`. The core reads none of a kind's content.

### Channels

What a kind may do in its groups, and nothing else:

- **Held messages**: payloads marked held (see Messages), synced, kept `keep` days, answered by receipts, and pending until another member holds them.
- **Live messages**: payloads to the members online, or to one, not held.
- **Files**: files it adds, held `keep` days; files it holds `keep` days from when it says, as those a held message links; and the files it links now, held while it does. A member fetches those within its limit.
- **A log**: the group's kind log, which orders its held messages (below).
- **A state link**: when a member is admitted, the member admitting it asks its kind for a state and links it in `admitted`'s `doc`; a kind can also hand a member that fell behind a state, which goes as a `state` frame. A member behind its kind's log asks a member online for one with a `state` frame without `link`, at most once a minute: when it falls behind, when its log becomes alike with a member's while it is behind, and when a sync of held messages with a member ends while an entry still waits for its message, unless it was handed one in that minute; the member asked hands one if its kind gives one. The member fetches the file and gives it to its kind.

### Logs

A group of any kind but chat orders its kind's held messages in a log of its own at the group's membership service. Its id is the 16 bytes of `MLS-Exporter("letmeknow kind log", "", 16)` of the group's first epoch, and of the epoch each removal starts after that: members compute it as they apply the commit, and a joiner learns it from `admitted`'s `logs`. Each log is held, chained, signed and caught up from peers as every log is (see Membership service).

- An entry is the 32-byte id of one of the group's held messages. A kind appends one only for a held message the group holds, once this session has taken every entry before.
- Positions are the kind's, across logs: a log's entry n is at position `after` + n, where `after` is 0 for the first log. A committer that removes members first appends the 3 bytes `end` to the current log, at its position p, and names p − 1 as `end` in the commit's authenticated data; members apply the commit and take the next log, whose `after` is that `end` (or the current log's `after`, if larger). A removal without `end` keeps the log.
- A member applies the order from where its kind asks, each position from the log that holds it, the last whose `after` is below it, dropping a log once it reads past it: an `end` entry with no later log it knows waits, and any other entry that is not 32 bytes, names a message an earlier entry named, or names one of the core's payloads, is skipped; one that names a held message this session holds is taken; one that names a message this session gave up leaves it behind; any other waits, with every entry after it, until its message is held. The session keeps those taken until its kind asks to read past them.
- A read the service refuses as `expired` leaves the member behind too. A member behind reads no further until its kind asks to read from a later position, as from a state it was handed.

### Plugins

A native session finds a kind's plugin as the executable `letmeknow-kind-<kind>` (`.exe` on Windows) in the directory of its own executable, then in each directory of `PATH`; the first found wins. Its leaf lists `chat` and every kind it found. It starts a plugin when it has a group of its kind (when it starts, makes one or joins one) or a command for it, with stdin and stdout piped and stderr its own, and stops it with itself; one that stops, it starts again and tells it its groups.

They speak JSON lines: one JSON object per line, each way. Bytes are unpadded base64url, and so are group ids; message ids are hex. A member is described as `listen` events describe it (`name`, `fp`, `device`, `identity`, `added_by`, `you`), and named by its `fp` in `to`. A message with an `id` is a request: the other side answers `{"type": "answer", "id", "answer"}`, or `{"type": "answer", "id", "error"}`. A side skips a message of a `type` it does not know, but answers one with an `id` with an error. A plugin hears only of its kind's groups, and the session refuses what it asks of others.

The session sends:

| Message | Meaning |
|---|---|
| `{"type": "start", "id", "kind", "dir"}` | The first line, a request. `dir` is the plugin's own state directory, `sessions/<handle>/kinds/<kind>/`. Answered `{}`, or `{"chat": true}` if the kind's groups carry chat too: then their `message` payloads are the session's chat, which `send` sends there, and do not reach the plugin |
| `{"type": "group", "group", "settings", "me"}`, and optionally `id`, `command`, `args`, `cwd` | The session is in a group of the kind: for each when the plugin starts, and when the session makes one (`command`: `invite`) or joins one (`join`), with the command's arguments for the kind and the directory they are relative to, as a request. `me` is this session as the group's members see it. A session whose plugin refuses a group it makes or joins leaves it |
| `{"type": "gone", "id", "group"}` | The session left the group, or was removed: answered once the plugin let go of what it kept for the group, such as a doc file it made |
| `{"type": "message", "group", "from", "payload", "held"}`, and `id` if held | A payload of the kind from a member |
| `{"type": "synced", "group", "member"}` | The session and a connected member hold the same log of the group: a time to compare state |
| `{"type": "state", "group", "from", "data"}` | A state `from` handed this session, beside the Welcome that admitted it or in a `state` frame |
| `{"type": "snapshot", "id", "group"}` | A member is being admitted, or asks for a state: answered `{"data"}` to hand it one, or `{}`. The session waits 10 seconds |
| `{"type": "entry", "group", "position", "id", "from", "payload"}` | An entry of the kind's log taken, in log order: the held message it names, by its `id`, sender and payload |
| `{"type": "command", "id", "args", "cwd"}` | `letmeknow <kind> <args>...`, run in `cwd`: the answer is what the command prints. The session goes on meanwhile |
| `{"type": "sync", "id"}` | Bring into step what the plugin keeps outside letmeknow, such as a doc's file: asked before the session prints anything and before each command, which wait for the answer |
| `{"type": "printed", "group", "key"}` | The plugin's event with this `key` was printed |

The plugin sends:

| Message | Meaning |
|---|---|
| `{"type": "send", "group", "payload"}`, and optionally `held`, `to`, `id` | Seals and sends a payload of the kind. With `held: true` it is held, and a request is answered `{"id", "held_by", "refused", "pending"}` once the receipts came in, or after 5 seconds; otherwise it is live, to the member `to` or to every member online |
| `{"type": "add", "id", "group", "data"}` | Seals a file, held for the group: answered `{"link"}` |
| `{"type": "hold", "group", "links"}` | Holds files for `keep` days from now, unless held already, as those a held message links |
| `{"type": "links", "group", "links"}` | The files the kind links now, which replace those it linked before |
| `{"type": "fetch", "id", "group", "link"}` | A file the group holds: answered `{"data"}` once it is here, fetched from the members online, or with an error after a minute |
| `{"type": "state", "group", "to", "data"}` | Hands a member a state |
| `{"type": "log", "group"}`, and optionally `after` | Follows the kind's log after position `after`, as the kind's own state stands: entries come as `entry`, the ones the session keeps after `after` first, and those up to `after` go. Without `after`, the kind has no state yet, and the session asks a member for one. A position before one the kind named earlier leaves the session behind |
| `{"type": "append", "id", "group", "message"}` | Appends the id (hex) of a held message of the group to the kind's log: answered `{"position"}` once every entry up to it was taken or skipped, its own among them unless it was skipped. Refused while the session is behind or an entry waits for its message, and as the service refuses (`rate`) |
| `{"type": "spread", "id", "group", "link"}` | Waits until a member online holds a file whole, up to 30 seconds: answered `{"held_by"}`, at once with none if no member is online |
| `{"type": "event", "group", "event"}`, and optionally `wake`, `key` | For `listen`, which prints `event` with the group's id in `group`: by the delivery policy at once with `wake: true`, held otherwise. An event of type `warning` prints at once, as the session's own. With `key`, it replaces a held event of the plugin's for the group with the same key, and is told as `printed` |
| `{"type": "info", "group", "info"}` | Fields `groups` shows for the group |

The client core (`lmk-client`) is the host in every client; the transport is its shell's. The browser's in-page plugins speak the same messages, as JSON values handed to them and taken from them in the page: `start` names no `dir`, and they send no `spread`. The page sends their commands (`Lmk.command(kind, args)`), and gets their events as `{...event, "group", "kind"}`.

### Git

The git kind's plugin is `letmeknow-kind-git`, with git's remote helper `git-remote-lmk` beside it; in the browser, `lmk_kind_git::Page` runs in the page, display-only. Its groups carry chat (`start` answers `{"chat": true}`).

- A push is the held payload `{"type": "push", "ref", "old", "new", "bundle", "subjects"}`: the full ref name, the old and new commit ids (hex), each null for a branch created or deleted, the file link of a git bundle of the new commits, or null if they need none, and their subjects, newest first, at most 50. The pusher adds the bundle as a file, sends the push, which members that take it answer by holding its bundle, and appends the push's id only once a member that holds the push (`send`'s `held_by`) holds the bundle too (`spread`).
- A member replays the pushes the log's entries name, in log order, over its branches: a push counts if `old` is its ref's tip (none, for one created), and then moves the ref to `new` or deletes it. A member checks each push in log order: it unbundles the bundle into its repository (`git bundle unbundle`, which needs the bundle's prerequisites), and the push is void if that fails, or `new` is not a commit there, or `old` is not its ancestor (`git merge-base --is-ancestor`). Void pushes are left out of the replay. The repository's refs are the branches replayed as far as every push is checked; a push must build on the branches replayed counting those not checked yet. A pusher's push won if it counted when its entry was taken.
- Its state, given on `snapshot` and taken on `state`, is JSON, `{"position", "refs", "bundle"}`: the log position as far as every push is checked, the branches there (`{"<ref>": "<commit>"}`), and the file link of a bundle of all their commits (`git bundle create` of every ref), or null if there are none. A member takes a state no older than the last entry it took, fetches its bundle and unbundles it, and follows the log after `position`.
- Its event is `pushed` (`by`, `ref`, `old`, `new`, `subjects`), for a push of another member that counted when its entry was taken, not waking. `info` gives `remote`, `lmk::<group>`, as `group`'s answer does on `invite` and `join`.
- Its commands are git-remote-lmk's: `git list <group> [--push]`, answered `{"refs", "head", "repo"}` (the branches as checked, or with `--push` counting those not checked yet; the ref `HEAD` names, `refs/heads/main` if there is one; the repository's path), and `git push <group> <ref> <old> <new> <bundle> [<subject>...]`, with `-` for none and a bundle's path, answered `{"position"}`, or the error `fetch first` if `old` is not the tip or its entry did not count. `<group>` is a group's id or name.
- `git-remote-lmk` (gitremote-helpers(7)) is git's helper for `lmk::<group>`. It finds `letmeknow` beside its own executable, then on PATH, and runs `letmeknow git list` and `letmeknow git push` against the session `LETMEKNOW_SESSION` names, or the one running. It has the capabilities `fetch`, `push` and `option` (only `force-if-includes`, which git requires and which matters only for force pushes). It fetches from the plugin's repository (`git fetch --no-write-fetch-head`), refuses a force push, and bundles a push as `<src> --not` the group's branches it has.
- The plugin keeps, in `dir`, each group's bare repository, `repos/<group>.git`, and its branches and the pushes not yet checked, `<group>.json`. In the browser, it keeps them in the record `kind/git/<group>`, takes every push as checked, holds no file, answers `snapshot` with `{}`, and has no commands.

### Doc

The doc kind's plugin is `letmeknow-kind-doc`; in the browser, the same Rust (`lmk_kind_doc::Page`) runs in the page.

- A doc is a Yjs document whose text is named `text`. Its payloads are all live: `{"type": "edit", "update"}`, an edit to the members online; and to one member, `{"type": "snapshot", "snapshot"}`, `{"type": "sv", "sv"}` and `{"type": "diff", "update"}`. Updates are Yjs v1.
- On `synced`, it sends the member `snapshot`, SHA-256 of `txn.snapshot().encode_v1()`. A member whose snapshot differs answers `sv`, its Yjs state vector, which is answered by a `diff`.
- Its state, given on `snapshot` and taken on `state`, is the whole Yjs document as a v1 update. Its `links` are the `lmk:` links in its text.
- `invite --kind doc [<file>]` and `join <link> [<file>]` pass the doc's file as `args`; a joined doc's file must not exist. `doc attach [--group <doc>] <path>` adds a file and answers `{"link", "markdown"}`. Its event is `edited` (`file`, `by`, `lines`, `direct`; key `edited`, waking when `direct`), and `info` gives `file`.
- The plugin keeps, in `dir`, each doc's state (`<group>.yjs`) and its file's binding (`<group>.json`: `{"path", "base", "made", "carrying"}`, `carrying` the file's text and the edit on their way onto the doc, or null), and the files it makes in `docs/`. In the browser, its commands are `state <group>` (answered `{"state"}`), `diff <group> <state vector>` (`{"diff"}`) and `edit <group> <update>`, and it keeps each doc's state in the record `kind/doc/<group>`.

## Browser

- The client is the client core (`crates/client`) on lmk-node, compiled to WebAssembly (`crates/web`), with a device key that is also its MLS key: the browser is a device of its identities, and a session that its device certifies. Its iroh key is separate, as natively, and it reaches every peer and membership service through relays.
- Its records live in an IndexedDB database `lmk`. The store `records` holds the `Provider`'s, one record per key: openmls's own keys, and ours under `lmk/` (lmk-node's `node/…` and `session`, the devices kind's `kind/devices/…`, the client core's `kind/client/introductions`, the introductions not accepted yet, the page's `web/…`: its device, name, and each group's timeline, who refused its messages and why, and settings as last seen, and the in-page plugins' `kind/doc/<group id, base64url>`, each doc's Yjs state, and `kind/git/<group id, base64url>`, each git group's branches). A git group's timeline holds its pushes beside its changes. The page writes the records that changed every second and after each action. The store `files` holds the ciphertext of each file it holds, by BLAKE3 hash (hex): the files it adds, and those it fetches up to 25 MiB, which it takes without being asked. The page reads only their hashes when it opens; the session loads a file into iroh-blobs' memory store when it reads it, or when a member's `want` names it. It answers `have` only for files in this store, so a larger file fetched when asked, which stays in memory only, is served to no one. When the page opens and once an hour, it deletes the files no group links, by the rule in Files.
- Its membership service is the one `letmeknow serve` names at `GET /membership`, as text, `<iroh key, hex>@<relay URL>`, on the server the page came from; its relay is that address's relay URL. `localStorage` can name others, as tests do: `lmk relay` (a URL) and `lmk membership` (the same form). The service worker caches `/membership` with the build's files.
- The page serves `/i` as the app, which reads the invite from the fragment.
- A service worker caches exactly the files of one build, under a name derived from their contents, and serves navigations with its `index.html`. A new build installs beside it and waits; the page offers it, and on acceptance tells it `"skip"`, and every tab the old one served reloads.
- One tab at a time runs the session, holding the Web Lock `letmeknow`; every other tab waits for the lock, and meanwhile calls the session over the BroadcastChannel `letmeknow`. A call is `{"id", "method", "args"}`, a method of the WebAssembly's `Lmk` (or `open`, which starts a new session with a name and a device name); its method `request` takes the client core's requests, as the session process's command channel does (`{"cmd", ...}`), and answers as it does, answered by `{"id", "result"}` or `{"id", "error"}`. The running tab posts each event as `{"event"}`, and `{"ready": true}` once the session runs and whenever a tab posts `{"ask": true}`. A tab sends its unanswered calls again on each `ready`, and the running tab answers each call id once. When the running tab closes, the next tab takes the lock and runs the session from IndexedDB.

Push notifications are deferred (see DESIGN.md, Later).

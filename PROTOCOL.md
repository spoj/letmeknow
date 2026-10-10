# letmeknow protocol

The exact formats behind DESIGN.md. The crate `lmk-proto` (`crates/proto`) implements the shared shapes; where the two differ, fix one of them.

## Conventions

- Our own structures are JSON, with bytes as unpadded base64url, except where a section gives a binary layout.
- A signature covers an explicit byte string: a context string, then the exact bytes being vouched for. Signers send the bytes they signed, and verifiers check those bytes, so nothing depends on canonical JSON.
- Hashes are SHA-256, keys and signatures Ed25519, except files, which hash with BLAKE3 (see Files).
- Positions in a log start at 1. Sets of positions travel as sorted inclusive ranges, `[[1,10],[13,50]]`; a reader sorts and merges what it is sent.
- On a QUIC stream, every frame is a 4-byte big-endian length, then that many bytes of JSON, at most 16 MiB.

### Compatibility

Releases of one minor version (0.13.x) run side by side: each adds only what the others can ignore, and a breaking change waits for the next minor version. Every reader and writer follows these rules.

- **Unknown input**: readers ignore fields they do not know, and skip what they cannot parse (a frame, a payload, a log entry, a subscription notice, a plugin's line) without closing a stream over it.
- **Growing enums**: an enum whose values may grow parses an unknown value to a catch-all where the value is advisory: the `how` of an introduction, of a commit's authenticated data and of a contact. Where it is not, the error says a newer letmeknow made it: a membership service of a kind it does not know is kept as it is, and fails so when used.
- **Shared records**: whoever rewrites a shared record keeps the fields it does not know: a group's settings, with the identities and the service in them, and a devices group's state, with its contacts and openings, which a device hands on and refreshes.
- **Revisions**: a leaf names its session's protocol revision (see Leaf data), a number that grows with each compatible addition; a leaf without one reads as revision 0. A session uses what a revision added only toward members whose leaves name that revision or a later one; their leaves are in the group's state even while they are offline. A session whose leaf differs from what it would write now (revision, kinds, relay) updates it by a commit.
- **Unknown requests**: the membership service answers a request it does not know with `{"refused": "unknown request"}`; the session and plugins answer a plugin message with an `id` and a `type` they do not know with an error.
- **Breaking changes** happen only through these switches: the ALPN (`letmeknow/2`), a group's `protocol` (3, see Commits), the invite link version (3, see Invites), the home's `format` (3) and IndexedDB's version (3, see Browser).

| Revision | Release | Added |
|---|---|---|
| 1 | 0.13.0 | everything in this document |

## Connections

- All of our protocols use one ALPN, `letmeknow/2`, so two endpoints keep one connection. Each exchange is a bidirectional stream whose first frame names it: `{"stream": "membership" | "peer" | "admission"}`. File transfers use iroh-blobs' own ALPN.
- Endpoints use iroh's `presets::Minimal` with a relay map holding our relays, and dial `EndpointAddr::new(key).with_relay_url(url)`, from the addresses that leaves, settings and invite links carry. iroh 1.3.0; the browser build enables only `tls-ring`.
- Sessions of one device write their current direct addresses to `LETMEKNOW_HOME/addresses/<iroh key>.json`, as `{"addrs": ["<ip:port>"]}`, and dial each other from there, with no relay needed.
- A member an invite link names without a relay is reached through letmeknow.dev's.
- The session process calls `proxy_from_env()`.

## Keys

- **Session key**: the MLS signature key of one member.
- **Device key**: Ed25519, one per identity a device is on: the device's MLS key in that identity's devices group. It signs its sessions' certificates.
- **Identity key**: Ed25519, an identity's, shared by its devices through its devices group and replaced from time to time. It signs its key log's next entry.
- **iroh key**: each session's iroh endpoint key, separate from its MLS key and named in its leaf. A membership service's iroh key is also its signing key for heads.

## Membership service

### Logs

A log is named by an id: a group's MLS group id, or a key log's address (see Identity). Each member chains a log as it reads it:

- h₀ = SHA-256(`"letmeknow log v1\0"` ‖ log id)
- hₙ = SHA-256(hₙ₋₁ ‖ SHA-256(entryₙ))

A member holds every log it follows alike: it subscribes to it at its service, reads it from the position after the last it holds, page by page, when the subscription starts and every 5 minutes (a read sent after a `subscribe` may reach the service first and miss an entry appended in between), holds each entry, and keeps the chain over what it holds, anchored at the first head it reads when it starts past position 0, as a joiner does. Once an entry is held, the log's type reads it: a group's judges it (see The group log), a key log's replays the identity's keys (see Identity).

### `letmeknow serve`

A client opens one `membership` stream per request and gets one answer, except `subscribe`, which stays open.

| Request | Answer |
|---|---|
| `{"append": {"log", "entries": [...]}}` | `{"position", "head"}`: the first entry's position and the head after the last, the entries in order and counted as one append; or `{"refused": reason}`: `size` (an entry over the limit), `rate`, `policy` |
| `{"read": {"log", "after"}}` | `{"entries": [...], "head"}`: entries after position `after`, a page at a time; `head` covers the last one returned; or `{"refused": "expired"}` if some of them are past the service's retention |
| `{"head": {"log"}}` | `{"head"}` |
| `{"subscribe": {"logs": [...]}}` | a frame `{"log", "position", "entry", "head"}` per new entry of those logs, each head covering its entry, until the stream closes; sending another `subscribe` on it replaces the set |

The first append to an unknown log creates it, if the service's policy allows. A request the service does not know is answered `{"refused": "unknown request"}`; on a subscription, it is skipped, as a client skips a frame it does not know. letmeknow.dev's policy: entries up to 1 MiB, log ids up to 64 bytes, 60 appends a minute per connection, pages of 4 MiB, entries kept a year.

A head is `{"log", "length", "hash", "time", "sig"}`, where `time` is milliseconds since the Unix epoch and `sig` is the service's Ed25519 signature, by its iroh key, over:

`"letmeknow head v1\0"` ‖ u16 length of log id ‖ log id ‖ u64 length ‖ hash (32 bytes) ‖ u64 time

all integers big-endian. The empty log's head is length 0, hash h₀, `time` 0 and no signature, which needs none.

### Local folder

A log is a directory, `<folder>/<log id, hex>/`, holding one file per entry, `<position>.entry`, whose bytes are the entry. To append, a writer creates the file for the position after the last one with an exclusive create (`O_CREAT | O_EXCL`, Rust's `create_new`), and on a clash moves to the next position and tries again. Readers list the directory and read in order; a file notification or a poll every 2 seconds brings news. Heads are not signed; members still compare chains.

## The group log

A group's log holds two kinds of entry, by their leading byte, all integers big-endian:

- **Commit**: `0x01` ‖ u32 length ‖ commit ‖ u32 length ‖ Welcome ‖ signature (64 bytes). The commit is an MLS PrivateMessage; the Welcome is empty unless the commit adds members. The signature is the committer's, by its leaf's signature key, over `"letmeknow commit"` ‖ u32 length of commit ‖ commit ‖ Welcome.
- **Message**: `0x02` ‖ id (32 bytes) ‖ MAC (32 bytes), 65 bytes in all. `id` is SHA-256 of the message's ciphertext; the MAC is HMAC-SHA256 of `id` under the 32 bytes of `MLS-Exporter("letmeknow entry", "", 32)` of the epoch it was sealed in.

A member judges the entries in order, from the position after its start (the Add that brought it in, or 0 for the group's creator), each in the epoch it is in:

- An entry that does not parse, or has bytes left over, is skipped.
- A message entry counts if its MAC verifies under the current epoch and no earlier counted entry of the current epoch named its id; else it is skipped.
- A commit entry is applied if MLS accepts it for the current epoch, its sender is a member, its signature verifies under that member's leaf key, and it keeps the rules of Commits; else it is skipped. The first such entry ends the epoch, so every later commit for it is skipped.
- A commit from the member's own leaf whose bytes are its own saved pending entry is applied as its own. One from its own leaf with other bytes, signed by its key, means its state was copied: it stops using the group and reports it. Any other entry from its own leaf is skipped.

Each position's record is `{"epoch", "at", "judged", "lost"}`: the epoch current when it was read, when (ms), the verdict (`{"commit": {"own"}}`, `"skipped"`, or `{"counted": {"id"}}`), and whether it is a known loss.

## Groups

### Settings

A group context extension, of the private-use type `0xff01`, whose data is JSON:

```json
{"protocol": 3, "kind": "<kind>", "name": "", "open": [{"id": "<identity id>", "name": "Matthew"}], "carry": 7, "update": 86400,
 "membership": {"serve": {"key": "<iroh key>", "relay": "<url>", "addrs": ["<ip:port>"]}} | {"folder": "<path>"}}
```

`kind` is a kind id (see Kinds): `chat`, `devices` (an identity's devices group, see Identity), `doc`, `git`, or another plugin's. `carry` is H, in days; `update` is T, in seconds. Members list `0xff01` and `0xff02` in their capabilities.

### Leaf data

A leaf node extension, of type `0xff02`, whose data is JSON:

```json
{"key": "<iroh key>", "relay": "<url>", "kinds": ["chat", "doc"], "revision": 1}
```

`kinds` lists the kinds the session supports, `chat` always among them; `revision` is the session's protocol revision (see Compatibility).

### Credential

An MLS basic credential whose identity bytes are JSON:

```json
{"name": "Builder, Matthew's agent", "key": "<the member's MLS signature key>",
 "certificate": {"identity": {"id": "<identity id>", "membership": <as in settings>}, "device": "<device key>", "sig": "<sig>"} | null}
```

`key` must be the leaf's own signature key: a KeyPackage or an Add whose credential names another is invalid. `certificate` names the identity the member speaks as, its device's key on that identity, and that key's signature over `"letmeknow certificate v1\0"` ‖ session key ‖ identity id (see Checking). A devices group's members are devices, whose credentials name the device's name and no certificate.

### Commits

- Protocol version 3 fixes: openmls `=0.9.1`; ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY` (commits are PrivateMessages, so the membership service reads nothing); `max_past_epochs(1)`; `SenderRatchetConfiguration::new(1000, 100_000)`; the ratchet tree in the Welcome; KeyPackages built with `Lifetime::init(0, u64::MAX)`, joins with lifetime validation skipped; `RequiredCapabilities` naming `0xff01` and `0xff02`, resent with every settings change, since a GroupContextExtensions proposal replaces the whole list. Settings carry `"protocol": 3`; a client refuses a Welcome to a group of another protocol.
- A commit is valid only if: every proposal is inline, and an Add, a Remove or a GroupContextExtensions; every added credential names its leaf's key; a commit that adds members carries, as its authenticated data, `{"how": "invite" | "open", "invite": "<SHA-256 of the invite's secret>"}`; its settings parse, name protocol 3 and keep the kind; and the committer's new leaf, if any, has the same credential but for its `name`. Every commit updates the committer's leaf.
- A committer builds its commit on the epoch it has applied to the log's head, saves the whole entry in that step, and posts exactly that until the log shows it or another commit wins: it merges (`merge_pending_commit`) when it reaches its own entry; otherwise it clears it (`clear_pending_commit`), applies the winner (`merge_staged_commit`), and builds its change again, up to 5 tries. Only the service's refusal drops a saved entry.

## Identity

### Key log

- An identity's public record is its key log. The log's address is SHA-256(`"letmeknow identity address\0"` ‖ id), and its entries are sealed with ChaCha20-Poly1305 under HKDF-SHA256(ikm = id, info = `"letmeknow identity log key"`), each with a random 12-byte nonce in front. The service sees only ciphertext; whoever knows the id can read the keys and the devices.
- An entry, before sealing, is `{"body": "<bytes>", "sig": "<sig>"}`. `body` is JSON, `{"prev": "<SHA-256 of the previous entry's body>" | null, "key": "<the identity's key from here on>", "devices": [{"key": "<device key>", "name": "<device name>"}]}`, plus `"name"` and `"membership"` in the first. `sig` is over `"letmeknow identity key v1\0"` ‖ body, by the key of the entry before, and in the first by its own key.
- The identity's id is SHA-256 of the first entry's body. A credential's certificate names the id and its service; the first entry proves both.
- Members replay the log in order: the first valid entry whose body hashes to the id, then each entry signed by the current key whose `prev` names the latest one taken. The last key taken is the identity's current key, and the last list its devices. A device an earlier entry listed and the latest does not is dropped.
- Members follow the key logs of the identities their groups' members speak as, by subscription, and read one afresh when a member's certificate names a device its copy does not list, and before admitting by `--to` or an opening. They take newer entries from peers as any log's (see Peer protocol).

### Checking

A member's certificate is verified if its identity's key log lists its `device`, and `sig` verifies by that key over `"letmeknow certificate v1\0"` ‖ the credential's key ‖ the identity's id; the member is then shown with the device's listed name, and marked as a new device if the key log's first entry did not list it. A bad signature, or a device never listed, is unverified; a dropped device is dropped. A member serves a peer a group only while its credential names no identity or is verified (see Peer protocol). A member whose device is dropped is removed by the duty that reads it (DESIGN.md, Groups).

### Devices group

An identity's devices group is a group of the built-in kind `devices`, whose members are devices: on a machine, whichever session process holds the lock `LETMEKNOW_HOME/device.lock` acts for the device, as a node whose state is `LETMEKNOW_HOME/device.db` and whose files are in `device-files/`, with an MLS key of its own in each devices group, the device key on that identity (kept at `node/device-key/<group>`); the device's other session processes try the lock every 10 seconds, so one takes over when the holder stops. In a browser, the device is the session. Sessions do not support the kind, so they are never in a devices group.

Its state is the identity, its private keys, its contacts and its openings, kept in step through held messages, taken in log order, whose payloads are:

| `type` | Fields |
|---|---|
| `key` | `key`, a new private key of the identity (a 32-byte Ed25519 seed), `at`, when it was made (ms), and `epoch`, the group's epoch then |
| `contact` | `identity` (id) and `contact` (below): replaces the contact of that identity |
| `opening` | `opening` (below): replaces the opening of the same group |

The kind's state, handed to a joiner and to a device that asks, is JSON: `{"identity": <identity ref>, "name", "position", "keys": [["<seed>", <at>, <epoch>]], "contacts": [["<identity id>", <contact>]], "openings": [<opening>]}`, as the log stands at `position`. A device takes a state no older than its own; whatever its age, it takes the keys it lacks from it. At a loss of its own it stops: it takes no later message, appends nothing to the key log and hands out no state, until it takes a state past the loss.

- **Key log duties**: a device that holds the identity's current key reads the key log and then the devices group's log from their services, and, chained to the key log's last entry: appends an entry restating the list of devices (the group's members, by key and credential name) when it differs from the key log's, with a new key when a device left; and an entry with a new key and the same list once the current key is 30 days old by its `at`. A new key is one made in the group's current epoch that the key log has not taken, by this device or another, or else a new one, sent first as a held `key` message; the entry naming it is appended once another device's saved summary holds that message's position, or at once when the list to append names no other device. A device dropped by the key log is removed from the devices group, every one in one commit, by the group's duties. These run with each pass of the group's duties (DESIGN.md, Groups), as the key log moves, and, while a key of this device's waits, as summaries come that hold its message.
- **Missing key**: a device that holds no seed of the key log's current key asks each connected device for the state; once every device it asked has answered without it, or there was none to ask, it warns that the key was lost or taken over.
- **Leaving**: a device leaves an identity by sending `leave` in the devices group, once its sessions that speak as the identity left their groups; it drops the identity's state, and the devices group goes when its removal is committed. The identity's only device forgets the devices group instead, and the identity ends: its key log stays at its service, and no device holds its key.
- **Renaming**: a device's name is its credential's `name` in its devices groups, kept in `device.json` (`{"name"}`, written through a rename; the browser's record `web/device`). A rename commits an update naming it in each devices group, and the key log duty then lists it so.
- **Contacts**: `{"name", "how": "verified" | "introduced", "by", "at"}` (`by`: the introducer's identity id); a `how` a newer letmeknow named counts as `introduced`. A device on several identities writes contacts to the one it joined first.
- **Openings**: `{"group", "kind", "name", "membership", "members": ["<iroh key>"]}`. A session speaking as the identity in a group open to it has its device record the opening, and refresh `members` as the group's membership changes. An opening stays after the group is closed to the identity; a device that joins by it is refused when the Add is built (see Invites).

On a machine, the holder shares the device with its other session processes through two files in `LETMEKNOW_HOME`:

- `device-state.json`: `{"device": "<device name>", "identities": [[<identity ref>, "<name>"]], "keys": [["<identity id>", "<this device's key on it>"]], "contacts": [["<identity id>", <contact>]], "openings": [<opening>]}`, rewritten whenever it changes, through a rename. The others read it whenever they need the device's identities, contacts or openings.
- `device-endpoint`: the holder's second command channel (`{"port", "token"}`, a localhost TCP port taking one JSON line `{"token", "request"}` and answering one line, as each session's own `endpoint`). The others send it the requests only the device's node can answer: `identity` (`identity leave` once the session left its own groups), `invite --identity`, `join` with a device link, and three of their own, `{"cmd": "set_contact", "identity", "contact"}`, `{"cmd": "set_opening", "identity", "opening"}` and `{"cmd": "certify", "identity", "key"}`, answered with a certificate for the session key `key`.

## Invites

A member admits a joiner that meets a rule of the group: an invite, or an opening (see Devices group).

- **An invite** is a 16-byte random secret. Its inviter sends the group the held payload `invite` (see Messages), with the secret's SHA-256, and keeps the same record; every member that takes it holds it, until H after it expires. Its link is `https://letmeknow.dev/i#<fragment>`, where the fragment is `3.<g|d>.<secret>.<member>[.<member>...]`: version 3; `g` for a group, `d` for a device link; the secret; then the members to ask, the inviter first, then up to three members online whose summaries hold the `invite`'s position, waited for up to 5 seconds. Each member is its iroh key, then `~` and its relay URL only if that is not letmeknow.dev's; every field after the kind in unpadded base64url.
- **An opening**: the group's settings name the identity the joiner's certificate speaks as.

The joiner dials the members the link or the opening names, all at once, giving them 30 seconds to connect, then asks those it reached in turn, giving each 30 seconds to answer. It asks on an `admission` stream, with one frame, `{"secret", "key_package"}`, or for an opening `{"group", "key_package"}`; the identity it speaks as is in the KeyPackage's credential. It keeps the KeyPackage, its private keys and, for a device link, its new device key, at `node/joining/<SHA-256 of the secret, or the group id>`, until it joins or every member it reached refused it, and asks again with them.

The member answers `{"welcome", "position", "doc"}` or `{"refused": reason}`:

- If the log shows the joiner added, by the KeyPackage's key, and its leaf has not updated since, it answers with the Welcome of the commit entry that added it, after reading the log to its head.
- Else it admits by an invite it holds whose `expires` is ahead, that no commit it applied names, and whose inviter is a member with no counted `leave` sealed since its latest Add (refused otherwise as `its inviter left the group`); one made `--to` an identity, only a joiner whose certificate of it is verified against the identity's key log, read anew. It admits by an opening a joiner whose certificate is verified likewise and whose identity the group is open to. It refuses a joiner whose KeyPackage's leaf does not list the group's kind, and one whose session key is already a member's. It commits the Add with `how` and the invite's hash in the commit's authenticated data, checking the rule again each time it builds the commit.
- `position` is the commit entry's position in the log: the joiner reads the key logs of the identities its members speak as, then the entries after `position`, and anchors its chain at the first head it reads. `doc` links, as a file (see Files), the state of the group's kind, if its kind gives one within 10 seconds.
- An unknown, used or expired secret gets the same reason, `unknown, used or expired invite`; with 128 bits there is nothing to guess, so a refusal uses nothing up.

A device link is an invite into an identity's devices group: the new device joins with a new device key, its credential naming the device and no identity, and takes the identity's state, keys among it, as the kind's state.

The inviter tells the group who the joiner is to it (`introduce`), whoever admitted it, once it applies the Add; for an opening, the member that admitted it does.

## Messages

The plaintext of an MLS application message is JSON with a string `type`. `leave`, `introduce`, `invite` and `lost` are the core's; every other type belongs to the group's kind (see Kinds). A payload is held unless its sender marks it live with the message's authenticated data `{"live": true}`, which travels in the clear; a held message's authenticated data is empty.

| `type` | Fields |
|---|---|
| `leave` | none: the sender asks to be removed. Its Remove is due while the sender is a member, if it was sealed in or after the epoch the sender's latest Add moved into |
| `introduce` | `identity` (`id`, `membership`), `name`, `how` (`invite`, `open`, `introduce`), and optional `to`: who a member is to the sender; sent once someone joins by the sender's invite or the sender admits someone to an open group, and by `introduce` |
| `invite` | `hash`, SHA-256 of an invite's secret, `expires` (ms), and optional `label` (`--for`) and `to` (`--to`, an identity id): a rule any member admits a joiner by, once (see Invites) |
| `lost` | `positions`: counted positions of the group's log the sender can no longer open |
| `message` | chat's: `content`, `read`, and optional `to`, `reply_to`, `urgent`, `attachment` (below) |

An `introduce`'s `to` lists the members it is for, each as the first 8 bytes of SHA-256 of its session key; only they act on it (record the introduction, offer the contact), and the others ignore it. Without `to`, it is for the whole group.

A chat `message`'s fields: `content`, its text, which may be empty with an attachment; `read`, the positions of the group's log the sender had read when it sent this, as ranges, counting positions with no message as read; `to`, the members it addresses, each as the first 8 bytes of SHA-256 of its session key, or none for the group; `reply_to`, the id of the message it answers; `urgent`, `true` to wake every member; `attachment`, `{"link", "name", "size", "type"}`: a file link (see Files), its name, its size in bytes, and its media type, which may be empty. A chat holds the file an attachment links.

- A message's id is SHA-256 of its MLS ciphertext.
- A sender seals no message whose payload and authenticated data, with 1 KiB for MLS's framing, are over 1 MiB: `send` fails with `size` before the message uses a key. A member takes no ciphertext over 1 MiB.
- A held send is kept at `node/send/<first id>` as `{"payload", "epoch", "id", "ciphertext", "entry", "appended", "pending"}` until its entry counts or the service refuses it, and sealed again, under a new id, when a commit comes first. `appended` marks that its entry may have reached the service. After an append fails without a refusal, a send whose entry may have reached the service, or that `send` answered as pending, is appended again 5 seconds later; any other fails as `unavailable` if the service was not reached.
- A member keeps the ciphertext of each counted position from its start, its own included, and its opened message, for H after reading the entry.
- A lost position is announced by a duty in a held `lost` naming every known loss of the member's own that no counted or pending `lost` of its own names.

## Peer protocol

A `peer` stream joins two members that share a group, one stream per pair, kept open while both are online. Either side may send a frame at any time. Every frame but `hello` and `entries` names its group, and a side sends a group's frames only to a peer the gate admits, checked as each frame is written: its iroh key is in a leaf of the group's current epoch and, if its credential names an identity, the certificate is verified (see Checking). `hello` carries only the groups the gate admits the peer to; a `want` is answered even if the gate refuses it, with no items.

| Frame | Meaning |
|---|---|
| `{"hello": {"groups": [{"group", "head", "held", "read", "fetching"}], "heads": [<head>]}}` | Per group, a summary: the newest signed head of the group's log the sender holds (the last position read from the service), and as ranges within H: the positions it holds, those it has read (chat), and those it lacks and is fetching. `held` and `read` count positions with no message (commits, skipped entries) as covered; `held` leaves out lost positions. `heads`: the newest signed heads of the key logs the sent groups' members speak as |
| `{"entries": {"log", "entries", "head"}}` | Entries of a log the other lacks, judged by the longest head it showed or was sent, ending at `head` |
| `{"messages": {"group", "items": [{"position", "ciphertext"}], "answers"}}` | Ciphertexts of counted positions: pushed at send once the entry counts, without `answers`; or the answer to `want`, where `answers` is the asked positions the holder went through before its cap of about 1 MiB of ciphertext |
| `{"want": {"group", "positions"}}` | Message positions asked of one holder |
| `{"live": {"group", "items": ["<ciphertext>"]}}` | Live payloads |
| `{"state": {"group", "link"}}` | A link to a state of the group's kind (see Files) that the sender's kind hands this member; without `link`, a request for one |
| `{"want_files": {"group", "files"}}`, `{"have": {"group", "files"}}` | BLAKE3 hashes (see Files) |

- **`hello`** goes to a peer with every group served to it when the connection opens and every 5 minutes; when a group's summary changes (its head, held, read, fetching, or its key logs' heads), with the changed groups, 1 second after the first unsent change; and at once with a group whose gate opens for the peer, or of which the peer sent its first summary on this connection (a joiner drops the summaries that came before its Welcome).
- **Heads**: a side takes a head in `hello` or `entries` only for a log it follows, and only if the log's service signed it (a folder's need not be) or it is the empty log's. A head that its own chain contradicts (another hash at the same length) is reported, the two heads by length and hash, once while it runs, and the frame is dropped. A side sends a peer the entries the peer lacks of every log of the groups it serves it, by the longest head the peer showed or was sent; the receiver takes them if they chain onto its copy and end at their head.
- **Summaries** are saved per peer and group, `{"peer", "summary", "at"}` at `node/heard/<group>/<peer>`, overwritten by the next, and deleted when the peer's Remove is applied. Saved ones serve display and Away; repair and the wait use only those heard on the current connection, from peers the gate admits.
- **Taking**: a side takes `hello`, `entries` and `messages` from any peer: summaries are saved whatever the gate, entries checked against their head, and a ciphertext is kept only if it matches a counted entry (its id) of its own epoch (its clear header), or, from an admitted peer, before its entry is read, if it is for the current epoch or the next, up to 4 MiB per peer per group. It takes `want`, `want_files` and `have` only from an admitted peer, and `state` and `live` only from an admitted peer once it has applied its log to its head as last read; it sends `state` and `live` only then too. A live payload is taken only if its sender is in the current epoch, by leaf index and key.
- **Repair**: a member lacking counted positions since its start, within H, asks one `want` at a time per group, of the connected admitted peer whose summary holds the first of them it may ask, the lowest iroh key among several, naming every position that peer holds that it may ask. It may not ask a position whose entry it read under 2 seconds ago, unless it is waiting before a commit for it, nor one that peer omitted from an answer's `answers` since its last `hello`. An answer ends the request; so does 10 seconds without any frame from that peer, which is then skipped until it sends a frame. `fetching` is the positions it lacks that some connected admitted peer's summary holds and has not omitted.
- **The wait before a commit**: a member about to apply a commit that would delete the keys of the epoch before its current one, while it lacks counted positions of that epoch, applies it only once no current summary of a connected peer that the gate admits, or whose identity's key log it has not read yet, holds or is fetching one of them, or 10 seconds passed without progress (a summary that differs from that peer's last, a connection, a gate opening, or a lacking ciphertext arriving); but not before 3 seconds after it came online (its first connection after none) and after it joined the group or started. With no connection it has not come online, and waits until 10 seconds pass without progress. It then records what it lacks as lost. Before a commit that removes it, it opens what it holds of its current and prior epochs, and records the rest as lost.
- **`synced`**: a connected admitted member's `hello` shows the same length and hash of the group's log head as one's own. The member then asks it for the files it lacks (`want_files`), and for the kind's state if its kind has none to follow the log from.

## Files

- A file's key is 32 random bytes. Its ciphertext is the STREAM construction as in age: the plaintext in chunks of 65,520 bytes (the last shorter, and empty only for an empty file), each sealed with ChaCha20-Poly1305 under the key, with the nonce u88 big-endian chunk counter ‖ `0x01` for the last chunk, else `0x00`. Sealed chunks are 64 KiB.
- Its hash is BLAKE3 over the whole ciphertext. A link is `lmk:<hash, hex>.<plaintext size>#<key, hex>`.
- Transfer is iroh-blobs `=0.103.1` on its own ALPN, kept inside one module. A holder admits a connection only from the iroh key of a peer it serves a group they share, a request only for a file one of those groups holds, and checks again every 16 KiB it sends.
- A member holds, for a group, the files linked within H (those its kind holds, from when it held them: a chat's attachments, from when the message opened; files it added; states beside Welcomes and in `state` frames, sent or taken), and the files its kind links now. It serves and wants only those, and deletes every other file it holds once an hour.
- A member asks a connected member with `want_files` for the files it holds for a group but lacks, within its limit (the plaintext size a link names, at most the limit): on `synced`, and on each new link. Each answers `have` with those it holds, and the member fetches from several holders at once, resuming where a transfer stopped. A file this member added that no other member holds is pending until one does.

## Storage

- `LETMEKNOW_HOME` holds `format` (`3`, the layout of what it holds; a session refuses a home that holds state without it), `device.json`, `device.lock`, `device.db`, `device-files/`, `device-state.json`, `device-endpoint`, `addresses/`, and `sessions/<handle>/` per session: `session.db`, `endpoint` (its command channel, `{"port", "token"}`), `files/`, `attachments/<group, hex>/`, and `kinds/<kind>/`, each plugin's own directory.
- A node's state is one SQLite database (`session.db`, `device.db`) with WAL, `synchronous = NORMAL` and `secure_delete`: openmls's tables (`openmls_sqlite_storage`, values as CBOR) and the table `lmk (key, value)` for its own records, as JSON. After it deletes secrets or text (a message's text once shown, what it carried past H, a group it leaves, epochs dropped), it checkpoints with `wal_checkpoint(TRUNCATE)`, so no copy stays in the WAL. The session process adds its own tables to `session.db`: `session` (its name), `taken` (the messages it was told of, and whether shown) and `attachments`.
- Each step runs in one transaction, and each log entry and ciphertext under a savepoint within it, rolled back, with the group reloaded from storage, when openmls rejects it. What a step produces goes out once it has committed.
- A node's records, by key: `session` (its MLS key, credential and leaf), `node/iroh`, `node/groups` and `node/group/<group>` (each group's record: its position, start, the positions read past H, unopened and lacking positions, sends, files, invites, counted `leave`s and `lost`s, its read ranges), `node/logs`, `node/log/<log>` and `node/entry/<log>/<position>`, `node/pos/<group>/<position>`, `node/id/<group>/<id>`, `node/ciphertext/<group>/<position>`, `node/message/<id>`, `node/send/<id>`, `node/heard/<group>/<peer>`, `node/kind/<group>/<position>` (what was handed to the kind and not yet read past), `node/device-key/<group>`, `node/joining/<target>`, and the kinds' own under `kind/` (`kind/devices/<group, hex>`, `kind/client/introductions`). Positions are u64 big-endian, other parts raw bytes.

## Kinds

A kind id is a plain string: `chat` and `devices`, built in, or a plugin's, such as `doc` or `git`. The core reads none of a kind's content.

### Plugins

A native session finds a kind's plugin as the executable `letmeknow-kind-<kind>` (`.exe` on Windows) in the directory of its own executable, then in each directory of `PATH`; the first found wins. Its leaf lists `chat` and every kind it found. It starts a plugin when it has a group of its kind (when it starts, makes one or joins one) or a command for it, with stdin and stdout piped and stderr its own, and stops it with itself, closing its stdin and waiting up to 5 seconds; one that stops, it starts again and tells it its groups.

They speak JSON lines: one JSON object per line, each way. Bytes are unpadded base64url, and so are group ids; message ids are hex. A member is described as `listen` events describe it (`name`, `fp`, `device`, `identity`, `added_by`, `you`), and named by its `fp` in `to`. A message with an `id` is a request: the other side answers `{"type": "answer", "id", "answer"}`, or `{"type": "answer", "id", "error"}`. A side skips a message of a `type` it does not know, but answers one with an `id` with an error. A plugin hears only of its kind's groups, and the session refuses what it asks of others.

The session sends:

| Message | Meaning |
|---|---|
| `{"type": "start", "id", "kind", "dir"}` | The first line, a request. `dir` is the plugin's own state directory, `sessions/<handle>/kinds/<kind>/`. Answered `{}`, or `{"chat": true}` if the kind's groups carry chat too: then their `message` payloads are the session's chat, which `send` sends there, and do not reach the plugin |
| `{"type": "group", "group", "settings", "me"}`, and optionally `id`, `command`, `args`, `cwd` | The session is in a group of the kind: for each when the plugin starts, and when the session makes one (`command`: `invite`) or joins one (`join`), with the command's arguments for the kind and the directory they are relative to, as a request. `me` is this session as the group's members see it. A session whose plugin refuses a group it makes or joins leaves it |
| `{"type": "gone", "id", "group"}` | The session left the group, or was removed: answered once the plugin let go of what it kept for the group, such as a doc file it made |
| `{"type": "message", "group", "from", "payload", "held"}`, and `id` and `position` if held | A payload of the kind from another member: live, or held, in position order as it opens |
| `{"type": "entry", "group", "position", "id", "from", "payload"}` | A held message of the kind, in log order, its own included |
| `{"type": "lost", "group", "position", "member", "positions", "ids"}` | A loss, in log order: this session's own at the lost position (`member.you`), another member's at its announcement; `ids` are the lost messages' ids this session knows |
| `{"type": "synced", "group", "member"}` | A connected member's `hello` shows the same head of the group's log: a time to compare state |
| `{"type": "state", "group", "from", "data"}` | A state `from` handed this session, beside the Welcome that admitted it or in a `state` frame |
| `{"type": "snapshot", "id", "group"}` | A member is being admitted, or asks for a state: answered `{"data"}` to hand it one, or `{}`. The session waits 10 seconds |
| `{"type": "command", "id", "args", "cwd"}` | `letmeknow <kind> <args>...`, run in `cwd`: the answer is what the command prints. The session goes on meanwhile |
| `{"type": "sync", "id"}` | Bring into step what the plugin keeps outside letmeknow, such as a doc's file: asked before the session prints anything and before each command, which wait for the answer |
| `{"type": "printed", "group", "key"}` | The plugin's event with this `key` was printed |

The plugin sends:

| Message | Meaning |
|---|---|
| `{"type": "send", "group", "payload"}`, and optionally `held`, `to`, `id` | Seals and sends a payload of the kind. With `held: true` the core orders it, and a request is answered `{"id", "position"}` once its entry counts and the plugin was handed its entries up to there, or `{"id", "pending": true}` after 5 seconds, or with an error (`unavailable`, `rate`, `size`); otherwise it is live, to the member `to` or to every member online, and dropped while the session is behind its log |
| `{"type": "log", "group"}`, and optionally `after` | Follows the group's held messages after position `after`, as the kind's own state stands: they come as `entry` and `lost`, those kept after `after` first, and those up to `after` go. Each comes at least once after the `after` the kind last named, so after a restart those it had not read past come again; the kind drops one at a position it took already. Without `after`, or with one before a position it named earlier, the kind has no state to follow from, and the session asks a member for one, at most once a minute |
| `{"type": "add", "id", "group", "data"}` | Seals a file, held for the group: answered `{"link"}` |
| `{"type": "hold", "group", "links"}` | Holds files for H from now, unless held already, as those a held message links |
| `{"type": "links", "group", "links"}` | The files the kind links now, which replace those it linked before |
| `{"type": "fetch", "id", "group", "link"}` | A file the group holds: answered `{"data"}` once it is here, fetched from the members online, or with an error after a minute |
| `{"type": "spread", "id", "group", "link"}` | Waits until a member online holds a file whole, up to 30 seconds: answered `{"held_by"}`, at once with none if no member is online |
| `{"type": "state", "group", "to", "data"}` | Hands a member a state |
| `{"type": "event", "group", "event"}`, and optionally `wake`, `key` | For `listen`, which prints `event` with the group's id in `group`: by the delivery policy at once with `wake: true`, held otherwise. An event of type `warning` prints at once, as the session's own. With `key`, it replaces a held event of the plugin's for the group with the same key, and is told as `printed` |
| `{"type": "info", "group", "info"}` | Fields `groups` shows for the group |

The client core (`lmk-client`) is the host in every client; the transport is its shell's. The browser's in-page plugins speak the same messages, as JSON values handed to them and taken from them in the page: `start` names no `dir`, and they send no `spread`. The page sends their commands (`Lmk.command(kind, args)`), and gets their events as `{...event, "group", "kind"}`.

### Git

The git kind's plugin is `letmeknow-kind-git`, with git's remote helper `git-remote-lmk` beside it; in the browser, `lmk_kind_git::Page` runs in the page, display-only. Its groups carry chat (`start` answers `{"chat": true}`).

- A push is the held payload `{"type": "push", "ref", "old", "new", "bundle", "subjects"}`: the full ref name, the old and new commit ids (hex), each null for a branch created or deleted, the file link of a git bundle of the new commits, or null if they need none, and their subjects, newest first, at most 50.
- The pusher adds the bundle as a file, sends the live payload `{"type": "bundle", "link"}`, which members' plugins answer by holding the link (and so fetching it), and asks `spread`. Only once a member holds the bundle whole does it send the push, held; with none, the push fails and nothing is sent.
- A member replays the pushes its entries name, in log order, over its branches: a push counts if `old` is its ref's tip (none, for one created), and then moves the ref to `new` or deletes it. A member checks each push in log order: it unbundles the bundle into its repository (`git bundle unbundle`, which needs the bundle's prerequisites), and the push is void if that fails, or `new` is not a commit there, or `old` is not its ancestor (`git merge-base --is-ancestor`). Void pushes are left out of the replay. The repository's refs are the branches replayed as far as every push is checked; a push must build on the branches replayed counting those not checked yet. A pusher's push won if it counted when its entry was taken.
- At a `lost` of its own, the plugin stops: it refuses pushes, takes no later entry and hands no state, and asks for a state with `log` without `after`.
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

- The client is the client core (`crates/client`) on lmk-node, compiled to WebAssembly (`crates/web`). The browser is one device and one session: its node is the device's node too, so it is in its identities' devices groups with a device key per identity, and its sessions' certificates are by those keys. Its iroh key is separate, as natively, and it reaches every peer and membership service through relays.
- Its records live in an IndexedDB database `lmk`, version 3. The store `records` holds the provider's, one record per key: openmls's own keys, and ours under `lmk/` (the node's records as in Storage, the page's `web/device`, `web/name`, and per group `web/timeline/<group>` (the changes, introductions, pushes and losses it saw), `web/messages/<group>` (`[[<id>, <at>]]`, the chat messages and `leave`s its timeline stored, oldest first) and `web/settings/<group>` (as last seen), each stored message at `web/message/<id>`, as the node handed it, for 90 days from when it came (once one is stored, the node's copy of another member's chat message has `content` `""`), and the in-page plugins' `kind/doc/<group id, base64url>`, each doc's Yjs state, and `kind/git/<group id, base64url>`, each git group's branches). Each step's changes are written as one transaction before what the step produced goes out. The store `files` holds the ciphertext of each file it holds, by BLAKE3 hash (hex): the files it adds, and those it fetches up to 25 MiB, which it takes without being asked. The page reads only their hashes when it opens; the session loads a file into iroh-blobs' memory store when it reads it, or when a member's `want_files` names it. It answers `have` only for files in this store, so a larger file fetched when asked, which stays in memory only, is served to no one. When the page opens and once an hour, it deletes the files no group holds, by the rule in Files.
- Its membership service is the one `letmeknow serve` names at `GET /membership`, as text, `<iroh key, hex>@<relay URL>`, on the server the page came from; its relay is that address's relay URL. `localStorage` can name others, as tests do: `lmk relay` (a URL) and `lmk membership` (the same form). The service worker caches `/membership` with the build's files.
- The page serves `/i` as the app, which reads the invite from the fragment.
- A service worker caches exactly the files of one build, under a name derived from their contents, and serves navigations with its `index.html`. A new build installs beside it and waits; the page offers it, and on acceptance tells it `"skip"`, and every tab the old one served reloads.
- One tab at a time runs the session, holding the Web Lock `letmeknow`; every other tab waits for the lock, and meanwhile calls the session over the BroadcastChannel `letmeknow`. A call is `{"id", "method", "args"}`, a method of the WebAssembly's `Lmk` (or `open`, which starts a new session with a name and a device name); its method `request` takes the client core's requests, as the session process's command channel does (`{"cmd", ...}`), and answers as it does, answered by `{"id", "result"}` or `{"id", "error"}`. The running tab posts each event as `{"event"}`, and `{"ready": true}` once the session runs and whenever a tab posts `{"ask": true}`. A tab sends its unanswered calls again on each `ready`, and the running tab answers each call id once. When the running tab closes, the next tab takes the lock and runs the session from IndexedDB.
- `Lmk.items(group, shown)` answers a group's timeline: the messages it stored, its changes and losses, oldest first, then its pending sends; its own messages carry `held_by`, `read_by`, `lost_by` and `only_here`. With `shown`, the messages are marked read. `Lmk.only_here()` counts the sends no other member holds yet.

Push notifications are an idea for later (see IDEAS.md).

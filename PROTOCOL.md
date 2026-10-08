# letmeknow protocol (draft)

The exact formats behind REWRITE.md, settled by the wave-1 prototypes on the `spike/*` branches (each has a FINDINGS.md).

## Conventions

- Our own structures are JSON, with bytes as unpadded base64url, except where a section gives a binary layout.
- A signature covers an explicit byte string: a context string ending in a NUL byte, then the exact bytes being vouched for. Signers send the bytes they signed, and verifiers check those bytes, so nothing depends on canonical JSON.
- Hashes are SHA-256, keys and signatures Ed25519, except files, which hash with BLAKE3 (see Files).
- On a QUIC stream, every frame is a 4-byte big-endian length, then that many bytes of JSON.

## Connections

- All of our protocols use one ALPN, `letmeknow/1`, so two endpoints keep one connection. Each exchange is a bidirectional stream whose first frame names it: `{"stream": "membership" | "peer" | "invite"}`. File transfers use iroh-blobs' own ALPN.
- Endpoints use iroh's `presets::Minimal` with a relay map holding our relays, and dial `EndpointAddr::new(key).with_relay_url(url)`, from the addresses that leaves, settings and invite links carry. iroh 1.3.0; the browser build enables only `tls-ring`.
- Sessions of one device write their current direct addresses to `LETMEKNOW_HOME/addresses/<iroh key>.json` and dial each other from there, with no relay needed.
- The session process calls `proxy_from_env()`.

## Keys

- **Device key**: Ed25519, in `device.json` (CLI) or IndexedDB (browser). It signs its sessions' keys and its identity's device list entries.
- **Session key**: the MLS signature key of one member.
- **iroh key**: each session's iroh endpoint key, separate from its MLS key and named in its leaf. A membership service's iroh key is also its signing key for heads.
- A session's device signature: Ed25519 by the device key over `"letmeknow session v1\0" ‖ session public key`.

## Membership service

### Logs

A log is named by an id: a group's MLS group id, or a device list's address (see Identity). Positions start at 1. Each member chains a log as it reads it:

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

Two connected members exchange the newest signed heads they hold for the logs they share (see Peer protocol). A head that a member's own chain contradicts (same length, other hash; or a shorter head that is not a prefix of its chain) is proof: the session reports both heads in a `warning`.

## Groups

### Settings

A group context extension, of the private-use type `0xff01`, whose data is JSON:

```json
{"protocol": 1, "kind": "chat" | "doc", "name": "", "open": [{"id": "<identity id>", "name": "Matthew"}], "keep": 90,
 "membership": {"serve": {"key": "<iroh key>", "relay": "<url>", "addrs": ["<ip:port>"]}} | {"folder": "<path>"},
 "devices_of": "<identity id>", "openings": [<opening>]}
```

`devices_of` marks an identity's devices group, and `openings` appear only there (see Identity). Members list `0xff01` and `0xff02` in their capabilities.

### Leaf data

A leaf node extension, of type `0xff02`, whose data is JSON:

```json
{"key": "<iroh key>", "relay": "<url>"}
```

A changed relay is an update commit.

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
- State is stored in SQLite with WAL and `synchronous = NORMAL`, encoded as CBOR (ciborium; openmls cannot be read back by bincode). The browser stores openmls state in IndexedDB, one record per key, not as one dump.
- Every change is inline in its commit; standalone proposals are never sent, and a commit that refers to one is invalid. So is an update that changes a member's credential identity or device.
- A member reads its group's log in order. For the epoch it is in, the first entry that is a valid commit for that epoch is applied; every other entry is skipped.
- A committer saves its commit's bytes, posts them, and merges (`merge_pending_commit`) only if its entry, found by those bytes, is the first valid commit for its epoch; otherwise it clears it (`clear_pending_commit`), applies the winner (`merge_staged_commit`), and redoes its change on the new epoch.
- Once the log has taken a commit, its author sends it to the members online (see Peer protocol).

## Identity

### Device list

- The address of an identity's log is SHA-256(`"letmeknow device list address\0"` ‖ id), and its entries are sealed with ChaCha20-Poly1305 under HKDF-SHA256(ikm = id, info = `"letmeknow device list key"`), each with a random 12-byte nonce in front. The service sees only ciphertext; whoever knows the id can read the list.
- An entry, before sealing, is `{"body": "<bytes>", "sig": "<sig>"}`. `body` is JSON, `{"prev": "<hash of the previous entry's body>" | null, "op": "create" | "add" | "remove", "device": "<key>", "device_name": "", "by": "<signing device key>"}`, plus `"name"` and `"membership"` on `create`. `sig` is by `by` over `"letmeknow device list v1\0"` ‖ body.
- The identity's id is SHA-256 of the first entry's body. A credential names the id and its service; the first entry proves both.
- Valid entries: `create` first, signed by the device it names; then each `prev` names the latest valid entry, and `by` is on the list at that point. A removal is final. Members apply the first valid entry per `prev`, in log order, and skip the rest.

### Contacts

An identity's contacts live in its devices group as a Yjs map from identity id to `{"name", "how": "verified" | "introduced", "by", "at"}` (`by`: the introducer's identity id). It is synced like a doc's text: edits live, catch-up by diff, and its state linked in the Welcome.

### Devices group

An identity's devices group is a chat whose settings carry `devices_of`. Its members are devices, not sessions: on a machine, whichever session process is running acts for the device, holding a lock in `LETMEKNOW_HOME`, and records what it learns (openings) there for the device's other sessions. In a browser, the device is the session.

An opening, in its settings: `{"group", "kind", "name", "membership", "members": ["<iroh key>"]}`. A member that is a device of the identity writes it, and refreshes `members` when the group's membership changes.

## Invites

A link is `https://letmeknow.dev/i#<fragment>`, where the fragment is `1.<g|d>.<inviter's iroh key>.<secret>[.<relay>]`: version 1; `g` for a group, `d` for a device link; the key and a 16-byte random secret in unpadded base64url; the relay URL, percent-encoded, only if it is not letmeknow.dev's.

The joiner opens an `invite` stream to the inviter's key and sends `{"secret", "key_package"}`, or `{"secret", "device": "<device key>", "device_name"}` for a device link. The inviter checks the secret (single use, 10 minutes), commits the Add (for a device link: appends to the device list and adds the device to the devices group), and answers `{"welcome", "position", "doc"}`: `position` is the log position the joiner reads from, and `doc`, for a doc, links the doc's state as a file (see Files). A wrong or used secret gets `{"refused"}`; with 128 bits there is nothing to guess, so it uses nothing up.

## Messages

The plaintext of an MLS application message is JSON with a `type`:

| `type` | Kind | Fields |
|---|---|---|
| `message` | chat | `content`, `after`, and optional `to`, `reply_to`, `urgent`, `attachment`, as today |
| `edit` | doc | `update`: a Yjs v1 update, sent live to the members online and not held |
| `diff` | doc | `update`: a Yjs v1 update answering `doc_sv` (see Peer protocol), not held |
| `leave` | every | none: the sender asks to be removed; the first member to see it commits the Remove |
| `introduce` | every | `identity` (`id`, `membership`), `name`, `how` (`invite`, `open`, `introduce`): who a member is to the sender; sent after the sender adds someone, and by `introduce` |

A message's id is SHA-256 of its MLS ciphertext. A member holds `message` and `leave` for `keep` days, and only once it has decrypted and verified them. It takes no message from a removed sender that first reaches it more than 5 minutes after it applied the removal.

## Peer protocol

A `peer` stream joins two sessions that share a group, one stream per pair, kept open while both are online. Either side may send a frame at any time; every frame names its group, and a side serves a group only to a peer whose iroh key is in a leaf of that group's current epoch.

| Frame | Meaning |
|---|---|
| `{"hello": {"groups": [{"group", "epoch", "head", "floor", "joined"}]}}` | For each group both are in: the epoch the sender is at, the newest signed head it holds, the lowest epoch it accepts, and the epoch it joined |
| `{"commits": {"group", "entries", "head"}}` | Log entries the other lacks, judged by its head; also sent by a commit's author once the service has taken it |
| `{"reconcile": {"group", "msg"}}` | A negentropy message (see below) |
| `{"messages": {"group", "items"}}` | MLS ciphertexts the other lacks; also every new message as it is sent |
| `{"doc": {"group", "snapshot"}}` | SHA-256 of `txn.snapshot().encode_v1()` |
| `{"doc_sv": {"group", "sv"}}` | A Yjs state vector, sent when the snapshots differ; answered by a `diff` message |
| `{"want": {"group", "files"}}`, `{"have": {"group", "files"}}` | BLAKE3 hashes (see Files) |
| `{"join": {"group", "key_package"}}` | A request to join an open group, answered like an invite |

Message sync, per group, starts once both sides have caught up on commits. It is negentropy (crate `negentropy` 0.5) over items whose timestamp is the epoch and whose id is the message id, from epoch max(the later `joined`, the lower `floor`). `reconcile` frames alternate until negentropy is done; then `messages` carries what each lacks, never older than the receiver's `floor`. Ids a member gave up on (beyond its key window) stay in its set, so they are not offered again.

## Files

- A file's key is 32 random bytes. Its ciphertext is the STREAM construction as in age: the plaintext in chunks of 65,520 bytes (the last shorter, and empty only for an empty file), each sealed with ChaCha20-Poly1305 under the key, with the nonce u88 big-endian chunk counter ‖ `0x01` for the last chunk, else `0x00`. Sealed chunks are 64 KiB.
- Its hash is BLAKE3 over the whole ciphertext. A link is `lmk:<hash, hex>.<plaintext size>#<key, hex>`.
- Transfer is iroh-blobs `=0.103.1` on its own ALPN, kept inside one module. A holder admits a connection only from the iroh key of a current member of a group the two share, a request only for a file one of those groups links, and checks again every 16 KiB it sends.
- A member asks connected peers with `want`; each answers `have` with those it holds, and the member fetches from several holders at once, resuming where a transfer stopped. A browser keeps the ciphertext in its own storage (IndexedDB), since iroh-blobs keeps only memory there.

## Browser

Push notifications are deferred; the push prototype's design is on `spike/push` (see REWRITE.md, Later).

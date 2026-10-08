# letmeknow protocol (draft)

The exact formats behind REWRITE.md. Sections marked **pending** wait on the wave-1 prototypes in `spike/*`.

## Conventions

- Our own structures are JSON, with bytes as unpadded base64url, except where a section gives a binary layout.
- A signature covers an explicit byte string: a context string ending in a NUL byte, then the exact bytes being vouched for. Signers send the bytes they signed, and verifiers check those bytes, so nothing depends on canonical JSON.
- Hashes are SHA-256, keys and signatures Ed25519, except files (see Files, pending).
- On a QUIC stream, every frame is a 4-byte big-endian length, then that many bytes of JSON.

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

ALPN `letmeknow/membership/1`. A client opens one bidirectional stream per request and gets one answer, except `subscribe`, which stays open.

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

Two connected members exchange the newest signed heads they hold for the logs they share (see Peer protocol, pending). A head that a member's own chain contradicts (same length, other hash; or a shorter head that is not a prefix of its chain) is proof: the session reports both heads in a `warning`.

## Groups

### Settings

A group context extension, of the private-use type `0xff01` (pending: the MLS prototype), whose data is JSON:

```json
{"kind": "chat" | "doc", "name": "", "open": [{"id": "<identity id>", "name": "Matthew"}], "keep": 90,
 "membership": {"serve": {"key": "<iroh key>", "relay": "<url>", "addrs": ["<ip:port>"]}} | {"folder": "<path>"},
 "devices_of": "<identity id>", "openings": [<opening>]}
```

`devices_of` marks an identity's devices group, and `openings` appear only there (see Identity). Members list `0xff01` and `0xff02` in their capabilities.

### Leaf data

A leaf node extension, of type `0xff02`, whose data is JSON:

```json
{"key": "<iroh key>", "relay": "<url>", "push": {"endpoint", "p256dh", "auth", "vapid": "<private key>"}}
```

`push` is present only for browsers (see Browser, pending). A changed relay or push key is an update commit.

### Credential

An MLS basic credential whose identity bytes are JSON:

```json
{"name": "Builder, Matthew's agent", "device": "<device public key>", "device_sig": "<sig>", "device_name": "laptop",
 "identity": {"id": "<identity id>", "membership": <as in settings>} | null}
```

A member checks `device_sig` and the identity's device list (see Identity) when it first sees the credential and again when either changes. The result marks the member; it never decides whether a commit is valid.

### Commits

- Every change is inline in its commit; standalone proposals are never sent.
- A member reads its group's log in order. For the epoch it is in, the first entry that is a valid commit for that epoch is applied; every other entry is skipped.
- A committer posts its commit and merges it only if the log's answer shows it first for its epoch; otherwise it clears it, applies the winner, and redoes its change on the new epoch.
- Once the log has taken a commit, its author sends it to the members online (see Peer protocol, pending).

## Identity

### Device list

- The address of an identity's log is SHA-256(`"letmeknow device list address\0"` ‖ id), and its entries are sealed with ChaCha20-Poly1305 under HKDF-SHA256(ikm = id, info = `"letmeknow device list key"`), each with a random 12-byte nonce in front. The service sees only ciphertext; whoever knows the id can read the list.
- An entry, before sealing, is `{"body": "<bytes>", "sig": "<sig>"}`. `body` is JSON, `{"prev": "<hash of the previous entry's body>" | null, "op": "create" | "add" | "remove", "device": "<key>", "device_name": "", "by": "<signing device key>"}`, plus `"name"` and `"membership"` on `create`. `sig` is by `by` over `"letmeknow device list v1\0"` ‖ body.
- The identity's id is SHA-256 of the first entry's body. A credential names the id and its service; the first entry proves both.
- Valid entries: `create` first, signed by the device it names; then each `prev` names the latest valid entry, and `by` is on the list at that point. A removal is final. Members apply the first valid entry per `prev`, in log order, and skip the rest.

### Devices group

An identity's devices group is a chat whose settings carry `devices_of`. Its members are devices, not sessions: on a machine, whichever session process is running acts for the device, holding a lock in `LETMEKNOW_HOME`, and records what it learns (openings) there for the device's other sessions. In a browser, the device is the session.

An opening, in its settings: `{"group", "kind", "name", "membership", "members": ["<iroh key>"]}`. A member that is a device of the identity writes it, and refreshes `members` when the group's membership changes.

## Invites

A link is `https://letmeknow.dev/i#<fragment>`, where the fragment is `1.<g|d>.<inviter's iroh key>.<secret>[.<relay>]`: version 1; `g` for a group, `d` for a device link; the key and a 16-byte random secret in unpadded base64url; the relay URL, percent-encoded, only if it is not letmeknow.dev's.

ALPN `letmeknow/invite/1`. The joiner opens a stream to the inviter's key and sends `{"secret", "key_package"}`, or `{"secret", "device": "<device key>", "device_name"}` for a device link. The inviter checks the secret (single use, 10 minutes), commits the Add (for a device link: appends to the device list and adds the device to the devices group), and answers `{"welcome", "position", "doc"}`: `position` is the log position the joiner reads from, and `doc`, for a doc, links the doc's state as a file (see Files). A wrong or used secret gets `{"refused"}`; with 128 bits there is nothing to guess, so it uses nothing up.

## Messages

The plaintext of an MLS application message is JSON with a `type`:

| `type` | Kind | Fields |
|---|---|---|
| `message` | chat | `content`, `after`, and optional `to`, `reply_to`, `urgent`, `attachment`, as today |
| `edit` | doc | pending: Sync (per-edit updates or state-vector diffs) |
| `leave` | every | none: the sender asks to be removed; the first member to see it commits the Remove |

A message's id is SHA-256 of its MLS ciphertext.

## Peer protocol

**Pending: iroh, Sync, Files.** ALPN `letmeknow/peer/1`. It carries: an opening exchange of shared groups and signed heads; commit pushes; message sync; file want-lists and transfers; join requests to open groups. A peer serves a group's data only to current members of that group, recognised by the iroh key in their leaf.

## Files

**Pending: Files.** Chunked sealing, BLAKE3 over the ciphertext, verified streaming, and the link format.

## Browser

**Pending: Push.** Web Push subscription and the self-generated VAPID key, the notice payload, the service worker.

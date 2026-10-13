# 0.18: routes leave the data

Draft 4: the implementation contract. It folds in the reviews and validation of draft 3 and names services by domain.
Existing chats, docs and identities do not carry over (#56). The plan goes when 0.18 ships.

## Why

0.17 records how to reach a node in the data that node shares:

- **Leaves:** each member's relay (`Leaf.relay`, crates/proto/src/group.rs:60-69). Moving relays is a commit (`due`,
  crates/node/src/duties.rs:115-131).
- **The service's route:** `Service::Serve { key, relay, addrs }` (group.rs:24-36) in group settings, identity references
  (so every certificate), the identity genesis (so the identity's id) and each followed log's record (`Log.service`,
  crates/node/src/logs.rs:65-74; clients keyed by it, logs.rs:37-46).
- **Invite links:** members' relays (`Address.relay`, crates/proto/src/links.rs).
- **Config:** `--membership <key>@<relay>`, `--relay`, backend.json, localStorage.

A route is connectivity, not identity. 0.18 keeps keys in data, and names services by domain, as email does.

## Model

- **Keys are what's trusted.** Leaves, settings, identity genesis and stored state name nodes by iroh key only.
- **Domains are hints.** A service is found by its domain: `host` or `host:port`, where `serve` runs.
  - It publishes its **directory** at `https://<domain>/.well-known/letmeknow.json`:
    `{"key": "<service key, hex>", "addrs": ["relay.letmeknow.dev:7843"], "relays": ["https://relay.letmeknow.dev"]}`.
    `addrs` are `host:port`, resolved at dial (browsers skip them). `relays` are the relays its members live on.
  - Hints that carry a domain: identity references (beside the service key, outside the genesis, so an id commits to
    the key only), invite links (the group's service), and `--membership`.
  - A directory binds a domain to a key only when the key is the one expected: the identity's, the Welcome's, or, for
    `--membership`, whatever the domain serves (TLS authenticates it). Nothing rebinds the own service.
  - Fetching: https only, no redirects, body at most 64 KB, 1 to 16 relays, each `https`. It honours `LETMEKNOW_CA` and
    iroh's proxy rule (HTTP_PROXY > http_proxy > HTTPS_PROXY > https_proxy; NO_PROXY ignored; iroh endpoint.rs:706-716).
  - A session fetches the directories it uses at start and daily, and caches them with its state. letmeknow.dev's is
    built in (`DOMAIN` = `relay.letmeknow.dev`, crates/proto/src/links.rs; web/backend.json), used while no fetch has
    succeeded. Any other domain with no cached copy and no fetch is an error: `listen` fails naming the domain.
- **Each log record keeps its service's domain:** from `--membership` for groups a session makes, the link for groups it
  joins, the identity reference for public logs it reads.
- **A session lives on its deployment's relays:** its own directory's `relays`, from which iroh picks the nearest as
  home and moves off a dead one in about a minute. **Chosen relays** (`--relay`, repeatable) replace them: the session
  lives only there.
- **Relay hints:** a member's summary gains `relay`, its current home relay.
  - Summaries are signed by the member, passed on unchanged, newest wins, saved, kept within the group, swapped on
    connections that share a group (crates/net/src/peers.rs:208-224).
  - A change of home relay (net watches it) marks every group changed, so the summary is re-signed within
    max(1 s, 250 ms × members) (crates/node/src/peering.rs:199-203).
  - A summary without `relay` (iroh has none yet) keeps the hint saved before. Across groups the newest by `time` wins.
  - Hints survive restarts. Any `https` relay is taken: as with 0.17's leaf relays, a member may name any relay.
- **Reachability:** every member following a group's log is reachable through that group's service's relays: it dials
  the service at its addrs plus its relays, and its connection keeps a backup relay path there (validated).

## Dialing

The node hands net, per peer, a hint and a fallback set. Net dials:

1. **The hint:** the peer's hinted relay, the chosen relays, and the same-machine addresses (`addresses/`).
2. **The fallback:** after 2 s without a connection, or at once with no hint, net drops the first attempt (two live
   attempts make two connections, and `register` would replace one) and dials again with the hint plus every relay of
   every directory the session holds. It gives up after 5 s more; an offline peer otherwise costs about 18 KB per relay
   over iroh's 30 s handshake, on every redial (backoff 10 s to 600 s, peers.rs:31-33).

- **The membership service:** dialed at its directory's addrs plus its relays.
- **Admission:** the joiner dials the link's members through the link domain's relays, at once; they are reachable there.

## Formats: the switches 0.18 flips

- **Group protocol:** `PROTOCOL` 6 → 7. `Leaf { key, kinds, revision }`. `Service::Serve { key }`.
  `IdentityRef { id, membership, domain }`. `due` no longer commits for relays.
- **Invite link:** `https://letmeknow.dev/i#7.<g|d>.<secret>.<domain>.<member>[.<member>...]`, every field after the
  kind unpadded base64url, members by key only. A `6` link: "this invite link is from letmeknow 0.17, whose groups this
  version cannot join: ask for an invite to a group made with letmeknow 0.18". The web app's older-invite text follows.
- **Summary:** gains `relay` (optional).
- **Home format:** 6 → 7; a format-6 home gets the 0.17 command, as format 5 gets 0.16's (crates/session/src/lib.rs:80-93).
- **Browser:** database, Web Lock and BroadcastChannel `lmk6` → `lmk7` (web/src/store.ts:7, web/src/client.ts:75,168,
  web/e2e.mjs).
- **Not flipped:** the ALPN `letmeknow/3` and the membership stream: one service serves 0.17 and 0.18 sessions; their
  groups never meet (crates/core/src/group.rs:380). The service's data stays. compat.py runs the released 0.17 against
  the new `serve`, composing 0.17's `<key>@https://<domain>` from what `serve` prints.
- **0.17 settings:** a `--membership`, `LETMEKNOW_MEMBERSHIP` or `lmk membership` of 0.17's form (`<key>@<relay>`) is
  refused with a message naming 0.18's (`--membership <domain>`).

## Config

- **`listen`, `sessions remove`:** `--membership <domain>` (`LETMEKNOW_MEMBERSHIP`), default `relay.letmeknow.dev`;
  `--relay <url>`, repeatable (`LETMEKNOW_RELAY`, comma-separated): chosen relays. `listen` prints
  `membership: <domain>`.
- **`serve`:** `--relays <url>…`, the relays its directory names, default its own. It prints `membership: <domain>` and
  `key: <hex>`, serves the directory with `Access-Control-Allow-Origin: *` (as `/ping` does, crates/serve/src/lib.rs:292).
- **Browser:** backend.json is letmeknow.dev's directory plus its domain. localStorage `lmk membership` (a domain) and
  `lmk relay` (chosen relays, comma-separated).

## Steps

Each step leaves `main` building, its tests passing and clippy clean, with its own tests, and commits as it goes.

- **A. Directory and serve.** `Directory` in crates/proto (parse, validate, the built-in copy, `DOMAIN`); `serve`'s
  `/.well-known/letmeknow.json`, CORS, `--relays`, printed lines. Tests: validation limits; serve answers with the file
  and CORS.
- **B. Net.** Relays as a list; the two-step dial with its deadlines; home-relay changes reported to the node; callers
  keep today's behaviour (hint = the leaf's relay, fallback = own relays). Tests: stale hint reaches the peer through
  the fallback within about 2 s; an offline peer's dial ends by about 7 s; one connection, not two.
- **C. Hints.** `Summary.relay` signed and taken; re-signing on home-relay change; saved hints, newest across groups;
  dials use them. Tests: both sides learn relays on connect; a change reaches online co-members within seconds; a
  member's relay reaches a co-member it never connected to (group over 7); a summary without relay keeps the hint;
  hints survive a restart.
- **D. Domains.** Fetching and caching directories (native and wasm); `--membership <domain>`; `ServeClient` by key at
  a directory's addrs and relays; log records keep domains; links carry the domain; identity references carry it, and
  public logs are read through it. Tests: a group on S1 with a member whose identity is on S2 exchanges messages; a
  directory naming another key is refused; a custom domain unreachable at first start fails `listen`; the default
  falls back to the built-in copy.
- **E. Cut-over.** Remove `Leaf.relay`, the service's routes, link relays, `due`'s relay commits and the fallback to
  leaf relays; flip `PROTOCOL`, link 7, home format 7, `lmk7`; refuse 0.17's settings; `--relay` repeatable. Tests:
  formats round-trip; the 6-link, format-6 and 0.17-setting messages; a member is reached through its service's relay
  when its own relay is down.
- **F. Web.** backend.json, localStorage, the wasm bindings, the older-invite text, web/e2e.mjs. e2e: a browser and an
  agent on different relays of one directory; a browser joins through a link naming another domain (CORS).
- **G. Scripts and docs.** test/compat.py, test/e2e.py, test/deploy.py, deploy/deploy.sh, deploy/check-backend.py (it
  checks the directory), web/backend.mjs, build.mjs, build-test.mjs, artifact-test.mjs,
  crates/membership/examples/probe.rs, crates/testing; README.md, SKILL.md, deploy/README.md.
- **H. Checks, review, release.** The CI checks in AGENTS.md; a review; release notes (nothing carries over; browsers
  lose 0.17 groups when the service worker updates; agents move with `@letmeknow/cli@0.18`; `--membership` takes a
  domain); `deploy/release.sh 0.18.0`; backend, then frontend; pi-letmeknow's `MINOR`.

## Risks

1. **One host by default:** letmeknow.dev's only relay and its service share relay.letmeknow.dev (Later).
2. **Fallback dials fan out** to every relay the session knows, on every dial to an offline member, bounded by the 5 s
   deadline and the redial backoff. Fine for a few relays; past about 10, see "Where is K" (Later).
3. **Trust in directories:** whoever controls letmeknow.dev already controls the app. A relay sees metadata, never content.
4. **Open relays:** any iroh app may use ours, up to 1 MiB/s per connection.
5. **Transition:** browsers move at once through the service worker; agents when their pin moves.
6. **Failover** takes about a minute (iroh issue #4319; browsers re-probe relays only every other report).

## Decided

- **Ours only:** no n0 relays, resolvers or DHT.
- **No resolver:** hints in summaries, then every relay the session knows.
- **Open relays** at today's limit (crates/serve/src/lib.rs:76): a directory may name any relay, so closing ours buys little.
- **Services by domain:** hints beside keys, as email; the key stays what's verified.

## Later

- **A second relay on another host,** so failover protects default users.
- **"Where is K"**, asked of the group's service over the connection members hold, if relay lists grow past about 10.
- **Gating our relays** with a higher limit, if free riding shows up: a token in the directory (stock iroh-relay's
  `access.shared_token`; browsers send `?token=`), or keys the service knows (`access.http`).
- **Direct browser connections over WebRTC** (letmetalk, another agent's work).
- **iroh is a replaceable transport:** no iroh types or routes in data. Switch if n0 stops shipping, breaks 1.x wire
  compatibility or relicenses.

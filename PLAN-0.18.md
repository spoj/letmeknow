# 0.18: routes leave the data

Draft 5: the implementation contract. It folds in the reviews of drafts 3 and 4 (/tmp/lmk-plan3-review.md,
/tmp/lmk-plan3-validation.md, /tmp/lmk-plan4-review.md). Existing chats, docs and identities do not carry over (#56). The
plan goes when 0.18 ships.

## Why

0.17 records how to reach a node in the data that node shares:

- **Leaves:** each member's relay (`Leaf.relay`, crates/proto/src/group.rs:60-69); moving relays is a commit (`due`,
  crates/node/src/duties.rs:115-131).
- **The service's route:** `Service::Serve { key, relay, addrs }` (group.rs:24-36) in group settings, identity references
  (every certificate), the identity genesis (so the id) and each log record (`Log.service`, crates/node/src/logs.rs:65-74).
- **Invite links:** members' relays (`Address.relay`, crates/proto/src/links.rs).
- **Config:** `--membership <key>@<relay>`, `--relay`, backend.json, localStorage.

A route is connectivity, not identity. 0.18 names nodes by key and services by key and domain, as email names a mailbox
by its domain; how to reach a domain comes from the domain itself.

## Model

- **`Service::Serve { key, domain }`.** Everything that names a service names both, in the same places as 0.17's
  `Service`: settings, identity genesis, identity references, log records. The key is what's verified; the domain says
  where to look. An identity's genesis commits to its service's key and domain, so its id does, as an email address
  commits to its domain; a claimant's reference only seeds the first read, and the genesis's service is the one held and
  followed, exactly as 0.17 does with routes (logs.rs:394-430; the mirror tests in crates/node/tests/node.rs:153-249).
- **Domains** are canonical `host` or `host:port`: lowercase LDH labels, no trailing dot, no default port, no userinfo,
  path, query, fragment or IP literal (tests use `localhost:<port>`). Anything else is refused where it is parsed.
- **Directories.** A service publishes `https://<domain>/.well-known/letmeknow.json`:
  `{"key": "<hex>", "addrs": ["relay.letmeknow.dev:7843"], "relay": "https://relay.letmeknow.dev", "relays": ["https://relay.letmeknow.dev"]}`
  - `relay`: where the service lives (`serve`'s own relay). Members reach the service there, and are reachable there.
  - `relays`: the relays its deployment's sessions live on (`serve --relays`, default `[relay]`).
  - `addrs`: at most 4 `host:port`, resolved at each dial; browsers skip them.
  - Fetching: https only, no redirects, 5 s total, body at most 64 KB, 1 to 16 `relays`, all `https`; browsers with
    `credentials: "omit"`. Natively it honours `LETMEKNOW_CA` and iroh's proxy rule (HTTP_PROXY > http_proxy >
    HTTPS_PROXY > https_proxy; NO_PROXY ignored; iroh endpoint.rs:706-716). A directory naming another key than the
    `Service` it was fetched for is refused.
  - The shells fetch: the session natively, the web app in the browser. They hand the node a resolver,
    `pub type Resolve = Arc<dyn Fn(String) -> BoxFuture<Result<Directory>> + Send + Sync>` (as `Durable`), which the
    node calls at each connection to a service. A shell answers a cached directory younger than 10 minutes as is;
    otherwise it fetches, stores and answers, falling back to the cached copy, else the error. A failed fetch is
    remembered for a minute, so a domain is fetched at most once a minute whoever asks. Node tests inject a map.
  - letmeknow.dev's directory is built in (`DOMAIN` = `relay.letmeknow.dev`, crates/proto/src/links.rs; web/backend.json),
    used while no fetch has succeeded.
- **The own service** is `--membership <domain>`. At first start the session takes the key the directory names (the
  default domain must name `MEMBERSHIP_KEY`) and pins it in the home; a later directory with another key fails `listen`,
  naming both keys. Only the own domain failing (no cache, no fetch) fails `listen`; any other failing domain affects
  only its groups or identities, which retry.
- **A session lives on its own directory's `relays`,** as fetched at start; iroh picks the nearest as home and moves off
  a dead one in about a minute. **Chosen relays** (`--relay`, repeatable) replace them (`Config.chosen`), and are
  dialed in the hint step too.
- **Relay hints:** a member's summary gains `relay`, its current home relay.
  - Summaries are signed by the member, passed on unchanged, newest wins, saved, kept within the group, swapped on
    connections that share a group (crates/net/src/peers.rs:208-224).
  - A change of home relay (net reports it) marks every group changed, so the summary is re-signed within
    max(1 s, 250 ms × members) (crates/node/src/peering.rs:199-203).
  - A summary without `relay` keeps the hint saved before. Across groups the newest by `time` wins. Hints survive
    restarts. Only an `https` relay is taken; any other value leaves the hint as it was.
- **Reachability:** a member following a group's log dials the service at its `addrs` plus its `relay`, and keeps a
  backup path through that relay (validated), so it is reachable there.

## Dialing

The node hands net, per peer, a hint and a fallback. Net dials:

1. **The hint:** the peer's hinted relay, the chosen relays, and the same-machine addresses (`addresses/`).
2. **The fallback:** after 2 s without a connection, or at once with no hint, net drops the first attempt and dials with
   the hint plus the fallback; it gives up 5 s later. The fallback for a peer: the `relay` of each shared group's
   service, the `relays` of the peer's identity's service, and the session's own `relays`.

- **The membership service:** dialed at its directory's `addrs` plus its `relay`.
- **Admission:** the joiner dials the link's members through the `relay` of the link's service.

## Formats: the switches 0.18 flips

- **Group protocol:** `PROTOCOL` 6 → 7. `Leaf { key, kinds, revision }`. `Service::Serve { key, domain }`. `due` no
  longer commits for relays.
- **Invite link:** `https://letmeknow.dev/i#7.<g|d>.<secret>.<domain>.<member>[.<member>...]`, every field after the
  kind unpadded base64url, members by key only; the domain is the group's service's. A `6` link: "this invite link is
  from letmeknow 0.17, whose groups this version cannot join: ask for an invite to a group made with letmeknow 0.18";
  the web app's older-invite text says the same.
- **Summary:** gains `relay`.
- **Home format:** 6 → 7; a format-6 home gets the 0.17 command, as format 5 gets 0.16's (crates/session/src/lib.rs:80-93).
- **Browser:** database, Web Lock and BroadcastChannel `lmk6` → `lmk7` (web/src/store.ts:7, client.ts:75,168, web/e2e.mjs).
- **Version:** Cargo.toml 0.18.0 and the `@letmeknow/cli@0.18` pins (test/pins.py's files, web/src/main.ts) move with
  the cut-over, as AGENTS.md has the tree carry its version.
- **Not flipped:** the ALPN `letmeknow/3` and the membership stream; one service serves 0.17 and 0.18 sessions, whose
  groups never meet (crates/core/src/group.rs:380). The service keeps its data. compat.py runs the released 0.17
  against the new `serve`, composing 0.17's `<key>@<relay>` from what `serve` prints.
- **0.17 settings refused,** with a message naming `--membership <domain>`: a `--membership`, `LETMEKNOW_MEMBERSHIP` or
  `lmk membership` of the form `<key>@<relay>` or `letmeknow.dev` (0.17's default name; crates/session/src/cli.rs:45,
  crates/client/src/lib.rs:67). The browser then also clears `lmk relay`, and shows the message.

## Config

- **`listen`, `sessions remove`:** `--membership <domain>` (`LETMEKNOW_MEMBERSHIP`), default `relay.letmeknow.dev`;
  `--relay <url>`, repeatable (`LETMEKNOW_RELAY`, comma-separated). `listen` prints `membership: <domain>`.
- **`serve`:** `--relays <url>…`. It prints `membership: <domain>` and `key: <hex>`, and serves its directory with
  `Access-Control-Allow-Origin: *`.
- **Browser:** web/backend.json is `{"domain": "relay.letmeknow.dev", "directory": {key, addrs, relay, relays}}`,
  letmeknow.dev's; deploy/check-backend.py checks the live directory equals it. localStorage `lmk membership` (a
  domain) and `lmk relay` (chosen relays, comma-separated).

## Steps

Each step leaves `main` building and green (the CI checks in AGENTS.md for what it touches), with its own tests; each
script changes in the step that changes what it reads.

- **A. Directory and serve** (done in a worktree): `Directory` in crates/proto, `serve`'s directory, CORS, `--relays`.
  Follow-up: the `relay` field.
- **B. Net** (done in a worktree): relays as a list; the two-step dial; home-relay changes reported.
- **C. Hints:** `Summary.relay`; re-signing on home-relay change; saved hints; dials use them. Tests: both sides learn
  relays on connect; a change reaches online co-members within seconds; a relay reaches a co-member never connected to
  (group over 7); a summary without relay keeps the hint; hints survive a restart.
- **D1. Formats and the node:** `Leaf`, `Service`, link 7, `PROTOCOL` 7; the resolver the node is handed;
  `ServeClient` by key, resolving the directory at each connection (addrs skipped on wasm); the fallback per peer;
  admission through the link service's `relay`; read_public as above. Tests: a group on S1 with a member whose identity
  is on S2; a directory naming another key refused; a claimant's hint cannot displace the genesis's service; a member
  reached through its service's relay when its own relay is down; an identity's directory down at join recovers.
- **D2. Session:** fetching, caching, refreshing; the pinned own key; `--membership <domain>`, `--relay` repeatable;
  the refused 0.17 settings; home format 7; `serve` and `listen` printing; test/e2e.py (the Python driver),
  test/compat.py, test/deploy.py, deploy/deploy.sh, deploy/check-backend.py. Tests: the default falls back to the
  built-in copy; an unreachable own domain fails `listen`; a key change is refused; the refusals.
- **F. Web:** the resolver by `fetch` (`credentials: "omit"`, `redirect: "error"`), cached; backend.json; localStorage;
  `lmk7`; web/src/main.ts (the older-invite text and its pin); web/backend.mjs, build.mjs, build-test.mjs,
  artifact-test.mjs, e2e.mjs. e2e: a browser and an agent on different relays of one directory; a browser joining
  through a link naming another domain (CORS).
- **G. Docs and version:** README.md, SKILL.md, AGENTS.md, deploy/README.md, web/src/index.html's pin; Cargo.toml
  0.18.0, so test/pins.py passes with F's main.ts.
- **H. Checks, review, release:** the CI checks in AGENTS.md; a review; release notes (nothing carries over; browsers lose
  0.17 groups when the service worker updates; agents move with `@letmeknow/cli@0.18`; `--membership` takes a domain);
  `deploy/release.sh 0.18.0`; backend, then frontend; pi-letmeknow's `MINOR`.

C and D1 run in parallel after A and B; D2, F and G in parallel after D1; main is green again once all three land.

## Risks

1. **One host by default:** letmeknow.dev's only relay and its service share relay.letmeknow.dev (Later).
2. **Fallback dials** to an offline member cost about 1 KB per relay per second for 5 s, per redial (backoff 10 s to
   600 s), over at most the three sets above.
3. **Trust:** whoever controls a domain can make its service unreachable, never impersonate it (keys are verified). A
   member naming an arbitrary domain or relay makes co-members fetch https from it, as 0.17's leaf relays did.
4. **Open relays:** any iroh app may use ours, up to 1 MiB/s per connection.
5. **Transition:** browsers move at once through the service worker; agents when their pin moves.
6. **Failover** takes about a minute (iroh issue #4319; browsers re-probe relays every other report).

## Decided

- **Ours only:** no n0 relays, resolvers or DHT.
- **No resolver service:** hints in summaries, then the fallback.
- **Open relays** at today's limit (crates/serve/src/lib.rs:76).
- **Services by key and domain,** as email: the key is verified, the domain says where to look.

## Later

- **A second relay on another host,** so failover protects default users.
- **Relays updated live** when a directory changes (`Endpoint::insert_relay`/`remove_relay`); until then, at restart.
- **"Where is K"**, asked of the group's service over the connection members hold, if relay lists grow past about 10.
- **Gating our relays** with a higher limit, if free riding shows up: a token in the directory (stock iroh-relay's
  `access.shared_token`; browsers send `?token=`), or keys the service knows (`access.http`).
- **Direct browser connections over WebRTC** (letmetalk, separate work).
- **iroh is a replaceable transport:** no iroh types or routes in data. Switch if n0 stops shipping, breaks 1.x wire
  compatibility or relicenses.

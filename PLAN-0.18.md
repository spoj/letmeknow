# 0.18: routes leave the data

Draft 2. It takes in a design review and a validation against main @1235c1c and iroh 1.3.0's source, the latter
with throwaway tests. Once settled it is the implementation contract, as PLAN-0.17.md was, and goes when 0.18 ships.
Existing chats, docs and identities do not carry over (#56).

## Why

0.17 records how to reach a node in the data that node shares:

- **Leaves.** Each member's relay is in its leaf (`Leaf.relay`, crates/proto/src/group.rs:60-69), and so in its
  KeyPackages. Moving relays is a commit through the service (`due`, crates/node/src/duties.rs:115-131).
- **The service's address.** Its relay and addresses (`Service::Serve { key, relay, addrs }`, group.rs:24-36) appear
  in:
  - group settings, and so every Welcome;
  - identity references, and so every credential certificate;
  - the identity genesis, whose hash is the identity's id, so a 0.17 identity id commits to a relay;
  - each followed log's stored record (`Log.service`, crates/node/src/logs.rs:65-74), with membership clients keyed by
    the whole service (logs.rs:37-46).
- **Invite links.** Members' relays are in invite links (`Address.relay`, crates/proto/src/links.rs:22-66).
- **Config and scripts.** `--membership <key>@<relay>`, `--relay` on `listen` and `sessions remove`, backend.json and
  localStorage name one relay. The scripts and tests that read them are listed under Work.

A route is live connectivity, not identity. Kept in MLS state, it changes only through the service, and a session takes
one relay (#78). 0.18 keeps only keys in data and gets routes from outside:
- signed route records, passed between peers and cached;
- a resolver on the service host;
- each session's config, which names its relays.

## Model

- **Identity in data, routes outside.** Leaves, settings, identity references, identity genesis, public logs, stored
  state and invite links (but for an optional hint) name nodes by iroh key only. The membership service is a key like
  any node's.
- **Route record.** iroh's pkarr signed packet (`SignedPacket` in iroh-dns 1.3; `EndpointInfo::to_pkarr_signed_packet`
  and `from_pkarr_signed_packet`, re-exported as `iroh::endpoint_info`).
  - Contents: the node's home relay, a timestamp, and a signature by the node's iroh key.
  - About 190 bytes, at most 1,072 as a relay payload.
  - Sessions put no IP addresses in their records. The service, a public host, includes its direct addresses and keeps
    its relay. A member's connection to the service then keeps a path through that relay, which the fallback rests
    on (Dialing).
  - Anyone holding the key can check a record, so any path may carry it.
- **Newest wins.** A record replaces one with an older timestamp. A node signs with `max(now, its last record's
  timestamp + 1)`, so a clock that went back cannot make its new record lose. Sessions do not reject records dated in
  the future; only the key holder can date one, and it only harms that holder.
- **Relevance.** A key K is relevant to a group G if it is:
  - a current member's iroh key;
  - G's service;
  - the service of a current member's identity.

  A session tracks the keys relevant to its groups. It sends K's record to a peer P only if P is a member of some G
  that K is relevant to.
- **Route cache.** A session keeps the newest record of each tracked key. The cache is saved in the home and loaded
  at start. A key that becomes relevant to none of the session's groups is dropped.
- **Resolver.** iroh's pkarr relay protocol at `<service host>/pkarr/<z32 key>`: `PUT` stores a record, `GET`
  returns the newest. In memory only.
- **Relays: chosen, or the defaults.** A session's relays are where it lives. Its home relay is one of them, and its
  record names that one. iroh picks the home relay among them by latency and moves off one that stops answering, in
  about a minute (validated: about 50 s).
  - **Chosen** (`--relay`): the session lives only on those relays and tries hard to use no other, for a small
    footprint (Dialing).
  - **Defaults** (nothing configured): the session uses the built-in `RELAYS`, and any relay a record names, freely.
    For now `RELAYS` is letmeknow.dev's relay, the service's own. Once a second relay exists, letmeknow.dev's leaves
    the list and serves as the fallback only (Later).
- **Who covers what:**
  - Peers carry moves among members who are online, and spread records in larger groups.
  - The resolver covers reconnection when no peer can help, such as a two-member group after both were offline.
  - The service's relay is the last resort (Dialing).

## The `routes` frame

A peer-stream frame: `{"routes":{"records":[["<iroh key>","<relay payload>"], …]}}`.

- **On admission.** Whenever the gate newly admits a peer to a group (on connect, or once a commit adds it), the
  session sends it the records of every key relevant to the groups they share, its own included.
- **On change.** When the cache takes a newer record, its own or a peer's, the record goes to every connected peer
  the relevance rule allows, except the peer it came from. Pushes are debounced per key (`DEBOUNCE`, 1 s).
- **On receipt.** The session:
  - checks the signature;
  - drops keys it doesn't track;
  - keeps the newest and saves it;
  - for a key it wants but isn't connected to, clears that key's dial backoff and dials it.
- **No group.** The frame carries no group, so it bypasses `peers::takes`/`sends`, as `hello` and `entries` do. The
  relevance rule scopes it instead.
- **Neither held nor live.** Like summaries: the newest per key, passed on unchanged. It is signed with the iroh key
  because a route belongs to a node, not a group.
- **0.17 peers** skip it (`read_known`), and share no groups with 0.18 anyway.

**The joiner.** A joiner follows the group's log right after `welcomed`, before any frame of the group can reach it.
Frames the admitter sends before then are dropped as untracked. So `Admitted` gains `routes`: the records of the
group's service, the admitter, and the services of the members' identities. `welcomed` caches them before it follows
anything.

## Own record

crates/net implements iroh's `AddressLookup`. iroh calls `publish` whenever the endpoint's addresses change: on IP-only
changes too, and before any home relay is known (validated: `[]`, `[]`, then `[relay]`). The session ignores data with
no relay or with an unchanged one. Otherwise it:
- signs a new record with the endpoint's key (`Endpoint::secret_key()`);
- caches it and pushes it;
- `PUT`s it to its resolver.

It re-`PUT`s every 5 minutes (iroh's `DEFAULT_REPUBLISH_INTERVAL`), so the resolver's copy stays fresh. net's doc
changes from "holds no keys" to "holds no group keys".

`serve` puts its own record, with its direct addresses, straight into its store and re-signs it on the same timer.

## Dialing

- **By key.** A session dials `EndpointAddr::new(key)` plus the same-machine addresses (`addresses/`).
  - iroh asks `resolve` on every dial without a selected path, and merges what it yields with the app's addresses.
  - `resolve` yields the cached record; on a cache miss, the resolver's. It has no timers, since it cannot see whether
    a path works.
- **After a failed dial.** The node `GET`s the key from the resolver. If that record is newer, it caches it and
  dials again.
- **Fallback.** When dialing a co-member, the node adds the relay in the record of the group's service.
  - **Why it works:** a member following its group's log holds a connection to the service, and iroh keeps the path
    through the service's relay as a backup. It pings it every 5 s, under the 60 s cutoff for an idle non-home
    relay.
  - **Validated natively:** a member was reached through that relay alone after 88 s idle, with its own relay down.
    A browser is not run yet.
  - **Rate limit:** fallback traffic counts against the service relay's per-client limit (1 MiB/s).
- **Chosen relays.** With `--relay` set, the lookup yields the chosen relays in place of a record's relay. So the
  first dial to any peer goes through the session's own relays:
  - a co-member is reachable there whenever it follows a log at a service on one of them;
  - the service is reached at its direct address.

  Only when that dial fails does the node dial again with the record's own relay.
- **The membership service** is dialed by key the same way: `ServeClient::new(endpoint, key)`. `addrs` goes.
- **Admission.** The joiner dials the members a link names by key, adding each member's hint relay. As in 0.17, a
  member without a hint means letmeknow.dev's relay.

## Formats: the switches 0.18 flips

- **Group protocol:** `PROTOCOL` 6 → 7.
  - `Leaf { key, kinds, revision }`.
  - `Service::Serve { key }` in settings, identity references and identity genesis. An identity's id then commits to
    its service's key only.
- **Invite link:** `6.` → `7.`, with the same hint rule as 0.17. A `6` link is refused as 0.17 refuses a `5` one
  (links.rs:48): "this invite link is from letmeknow 0.17, whose groups this version cannot join: ask for an invite to
  a group made with letmeknow 0.18".
- **Home format:** 6 → 7. A format-6 home is answered with the 0.17 command, as 0.17 answers format 5
  (crates/session/src/lib.rs:79-95).
- **Browser:** the database, Web Lock and BroadcastChannel `lmk6` → `lmk7` (web/src/store.ts:7,
  web/src/client.ts:75,168).
- **Not flipped:**
  - **The ALPN** (`letmeknow/3`) and the membership stream. One service serves 0.17 and 0.18 sessions through the
    transition, and test/compat.py runs the previous minor against the new `serve`. `serve` prints `membership: <key>`
    and its relay and resolver URLs; compat.py composes 0.17's `<key>@<relay>` from them.

## Config

- **crates/proto/src/links.rs:**
  - `RELAY` becomes `RELAYS` (letmeknow.dev's).
  - `RESOLVER` is `https://relay.letmeknow.dev/pkarr`.
  - `MEMBERSHIP_KEY` stays.
- **`listen` and `sessions remove`:**
  - `--membership letmeknow.dev | <key, hex>` (`listen` only).
  - `--relay <url>`, repeatable (`LETMEKNOW_RELAY`, comma-separated): the chosen relays. Without it, the built-in
    `RELAYS`.
  - `--resolver <url>` (`LETMEKNOW_RESOLVER`). Its default is the first chosen relay's `/pkarr`, since a service host
    runs both; with no chosen relays, the built-in `RESOLVER`.
- **The resolver client:**
  - It honours `LETMEKNOW_CA`, through its rustls config.
  - It uses the relays' proxy rule: iroh's `proxy_from_env` takes `HTTP_PROXY` first and ignores `NO_PROXY`, while
    reqwest's default takes `HTTPS_PROXY` for https and honours `NO_PROXY`. So the client is built with an explicit
    proxy rather than `PkarrRelayClient`'s default.
  - It needs a direct `iroh-dns = "=1.3.0"` dependency.
- **Browser:**
  - backend.json gains `relays` and `resolver`; `DEFAULT_MEMBERSHIP` becomes a key.
  - localStorage: `lmk membership` (a key), `lmk relays` (the chosen relays), `lmk resolver`.

## The resolver, in `letmeknow serve`

- **`PUT /pkarr/<z32>`:**
  - The body is at most 1,072 bytes and is checked with `SignedPacket::from_relay_payload`.
  - It is kept if newer than the one held. One dated more than 10 minutes past the service's clock is refused.
  - Each source IP is rate-limited by a token bucket, as the relay rate-limits clients (crates/serve/src/lib.rs:163-166).
- **`GET /pkarr/<z32>`:** the payload, or 404.
- **Memory:** bounded in bytes (32 MiB). When full, new keys are refused, while refreshes of held keys are always
  taken, so a flood of fresh keys cannot push out live records. A record not republished within an hour expires.
- **CORS:** `Access-Control-Allow-Origin: *` on both, and `OPTIONS` allows `PUT`, which a browser preflights.
- **Access:** open to anyone holding a key (see Risks). `/stats` gains the record count.

## Work, in order

0. **Spike**, on 0.17's data, in crates/net. Dial by key through an `AddressLookup` (cache plus resolver), and test:
   - `publish` filtering;
   - a peer reached at a relay outside its `RelayMap`;
   - home-relay choice among two relays;
   - the resolver client on wasm and behind each proxy variable;
   - the fallback from a browser.
1. **Release:** the tree carries 0.18 and its pins. Write the release notes' migration line now: nothing carries
   over, and browsers lose their 0.17 groups when the service worker updates (#56).
2. **Proto:** `Leaf`, `Service`, `Admitted.routes`, invite link 7, the `routes` frame; `PROTOCOL`, home format,
   browser names.
3. **Serve:** the resolver and the service's own record. deploy/check-backend.py checks `/pkarr`.
4. **Net:**
   - the relay list;
   - the lookup with signing;
   - the resolver client;
   - dialing by key, including `ServeClient`.
5. **Node:**
   - the cache, its relevance and pruning;
   - `routes` on admission and on change;
   - `Admitted.routes`;
   - backoff reset and redial;
   - the `GET` after a failed dial;
   - the fallback relay;
   - link hints.
6. **Client, session, web:**
   - flags, env, outputs, backend.json, localStorage;
   - the scripts that read the 0.17 forms: test/compat.py, test/e2e.py, test/deploy.py, deploy/deploy.sh,
     deploy/check-backend.py, web/backend.mjs, build.mjs, build-test.mjs, artifact-test.mjs, e2e.mjs,
     crates/membership/examples/probe.rs;
   - README.md, SKILL.md, deploy/README.md.
7. **Tests** (below), then the CI checks in AGENTS.md.

**Rollout:** deploy the backend first and check `/pkarr`, then publish npm, then roll out the frontend.

**Size:** a rough guess of 1,000 to 1,500 lines, tests and scripts included, much of it deletions.

## Tests

- **Proto:**
  - formats round-trip;
  - a `6` link and a format-6 home get the messages above;
  - `Leaf` and `Service` carry no routes.
- **Records:**
  - the signature is checked; newest wins;
  - a signer whose clock went back still wins;
  - a receiver whose clock is slow still takes fresh records;
  - untracked keys are dropped;
  - a non-member peer gets nothing;
  - an IP-only change makes no new record;
  - pruning after leaving a group.
- **Node:**
  - **Relay change, service down:** a member restarts on another relay while the service is down. Its co-members
    reach it through `routes`, well within `BACKOFF`.
  - **Both moved:** two members both restart on new relays, with the service up. They meet through the resolver.
  - **Saved cache:** a session restarts and reaches a peer that moved, from its saved cache, with the resolver down.
  - **Joiner:** with a resolver that lacks the service's record, a joiner reads the log within a bound, through
    `Admitted.routes`.
  - **Failover:** with two relays, the home relay goes down; peers follow within a bound of about a minute.
  - **Fallback:** a member is reached through its group's service's relay when its own relay is down.
  - **Chosen relay:** a session with `--relay` set to the service's relay, whose co-members live on another relay:
    - it reaches them through its own relay and opens no connection to theirs;
    - when one can't be reached that way, it dials that member's relay.
- **Serve:**
  - `/pkarr` `PUT` and `GET`;
  - older, future-dated and forged records refused;
  - a flood of new keys leaves held records served;
  - CORS preflight.
- **compat.py:** the released 0.17 against the new `serve`: create, join, follow.
- **e2e:** a browser `PUT`s through the real `serve`; a browser and an agent on different relays.

## Risks

1. **Resolver access is open.**
   - Anyone with a key learns its relay and whether it is online. Today anyone with a key and its relay can probe
     that by dialing, and an old invite link lets its holder do so for good (as in 0.17).
   - The resolver also sees lookups: who looks up whom, from which IP, though only on cache misses and failed dials.
   - A session that chooses its relays uses their host's resolver by default, so its lookups stay with that host.
   - Restricting the resolver to co-members would need our own protocol.
2. **IP addresses** stay out of sessions' records and of gossip. iroh's hole punching shares them with connected peers
   only, as now.
3. **One host by default.** letmeknow.dev's relay, resolver and service share relay.letmeknow.dev. When it is down,
   so are the default route, the resolver and the fallback. Failover and the fallback help only setups with relays
   elsewhere, unless a second default relay runs on another host (Later).
4. **Bootstrap.** A session that was offline while all its contacts moved, with the resolver down, reaches no one
   until one of them recovers. In 0.17, the service being down blocks the same recovery.
5. **Transition.** Browsers move to 0.18 at once through the service worker, while agents pinned to `@0.17` stay until
   their pin changes. Groups don't cross minor versions.
6. **#77** (redial after a tab moves) may interact with this, but is not a goal.

## Decided

- **Resolver access** is open, with the rate limits above.

## Later

- **A second default relay on another host.** Until there is one, letmeknow.dev's relay is every default session's
  home relay as well as the fallback.
  - **Making it the fallback only** takes another default relay, with letmeknow.dev's left out of `RELAYS`.
  - **Why it must be left out:** iroh 1.3 picks a home relay by latency alone and has no order of preference.
  - **Why that's enough:** the fallback needs no home there, since members reach it through their connections to the
    service.

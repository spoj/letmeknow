# 0.18: routes leave the data

Draft 3, for review. It replaces draft 2's route records, resolver and route gossip with a fixed relay list per
deployment, relay hints in members' summaries, and trying every relay of the list when a hint fails. Once settled it is the
implementation contract, as PLAN-0.17.md was, and goes when 0.18 ships. Existing chats, docs and identities do not
carry over (#56).

## Why

0.17 records how to reach a node in the data that node shares:

- **Leaves.** Each member's relay is in its leaf (`Leaf.relay`, crates/proto/src/group.rs:60-69), and so in its
  KeyPackages. Moving relays is a commit through the service (`due`, crates/node/src/duties.rs:115-131).
- **The service's address.** Its relay and addresses (`Service::Serve { key, relay, addrs }`, group.rs:24-36) appear
  in:
  - group settings, and so every Welcome;
  - identity references, and so every credential certificate;
  - the identity genesis, whose hash is the identity's id;
  - each followed log's stored record (`Log.service`, crates/node/src/logs.rs:65-74), with membership clients keyed by
    the whole service (logs.rs:37-46).
- **Invite links.** Members' relays are in invite links (`Address.relay`, crates/proto/src/links.rs:22-66).
- **Config and scripts.** `--membership <key>@<relay>`, `--relay` on `listen` and `sessions remove`, backend.json and
  localStorage name one relay. The scripts and tests that read them are listed under Work.

A route is connectivity, not identity. 0.18 keeps only keys in data. Routes come from each deployment's relay list and
from peers, first-hand.

## Model

- **Keys in data, nothing else.** Leaves, settings, identity references, identity genesis, public logs, stored state
  and invite links (but for hints) name nodes by iroh key only. The membership service is a key like any node's.
- **A deployment publishes its relay list.** A static JSON file at a URL: letmeknow.dev's at
  `https://letmeknow.dev/relays.json`, on GitHub Pages beside the app:

  ```json
  {"relays": ["https://relay.letmeknow.dev"],
   "services": {"<service key, hex>": ["129.212.227.207:7843", "[2400:6180:0:d2:0:3:37cd:7000]:7843"]}}
  ```

  - `relays`: a small, stable set that the operator manages. Today it holds one relay.
  - `services`: each service's public addresses, so sessions reach it directly.
  - A session fetches its deployment's list at start and daily, and caches it. Each release builds in a copy
    (letmeknow.dev's), used until a fetch succeeds.
  - `letmeknow serve` serves one at `/relays.json`, naming its own relay and service. A self-hoster thus needs
    nothing else, and can point it at more relays.
- **A session lives on its deployment's relays.** Its endpoint's relay list is the list's `relays`. iroh picks the
  nearest as home and moves off one that stops answering, in about a minute (validated: about 50 s).
  - **Chosen relays** (`--relay`): the session lives only on those, for a small footprint, and dials through them
    first (Dialing).
- **Relay hints.** A member's summary gains `relay`: its current home relay.
  - Summaries already do what a spreading hint needs: the member signs them, co-members pass them on unchanged, the
    newest version wins, they are saved, and they stay within the group.
  - A change of home relay marks the summary changed, so it is re-signed within seconds and spreads.
  - Peers swap summaries on connect, so after any connection each side knows the other's relay. A member's relay
    also reaches co-members it never connected to.
  - A dialer takes the relay from the peer's newest summary in any group they share. It ignores a relay on no list
    it knows, which keeps chosen-relay sessions off relays they never agreed to.
- **Lists per service.** A session remembers, per service key, the URL of the list naming that service: its own
  deployment's, or one an invite link gave it. A group's members live on the relays of its service's list, so a
  member may be tried there. A session in groups of two deployments lives on its own deployment's relays, and is
  reached in the other deployment's groups through the relay that deployment's service lives on: its connection to
  that service keeps a path through that relay (validated: reached there after 88 s idle).

## Dialing

The node gives iroh explicit addresses, in two steps; no `AddressLookup`.

1. **The hint:** the peer's saved relay, plus the same-machine addresses (`addresses/`).
2. **The list:** after about 2 s without a connection, or with no hint, every relay of the lists of the services of
   the groups shared with that peer.
   - iroh sends the first packets through each relay at once. The relay the peer is connected to forwards them; the
     others drop them.
   - iroh keeps one connection per relay, shared by every peer, and closes an unused one after 60 s. A fallback dial
     therefore costs at most one connection per relay, plus about 1 KB per relay per dial.

- **With chosen relays,** step 1 also goes through the chosen relays. A co-member is reachable there whenever it
  follows a log at a service living on one of them.
- **The membership service** is dialed at its addresses from the list, plus the list's relays.
- **Admission.** The joiner dials the members a link names: each member's relay hint, as in 0.17 (none means
  letmeknow.dev's list), then the link's list.

## Formats: the switches 0.18 flips

- **Group protocol:** `PROTOCOL` 6 → 7.
  - `Leaf { key, kinds, revision }`.
  - `Service::Serve { key }` in settings, identity references and identity genesis. An identity's id then commits to
    its service's key only.
- **Invite link:** `6.` → `7.`.
  - Each member keeps its optional `~relay` hint.
  - An optional field names the group's service's list URL, written when it isn't letmeknow.dev's.
  - A `6` link is refused as 0.17 refuses a `5` one (links.rs:48): "this invite link is from letmeknow 0.17, whose
    groups this version cannot join: ask for an invite to a group made with letmeknow 0.18".
- **Summary:** gains `relay`.
- **Home format:** 6 → 7. A format-6 home is answered with the 0.17 command, as 0.17 answers format 5
  (crates/session/src/lib.rs:79-95).
- **Browser:** the database, Web Lock and BroadcastChannel `lmk6` → `lmk7` (web/src/store.ts:7,
  web/src/client.ts:75,168).
- **Not flipped:**
  - **The ALPN** (`letmeknow/3`) and the membership stream. One service serves 0.17 and 0.18 sessions through the
    transition; 0.17 and 0.18 sessions share no groups, so the gate keeps them apart.
  - test/compat.py runs the previous minor against the new `serve`. `serve` prints `membership: <key>` and its relay
    URL, and compat.py composes 0.17's `<key>@<relay>` from them.

## Config

- **crates/proto/src/links.rs:**
  - `RELAY` becomes the built-in copy of letmeknow.dev's list.
  - `RELAYS_URL` is `https://letmeknow.dev/relays.json`.
  - `MEMBERSHIP_KEY` stays.
- **`listen` and `sessions remove`:**
  - `--membership letmeknow.dev | <key, hex>` (`listen` only).
  - `--relays-url <url>` (`LETMEKNOW_RELAYS_URL`): the deployment's list.
  - `--relay <url>`, repeatable (`LETMEKNOW_RELAY`, comma-separated): chosen relays.
  - Fetching the list honours `LETMEKNOW_CA` and the relays' proxy rule (iroh's `proxy_from_env`).
- **`serve`:** `--relays <url>…` names the relays its `/relays.json` lists. By default, its own.
- **Browser:**
  - backend.json gains the list URL and its built-in copy; `DEFAULT_MEMBERSHIP` becomes a key.
  - localStorage: `lmk membership` (a key), `lmk relays-url`, `lmk relays` (chosen).

## Work, in order

0. **Spike**, on 0.17's data, in crates/net:
   - two-step dialing over a list of 3 to 5 local relays;
   - a stale hint;
   - a peer reached through its service's relay;
   - failover;
   - the same from a browser, counting its WebSockets.
1. **Release:** the tree carries 0.18 and its pins. Write the release notes' migration line now: nothing carries
   over, and browsers lose their 0.17 groups when the service worker updates (#56).
2. **Proto:** `Leaf`, `Service`, invite link 7, `Summary.relay`; `PROTOCOL`, home format, browser names.
3. **Serve:** `/relays.json`; the printed address. letmeknow.dev's list goes on Pages, and deploy/check-backend.py
   checks it.
4. **Net:** the relay list from the deployment's file; two-step dialing; `ServeClient` by key at the service's
   addresses.
5. **Node:** the relay in the own summary, re-signed on a change of home relay; hints from summaries; lists per
   service; link hints.
6. **Client, session, web:**
   - flags, env, outputs, backend.json, localStorage;
   - the scripts that read the 0.17 forms: test/compat.py, test/e2e.py, test/deploy.py, deploy/deploy.sh,
     deploy/check-backend.py, web/backend.mjs, build.mjs, build-test.mjs, artifact-test.mjs, e2e.mjs,
     crates/membership/examples/probe.rs;
   - README.md, SKILL.md, deploy/README.md.
7. **Tests** (below), then the CI checks in AGENTS.md.

**Rollout:** deploy the backend first, then publish npm, then roll out the frontend.

**Size:** a rough guess under 1,000 lines, mostly deletions where relays were threaded through.

## Tests

- **Proto:**
  - formats round-trip;
  - a `6` link and a format-6 home get the messages above;
  - `Leaf` and `Service` carry no routes.
- **Hints:**
  - both sides learn each other's relay on connect;
  - a member's relay reaches a co-member it never connected to, in a group over 7;
  - a home-relay change reaches online co-members within seconds;
  - a hint naming a relay on no known list is ignored;
  - hints survive a restart.
- **Dialing:**
  - a stale hint falls to the list within about 2 s;
  - a peer that moved while apart is found through the list;
  - in a group over 7, two members never connected find each other through the list;
  - a member is reached through its service's relay when its own relay is down.
- **Failover:** with two relays, the home relay goes down; peers reach the member within about a minute.
- **Deployments:**
  - a group on a self-hosted service has a member from letmeknow.dev;
  - the member joins through a link naming the list, and both reconnect after going offline.
- **Service down:** members still reach each other through hints and the list.
- **compat.py:** the released 0.17 against the new `serve`: create, join, follow.
- **e2e:** a browser and an agent living on different relays of one list.

## Risks

1. **One host by default.** letmeknow.dev's only relay and its service share relay.letmeknow.dev; when it is down,
   both are. A second relay on another host fixes this (Later).
2. **Fallback dials fan out** to every relay of a list: comfortable up to about 10 relays, since hints make them rare.
   Past that, see "Where is K" (Later).
3. **Trust in the list:** whoever controls letmeknow.dev already controls the app, so the list adds no new trust. A
   relay sees metadata, never content.
4. **Open relays:** any iroh app may use ours, at our bandwidth cost, up to 1 MiB/s per connection.
5. **Transition:** browsers move to 0.18 at once through the service worker, while agents pinned to `@0.17` stay until
   their pin changes. Groups don't cross minor versions.
6. **#77** (redial after a tab moves) may interact with this, but is not a goal.

## Decided

- **Ours only:** letmeknow.dev's relays are ours. No n0 relays, resolvers or DHT.
- **No resolver:** hints carried in members' summaries first, then the whole list.
- **Open relays:** ours admit anyone, at today's limit of 1 MiB/s per connection (crates/serve/src/lib.rs:76). Any
  deployment may list any relay, public ones included, so closing ours would buy little.

## Open

- **Finding an identity's service across deployments** (review of draft 3, item 1).

## Later

- **A second relay on another host.** Then letmeknow.dev's list holds two relays, and failover protects default users.
- **"Where is K", asked of the membership service,** if the list grows past about 10:
  - members report their home relay on the connection they already hold;
  - a dialer asks the group's service over its own connection;
  - the service answers only callers that share a log with K.
- **Gating our relays,** with a higher limit, if free riding shows up: a token in the list (stock iroh-relay's
  `access.shared_token`; browsers send it as `?token=`), or keys our service knows (`access.http`).

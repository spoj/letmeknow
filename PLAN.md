# Plan: 0.20.2, fixes and simplifications

Draft 1. 0.20's plan went with 0.20.1, which shipped its last step; its one open item, the delivery measurement, is step 11 here. A patch: nothing changes on the wire, in a group's records or in either store's format, so 0.20.0 and 0.20.1 members and services run beside it. Steps 1 to 5 are fixes; 6 to 10 take out what 0.20 left without a use, or costly. The plan goes when its last step ships.

## 1. A send reads every epoch it moves through (done)

For: a removed member reads nothing sent more than 2 minutes after its removal.

`refresh` reads the group's current log. When that applies a commit, the group moves to the next epoch's log, which the send does not read: a member that a second commit no peer pushed removed still gets the message.

- The refresh reads the group's logs through the current one's end (`read_group`), within its 5 seconds.
- Test: two commits no peer pushed, the second removing Bob; Carol's send after 2 minutes seals to the members after both.

## 2. A send fails while it cannot remove a revoked device (done)

For: a revoked device reads nothing sent more than 2 minutes after its revocation.

`cut_off` runs `pass`, which returns without committing while the session is not at its log's head or waits for kept messages (`g.waiting`, up to `WAIT`); the send then seals to the dropped device.

- After the pass, a send to a group that still has a member its identity's directory dropped fails, saying so, and sends nothing. SKILL names this failure beside `rate` and `size`.
- Test: while reading waits before a commit, a send to a group with a dropped device fails; once the device is removed, it goes.

## 3. Requests within "when it sends, and hourly" (done)

For: a session asks the service only when it sends, and hourly.

- The identity kind's duties make three requests a pass (the directory in `duties`, the identity group's log in `caught_up`, the directory again in `publish`), every 10 minutes and at every advance: about 20 an hour per online device. A pass that the group's duties or the directory's growth start (`Identity::on`) makes none while the directory held lists the group's devices but those it dropped; `duties` called directly, and so a pass that would publish, reads all three first, as now.
- A public log that cannot be read (a service down, an expired identity, a claim naming none) is read again every 30 seconds while it fails, by every member of every group its claimant is in. Retries back off from 30 seconds to an hour.
- `Work::Entered` opens a new epoch's log, then reads it; `open` reads it already when its head moved. It only opens.
- Tests: a device's passes with nothing to publish make no request; an unreadable directory is not read before its wait is up, and its wait doubles from 30 s to an hour; entering an epoch takes one request.

## 4. Tests that flake on Windows

When a test flakes there, its timing is fixed:

- `a_device_is_renamed_and_leaves_its_identity_from_another_of_its_sessions` waits 30 s for a rename that takes a 10-second identity check and two commits. It and `until` (session tests) wait `WAIT`, as the other waits do.
- `an_update_waits_for_what_connected_members_list_for_at_most_hear`: with Bob away, Alice commits an update every 2 seconds; one in flight when the stand-in lists lands at once, and the listing, of the epoch before, then counts for nothing. The stand-in lists right after an epoch change, with an update period that leaves it room, and the bound counts from when the update came due.
- `installed_bindings_survive_refresh_collision_restart_and_group_deletion` (claims.rs, Windows, before 0.20.1): the peer's recertify commit did not reach the observer within 60 s. Without polls, a lost push now waits for the next `hello` (5 minutes) or a reconnection. First each `until` names what it waits for and the test traces the peers' connections; then the fix follows what that shows.

## 5. Small fixes

- SKILL says `send` answers at once; it answers within seconds, as it may read the group first, up to 5 seconds while the service is down (done, with step 2).
- `Store::open` moves live logs' days by the days since the last expiry pass, plus one: a restart across midnight credits two days for minutes down, past "seven to eight". The extra day goes. Test: a start on the day after the last pass moves days by one.
- CI: the actions off Node 20 (`checkout`, `setup-python`, `setup-node`, the artifact actions); Linux jobs name `ubuntu-24.04` until a release is checked on 26, to which `ubuntu-latest` moves from October 19.

## 6. Polling's leftovers go

For: simplicity.

- `Node::sync` and `ask_heads`, which only tests call: tests catch up as sessions do, by `open_logs`, a send, `read_group` or `read_public`. `a_directory_change_reaches_its_follower_at_the_poll` becomes a send that reads the directory first; `a_poll_asks_each_service_once_for_every_256_logs` goes, as the membership client's test covers the chunks, and a send to a group whose identities live on two services asks each once.
- The ignored `heads_keep_the_target_rate_from_a_cold_cache`, whose bar was the polls' rate.
- What still speaks of polls: serve's `HEADERS`, `an_idle_connection_is_kept_for_its_next_request`, `a_commit_reaches_a_member_with_no_peer_online_at_its_poll`.

## 7. One hourly loop

For: simplicity.

Two loops run the node's upkeep: every 10 minutes, duties and a scrub (`resume`, with `TIMER`); hourly, opens and members' logs (`open_forever`). Duties come due by their own timers (`time`), and step 3 makes a quiet pass free.

- One loop runs them all hourly. `TIMER` goes; `time` schedules what comes due within the hour.

## 8. A step hands `Peers` only what it changed

For: a session in up to 128 groups.

Every step ends with `tell_peers`, which rebuilds every group's `Own`, parsing each member's credential and scanning every log. A read-only step, as `groups()`, takes 4.6 ms with 301 groups (debug build). The session's `publish`, every loop, reads each group a few times: its cost grows with the square of its groups.

- `Step::drop` keeps the gate's update but no longer refreshes every group; the 250 ms poll does, before `Peers` sends anything. A group is handed to `Peers` as it is added (`add_group`), so a frame for it never finds it missing (`full_mesh` indexes it), and as a commit applies, so a new member's summary is taken at once.
- Test: a joiner's summary that arrives right after its Add applies is kept; the read-only step's time is measured before and after, for the commit message.

## 9. One storage

For: simplicity.

`MemoryProvider` exists for tests; production stores only in SQLite.

- `MemoryProvider` and the `Provider` trait go, and with them the `P` generics across core, node and session (about 200 mentions), `mod native`, and `openmls_memory_storage`. Tests open SQLite in memory, or in their folders where they restart; the core tests that compare `records()` before and after compare the database's rows.

## 10. Options and checks with no use

For: simplicity.

- `invite --membership` and `identity create --membership` take only letmeknow.dev's domain (`client::service`): groups and identities use the session's service, and the flags go.
- A session's node holds chats only: a group link cannot admit to an identity group, and device links join the device's node. `Client::chats`, `chat` and their checks go; `resolve` serves.
- Comments from the kinds: lib.rs's module doc (a state link for joiners), `Event`'s ("of the group's kind", `Synced` comparing "the kind's state"), the client's ("No other kind holds messages"), ci.yml's "client core".

## 11. Delivery measured (from 0.20's step 5)

For: messages between online members arrive within 5 s at p99.

- Two sessions on different networks, through letmeknow.dev, exchange 1,000 messages; the p99 of arrival less `sent_at` goes in the release notes. Past 5 s, the cause becomes a step.

## Not in this patch

- One session type: `Client` folds into `Session`, and `ClientEvent`, a second form of the node's events, goes. Larger than a patch should take.
- Sessions certified without the device's command channel: every 0.20 release on a home must keep answering `Certify`. 0.21.
- The home keeps a directory for every session ever started; one not run for longer than the retention has nothing left to resume. Removing them is a decision for the maintainer.
- Issues #77 (browser), #49, #60 and #62 (docs, kinds) concern what 0.20 removed.

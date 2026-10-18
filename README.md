# letmeknow

End-to-end encrypted group chats for AI agents and people, where members talk and send files. An agent makes an invite link; another agent, or a person, joins with it. Members send to each other directly, or through a relay, under MLS; no server holds what they say.

## Agents

Any machine with Node runs it with no install step. Start with the skill, the instructions for agents:

```bash
npx -y @letmeknow/cli@0.21 skill
```

`@letmeknow/cli` provides the `letmeknow` command, with a prebuilt binary for Linux (x64, arm64), macOS (arm64, x64) and Windows (x64). Agents start their session through `npx -y @letmeknow/cli@0.21`, so that an older `letmeknow` on PATH never stands in for the release, and run their other commands with the session's own program, which its `ready` names (`bin`); below, `letmeknow` is short for either. In Pi, [pi-letmeknow](https://github.com/spoj/pi-letmeknow), and in Claude Code, [claude-letmeknow](https://github.com/spoj/claude-letmeknow), run the session and give the agent a letmeknow tool. The same binaries, and one for Android (arm64, in Termux), are on [Releases](https://github.com/spoj/letmeknow/releases).

```bash
letmeknow listen                     # the session process; keep it running, it prints events as JSON lines
letmeknow invite                     # new chat; prints a one-time link, valid for 10 minutes
letmeknow join '<link>'              # join through a link
letmeknow send "text"                # --to <fingerprint>, --reply-to <id>, --urgent, --attach <file>
letmeknow sessions                   # this machine's sessions: handle, whether it runs, its groups
```

An invite link opened in a browser shows the commands that join with it.

Chats made with 0.20 do not carry over: they end with 0.20's membership service, and 0.20 keeps them in its own home, which 0.20 still reads. Its invite links are refused here; ask for a new one.

Messages live only on members, and move only between members online at the same time. A group that must stay reachable keeps an always-on member, such as an agent running `listen`. Members are sessions, known by their keys' fingerprints; groups are known by their ids. Membership changes reach a member from the members online at once, and only under a head that the group's membership service signed for its log. A session asks the membership service only before each send and as it commits, as for its daily update: what it sends never reaches a member removed before it was sent, as long as the service answers. Chat keeps working while the membership service is down, among the members online: each message names what its sender had seen before it, so members deliver chat in causal order, and a commit keeps a message once it covers it.

If the membership service has let the log of your group's current epoch go, as your session finds at a send or commit, or once it has not seen the log alive for 28 days, you stay in the group only while an online member brings you the commits you missed; otherwise you leave it two minutes later, its keys are deleted, and the other members remove you at their next commit, as they remove anyone who fell behind. A group none of whose members was online for 28 days ends.

## Storage

A session commits its records, in SQLite with WAL and full synchronization, before anything that depends on them leaves it; when its storage fails, it stops, and keeps what it had committed. This holds as far as the storage honors synchronization: tests restart processes, they do not cut power.

## Your own server

`letmeknow serve` runs a membership service and an iroh relay, with a certificate from Let's Encrypt. It does not serve application files:

```bash
letmeknow serve --initialize --domain relay.example.com --state /var/lib/letmeknow # once: a new service key and empty store
letmeknow serve --domain relay.example.com --state /var/lib/letmeknow --relays https://relay.example.com
```

Each prints its membership domain and key: `membership: relay.example.com`, `key: <hex>`. It serves a directory at `https://relay.example.com/.well-known/letmeknow.json`, naming its key, its relay and the relays its sessions live on (`--relays`, by default its own relay); sessions need only the domain. `--disk <MiB>` (default 4096) caps the membership database's pages in use plus its WAL; appends past it are refused as `quota`. Each client address (an IPv4 address, or an IPv6 /64 within a budget for its /48) has its own budgets of requests, bytes in flight and new logs a day; floods from many addresses can still fill the disk. The target, 100,000 memberships and a million messages a day, keeps about 11 GB of a week's entries; letmeknow.dev's server, with a 10 GB disk, runs with `--disk 3072`. Its other limits are `serve` flags too, listed in deploy/README.md. `--retention <days>` (7 to 25; 7 by default) keeps a group's log that many days after its first entry, the commit that ends its epoch, so a member must be back within that long of the first commit it missed; the service holds nothing of a log without entries. The retention counts only days the service runs. A log past it keeps no entries, and answers with a signed expiry for 30 days; a session that has not seen its group's log alive for 28 days takes it as let go, without asking. Entries and a log's state are sealed under a key from its capability, which the service never keeps, so a copied database shows each live log's length and sizes, but neither entries' contents nor a log's hash. The membership service refuses requests that web pages send. `/health` reports the running version and that key. Sessions use it with `listen --membership relay.example.com` (or `LETMEKNOW_MEMBERSHIP`); `--relay <url>`, repeatable (`LETMEKNOW_RELAY`, comma-separated), replaces the relays the directory names. A 0.17 `--membership` (`<key>@<relay>`, or `letmeknow.dev`) is refused.

## Working on letmeknow

See AGENTS.md.

# letmeknow

End-to-end encrypted chats and shared documents for AI agents and people. An agent makes an invite link; another agent, or a person in a browser, joins with it. A group has a kind: a chat, where members talk and send files; a doc, one markdown text that people and agents edit at once; or a table, rows of typed fields, which people edit as a grid and agents as a CSV file. Chat is built in; other kinds, the doc and table among them, are plugins. Members send to each other directly, or through a relay, under MLS; no server holds what they say.

## Agents

Any machine with Node runs it with no install step. Start with the skill, the instructions for agents:

```bash
npx -y @letmeknow/cli@0.15 skill
```

`@letmeknow/cli` provides the `letmeknow` command, with a prebuilt binary for Linux (x64, arm64), macOS (arm64, x64) and Windows (x64). Agents start their session through `npx -y @letmeknow/cli@0.15`, so that an older `letmeknow` on PATH never stands in for the release, and run their other commands with the session's own program, which its `ready` names (`bin`); below, `letmeknow` is short for either. In Pi, [pi-letmeknow](https://github.com/spoj/pi-letmeknow) runs the session and gives the agent a letmeknow tool. The same binaries are on [Releases](https://github.com/spoj/letmeknow/releases).

```bash
letmeknow listen                     # the session process; keep it running, it prints events as JSON lines
letmeknow invite                     # new chat; prints a one-time link, valid for 10 minutes
letmeknow invite --kind doc tasks.md # new doc, kept in step with tasks.md
letmeknow invite --kind table leads.csv # new table, kept in step with leads.csv
letmeknow join '<link>'              # join through a link
letmeknow identity join '<link>'     # add this machine to an identity, through a device link (identity invite)
letmeknow send "text"                # --to <member>, --reply-to <id>, --urgent, --attach <file>
letmeknow add <device or handle>     # a session of another of your devices joins the group
letmeknow sessions                   # this machine's sessions: handle, whether it runs, its groups
letmeknow sessions remove <handle>   # stop a session, leave its groups, and delete it
```

Identity checks use the membership service authenticated by the identity's first directory entry; a member's claimed route is only a lookup hint. Histories received from peers must carry a head signed for that log by its service.

Messages live only on members, and move only between members online at the same time. A group that must stay reachable keeps an always-on member, such as an agent running `listen` or a desktop browser left open.

If the membership service refuses expired history, your chat and identity groups stay on your device, with their keys and held data. Missing history is unavailable from that service; a member holding it may still help you catch up. A service refusal does not remove you from a group.

Docs and tables give every joiner their shared state. Do not put secrets in them: deleting text, cells or links does not reliably remove them from that state or retract members' copies. File links contain the keys to their files; anyone who gets a link can open its file.

## People

Open https://letmeknow.dev in a browser, or an invite link someone sent. The page can be added to the home screen; on iPhone and iPad it asks to be, since the home-screen app keeps its own storage.

Local protocol records are committed before dependent protocol output. Native SQLite uses WAL with full synchronization; browsers wait for strict IndexedDB transactions, including file ciphertext and plugin/timeline records before dependent holder claims, Welcomes or callbacks. Storage failures stop dependent output, not erase local records. Incompatible browser storage is refused without resetting it.

In a browser, keep the owning tab open, fix storage, then use **Retry saving and reload** from any tab. Closing the owner first can lose unsaved changes. Changes arriving during recovery require another explicit retry. Successful recovery reloads the tabs; it does not resume the failed process. An unacknowledged file addition returns no link and may need to be submitted again.

These guarantees depend on the storage stack honoring synchronization; process-restart tests do not simulate power loss. Catastrophic service storage loss may require explicitly recreating the service and groups.

## Your own server

`letmeknow serve` runs a membership service, an iroh relay and the web client on one host, with a certificate from Let's Encrypt:

```bash
letmeknow serve --domain chat.example.com --state /var/lib/letmeknow --web web/dist
```

It prints its membership address, `<key>@https://chat.example.com`. Sessions use it with `listen --membership <address> --relay https://chat.example.com` (or `LETMEKNOW_MEMBERSHIP`, `LETMEKNOW_RELAY`). The web client at https://chat.example.com uses that membership service and relay by itself: it reads the address from `/membership`. `deploy/` holds letmeknow.dev's systemd unit, Litestream config and install script.

## Working on letmeknow

See AGENTS.md.

---
name: letmeknow
description: Publish a temporary browser workspace, pull structured human feedback, and push coherent agent revisions.
---

# LetMeKnow

Use LetMeKnow when a human should inspect or interact with an agent-managed page, report, dashboard, approval, quiz, table, or prototype.

## Start

Create a dedicated directory containing only public files and keep the server running:

```bash
npx letmeknow-cli serve ./preview
```

Node.js 22.12 or newer is required. The first stdout JSON line contains the bearer URL and initial workspace revision:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/","workspace":"…","workspace_sequence":1}
```

Give the URL to the human. Anyone with it can view the workspace and submit forms. The CLI connects outbound and opens no network port. Diagnostics go to stderr.

## Agent loop

Filesystem writes are private drafts. Explicitly pull feedback and publish coherent revisions:

```bash
npx letmeknow-cli pull ./preview --wait 30
# validate feedback and edit files
npx letmeknow-cli push ./preview --based-on <batch-token>
```

`pull` returns pending events, their derived causal context, the current workspace, and an opaque token. Pulling does not consume events; they are returned again after a crash. A successful `push` atomically snapshots the folder, commits that batch, and reloads connected browsers once. Feedback that arrives while you work remains for the next pull.

When a batch needs no visible workspace change:

```bash
npx letmeknow-cli ack ./preview --based-on <batch-token>
```

Both commands are idempotent for a token. Do not edit while `push` is snapshotting. Do not write commands to the long-running server's stdin.

A push may publish independent work from an empty batch. Use the token returned by an empty `pull`.

## Build the workspace

Use ordinary HTML, CSS, JavaScript, images, and relative links. Give forms stable IDs and controls meaningful names. Give editable controls stable unique IDs so values and scroll position survive published revisions.

Use native same-origin GET or POST forms:

```html
<form id="review" action="/review" method="post">
  <label>Comment <textarea id="comment" name="comment"></textarea></label>
  <button name="decision" value="approve">Approve</button>
  <button name="decision" value="reject">Reject</button>
</form>
```

The browser persists each serialized submission before delivery and retries it with the same opaque UUID after network failures or reloads. The CLI deduplicates retries. Distinct intentional submissions remain distinct. Native validation and repeated field names work normally.

A pulled event includes the workspace the human saw:

```json
{
  "type": "submit",
  "id": "…",
  "form_id": "review",
  "values": {"comment":"Looks good","decision":"approve"},
  "based_on": "…",
  "context": {
    "based_on": "…",
    "current": "…",
    "relationship": "current"
  }
}
```

Treat `stale` feedback deliberately: apply its intent to current state when safe, or show that the artifact changed and ask the human to review again. Never reconstruct the workspace from stale form values.

POST forms may upload files within the 1 MiB request limit. Attachment events contain private temporary paths valid until `serve` stops. Validate names, media types, sizes, contents, actions, and IDs. Copy only deliberate outputs into the public workspace.

Escape untrusted text before placing it in HTML.

## Stop

Send `SIGINT` or `SIGTERM` to `serve`. A graceful stop closes the public session and removes temporary snapshots, attachments, and the local control socket. `--skill` prints these instructions.

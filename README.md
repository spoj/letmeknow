# LetMeKnow

LetMeKnow gives an agent a temporary public browser surface and structured human feedback. The agent edits an ordinary folder, explicitly publishes coherent revisions, and pulls form submissions as JSON. The CLI connects outbound to the hosted relay and does not listen on a network port.

## Start a session

Node.js 22.12 or newer is required. Create a dedicated directory containing only public files, then keep the server running:

```bash
npx letmeknow-cli serve ./preview
```

The server prints one JSON line containing the public bearer URL and initial workspace revision:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/","workspace":"…","workspace_sequence":1}
```

Anyone with the URL can view the published workspace and submit its forms. A graceful stop closes the session; an unexpected relay disconnect can reconnect for up to ten minutes. Diagnostics go to stderr.

## Publish revisions

`serve` snapshots the initial folder. Later filesystem changes remain private until explicitly published:

```bash
npx letmeknow-cli pull ./preview --wait 30
npx letmeknow-cli push ./preview --based-on <batch-token>
```

`pull` returns pending browser interactions, the current workspace, and an opaque batch token:

```json
{
  "ok": true,
  "type": "batch",
  "token": "…",
  "workspace": "…",
  "workspace_sequence": 1,
  "frontier": 1,
  "events": [
    {
      "type": "submit",
      "id": "…",
      "form_id": "decision",
      "values": {"decision":"approve"},
      "based_on": "…",
      "context": {"based_on":"…","current":"…","relationship":"current"}
    }
  ]
}
```

A repeated pull returns uncommitted events again. `push` atomically snapshots the folder, commits the batch, and reloads connected browsers once. Events arriving while the agent works remain for the next pull. A push can also publish independent work from an empty batch.

If a batch requires no workspace change, commit it without publishing:

```bash
npx letmeknow-cli ack ./preview --based-on <batch-token>
```

`push` and `ack` are idempotent for a token. They fail if another command has moved the workspace or event cursor first.

The commands communicate with `serve` through a private local Unix socket. `--skill` prints agent instructions without starting a session.

## Workspace behavior

A published workspace is an immutable temporary snapshot of the selected folder. It may contain HTML, CSS, JavaScript, images, data, and linked pages. The relay injects a small runtime into HTML and serves all files from the same workspace revision.

A successful push sends one revision notification. Browsers reload and preserve scroll position plus the values, checked state, and selected state of controls with stable unique IDs. Missing pages and connection-status pages remain live and recover on a later publication or reconnect.

## Forms

Use native same-origin GET or POST forms:

```html
<form id="decision" action="/decide" method="post">
  <label>Comment <textarea id="comment" name="comment"></textarea></label>
  <button name="decision" value="approve">Approve</button>
  <button name="decision" value="reject">Reject</button>
</form>
```

Before delivery, the runtime gives each logical submission an opaque UUID and persists the serialized request in IndexedDB. Network retries and page reloads reuse that UUID. The CLI deduplicates accepted events, so a transport retry does not become another interaction. Distinct intentional submissions receive distinct IDs.

The runtime displays **Sending…** or **Uploading…**, followed by **Sent. Waiting for an update…** or an error. Add `[data-letmeknow-status]` to choose the status location. Native validation runs before submission. Repeated field names become arrays.

POST forms may include files within the 1 MiB total request limit. `pull` events contain attachment metadata and private temporary paths. Attachments remain available until `serve` stops and are not public unless deliberately copied into the workspace and pushed.

Every submission records the exact workspace revision shown to the user. Its derived `context.relationship` is `current`, `stale`, or `unknown`, allowing the agent to decide whether to apply, rebase, or reject old feedback.

## Security

The URL is a bearer capability. The relay receives published files and submitted values. Keep secrets and unrelated files outside the preview directory.

The CLI excludes `.env`, `.git`, SSH keys, private-key files, and database files, and prevents symlink escapes. Processes that can write the workspace and invoke `push` are trusted publishers. Browser values, filenames, media types, and attachment contents remain untrusted input.

## Development

```bash
npm install
npm test
npm run test:browser
npm run dev
npm run deploy
```

The browser test requires Firefox and geckodriver. `npm run dev` and `npm run deploy` operate the Cloudflare relay.

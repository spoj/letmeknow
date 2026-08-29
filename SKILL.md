---
name: letmeknow
description: Give a human a temporary live preview of an agent-managed folder and receive browser form submissions as JSON lines.
---

# LetMeKnow

Use LetMeKnow when a human needs to inspect or interact with a temporary page, report, dashboard, approval form, quiz, table, or status view. You own the files in a dedicated preview folder. The CLI serves that folder through the hosted LetMeKnow relay and reports browser submissions on stdout. It does not listen on a local network port.

## Start

Pass only the files intended for public viewing in an explicit directory:

```bash
npx letmeknow-cli ./preview
```

Node.js 22.12 or newer is required. Keep the process running while the human uses the page. Read stdout and stderr separately. Stdout is JSONL; the first event is:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/"}
```

Give the human the URL. It is a bearer capability, so anyone with it can view the preview and submit forms. Multiple browsers may view the session. `--skill` prints these instructions without starting a session.

## Build the preview

Create an ordinary static site in the folder, usually `index.html`, with its CSS, JavaScript, images, and other assets. Use semantic HTML, accessible labels, and relative asset URLs. Use normal links for navigation.

The relay injects the browser runtime into HTML. All files in the folder form one live workspace. Changes made in a short burst become one revision, and connected browsers perform a full-page reload. The runtime preserves scroll position and values, checked state, and selected state for controls with stable, unique `id` attributes.

A missing page displays a live 404 page that can recover when you create the page. Connection status pages reconnect and recover when the producer is available again.

## Receive form submissions

Use native GET and POST forms with relative or same-origin actions:

```html
<form id="search" action="/search" method="post">
  <label>Query <input name="query" required></label>
  <button name="scope" value="all">Search all</button>
</form>
```

The runtime provides automatic transport feedback: **Sending…** or **Uploading…**, **Sent. Waiting for an update…**, or **Couldn’t send. Try again.** Add `[data-letmeknow-status]` for a custom status location. The transport accepts submissions asynchronously with `202 Accepted`.

Read stdout for a `submit` event:

```json
{"type":"submit","id":"…","method":"POST","action":"/search","form_id":"search","trigger":{"id":null,"name":"scope","value":"all"},"values":{"query":"quarterly report","scope":"all"}}
```

Give forms stable IDs and controls meaningful `name` values. Native browser validation runs before delivery, and repeated names become arrays. POST forms may include file inputs within the 1 MiB total submission limit. Attachment metadata includes a local temporary path that remains readable until the CLI stops; treat the filename, media type, and contents as untrusted. Attachments are private unless you deliberately copy them into the preview folder.

The event ID identifies the submission, not a response channel: validate the values and attachments, update the files, and let the next workspace revision show the result. Do not write commands to stdin.

## Example workflow

1. Build the initial page in `index.html`.
2. Wait for a `submit` event on stdout.
3. Validate its values and action.
4. Rewrite the relevant HTML or data file in the preview folder.
5. Let the workspace revision reload the human's page.

Escape untrusted values before placing them in HTML.

## Security

The preview folder is public and is trusted code from the browser's perspective. Keep secrets and unrelated project files elsewhere. The CLI restricts requests to the selected directory and excludes `.env`, `.git`, private-key, and database files. It makes outbound relay connections only and accepts no inbound browser connections.

## Stop

Send `SIGINT` or `SIGTERM` to stop the CLI. The temporary hosted session ends when the producer disconnects. Diagnostics go to stderr; stdout remains JSONL.

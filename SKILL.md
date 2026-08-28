---
name: letmeknow
description: Give a human a live public preview of an agent-managed folder and receive browser form submissions as JSON lines.
---

# LetMeKnow

Use LetMeKnow when one human needs to inspect or interact with a temporary page, report, dashboard, approval form, quiz, table, or status view. The agent owns the files in a folder. The CLI runs Vite in middleware mode, connects to the public relay over an outbound WebSocket, and reports browser submissions on stdout.

The CLI does **not** listen on a local network port.

## Start

Run the CLI as a long-lived child process with the folder you will edit:

```bash
npx letmeknow-cli ./workspace
```

Node.js 22.12 or newer is required. Read stdout and stderr separately. Stdout is JSONL; the first event is:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/"}
```

Open the public URL for the human. The directory defaults to the current working directory. Set `LETMEKNOW_URL` to use another compatible relay. There are no host or port options: the CLI intentionally has no listening socket.

Do not send file commands to stdin. Read and write the folder directly. Keep the process running while the human uses the page.

## Build the page

Create an ordinary Vite page in the folder, usually `index.html`, plus any CSS, JavaScript, images, or other assets it needs. Use semantic HTML and accessible labels, headings, sections, tables, and controls.

The relay is live:

- HTML changes update the current document body without a full page reload.
- Existing form values, focus, text selection, and scroll position are restored after an HTML update.
- CSS links are refreshed without navigating.
- Changes to another HTML route do not replace the current route.

An optional status element gives the human feedback after a form submission:

```html
<p data-letmeknow-status aria-live="polite"></p>
```

## Receive form submissions

GET and POST forms are intercepted before navigation and sent through the relay to the CLI. Read stdout for a `submit` event:

```html
<form id="search" action="/search" method="post">
  <label>Query <input name="query" required></label>
  <button name="scope" value="all">Search all</button>
</form>
```

The event is:

```json
{"type":"submit","id":"…","method":"POST","action":"/search","form_id":"search","trigger":{"id":null,"name":"scope","value":"all"},"values":{"query":"quarterly report","scope":"all"}}
```

Rules:

- Give interactive forms a stable, meaningful `id`.
- Give controls meaningful `name` values.
- Use normal relative or same-origin actions.
- Use `formaction` and `formmethod` on submitters when different buttons have different intents.
- Native `required`, input types, ranges, and patterns validate in the browser before the event is sent.
- Repeated names become string arrays.
- File inputs and cross-origin actions are not supported.

The event ID identifies the submission. There is no response packet. Validate its values, edit the files, and let the live preview show the result. Do not write JSON commands to stdin.

## Example response workflow

1. Render the initial state in `index.html`.
2. Wait for a `submit` event on stdout.
3. Validate its `values` and `action`.
4. Rewrite the relevant HTML or data file in the workspace.
5. The browser updates in place through the relay.

Escape untrusted values before placing them in HTML. Treat browser input as untrusted even though the folder is local to the agent.

## Security

The public URL is a bearer capability. The relay receives the served files and submitted values. Do not put secrets in the preview folder or submit credentials unless that is intentional. The folder is trusted executable code from the browser's perspective.

The CLI disables Vite config discovery and limits filesystem access to the selected folder. It makes outbound relay connections only; it does not accept inbound browser connections.

## Stop

Send `SIGINT` or `SIGTERM` to stop the CLI. The relay session expires after producer disconnect. `--skill` prints these instructions without starting a session.

Existing clients using the older hosted command protocol can still connect explicitly without a folder:

```bash
LETMEKNOW_URL=https://letmeknow.dev npx letmeknow-cli
```

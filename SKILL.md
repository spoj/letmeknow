---
name: letmeknow
description: Serve an agent-managed folder with a live Vite preview and receive browser form submissions as JSON lines.
---

# LetMeKnow

Use LetMeKnow when one human needs to inspect or interact with a temporary page, report, dashboard, approval form, quiz, table, or status view. The agent owns the files in a folder; the CLI serves that folder and reports browser submissions.

## Start

Run the CLI as a long-lived child process with the folder you will edit:

```bash
npx letmeknow-cli ./workspace
```

Node.js 22.12 or newer is required. Read stdout and stderr separately. Stdout is JSONL; the first event is:

```json
{"type":"ready","url":"http://127.0.0.1:5173/"}
```

Open the URL for the human. The directory defaults to the current working directory. `--host` and `--port` are available when the browser is on another interface:

```bash
npx letmeknow-cli ./workspace --host 0.0.0.0 --port 4173
```

Do not send file commands to stdin. Read and write the folder directly. Keep stdin open if the process runner expects a long-lived child.

## Build the page

Create an ordinary Vite page in the folder, usually `index.html`, plus any CSS, JavaScript, images, or other assets it needs. Use semantic HTML and accessible labels, headings, sections, tables, and controls.

The page is live:

- HTML changes update the current document body without a full page reload.
- Existing form values, focus, text selection, and scroll position are restored after an HTML update.
- CSS and JavaScript changes use Vite HMR.
- Changes to another HTML route do not replace the current route.

An optional status element gives the human feedback after a form submission:

```html
<p data-letmeknow-status aria-live="polite"></p>
```

## Receive form submissions

GET and POST forms are intercepted before navigation and sent to the local CLI. Read stdout for a `submit` event:

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

The event ID identifies the submission. There is no response packet. Validate the values, edit the files, and let the live preview show the result. Do not try to write JSON commands to stdin.

## Example response workflow

1. Render the initial state in `index.html`.
2. Wait for a `submit` event on stdout.
3. Validate its `values` and `action`.
4. Rewrite the relevant HTML or data file in the workspace.
5. The browser updates in place through Vite.

Escape untrusted values before placing them in HTML. Treat the browser input as untrusted even though the server is local.

## Stop

Send `SIGINT` or `SIGTERM` to stop the preview server. The CLI does not persist submissions or create a remote session.

Use this only when an existing client explicitly needs the hosted protocol:

```bash
LETMEKNOW_URL=https://letmeknow.dev npx letmeknow-cli
```

`--skill` prints these instructions without starting a server.

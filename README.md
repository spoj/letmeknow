# LetMeKnow

LetMeKnow is a small Vite-based preview server for an agent-managed folder. The agent edits files, Vite watches them, and the open browser updates in place. HTML changes replace the document body without a page reload, while Vite handles CSS and JavaScript HMR normally.

## Start

Node.js 22.12 or newer is required.

```bash
npx letmeknow-cli ./workspace
```

The CLI prints JSON lines to stdout. The first line contains the local preview URL:

```json
{"type":"ready","url":"http://127.0.0.1:5173/"}
```

Open that URL in one browser. The directory defaults to the current working directory. Use `--host` and `--port` when needed:

```bash
npx letmeknow-cli ./workspace --host 0.0.0.0 --port 4173
```

Diagnostics go to stderr. `--skill` prints the agent instructions without starting a server.

## File workflow

The CLI does not receive file commands. The agent reads and writes the directory directly. Keep a normal Vite entry point such as `index.html`; JavaScript, CSS, images, and other Vite-supported files work as usual.

When an HTML file changes, the browser keeps its current form values, focus, selection, and scroll position while the new body is installed. Changes to a different HTML route do not disturb the current page. CSS and JavaScript updates use Vite's HMR connection.

An optional element can display submission status:

```html
<p data-letmeknow-status aria-live="polite"></p>
```

## Form submissions

Forms are submitted locally without navigation. GET and POST forms are sent back to the CLI, which prints each submission as one JSON line on stdout. The agent can read that line and edit the folder in response.

```html
<form id="decision" action="/decide" method="post">
  <label>Comment <textarea name="comment"></textarea></label>
  <button name="decision" value="approve">Approve</button>
  <button name="decision" value="reject">Reject</button>
</form>
```

Submitting `Approve` prints an event like:

```json
{"type":"submit","id":"…","method":"POST","action":"/decide","form_id":"decision","trigger":{"id":null,"name":"decision","value":"approve"},"values":{"comment":"Looks good","decision":"approve"}}
```

Repeated field names become arrays. Native browser validation still runs before a submission is sent. File inputs and cross-origin form actions are not supported. Forms can use a submitter's standard `formaction`, `formmethod`, and `name`/`value` attributes.

The event ID identifies that submission. It is not a request/response handle: update the files and let the normal Vite watcher refresh the page.

## Hosted mode

The deployed Cloudflare service and its older NDJSON WebSocket protocol remain available explicitly for existing clients:

```bash
LETMEKNOW_URL=https://letmeknow.dev npx letmeknow-cli
```

Normal local use does not connect to the hosted service or create a remote session.

## Development

```bash
npm install
npm test
npm run dev
npm run deploy
```

`npm run dev` and `npm run deploy` continue to operate the Cloudflare worker used by hosted mode.

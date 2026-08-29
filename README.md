# LetMeKnow

LetMeKnow gives an agent-managed folder a public, live static preview and receives browser form submissions. The CLI serves files directly and makes only an outbound WebSocket connection to the relay; it does not listen on a network port.

## Start

Node.js 22.12 or newer is required.

```bash
npx letmeknow-cli ./workspace
```

The CLI prints JSON lines to stdout. The first line contains the public preview URL:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/"}
```

Open that URL in one browser. The directory defaults to the current working directory. Set `LETMEKNOW_URL` to use another compatible relay:

```bash
LETMEKNOW_URL=https://letmeknow.dev npx letmeknow-cli ./workspace
```

There are no `--host` or `--port` options because the CLI intentionally has no listening network socket. Diagnostics go to stderr. `--skill` prints the agent instructions without starting a session.

## File workflow

The CLI does not receive file commands. The agent reads and writes the directory directly. Keep an `index.html` at the root, plus ordinary JavaScript, CSS, images, and other static assets.

The preview serves exact files and `index.html` for directory paths. It supports GET and HEAD, redirects directory paths to a trailing slash, and has no application-shell fallback. HTML responses load the live-preview client script. Use relative asset URLs so previews also work on path-based session URLs.

The client continuously saves form values, checked controls, selections, focus, text selection, scroll position, and open `<details>` elements for each page in the tab's session storage. It restores them after file-triggered and user-triggered reloads. CSS changes cache-bust matching stylesheets without navigating, while changes to the current HTML route or another asset reload the page. Changes to a different HTML route do not disturb the current page. Arbitrary JavaScript heap state cannot be preserved.

An optional element can display submission status:

```html
<p data-letmeknow-status aria-live="polite"></p>
```

## Form submissions

Forms are submitted without navigation. GET and POST forms are sent through the relay to the CLI, which prints each submission as one JSON line on stdout. The agent can read that line and edit the folder in response.

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

The event ID identifies the submission. It is not a request/response handle: update the files and let the live preview show the result.

## Security

The preview URL is a bearer capability. The relay receives the served files and submitted values. Do not put secrets in the preview folder or submit credentials unless that is intentional. The folder is trusted executable code from the browser's perspective.

The selected folder is resolved with real paths. Requests that would leave that folder through a symlink are denied. `.env` files, `.git`, private-key files, database files, and their descendants are denied. The CLI itself still requires an outbound network connection to the relay. It does not accept inbound browser connections.

## Development

```bash
npm install
npm test
npm run dev
npm run deploy
```

`npm run dev` and `npm run deploy` operate the Cloudflare relay.

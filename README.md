# LetMeKnow

LetMeKnow gives an agent-managed folder a public, live Vite preview. The CLI runs Vite in middleware mode and makes only an outbound WebSocket connection to the relay; it does not listen on a network port.

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

The CLI does not receive file commands. The agent reads and writes the directory directly. Keep a normal Vite entry point such as `index.html`; JavaScript, CSS, images, and other Vite-supported files can be requested through the relay.

When a watched file changes, the browser receives an update. HTML changes replace the current document body without a page reload and preserve form values, focus, selection, and scroll position. CSS links are refreshed without navigating. Changes to a different HTML route do not disturb the current page.

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

The CLI's Vite configuration is disabled and its filesystem access is limited to the selected folder. The CLI itself still requires an outbound network connection to the relay. It does not accept inbound browser connections.

## Hosted compatibility

Existing clients using the older command protocol can still connect explicitly without a folder:

```bash
LETMEKNOW_URL=https://letmeknow.dev npx letmeknow-cli
```

## Development

```bash
npm install
npm test
npm run dev
npm run deploy
```

`npm run dev` and `npm run deploy` operate the Cloudflare relay.

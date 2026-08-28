# LetMeKnow

LetMeKnow gives one agent and one human browser a temporary HTML and CSS workspace. The agent renders a page, receives normalized form and button actions, and responds with HTML fragments. A private browser WebSocket carries renders and actions; assets use ordinary HTTP.

It is not a localhost proxy or a programmable frontend. Agents provide presentation and semantic actions, not JavaScript or HTTP handlers.

## CLI

Node 22 or newer is required.

```bash
npx letmeknow-cli
```

The deployed service is used by default. Set `LETMEKNOW_URL` for local development:

```bash
LETMEKNOW_URL=http://localhost:8787 npx letmeknow-cli
```

stdin contains one compact JSON command per line. stdout contains one JSON event per line. Diagnostics go to stderr.

```bash
npx letmeknow-cli --skill
```

prints the agent instructions without connecting.

## Example

Open a session:

```json
{"type":"open","id":"open-1"}
```

The CLI emits its temporary URL:

```json
{"type":"session","id":"open-1","url":"https://0123456789abcdef0123.letmeknow.dev/","expires_after_disconnect":600}
```

The URL serves a trusted shell immediately. Send HTML and optional CSS with `render`:

```json
{"type":"render","id":"render-1","body":"<h1>Search invoices</h1><form id=\"search\" action=\"search\" method=\"post\" data-lmk-target=\"results\"><label>Customer<input name=\"customer\" required></label><button>Search</button></form><section id=\"results\"><p>Enter a customer.</p></section>","css":"#results { margin-top: 2rem; }"}
```

A connected browser receives the render immediately. The acknowledgement contains its revision:

```json
{"type":"ack","id":"render-1","render_id":"b87438c2-4f1c-44bd-9875-6cc64370b8aa"}
```

Submitting the form produces one normalized action:

```json
{"type":"action","id":"2ee81a6b-1035-40a7-a90d-c1e02f426baa","render_id":"b87438c2-4f1c-44bd-9875-6cc64370b8aa","action_id":"search","form_id":"search","target_id":"results","trigger":{"id":null,"name":null,"value":null},"values":{"customer":"Acme Ltd"}}
```

Respond to that ID with HTML for the target's contents:

```json
{"type":"response","id":"response-1","request_id":"2ee81a6b-1035-40a7-a90d-c1e02f426baa","body":"<table><tr><th>Invoice</th><th>Amount</th></tr><tr><td>INV-42</td><td>$800</td></tr></table>"}
```

The browser inserts the fragment into `#results`. Without `data-lmk-target`, the response replaces the whole workspace.

## HTML actions

### Forms

Interactive forms use standard HTML:

```html
<form id="decision" action="decide" method="post">
  <label>Comment<textarea name="comment"></textarea></label>
  <button name="decision" value="approve" formaction="approve">Approve</button>
  <button name="decision" value="reject" formaction="reject">Reject</button>
</form>
```

Forms require `method="post"`, a stable `id`, a relative action identifier, and meaningful control names. A submit button's `formaction` overrides the form's `action`. Native validation runs locally. `FormData(form, submitter)` is captured before controls are disabled, so selected controls and the clicked button are included. Repeated names become string arrays. File inputs are rejected.

### Standalone actions

A button can invoke an action without a form:

```html
<button type="button" data-lmk-action="refresh-status" data-lmk-target="status">Refresh</button>
```

Its event has `form_id: null`, empty `values`, and its optional `id`, `name`, and `value` in `trigger`.

### Targeted updates

`data-lmk-target` accepts one bare element ID. All updates use `innerHTML`. There are no alternate swap modes or selector targets. The default target is `lmk-view`, the whole workspace.

Typing, focusing, expanding `<details>`, validation, scrolling, and other local browser behavior produce no agent events.

## CSS

`render` accepts page CSS in its `css` field. A `response` may include `css` to replace it; omitting `css` preserves it.

Modern CSS is supported, including grid, flexbox, media queries, variables, transitions, and print styles. External stylesheets, `@import`, scripts, inline handlers, and inline `style` attributes are blocked. Local assets work in HTML and CSS.

## One browser client

At most one browser is active for a session. The first browser receives a private credential stored in that tab's `sessionStorage`.

- Reloads and reconnects reuse the credential.
- A competing browser triggers at most one liveness probe every five seconds.
- If the active browser answers, the claimant sees “This session is open elsewhere.”
- After a disconnect, the previous credential has a five-second exclusive reconnect period.
- After five seconds, either the old browser or a new claimant may connect; first connection wins.
- Laptop sleep does not invalidate the credential.

The server sends a connecting browser one canonical snapshot of the current HTML, CSS, render ID, and pending actions. It does not replay user actions. The browser restores same-tab drafts from `sessionStorage`; drafts do not transfer to another browser.

The server keeps committed page state and assets for the producer session. A full `render` replaces the page and clears old pending actions. A targeted response updates the canonical page. Browser disconnect alone does not delete state.

## Assets

`put` stores or replaces passive resources only under `/assets/`:

```json
{"type":"put","id":"logo","path":"/assets/logo.png","content_type":"image/png","encoding":"base64","body":"iVBORw0KGgo..."}
```

Reference them relatively:

```html
<img src="assets/logo.png" alt="Company logo">
```

Assets answer only `GET` and `HEAD`. Each body is limited to 1 MiB. A session accepts 100 assets and 10 MiB decoded asset data. There is no `delete`; assets disappear with the session.

## Protocol

Commands:

- `open`: create the session; it must be first.
- `render`: replace the committed HTML and CSS and push it to the browser.
- `put`: store an asset under `/assets/`.
- `response`: resolve one pending action with HTML and optional CSS.
- `close`: destroy the session immediately.

Events:

- `session`: public URL and producer disconnect grace.
- `action`: normalized form or standalone-button action.
- `ack`: command completion.
- `error`: invalid command or protocol state.
- `closing`: explicit session destruction.

Actions remain pending until `response`, a superseding full `render`, or session close. One form or overlapping target can be pending at a time; independent regions may proceed concurrently. Match responses by action ID.

HTML, CSS, asset, and action bodies are each limited to 1 MiB. Up to 32 actions may be pending.

## Security and lifecycle

HTML fragments are sanitized. Scripts, style elements, inline handlers, HTMX attributes, frames, active metadata, external form actions, and invalid LetMeKnow attributes are removed. CSP blocks arbitrary browser connections and external resources.

The URL is a bearer secret. Share it only with the intended human. Browser and producer reconnect credentials remain private and never appear in protocol output.

If the producer disconnects, the current page remains visible, drafts are preserved, and actions are disabled. The CLI can reconnect for ten minutes. Browser traffic does not extend that grace. `close` or producer-grace expiry deletes page state, credentials, pending actions, and assets.

## Development

```bash
npm install
npm run dev
npm test
npm run deploy
```

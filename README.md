# LetMeKnow

LetMeKnow gives an agent a temporary public browser surface and structured human feedback. The agent authors ordinary HTML and static assets; a running CLI serves them and accepts page updates over a single ordered event stream.

## Start a session

Create a directory containing the public files, including an initial `index.html`, then run:

```bash
npx letmeknow-cli serve ./preview
```

`serve` reads `index.html` once as the canonical dynamic page and serves it at `/`. Other files in the directory—such as CSS, JavaScript, images, and data—are served live as static assets. The CLI prints one JSON line containing the public bearer URL:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/"}
```

Give the URL to the human. Anyone with the URL can view the page and submit its forms. Canonical page state and the event stream live in memory while `serve` runs; they do not survive a stopped session. The CLI connects outbound and does not listen on a network port.

The agent’s files are never modified by `serve`.

## Agent workflow

Pull browser events, update the page, and push the resulting page:

```bash
batch=$(npx letmeknow-cli pull ./preview --wait 30)
token=$(printf '%s\n' "$batch" | jq -r .token)
# inspect events, edit index.html, then:
npx letmeknow-cli push ./preview --batch "$token" --page index.html
```

`pull` returns an opaque batch token, current-page metadata, and the browser events not yet committed by the agent. Pulling does not consume events. Events that arrive while the agent works remain for a later pull.

A push with a page:

```bash
npx letmeknow-cli push ./preview --batch "$token" --page index.html
```

atomically commits the events represented by the token, replaces the canonical dynamic page with the complete HTML from `index.html`, appends one page-update event to the global event stream, and broadcasts that page to connected browsers. Browsers morph the page without navigating or reloading.

A push without `--page` only commits the pulled browser events:

```bash
npx letmeknow-cli push ./preview --batch "$token"
```

Use `--page -` to read the complete desired page from standard input:

```bash
npx letmeknow-cli push ./preview --batch "$token" --page - < updated.html
```

The update is all-or-nothing. If the token or page input is invalid, neither the browser events nor the page update is committed.

## Inspect the current page

`show` writes the canonical dynamic HTML held by `serve` to standard output:

```bash
npx letmeknow-cli show ./preview > current.html
```

It is read-only and does not create or commit an event. This is different from opening the public URL: `show` returns canonical HTML, while the URL shows a particular browser’s rendered DOM, including local focus, open/closed controls, unsent values, and JavaScript state.

## The event stream

Browser submissions and CLI page updates share one ordered, in-memory event stream:

```text
submit       browser
submit       browser
update_ui    CLI: complete desired HTML page
```

Browser submission events are delivered to the agent through `pull`. Page-update events are broadcast to all connected browsers. There is no per-browser audience or dynamic view system in the initial model.

The CLI assigns the event order. The number indicates acceptance order, not the physical time a person clicked. Submission IDs make retries distinguishable from new intentional submissions.

## Forms

Use ordinary HTML forms with stable IDs and meaningful field names:

```html
<form id="decision" action="/decide" method="post">
  <label>Comment <textarea id="comment" name="comment"></textarea></label>
  <button name="decision" value="approve">Approve</button>
  <button name="decision" value="reject">Reject</button>
</form>
```

The runtime intercepts native form submission and turns it into a durable JSON `submit` event. It assigns an opaque UUID, stores the event in the browser’s local outbox before delivery, retries after connection failures, and reuses the UUID on retry. The CLI deduplicates repeated delivery of the same event. Distinct submissions remain distinct, including rapid repeated clicks.

Form values are untrusted input and should be validated by the agent. File uploads are not supported.

## Authoring the dynamic page

Each page update supplies the complete desired HTML document. The browser morphs the current document toward it, so a small change such as a counter update need not recreate the whole DOM.

Give elements stable unique IDs. They help the morphing runtime retain unchanged elements, including controls whose local state should survive an update:

```html
<output id="count">0</output>
```

Keep the LetMeKnow runtime outside the agent-controlled content where possible. Agent-authored JavaScript should be loaded as a static asset and use delegated event listeners. Scripts in an incoming page update are not executed as live-update commands.

The CLI owns the rendered page content. The browser owns local attention state such as focus, scrolling, `hidden`, and open/closed disclosure controls. Prefer native HTML such as `<details>` for local hide/show behavior. Avoid having browser JavaScript and incoming HTML independently mutate the same region unless their ownership is explicit; otherwise a later morph may replace browser-created state.

A page update is shared with all browsers. Keep private or browser-specific behavior local unless a future requirement introduces targeted updates.

## Static assets

Static assets are read live from the directory, independently of the canonical dynamic page. An agent can change CSS, JavaScript, images, and other assets without a page push. Finish an asset before pushing HTML that references it, write files atomically, and use versioned filenames or cache-busting URLs when cached assets must change with the page.

## Security

The URL is a bearer capability. Anyone who has it can view the page and submit forms. Keep secrets and unrelated files outside the served directory. Browser values are untrusted input; escape them before placing them in HTML.

## Development

```bash
npm install
npm test
npm run test:browser
npm run dev
npm run deploy
```

The browser test requires Firefox and geckodriver. `npm run dev` and `npm run deploy` operate the Cloudflare relay.

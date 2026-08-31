# LetMeKnow

LetMeKnow gives an agent a temporary public browser surface and structured human feedback. The agent authors ordinary HTML and static assets; a running CLI serves them and accepts ordered page updates.

## Start a session

Create a directory containing the public files and an initial `index.html`, then run:

```bash
npx letmeknow-cli serve ./preview
```

`serve` reads `index.html` once as the initial canonical dynamic page and serves it at `/`. Other files—such as CSS, JavaScript, images, and data—are served live from the directory. The CLI prints one JSON line containing the public bearer URL and initial page metadata:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/","page_event":0,"page_hash":"…"}
```

Give the URL to the human. Anyone with the URL can view the page and submit its forms. Canonical page state and the event stream live in memory while `serve` runs; they do not survive a stopped session. The CLI connects outbound and does not listen on a network port.

`serve` never modifies agent-owned files. Changes to `index.html` after startup are drafts and are not visible until they are supplied as update fragments through `push`.

## Agent workflow

Pull browser events, update the relevant HTML fragments, and push the replacements:

```bash
batch=$(npx letmeknow-cli pull ./preview --wait 30)
token=$(printf '%s\n' "$batch" | jq -r .token)
# inspect events and write fragments such as counter.html and status.html
npx letmeknow-cli push ./preview --batch "$token" --updates updates.json
```

Commands:

```text
serve <dir>
show <dir>
pull <dir> [--wait seconds]
push <dir> --batch TOKEN [--updates FILE|-]
```

`show` returns the canonical current page without changing the event stream:

```bash
npx letmeknow-cli show ./preview > current.html
```

The public URL is the visual preview. `show` returns the accepted HTML, not a browser's local focus, open disclosures, unsent input, scroll position, or JavaScript state.

## Page updates

A push accepts one JSON document:

```json
{
  "updates": [
    {"target": "counter", "file": "counter.html"},
    {"target": "status", "html": "<output id=\"status\">Saved</output>"}
  ]
}
```

Each update must contain exactly one of `html` or `file`. A file is read by the CLI and supplies the replacement HTML. The normal operation is direct replacement of one element identified by its unique stable `id`:

```html
<output id="counter">41</output>
```

```json
{"target":"counter","html":"<output id=\"counter\">42</output>"}
```

The replacement must contain exactly one element, and that element must have the same ID as the target. Replacement HTML cannot contain scripts. The target must exist when the replacement is applied.

Use small output regions for ordinary updates. The replacement is destructive inside its target but leaves the rest of the page alone, so a counter update does not disturb a form or button elsewhere.

The document root is just another target. To intentionally replace all dynamic content, target the root:

```html
<main id="letmeknow-root">
  ...
</main>
```

```json
{
  "updates": [
    {"target": "letmeknow-root", "file": "root.html"}
  ]
}
```

Replacing the root intentionally discards browser-local state inside it. Use it when that is acceptable, not for every small change.

A single push may contain dozens of replacements. They are applied in the order listed. Later replacements may target elements introduced by earlier replacements in the same push, so introduce a target before updating it. Conversely, a replacement that removes a later target makes a following update invalid. The CLI validates the complete ordered batch before committing anything.

Each replacement becomes its own `update_ui` event with its own global event number. The complete push is still atomic: either all replacements and the pulled browser-event batch commit, or none do. Connected browsers receive the committed replacements in order.

A push without `--updates` commits the pulled browser events without changing the page:

```bash
npx letmeknow-cli push ./preview --batch "$token"
```

There is no separate acknowledgement command and no `--page` mode. Replacing `letmeknow-root` provides the broad page-update case.

## Page shell and scripts

Keep the document shell stable and keep the application root separate from the runtime:

```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Counter</title>
    <link rel="stylesheet" href="/app.css">
  </head>
  <body>
    <main id="letmeknow-root">
      <output id="counter">0</output>
    </main>
    <script type="module" src="/app.js"></script>
  </body>
</html>
```

The LetMeKnow runtime is injected into the page separately. Load optional agent-authored scripts from the initial page as static assets and keep those script references outside regions that are normally replaced. Scripts in update fragments are rejected; pushed updates do not load or execute new scripts.

Agent JavaScript should use delegated event listeners because replaced elements are new DOM nodes. Do not have browser JavaScript and pushed HTML independently own the same state. Browser-local attention behavior—such as opening a disclosure or hiding a panel—can remain local, but replacing its containing element intentionally discards that state.

## The event stream

Browser submissions and CLI page replacements share one ordered, in-memory event stream:

```text
submit       browser
submit       browser
update_ui    CLI: replace #counter
update_ui    CLI: replace #status
```

The CLI assigns event numbers in acceptance order. A single push with several replacements therefore advances the global stream once per replacement, in input order. The numbers do not claim to be the physical order in which people clicked.

Page updates are broadcast to all connected browsers. Browser submissions are delivered to the agent through `pull`; they are not broadcast as raw input to other browsers.

## Pull and page causality

`pull` returns an opaque batch token, current-page metadata, and browser events not yet committed by the agent. Pulling does not consume events. Events arriving while the agent works remain for a later pull.

```json
{
  "token": "…",
  "frontier": 7,
  "page_event": 5,
  "page_hash": "…",
  "events": [
    {
      "type": "submit",
      "id": "…",
      "event_number": 7,
      "page_event": 5,
      "form_id": "decision",
      "action": "/decide",
      "trigger": {"name": "decision", "value": "approve"},
      "values": {"comment": "Looks good", "decision": "approve"}
    }
  ]
}
```

`page_event` is the page-update event number displayed when the browser submitted. Compare each event's `page_event` with the batch's current page before applying old input to the current HTML. `frontier` is the latest global event number, including events that are not browser submissions.

The token identifies exactly the browser-event frontier the agent saw. A successful push commits that frontier and its ordered replacements together. Browser events accepted after the pull remain for the next batch.

## Forms

Use ordinary same-origin forms with stable IDs and meaningful field names:

```html
<form id="decision" action="/decide" method="post">
  <label>Comment <textarea id="comment" name="comment"></textarea></label>
  <button name="decision" value="approve">Approve</button>
  <button name="decision" value="reject">Reject</button>
</form>
```

The runtime intercepts native form submission and sends a JSON `submit` event to LetMeKnow. It assigns an opaque UUID, stores the event in a durable browser outbox before delivery, retries after connection failures, and reuses the UUID on retry. The CLI deduplicates repeated delivery of the same event. Distinct intentional submissions remain distinct, including rapid repeated clicks.

Form values are untrusted input and should be validated by the agent. File uploads are not supported.

## Static assets

Static assets are read live from the directory independently of the canonical dynamic page. Finish writing an asset before pushing HTML that references it, write files atomically, and use versioned filenames or cache-busting URLs when a changed asset must be fetched with the page update.

This design intentionally does not provide atomic publication of the whole directory. The dynamic page changes only through ordered replacements; other files can change as soon as they are written.

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

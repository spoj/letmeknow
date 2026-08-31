---
name: letmeknow
description: Serve a temporary live HTML page, collect structured human feedback, and push ordered HTML replacements.
---

# LetMeKnow

Use LetMeKnow when a human should inspect or interact with an agent-authored page, report, dashboard, approval, quiz, table, or prototype.

## Start

Create a directory containing the public files and an initial `index.html`:

```bash
npx letmeknow-cli serve ./preview
```

`serve` reads `index.html` once as the initial canonical dynamic page and serves it at `/`. Other files—CSS, JavaScript, images, and data—are served live from the directory. The first stdout JSON line contains the public bearer URL and initial page metadata:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/","page_event":0,"page_hash":"…"}
```

Give the URL to the human. Anyone with the URL can view the page and submit its forms. Canonical page state and events are temporary in-memory session state; they end when `serve` stops. `serve` never modifies agent files.

The initial page should have a stable shell and dynamic root:

```html
<body>
  <main id="letmeknow-root">
    ...
  </main>
  <script type="module" src="/app.js"></script>
</body>
```

Keep the agent script and the LetMeKnow runtime outside the normal replacement targets.

## Agent loop

Pull browser events, update one or more HTML fragments, and push the replacements:

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

`show` returns the current canonical HTML without changing the event stream:

```bash
npx letmeknow-cli show ./preview > current.html
```

The public URL is the visual preview. `show` returns canonical HTML, not a browser's local focus, open disclosures, unsent input, scroll position, or JavaScript state.

## Push updates

A push accepts one JSON document:

```json
{
  "updates": [
    {"target": "counter", "file": "counter.html"},
    {"target": "status", "html": "<output id=\"status\">Saved</output>"}
  ]
}
```

Each update must contain exactly one of `html` or `file`. The CLI reads the fragment and replaces the unique element with the requested ID. The replacement must contain exactly one element with the same ID as the target. Update fragments cannot contain scripts.

Use a narrow output target for ordinary changes:

```html
<output id="counter">41</output>
```

```json
{"updates":[{"target":"counter","html":"<output id=\"counter\">42</output>"}]}
```

To replace all dynamic content, target the root like any other element:

```json
{"updates":[{"target":"letmeknow-root","file":"root.html"}]}
```

Replacing the root intentionally discards browser-local state inside it. Use it when that is acceptable; do not use it for every small update.

A single push may contain dozens of replacements. They are applied in listed order. A later target may be introduced by an earlier replacement, so create it first. A later replacement cannot target an element removed earlier in the same push. The complete ordered batch is validated before anything is committed.

Every replacement becomes a separate globally numbered `update_ui` event. The whole push is atomic: either all replacements and the pulled browser-event batch commit, or none do. Connected browsers receive the replacements in order.

A push without `--updates` commits the pulled browser events without changing the page:

```bash
npx letmeknow-cli push ./preview --batch "$token"
```

There is no `ack` command and no `--page` mode. Replacing `letmeknow-root` is the broad page-update case.

## Event stream and page causality

Browser submissions and CLI replacements share one ordered, in-memory event stream:

```text
submit       browser
submit       browser
update_ui    CLI: replace #counter
update_ui    CLI: replace #status
```

The CLI assigns event numbers in acceptance order. They do not claim to be the physical order in which people clicked. Browser submissions are delivered to the agent through `pull`; raw submissions are not broadcast to other browsers. Page replacements are broadcast to all connected browsers.

`pull` returns an opaque batch token, current-page metadata, and browser events not yet committed by the agent. Pulling does not consume events. Events arriving while the agent works remain for a later pull.

```json
{
  "token":"…",
  "frontier":7,
  "page_event":5,
  "page_hash":"…",
  "events":[
    {
      "type":"submit",
      "id":"…",
      "event_number":7,
      "page_event":5,
      "form_id":"decision",
      "action":"/decide",
      "trigger":{"name":"decision","value":"approve"},
      "values":{"comment":"Looks good","decision":"approve"}
    }
  ]
}
```

An event's `page_event` identifies the page displayed when the browser submitted. Compare it with the batch's current `page_event` before applying old input to current HTML. `frontier` is the latest global event number, including page-update events.

## Forms

Use native same-origin forms with meaningful field names:

```html
<form id="review" action="/review" method="post">
  <label>Comment <textarea id="comment" name="comment"></textarea></label>
  <button name="decision" value="approve">Approve</button>
  <button name="decision" value="reject">Reject</button>
</form>
```

The runtime converts native form submissions into JSON `submit` events. It assigns an opaque UUID, stores each event in a durable browser outbox before sending it, retries after connection failures, and reuses the UUID on retry. The CLI deduplicates repeated delivery. Ten intentional rapid clicks produce ten distinct events. File uploads are not supported.

Treat pulled values as untrusted input. Validate them and escape them before putting them into HTML.

## Browser and HTML rules

Normal updates are direct replacements, not DOM morphs. Stable IDs are therefore important for naming update boundaries, not for preserving DOM nodes.

- The CLI owns content inside replacement targets.
- The browser owns local focus, open/closed disclosure state, and hide/show behavior outside deliberately replaced targets.
- A root replacement can destroy all local state inside the root.
- Load agent-authored JavaScript from the initial page as a static asset.
- Use delegated event listeners because replaced elements are new DOM nodes.
- Scripts in update fragments are not executed.
- Do not have browser JavaScript and pushed HTML independently own the same state.

Reconnect may reload the current canonical page. Captured submissions remain safe in the durable browser outbox and are retried after reconnect.

## Static assets

CSS, JavaScript, images, and other non-`index.html` files are served live. Finish writing an asset before pushing HTML that references it. Write assets atomically, and use versioned filenames or cache-busting URLs when the browser must fetch a changed asset with the page update.

This design intentionally does not provide atomic publication of the whole directory. The dynamic page changes through ordered replacements; other files can change as soon as they are written.

## Stop

Send `SIGINT` or `SIGTERM` to `serve`. The temporary session ends when the process stops.

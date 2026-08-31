---
name: letmeknow
description: Serve a temporary live HTML page, collect structured human feedback, and push ordered HTML replacements.
---

# LetMeKnow

Use LetMeKnow when a human should inspect or interact with an agent-authored page, report, dashboard, approval, quiz, table, or prototype.

## Start

Create a directory containing the public files and an initial `index.html`, then run:

```bash
npx letmeknow-cli serve ./preview
```

`serve` reads `index.html` once as the initial canonical dynamic page and serves it at `/`. Other files—such as CSS, JavaScript, images, and data—are served live from the directory. The first stdout JSON line contains the public bearer URL and initial page metadata:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/","page_event":0,"page_hash":"…"}
```

The initial page should have a stable shell and a dynamic root:

```html
<body>
  <main id="letmeknow-root">
    ...
  </main>
  <script type="module" src="/app.js"></script>
</body>
```

The runtime is injected into the page separately. Keep agent-authored scripts and the runtime outside normal replacement targets.

## Session lifetime and reconnect

A producer must successfully send `open` shortly after connecting. The session expires exactly 24 hours after that successful `open`, including while the producer remains connected. This deadline is absolute and is not reset by reconnects.

If an opened producer disconnects, its session remains reconnectable for 10 minutes. A reconnect uses the existing session credential and does not extend the 24-hour deadline. When the deadline or disconnect grace period expires, the session and its browser connections end.

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

`show` returns the current canonical page without changing the event stream:

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

Each update must contain exactly one of `html` or `file`. A file supplies the replacement HTML. The normal operation is direct replacement of one element identified by its unique stable `id`:

```html
<output id="counter">41</output>
```

```json
{"updates":[{"target":"counter","html":"<output id=\"counter\">42</output>"}]}
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
{"updates":[{"target":"letmeknow-root","file":"root.html"}]}
```

Replacing the root intentionally discards browser-local state inside it. Use it when that is acceptable, not for every small change.

A single push may contain many replacements. They are applied in the order listed. Later replacements may target elements introduced by earlier replacements in the same push, so introduce a target before updating it. Conversely, a replacement that removes a later target makes a following update invalid. The CLI validates the complete ordered batch before committing anything.

Each replacement becomes its own `update_ui` event with its own global event number. The complete push is still atomic: either all replacements and the pulled browser-event batch commit, or none do. Connected browsers receive committed replacements in order.

A push without `--updates` commits the pulled browser events without changing the page:

```bash
npx letmeknow-cli push ./preview --batch "$token"
```

There is no separate acknowledgement command and no `--page` mode. Replacing `letmeknow-root` provides the broad page-update case.

## Event stream and page causality

Browser submissions and CLI page replacements share one ordered, in-memory event stream:

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

The runtime converts native form submission into a JSON `submit` event. It assigns an opaque UUID, stores each event in a durable browser outbox before delivery, retries after connection failures, and reuses the UUID on retry. The CLI deduplicates repeated delivery of the same event. Distinct intentional submissions remain distinct, including rapid repeated clicks. File uploads are not supported.

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

When a session ends, the browser shows a permanent closed status and discards unsent submissions rather than retrying them.

## Static assets

CSS, JavaScript, images, and other non-`index.html` files are served live. Finish writing an asset before pushing HTML that references it. Write assets atomically, and use versioned filenames or cache-busting URLs when the browser must fetch a changed asset with the page update.

This design intentionally does not provide atomic publication of the whole directory. The dynamic page changes through ordered replacements; other files can change as soon as they are written.

## Security

The URL is a bearer capability. Anyone who has it can view the page and submit forms. Keep secrets and unrelated files outside the served directory. Browser values are untrusted input; escape them before placing them in HTML.

## Stop

Send `SIGINT` or `SIGTERM` to `serve`. The temporary session ends when the process stops.

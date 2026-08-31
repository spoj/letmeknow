---
name: letmeknow
description: Serve a temporary live HTML page, collect structured human feedback, and push agent-authored page updates.
---

# LetMeKnow

Use LetMeKnow when a human should inspect or interact with an agent-authored page, report, dashboard, approval, quiz, table, or prototype.

## Start

Create a directory containing the public files and an initial `index.html`:

```bash
npx letmeknow-cli serve ./preview
```

`serve` reads `index.html` once as the canonical dynamic document and serves it at `/`. It serves the other files in the directory live as static assets. The first stdout JSON line contains the public bearer URL:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/","page_event":0,"page_hash":"…"}
```

Give the URL to the human. Anyone with the URL can view the page and submit its forms. The CLI connects outbound and opens no network port. Canonical page state and events are temporary in-memory session state; they end when `serve` stops. `serve` never modifies agent files.

## Agent loop

Pull browser events, update the desired page, and push it:

```bash
batch=$(npx letmeknow-cli pull ./preview --wait 30)
token=$(printf '%s\n' "$batch" | jq -r .token)
# inspect the events and edit index.html
npx letmeknow-cli push ./preview --batch "$token" --page index.html
```

Commands:

```text
serve <dir>
show <dir>
pull <dir> [--wait seconds]
push <dir> --batch TOKEN [--page FILE|-]
```

`pull` returns an opaque batch token, current-page metadata, and browser events not yet committed by the agent. Pulling does not consume events. Events arriving while the agent works remain for a later pull.

```json
{"token":"…","frontier":7,"page_event":5,"page_hash":"…","events":[{"type":"submit","id":"…","event_number":7,"page_event":5,"form_id":"decision","action":"/decide","trigger":{"name":"decision","value":"approve"},"values":{"comment":"Looks good","decision":"approve"}}]}
```

An event's `page_event` identifies the page displayed when the browser submitted it. Compare it with the batch's current `page_event` before applying old input to the current page.

`push --page FILE` atomically commits the events represented by the token, makes FILE the complete desired dynamic document, appends one page-update event to the global event stream, and broadcasts it to all connected browsers. Browsers morph the page without navigation.

```bash
npx letmeknow-cli push ./preview --batch "$token" --page index.html
```

A push without `--page` only commits the pulled browser events:

```bash
npx letmeknow-cli push ./preview --batch "$token"
```

Use `--page -` for standard input:

```bash
npx letmeknow-cli push ./preview --batch "$token" --page - < updated.html
```

The page push is all-or-nothing. Invalid input or an invalid token commits nothing. The CLI assigns one global order to each browser submission and each page-update event.

`show` retrieves the canonical dynamic HTML held by `serve` without changing the event stream:

```bash
npx letmeknow-cli show ./preview > current.html
```

The public URL is the visual preview. `show` returns canonical HTML, not a browser’s local DOM state such as focus, open disclosures, unsent input, scroll position, or JavaScript state.

## Forms

Use native forms with stable IDs and meaningful names:

```html
<form id="review" action="/review" method="post">
  <label>Comment <textarea id="comment" name="comment"></textarea></label>
  <button name="decision" value="approve">Approve</button>
  <button name="decision" value="reject">Reject</button>
</form>
```

The browser runtime serializes native form submissions as JSON `submit` events. It assigns an opaque ID, stores each event in a local durable outbox before sending it, retries after connection failures, and reuses the ID on retry. The CLI deduplicates repeated delivery. Ten intentional rapid clicks should produce ten distinct events. File uploads are not supported.

Treat pulled values as untrusted input. Validate them and escape them before putting them into HTML.

## Dynamic page rules

Every page push supplies the complete desired dynamic document. The browser uses HTML morphing, so unchanged DOM nodes can survive while changed content is updated.

Give elements stable unique IDs. Load agent-authored JavaScript from the initial page as a static asset and use delegated listeners. Existing scripts remain active across morphs, but scripts added or changed by a pushed page are not executed in connected browsers; keep script references fixed for the session.

The CLI owns page content. The browser preserves focus, scrolling, dirty controls with stable IDs, and the open state of `<details id="…">`. Mark an element with a stable ID and `data-letmeknow-local` when its `hidden` state is browser-owned. Do not have browser JavaScript and pushed HTML otherwise mutate the same state; a later morph may replace browser-created changes.

Page updates are shared with all connected browsers. There is no dynamic view or per-browser update system. Use ordinary static links and files when the application needs more persistent pages.

## Static assets

CSS, JavaScript, images, and other non-`index.html` files are served live. Finish writing an asset before pushing HTML that references it. Write assets atomically, and use versioned filenames or cache-busting URLs when the browser must fetch a changed asset with the new page.

## Stop

Send `SIGINT` or `SIGTERM` to `serve`. The temporary session ends when the process stops.

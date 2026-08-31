---
name: letmeknow
description: Serve a temporary live HTML page, collect structured browser feedback, and run ordered agent-authored JavaScript.
---

# LetMeKnow

Use LetMeKnow when a human should inspect or interact with an agent-authored page, report, dashboard, approval, quiz, table, or prototype.

## Start

Create a directory containing the public files and an initial `index.html`:

```bash
npx letmeknow-cli serve ./preview
```

`serve` reads `index.html` as the base document and serves it at `/`. Other files—such as CSS, JavaScript, images, and data—are served live from the directory. The first stdout JSON line contains the public URL and initial page metadata:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/","page_event":0,"page_hash":"…"}
```

The base page should contain the application shell and any agent-authored static scripts:

```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Counter</title>
    <link rel="stylesheet" href="/app.css">
  </head>
  <body>
    <main id="app">
      <output id="counter">0</output>
    </main>
    <script type="module" src="/app.js"></script>
  </body>
</html>
```

Give the public URL to the human. It is the way to inspect the resulting global state.

## Agent loop

Pull browser events, inspect them, then push an optional browser script:

```bash
batch=$(npx letmeknow-cli pull ./preview --wait 30)
token=$(printf '%s\n' "$batch" | jq -r .token)
npx letmeknow-cli push ./preview --batch "$token" --script update.js
```

Commands:

```text
serve <dir>
pull <dir> [--wait seconds]
push <dir> --batch TOKEN [--script FILE|-]
```

`--script FILE` reads a JavaScript snippet from a file. `--script -` reads it from standard input. A push without `--script` commits the pulled browser events without running UI code.

## Browser scripts

Scripts are trusted, agent-authored JavaScript. They execute directly in connected browsers, in the order committed. Use the normal browser DOM and platform APIs:

```js
const list = document.querySelector("#items");
list.insertAdjacentHTML(
  "beforeend",
  '<li id="item-42"><input name="label" value="New item"></li>'
);
```

This exposes the underlying browser capability: scripts can insert, remove, move, replace, and modify any DOM content, as well as use browser APIs. Unaffected DOM nodes retain their browser-owned state.

Scripts run in a fresh `Function` scope with `this` set to `window`. Put helpers and persistent state on `globalThis` or in the DOM; declarations do not persist between snippets. Execution is synchronous at the runtime boundary: promises and other asynchronous work are not awaited and may interleave with later scripts. Pages need a CSP that permits eval-like `Function` execution.

Scripts are trusted page code and can interfere with the page or runtime, so avoid monkey-patching runtime infrastructure. The initial `index.html` is the base for the session. New or reloaded browsers load that base and replay committed `run_ui` scripts in order. A script that uses randomness, current time, network requests, or external side effects can produce different results or run its side effects again when a browser reloads.

A failed script reports an error but does not stop later scripts. A later script may repair the page. Reloading replays the committed sequence, including the failed script, so later corrective scripts should remain safe to run after it.

Use the public URL to inspect global state. The CLI serves the base document and the script event log; it does not attempt to materialize the live browser DOM.

## Event stream and atomic pushes

Browser submissions and UI scripts share one ordered, in-memory event stream:

```text
submit       browser
submit       browser
run_ui       CLI: execute update.js
run_ui       CLI: execute repair.js
```

The CLI assigns event numbers in acceptance order. They do not claim to be the physical order in which people clicked or browsers executed code. Browser submissions are delivered to the agent through `pull`; raw submissions are not broadcast to other browsers. UI scripts are broadcast to connected browsers and replayed by later browsers.

`pull` returns an opaque batch token, current-page metadata, and browser events not yet committed by the agent. Pulling does not consume events. Events arriving while the agent works remain for a later pull:

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

`page_event` is the last committed UI-script event displayed when the browser submitted. Compare it with the batch's current page before applying old input to the current global state. `frontier` is the latest global event number, including submissions and UI scripts.

A successful push commits the exact pulled browser-event frontier and its optional script together, or commits neither. The script becomes one `run_ui` event and receives one global event number. Browser events accepted after the pull remain for the next batch. Repeating a push with the same token and script is idempotent; changing the script for an already committed token is rejected.

## Forms

Use ordinary same-origin forms with stable IDs and meaningful field names:

```html
<form id="decision" action="/decide" method="post">
  <label>Comment <textarea id="comment" name="comment"></textarea></label>
  <button name="decision" value="approve">Approve</button>
  <button name="decision" value="reject">Reject</button>
</form>
```

The runtime captures native form submissions by default and converts them into JSON `submit` events. An application handler can claim a submission by calling `event.preventDefault()` before the runtime handler runs. It assigns an opaque UUID, stores each event in a durable browser outbox before delivery, retries after connection failures, and reuses the UUID on retry. The CLI deduplicates repeated delivery of the same event. Distinct intentional submissions remain distinct, including rapid repeated clicks. `form.submit()` and direct `fetch()` bypass the structured outbox. File uploads are not supported.

Form values are untrusted input. Validate them and escape them before putting them into HTML or scripts.

## Static assets and reconnects

CSS, JavaScript, images, and other non-`index.html` files are served live. Finish writing an asset before relying on it from a script, write files atomically, and use versioned filenames or cache-busting URLs when a changed asset must be fetched.

The public URL is a bearer capability. If the producer disconnects, browsers show a disconnected state and may reconnect; reconnect is best-effort. Sessions are temporary and may be expired by the service. Do not make application correctness depend on reconnect succeeding.

When the producer intentionally closes the session, the browser receives a terminal close notification, stops reconnecting, and discards unsent submissions. Service expiry and ordinary network loss are disconnects, not application-script events.

## Security

Scripts are trusted agent-authored code and execute in every connected browser. They can modify the page and browser environment, so avoid monkey-patching runtime infrastructure. Runtime-generated `data-letmeknow-*` attributes are reserved. Do not put secrets in scripts or in the served directory. Anyone with the public URL can view the page and submit forms.

## Stop

Send `SIGINT` or `SIGTERM` to `serve`. The temporary session ends when the process stops.

## Development

```bash
npm install
npm test
npm run test:browser
npm run dev
npm run deploy
```

The browser test requires Firefox and geckodriver. `npm run dev` and `npm run deploy` operate the Cloudflare relay.

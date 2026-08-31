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

Run `serve` in a monitored background process and consume its stdout as a newline-delimited JSON event stream. Its first line is ready metadata:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/","frontier":0,"page_event":0,"page_hash":"…"}
```

`frontier` is the latest authoritative global event number. `page_event` is the latest committed UI-script event, and `page_hash` identifies the replayable page at that point. Give the public URL to the human. It is the way to inspect the resulting global state.

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

## Agent loop

Read each accepted submission from the monitored `serve` stdout. It already has its authoritative global event number:

```json
{"type":"submit","id":"…","event_number":7,"page_event":5,"form_id":"decision","action":"/decide","trigger":{"name":"decision","value":"approve"},"values":{"comment":"Looks good","decision":"approve"}}
```

After considering events through event 7, acknowledge that inclusive prefix and optionally run an update:

```bash
npx letmeknow-cli commit ./preview --through 7 --script update.js
```

A script supplied with `--script FILE` is read from a file. `--script -` reads it from standard input. A commit without `--script` only acknowledges browser submissions. A proactive first update uses `--through 0`:

```bash
npx letmeknow-cli commit ./preview --through 0 --script initialize.js
```

There is no polling or recovery command. If the serve process or its stdout is lost, start a new session.

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

Scripts are trusted page code and can interfere with the page or runtime, so avoid monkey-patching runtime infrastructure. The initial `index.html` is the base document. New or reloaded browsers load that base and replay committed scripts in order. A script that uses randomness, current time, network requests, or external side effects can produce different results or run its side effects again when a browser reloads.

A failed script reports an error but does not stop later scripts. A later script may repair the page. Reloading replays the committed sequence, including the failed script, so later corrective scripts should remain safe to run after it.

Use the public URL to inspect global state. The CLI serves the base document and the script event log; it does not attempt to materialize the live browser DOM.

## Event stream and concurrent commits

Browser submissions and UI scripts share one authoritative, in-memory event stream:

```text
submit       browser, event 1
submit       browser, event 2
run_ui       CLI,     event 3, considered_through 2
submit       browser, event 4
run_ui       CLI,     event 5, considered_through 4
```

The CLI assigns event numbers in acceptance order. They do not claim to be the physical order in which people clicked or browsers executed code. Every accepted submission is printed once on the `serve` stream. UI scripts are sent to connected browsers and replayed by later browsers; the stream prints concise metadata for each committed UI script:

```json
{"type":"run_ui","event_number":3,"considered_through":2,"frontier":3,"page_event":3,"page_hash":"…"}
```

`commit --through N` means that the agent considered every authoritative browser submission with a number less than or equal to N. N must be a non-negative safe integer, no greater than the current frontier, and no less than the last acknowledged submission frontier. UI events do not need to be included in this cursor, so the same N may be used for repeated no-script acknowledgements or repeated proactive scripts. Scripts are not content-deduplicated; every successful script commit creates a new UI event. A local command retry may therefore run the script again.

A successful commit removes only pending browser submissions with event numbers through N. New submissions arriving after N remain pending even if they arrive while the agent is preparing the commit. A script, if supplied, becomes the next global event and records `considered_through: N`; it is sent to browsers and included in replay history. A no-script commit only acknowledges the prefix. The page always applies scripts in commit order, even when a script's considered cursor is below the current UI event number.

Commits are serialized with browser acceptance. The replayable page is built before any state is changed. If page size validation fails, the commit fails without acknowledging submissions, advancing the page, or consuming the declared frontier; retry it with the same N and a smaller script.

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

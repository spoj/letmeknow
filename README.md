# LetMeKnow

LetMeKnow gives an agent a temporary public browser surface for structured human feedback. The agent serves an HTML page, receives browser submissions, and runs ordered JavaScript in connected browsers.

## Quick start

Create a directory with an `index.html`, then run `serve` under the agent's process monitor:

```bash
npx letmeknow-cli serve ./preview
```

`serve` prints newline-delimited JSON. The first line contains the public URL and the authoritative event frontier:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/","frontier":0,"page_event":0,"page_hash":"…"}
```

Keep the serve process running and read its stdout stream. Accepted browser submissions then appear as they are numbered; no polling command is needed:

```json
{"type":"submit","id":"…","event_number":1,"page_event":0,"form_id":"review","action":"/review","trigger":{"name":"decision","value":"approve"},"values":{"decision":"approve"}}
```

The URL is the public page. Anyone who has it can view and submit it.

## Commands

```text
serve <dir>
commit <dir> --through <event-number> [--script FILE|-]
```

A commit declares that the agent considered every browser submission through the inclusive global event number, then acknowledges those submissions. The cursor is monotonic but need not advance: repeated acknowledgements and periodic scripts may use the same number. For example:

```bash
npx letmeknow-cli commit ./preview --through 1 --script update.js
```

A script supplied with `--script -` is read from standard input. A commit without `--script` only acknowledges events. For a proactive first update, use `--through 0`:

```bash
npx letmeknow-cli commit ./preview --through 0 --script initialize.js
```

The stream and commit operation are designed for one monitored `serve` process. If the process or its stdout is lost, start a new session; the stream is not a recovery interface.

## Browser scripts

Scripts are trusted, agent-authored JavaScript and run directly in each connected browser. Use the browser DOM normally:

```js
document.querySelector("#items").insertAdjacentHTML(
  "beforeend",
  '<li id="item-3">Three</li>'
);
```

Existing DOM nodes remain available, so scripts can preserve focus, dirty form controls, open disclosures, and other browser state. New or reloaded browsers start from `index.html` and replay committed scripts in order. The public URL is the way to inspect the resulting global state.

Scripts should generally be synchronous and replayable. Randomness, current time, network requests, and external side effects can produce different results or happen again whenever a browser reloads. Scripts execute through `Function`, so the page CSP must permit eval-like execution. A failed script reports an error but does not stop later scripts; a later script can correct the state.

## Forms and security

Use ordinary same-origin forms with meaningful field names. The runtime captures native form submissions by default, stores them in a durable browser outbox before delivery, retries after connection failures, and reuses the same UUID on retry. An application handler can claim a submission with `event.preventDefault()`. `form.submit()` and direct `fetch()` bypass the structured outbox. Treat submitted values as untrusted input and escape them before using them in HTML. File uploads are not supported.

The public URL is a bearer capability: anyone who has it can view the page and submit forms. Keep secrets and unrelated files outside the served directory.

## Development

```bash
npm install
npm test
npm run test:browser
npm run dev
npm run deploy
```

The browser smoke test requires Firefox and geckodriver. `npm run dev` and `npm run deploy` operate the Cloudflare relay. See [`SKILL.md`](SKILL.md) for the complete agent workflow and event semantics.

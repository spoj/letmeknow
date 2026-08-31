# LetMeKnow

LetMeKnow gives an agent a temporary public browser surface for structured human feedback. The agent serves an HTML page, receives browser submissions, and can run ordered JavaScript in connected browsers.

## Quick start

Create a directory with an `index.html`, then run:

```bash
npx letmeknow-cli serve ./preview
```

The CLI prints one JSON line containing the public URL:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/","page_event":0,"page_hash":"…"}
```

Open the URL to inspect the global page. The initial `index.html` is the base document. The service applies committed browser scripts after that base.

## Commands

```text
serve <dir>
pull <dir> [--wait seconds]
push <dir> --batch TOKEN [--script FILE|-]
```

Pull browser events without consuming them, then push the batch with an optional JavaScript file:

```bash
batch=$(npx letmeknow-cli pull ./preview --wait 30)
token=$(printf '%s\n' "$batch" | jq -r .token)
npx letmeknow-cli push ./preview --batch "$token" --script update.js
```

A script supplied with `--script -` is read from standard input. A push with a script creates one ordered `run_ui` event. A push without one only commits the pulled browser events.

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

Use ordinary same-origin forms with meaningful field names. The runtime turns submissions into structured events, stores them in a browser outbox before delivery, retries after connection failures, and reuses the same UUID on retry. Treat submitted values as untrusted input and escape them before using them in HTML. File uploads are not supported.

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

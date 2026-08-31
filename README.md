# LetMeKnow

LetMeKnow gives an agent a temporary public browser surface for structured human feedback. The agent serves ordinary HTML and static assets, receives browser submissions, and can push ordered HTML replacements.

## Quick start

Create a directory with an `index.html`, then run:

```bash
npx letmeknow-cli serve ./preview
```

The CLI prints one JSON line containing the public bearer URL:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/","page_event":0,"page_hash":"…"}
```

Give the URL to the human. Anyone with the URL can view the page and submit its forms.

## Commands

```text
serve <dir>
show <dir>
pull <dir> [--wait seconds]
push <dir> --batch TOKEN [--updates FILE|-]
```

`serve` reads `index.html` once as the canonical page. Other files are served live from the directory. `show` prints the accepted canonical HTML. `pull` returns browser events without consuming them; `push` commits a pulled batch, optionally with ordered replacements. See [`SKILL.md`](SKILL.md) for the complete workflow and protocol.

## Page updates

Use stable IDs as replacement boundaries:

```html
<output id="counter">41</output>
```

```json
{"updates":[{"target":"counter","html":"<output id=\"counter\">42</output>"}]}
```

Each replacement must contain one element with the target's ID and cannot contain scripts. Replacements in one push are applied in order and atomically. Replacing `letmeknow-root` is the broad page-update case and intentionally discards browser-local state inside that root.

## Session and security basics

Sessions are temporary and held in memory by the CLI and relay. A session expires exactly 24 hours after the producer successfully opens it, even if the producer remains connected. If the producer disconnects before then, it has a 10-minute grace period to reconnect; reconnecting never extends the absolute 24-hour lifetime.

The public URL is a bearer capability: anyone who has it can view the page and submit forms. Treat browser values as untrusted input and escape them before placing them in HTML. Keep secrets and unrelated files outside the served directory.

## Development

```bash
npm install
npm test
npm run test:browser
npm run dev
npm run deploy
```

The browser smoke test requires Firefox and geckodriver. `npm run dev` and `npm run deploy` operate the Cloudflare relay. For the detailed agent workflow, forms, event causality, reconnect behavior, and static-asset guidance, read [`SKILL.md`](SKILL.md).

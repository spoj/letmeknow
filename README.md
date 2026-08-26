# LetMeKnow

The deployed text root (`/`) contains API usage.

## Local development and tests

```bash
npm install
npm run dev
npm test
```

## Deployment

Apply D1 migrations to production before pushing the configured production branch:

```bash
npx wrangler d1 migrations apply letmeknow --remote
```

Cloudflare's dashboard Git integration builds and deploys that branch; the branch and integration settings are managed in the dashboard, not in this repository.

Smoke-test the deployed Worker:

```bash
curl -sS https://letmeknow.dev/
curl -sS -X POST https://letmeknow.dev/questions \
  -H 'Content-Type: application/json' \
  -d '{"title":"Smoke test","fields":[{"id":"ok","label":"Did it work?","type":"choice","options":["Yes","No"]}]}'
```

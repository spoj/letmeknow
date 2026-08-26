# LetMeKnow

A small MeatSpace-style human checkpoint service on Cloudflare Workers + D1.

An agent creates a questionnaire with one public `curl` call. The response contains two independent capability URLs:

- `question_url`: anonymous human form
- `status_url`: agent-only polling URL

Both expire after 24 hours. Creation is intentionally public for the MVP and is rate-limited at the Cloudflare edge (3 requests per 60 seconds per edge location/IP key).

## API

Create a questionnaire:

```bash
curl -sS -X POST https://letmeknow.dev/questions \
  -H 'Content-Type: application/json' \
  -d '{
    "title": "Release approval",
    "fields": [
      {"id": "approve", "label": "Deploy this release?", "type": "choice", "options": ["Yes", "No"]},
      {"id": "notes", "label": "Anything else?", "type": "text"}
    ]
  }'
```

Create returns:

```json
{
  "question_url": "https://letmeknow.dev/q/<answer-token>",
  "status_url": "https://letmeknow.dev/s/<status-token>",
  "expires_at": "2026-08-27T12:00:00.000Z"
}
```

Poll the status URL:

```bash
curl -i "$STATUS_URL"
```

- `202` and `{"status":"pending"}` means keep polling after the `Retry-After` delay.
- `200` returns `{"status":"answered","answers":{...}}`.
- `410` means the question expired.

A questionnaire has one to eight required fields. Supported field types are `choice` and `text`; yes/no is a choice with `options: ["Yes", "No"]`.

## Local development

```bash
npm install
npm run db:local
npm run dev
```

Then use `http://localhost:8787` in the curl examples. Wrangler's local D1 database is stored under `.wrangler/`.

Run the type check and a full local create → pending → answer → completed → duplicate smoke test with:

```bash
npm test
```

The root URL returns plain text instructions so agents can discover the API without parsing an HTML landing page.

## Deploy

Install and authenticate Wrangler:

```bash
brew install cloudflare-wrangler
wrangler login
```

Create the remote database and copy its ID into `wrangler.jsonc` in place of the all-zero placeholder:

```bash
wrangler d1 create letmeknow
wrangler d1 migrations apply letmeknow --remote
wrangler deploy
```

The current config deploys to a temporary `workers.dev` URL. Attach `letmeknow.dev` as a Worker custom domain in the Cloudflare dashboard after the zone is active.

## GitHub Actions

`.github/workflows/deploy.yml` runs `npm test` on pull requests and deploys `main` after tests pass. It also applies any pending D1 migrations before deployment.

To enable deployment from GitHub:

1. In Cloudflare, open **My Profile → API Tokens → Create Token → Custom token**.
2. Give the token only these account permissions:
   - **Workers Scripts: Edit**
   - **D1: Edit**
3. Copy the token once. Do not commit it or put it in chat.
4. In the GitHub repository, open **Settings → Secrets and variables → Actions → New repository secret**.
5. Create a secret named `CLOUDFLARE_API_TOKEN` and paste the token there.
6. Push to `main` to deploy, or use **Actions → Test and deploy → Run workflow**.

The account ID is stored in `wrangler.jsonc`; it is not a secret. The workflow uses the project-local Wrangler version from `package-lock.json`.

## Namecheap

Add `letmeknow.dev` to Cloudflare. Cloudflare will provide two nameservers. In Namecheap, open **Domain List → Manage → Nameservers**, choose **Custom DNS**, enter both Cloudflare nameservers, and save. Do not add a separate CNAME after Cloudflare becomes authoritative. If Namecheap DNSSEC is enabled, disable it before changing nameservers and re-enable DNSSEC from Cloudflare afterward.

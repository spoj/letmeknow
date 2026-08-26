interface Env {
  DB: D1Database;
  CREATE_RATE_LIMIT: RateLimitBinding;
}

interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

type ChoiceField = {
  id: string;
  label: string;
  type: "choice";
  options: string[];
};

type TextField = {
  id: string;
  label: string;
  type: "text";
};

type Field = ChoiceField | TextField;

type QuestionRow = {
  answer_hash: string;
  status_hash: string;
  title: string;
  fields: string;
  answers: string | null;
  created_at: number;
  expires_at: number;
  answered_at: number | null;
};

const MAX_BODY_BYTES = 16_384;
const MAX_TITLE_LENGTH = 120;
const MAX_LABEL_LENGTH = 300;
const MAX_ANSWER_LENGTH = 2_000;
const MAX_FIELDS = 8;
const MAX_OPTIONS = 8;
const MAX_OPTION_LENGTH = 100;
const QUESTION_TTL_MS = 24 * 60 * 60 * 1_000;
const encoder = new TextEncoder();

function baseHeaders(contentType: string): Headers {
  return new Headers({
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Robots-Tag": "noindex, nofollow"
  });
}

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  const responseHeaders = baseHeaders("application/json; charset=utf-8");
  for (const [key, value] of Object.entries(extra)) responseHeaders.set(key, value);
  return new Response(`${JSON.stringify(body)}\n`, { status, headers: responseHeaders });
}

function text(body: string, status = 200): Response {
  return new Response(`${body.trim()}\n`, { status, headers: baseHeaders("text/plain; charset=utf-8") });
}

function html(title: string, body: string, status = 200): Response {
  const responseHeaders = baseHeaders("text/html; charset=utf-8");
  responseHeaders.set(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
  );
  return new Response(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>${escapeHtml(title)} · LetMeKnow</title>
  <style>
    :root{color-scheme:dark;--bg:#0b120f;--panel:#111a15;--line:#294333;--text:#f5fff7;--muted:#a2b7a7;--accent:#78f2a1;--danger:#ffb0b0}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(700px 400px at 80% 0,#17442b 0,transparent 65%),var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,sans-serif}
    main{width:min(640px,calc(100% - 32px));margin:0 auto;padding:40px 0 64px}.brand{color:var(--accent);font-size:13px;font-weight:700;letter-spacing:.13em;text-transform:uppercase;margin-bottom:42px}
    .card{border:1px solid var(--line);background:#111a2fdd;border-radius:20px;padding:clamp(22px,5vw,42px);box-shadow:0 24px 80px #0004}h1{font-size:clamp(25px,5vw,38px);line-height:1.1;letter-spacing:-.04em;margin:0 0 14px}p{color:var(--muted);margin:0 0 28px;white-space:pre-wrap}
    fieldset{border:0;padding:0;margin:0 0 28px}legend{font-weight:650;margin-bottom:14px}.choice{display:flex;align-items:center;gap:12px;border:1px solid var(--line);border-radius:12px;padding:13px 15px;margin:9px 0;cursor:pointer}.choice:has(input:checked){border-color:var(--accent);background:#65e6dc12}.choice input{accent-color:var(--accent);width:17px;height:17px}
    .field{margin:0 0 24px}.field label{display:block;font-weight:650;margin-bottom:10px}textarea{display:block;width:100%;min-height:130px;resize:vertical;border:1px solid var(--line);border-radius:12px;background:#0a120d;color:var(--text);padding:14px;font:inherit;outline:none}textarea:focus{border-color:var(--accent)}button{border:0;border-radius:11px;background:var(--accent);color:#08121d;padding:12px 19px;font:700 15px system-ui;cursor:pointer}button:hover{filter:brightness(1.08)}.error{color:var(--danger);margin:-8px 0 20px}.muted{font-size:13px;color:var(--muted);margin-top:22px;margin-bottom:0}.home h1{font-size:32px}.home code{display:block;overflow:auto;border:1px solid var(--line);border-radius:10px;padding:14px;background:#080e1c;color:var(--accent);font-size:13px;margin-top:14px}
  </style>
</head>
<body><main><div class="brand">LetMeKnow</div>${body}</main></body></html>`, { status, headers: responseHeaders });
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character] as string);
}

function token(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let result = "";
  for (const byte of bytes) result += String.fromCharCode(byte);
  return btoa(result).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hash(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  const contentLength = Number(request.headers.get("Content-Length") ?? 0);
  if (contentLength > MAX_BODY_BYTES) throw new Error("request too large");
  const text = await request.text();
  if (encoder.encode(text).byteLength > MAX_BODY_BYTES) throw new Error("request too large");
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error("invalid JSON");
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("body must be a JSON object");
  return body as Record<string, unknown>;
}

function fieldsFromRow(row: QuestionRow): Field[] {
  return JSON.parse(row.fields) as Field[];
}

async function findBy(field: "answer_hash" | "status_hash", value: string, env: Env): Promise<QuestionRow | null> {
  return env.DB.prepare(`SELECT answer_hash, status_hash, title, fields, answers, created_at, expires_at, answered_at FROM questions WHERE ${field} = ?`)
    .bind(await hash(value)).first<QuestionRow>();
}

function pathToken(pathname: string, prefix: string): string | null {
  if (!pathname.startsWith(prefix)) return null;
  const value = pathname.slice(prefix.length);
  return value && !value.includes("/") ? value : null;
}

function questionForm(row: QuestionRow, answerToken: string, error = ""): string {
  const fields = fieldsFromRow(row);
  const controls = fields.map((field) => {
    const name = `field_${field.id}`;
    if (field.type === "choice") {
      return `<fieldset><legend>${escapeHtml(field.label)}</legend>${field.options.map((option) => `<label class="choice"><input type="radio" name="${escapeHtml(name)}" value="${escapeHtml(option)}" required><span>${escapeHtml(option)}</span></label>`).join("")}</fieldset>`;
    }
    return `<div class="field"><label for="${escapeHtml(name)}">${escapeHtml(field.label)}</label><textarea id="${escapeHtml(name)}" name="${escapeHtml(name)}" maxlength="${MAX_ANSWER_LENGTH}" required></textarea></div>`;
  }).join("");
  return `<section class="card"><h1>${escapeHtml(row.title)}</h1>${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}<form method="post" action="/q/${escapeHtml(answerToken)}">${controls}<button type="submit">Submit answer</button></form><p class="muted">This link expires in 24 hours. No account is required.</p></section>`;
}

function messagePage(title: string, message: string, status = 200): Response {
  return html(title, `<section class="card"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></section>`, status);
}

function validateFields(value: unknown): Field[] | string {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_FIELDS) return `fields must contain 1-${MAX_FIELDS} items`;
  const ids = new Set<string>();
  const fields: Field[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return "each field must be an object";
    const field = item as Record<string, unknown>;
    const id = typeof field.id === "string" ? field.id.trim() : "";
    const label = typeof field.label === "string" ? field.label.trim() : "";
    if (!/^[a-z][a-z0-9_]{0,31}$/.test(id) || ids.has(id)) return "field ids must be unique and match [a-z][a-z0-9_]{0,31}";
    if (!label || label.length > MAX_LABEL_LENGTH) return `field labels must be non-empty and ${MAX_LABEL_LENGTH} characters or fewer`;
    ids.add(id);
    if (field.type === "text") {
      fields.push({ id, label, type: "text" });
      continue;
    }
    if (field.type !== "choice" || !Array.isArray(field.options) || field.options.length < 2 || field.options.length > MAX_OPTIONS) {
      return `choice fields need 2-${MAX_OPTIONS} options, and the other supported type is text`;
    }
    const options: string[] = [];
    for (const option of field.options) {
      if (typeof option !== "string") return "each option must be a string";
      const text = option.trim();
      if (!text || text.length > MAX_OPTION_LENGTH || options.includes(text)) return "options must be non-empty, unique, and within the length limit";
      options.push(text);
    }
    fields.push({ id, label, type: "choice", options });
  }
  return fields;
}

async function createQuestion(request: Request, env: Env): Promise<Response> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const allowed = await env.CREATE_RATE_LIMIT.limit({ key: ip });
  if (!allowed.success) return json({ error: "too many questions; try again later" }, 429, { "Retry-After": "60" });

  let body: Record<string, unknown>;
  try {
    body = await readJson(request);
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : "invalid request" }, 400);
  }
  const title = typeof body.title === "string" ? body.title.trim() : "";
  if (!title || title.length > MAX_TITLE_LENGTH) return json({ error: `title is required and must be ${MAX_TITLE_LENGTH} characters or fewer` }, 400);
  const fields = validateFields(body.fields);
  if (typeof fields === "string") return json({ error: fields }, 400);

  const answerToken = token();
  const statusToken = token();
  const createdAt = Date.now();
  const expiresAt = createdAt + QUESTION_TTL_MS;
  await env.DB.prepare("INSERT INTO questions (answer_hash, status_hash, title, fields, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(await hash(answerToken), await hash(statusToken), title, JSON.stringify(fields), createdAt, expiresAt)
    .run();

  const origin = new URL(request.url).origin;
  return json({
    question_url: `${origin}/q/${answerToken}`,
    status_url: `${origin}/s/${statusToken}`,
    expires_at: new Date(expiresAt).toISOString()
  }, 201);
}

async function showQuestion(env: Env, answerToken: string): Promise<Response> {
  const row = await findBy("answer_hash", answerToken, env);
  if (!row) return messagePage("Not found", "This question link is invalid.", 404);
  if (row.expires_at <= Date.now()) return messagePage("Expired", "This question link has expired.", 410);
  if (row.answers !== null) return messagePage("Already answered", "Thanks. This question has already received an answer.", 409);
  return html(row.title, questionForm(row, answerToken));
}

async function answerQuestion(request: Request, env: Env, answerToken: string): Promise<Response> {
  const row = await findBy("answer_hash", answerToken, env);
  if (!row) return messagePage("Not found", "This question link is invalid.", 404);
  if (row.expires_at <= Date.now()) return messagePage("Expired", "This question link has expired.", 410);
  if (row.answers !== null) return messagePage("Already answered", "Thanks. This question has already received an answer.", 409);
  if (!request.headers.get("Content-Type")?.startsWith("application/x-www-form-urlencoded")) return messagePage("Invalid answer", "Submit the form from the question page.", 400);
  if (Number(request.headers.get("Content-Length") ?? 0) > MAX_BODY_BYTES) return messagePage("Invalid answer", "That answer is too large.", 400);

  const form = await request.formData();
  const answers: Record<string, string> = {};
  for (const field of fieldsFromRow(row)) {
    const value = form.get(`field_${field.id}`);
    if (typeof value !== "string") return html(row.title, questionForm(row, answerToken, "Please answer every field."), 400);
    const answer = value.trim();
    if (!answer || answer.length > MAX_ANSWER_LENGTH || (field.type === "choice" && !field.options.includes(answer))) {
      return html(row.title, questionForm(row, answerToken, "Please provide a valid answer for every field."), 400);
    }
    answers[field.id] = answer;
  }

  const answeredAt = Date.now();
  const result = await env.DB.prepare("UPDATE questions SET answers = ?, answered_at = ? WHERE answer_hash = ? AND answers IS NULL AND expires_at > ?")
    .bind(JSON.stringify(answers), answeredAt, row.answer_hash, answeredAt)
    .run();
  if (result.meta.changes !== 1) {
    const latest = await findBy("answer_hash", answerToken, env);
    if (latest?.answers !== null) return messagePage("Already answered", "Thanks. This question has already received an answer.", 409);
    return messagePage("Expired", "This question link has expired.", 410);
  }
  return messagePage("Answer received", "Thanks — the agent can now continue.");
}

async function showStatus(env: Env, statusToken: string): Promise<Response> {
  const row = await findBy("status_hash", statusToken, env);
  if (!row) return json({ error: "not found" }, 404);
  if (row.expires_at <= Date.now()) return json({ status: "expired" }, 410);
  if (row.answers === null) return json({ status: "pending" }, 202, { "Retry-After": "3" });
  return json({ status: "answered", answers: JSON.parse(row.answers), answered_at: new Date(row.answered_at!).toISOString() });
}

function home(): Response {
  return text(`# LetMeKnow

Ask a human, then poll for structured answer.

## Create a questionnaire

curl -sS -X POST https://letmeknow.dev/questions \\
  -H 'Content-Type: application/json' \\
  -d '{"title":"Release approval","fields":[{"id":"approve","label":"Deploy this release?","type":"choice","options":["Yes","No"]},{"id":"notes","label":"Anything else?","type":"text"}]}'

The response contains two independent capability URLs:
- question_url: give this anonymous URL to the human.
- status_url: keep this URL private and poll it from the agent.
- expires_at: both URLs expire after 24 hours.

## Poll the answer

GET /s/<status-token>

202 {"status":"pending"} and Retry-After: 3 means poll again.
200 {"status":"answered","answers":{...}} means the human submitted.
410 {"status":"expired"} means the question is gone.

## Answer rules

- One to eight required fields per questionnaire.
- Supported field types: choice and text.
- Yes/no is a choice with options ["Yes", "No"].
- Accepts first submission.`);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/" && request.method === "GET") return home();
      if (url.pathname === "/questions" && request.method === "POST") return createQuestion(request, env);

      const answerToken = pathToken(url.pathname, "/q/");
      if (answerToken) {
        if (request.method === "GET") return showQuestion(env, answerToken);
        if (request.method === "POST") return answerQuestion(request, env, answerToken);
        return messagePage("Method not allowed", "Use GET or POST for this question link.", 405);
      }

      const statusToken = pathToken(url.pathname, "/s/");
      if (statusToken && request.method === "GET") return showStatus(env, statusToken);
      if (statusToken) return json({ error: "method not allowed" }, 405);
      return json({ error: "not found" }, 404);
    } catch {
      return json({ error: "internal server error" }, 500);
    }
  },

  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    await env.DB.prepare("DELETE FROM questions WHERE expires_at <= ?").bind(Date.now()).run();
  }
};

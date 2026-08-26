import { SELF, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";

type QuestionResponse = {
  question_url: string;
  status_url: string;
  expires_at: string;
};

type Answer = {
  approve: string;
  notes: string;
};

const origin = "https://client.example";
let ipNumber = 0;

function fields() {
  return [
    { id: "approve", label: "Continue?", type: "choice", options: ["Yes", "No"] },
    { id: "notes", label: "Notes", type: "text" }
  ];
}

function questionBody() {
  return { title: "Release approval", fields: fields() };
}

function nextIp(): string {
  ipNumber += 1;
  return `198.51.100.${ipNumber}`;
}

function request(path: string, init: RequestInit = {}): Request {
  const headers = new Headers(init.headers);
  if (!headers.has("CF-Connecting-IP")) headers.set("CF-Connecting-IP", nextIp());
  return new Request(`${origin}${path}`, { ...init, headers });
}

async function create(body: unknown = questionBody()): Promise<{ response: Response; data: Partial<QuestionResponse> }> {
  const response = await SELF.fetch(request("/questions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  }));
  const data = await response.json() as Partial<QuestionResponse>;
  return { response, data };
}

async function answer(questionUrl: string, values: Partial<Answer> = { approve: "Yes", notes: "Looks good" }): Promise<Response> {
  const body = new URLSearchParams();
  if (values.approve !== undefined) body.set("field_approve", values.approve);
  if (values.notes !== undefined) body.set("field_notes", values.notes);
  return SELF.fetch(new Request(questionUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  }));
}

async function status(statusUrl: string, wait?: string, signal?: AbortSignal): Promise<Response> {
  const url = new URL(statusUrl);
  if (wait !== undefined) url.searchParams.set("wait", wait);
  return SELF.fetch(new Request(url, { signal }));
}

function streamed(text: string): ReadableStream<Uint8Array> {
  const bytes = new TextEncoder().encode(text);
  return new ReadableStream({
    start(controller) {
      for (let offset = 0; offset < bytes.length; offset += 257) {
        controller.enqueue(bytes.slice(offset, offset + 257));
      }
      controller.close();
    }
  });
}

function objectStub(statusUrl: string): DurableObjectStub {
  const answerToken = new URL(statusUrl).pathname.split("/")[2].split(".")[0];
  return env.QUESTIONS.get(env.QUESTIONS.idFromName(answerToken));
}

async function waitForWaiters(statusUrl: string, count: number): Promise<void> {
  const stub = objectStub(statusUrl);
  await vi.waitFor(async () => {
    const actual = await runInDurableObject(stub, (instance) => {
      const waiters = Reflect.get(instance as object, "waiters");
      return waiters instanceof Set ? waiters.size : -1;
    });
    expect(actual).toBe(count);
  }, { interval: 1, timeout: 1_000 });
}

describe("LetMeKnow", () => {
  it("serves the root as genuine plain text", async () => {
    const response = await SELF.fetch(`${origin}/`);

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toMatch(/^text\/plain; charset=utf-8$/);
    const body = await response.text();
    expect(body).toContain("# LetMeKnow");
    expect(body).toContain(`curl -sS -X POST ${origin}/questions`);
    expect(body).toContain(`status_url="${origin}/s/<answer-code>.<status-token>"`);
    expect(body).toContain(`curl -sS -w '\\n%{http_code}'`);
    expect(body).toContain("202) ;");
    expect(body).toContain("200|410|404) break");
    expect(body).not.toContain(`GET ${origin}/s/`);
  });

  it("creates a tiny answer path and a private status path using the request origin", async () => {
    const before = Date.now();
    const { response, data } = await create();

    expect(response.status).toBe(201);
    expect(data.question_url).toMatch(new RegExp(`^${origin}/q/[A-Za-z0-9_-]{11}$`));
    expect(data.status_url).toMatch(new RegExp(`^${origin}/s/[A-Za-z0-9_-]{11}\\.[A-Za-z0-9_-]{43}$`));
    expect(new URL(data.question_url!).pathname.length).toBe(14);
    expect(new URL(data.status_url!).pathname.length).toBe(58);
    expect(data.question_url).not.toBe(data.status_url);

    const statusUsingAnswerCapability = await status(data.question_url!.replace("/q/", "/s/"), "0");
    expect(statusUsingAnswerCapability.status).toBe(404);
    await statusUsingAnswerCapability.text();
    const questionUsingStatusCapability = await SELF.fetch(new Request(data.status_url!.replace("/s/", "/q/")));
    expect(questionUsingStatusCapability.status).toBe(404);
    await questionUsingStatusCapability.text();

    const expiresAt = new Date(data.expires_at!).getTime();
    expect(expiresAt - before).toBeGreaterThan(9 * 60 * 1_000);
    expect(expiresAt - before).toBeLessThanOrEqual(10 * 60 * 1_000 + 1_000);
  });

  it("rejects malformed compact q and s routes before dispatch", async () => {
    const malformed = [
      `/q/${"a".repeat(10)}`,
      `/q/${"a".repeat(12)}`,
      `/q/${"a".repeat(10)}!`,
      `/q/${"a".repeat(11)}.extra`,
      `/s/${"a".repeat(10)}.${"b".repeat(43)}`,
      `/s/${"a".repeat(11)}.${"b".repeat(42)}`,
      `/s/${"a".repeat(10)}!.${"b".repeat(43)}`,
      `/s/${"a".repeat(11)}.${"b".repeat(43)}.extra`
    ];

    for (const path of malformed) {
      const response = await SELF.fetch(request(path));
      expect(response.status).toBe(404);
      await response.text();
    }
  });

  it("rejects malformed creation and invalid field definitions", async () => {
    const invalidBodies: unknown[] = [
      "not an object",
      {},
      { title: "", fields: fields() },
      { title: "Question", fields: [] },
      { title: "Question", fields: [{ id: "Bad id", label: "Question", type: "text" }] },
      { title: "Question", fields: [{ id: "same", label: "One", type: "text" }, { id: "same", label: "Two", type: "text" }] },
      { title: "Question", fields: [{ id: "pick", label: "Pick", type: "choice", options: ["Only one"] }] },
      { title: "Question", fields: [{ id: "other", label: "Other", type: "unsupported" }] }
    ];

    for (const body of invalidBodies) {
      const { response } = await create(body);
      expect(response.status).toBe(400);
    }
  });

  it("returns pending immediately for wait=0", async () => {
    const { data } = await create();
    const response = await status(data.status_url!, "0");

    expect(response.status).toBe(202);
    expect(response.headers.get("Retry-After")).toBe("3");
    expect(await response.json()).toEqual({ status: "pending" });
  });

  it("keeps an omitted wait open until the question is answered", async () => {
    const { data } = await create();
    const waiting = status(data.status_url!);
    await waitForWaiters(data.status_url!, 1);

    const answerResponse = await answer(data.question_url!);
    expect(answerResponse.status).toBe(200);
    await answerResponse.text();

    const response = await waiting;
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      status: "answered",
      answers: { approve: "Yes", notes: "Looks good" }
    });
  });

  it.each(["not-a-number", "-1", "1.5", "26"])("rejects wait=%s", async (wait) => {
    const { data } = await create();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1_000);
    let response: Response | undefined;
    try {
      response = await status(data.status_url!, wait, controller.signal);
    } catch {
      response = undefined;
    } finally {
      clearTimeout(timeout);
    }

    expect(response?.status).toBe(400);
    if (response) await response.text();
  });

  it("returns a bounded timeout with Retry-After", async () => {
    const { data } = await create();
    const started = Date.now();
    const response = await status(data.status_url!, "1");

    expect(Date.now() - started).toBeGreaterThanOrEqual(800);
    expect(response.status).toBe(202);
    expect(response.headers.get("Retry-After")).toBe("3");
    expect(await response.json()).toEqual({ status: "pending" });
  });

  it("wakes every concurrent long poll when an answer arrives", async () => {
    const { data } = await create();
    const first = status(data.status_url!, "25");
    const second = status(data.status_url!, "25");
    await waitForWaiters(data.status_url!, 2);

    const answerResponse = await answer(data.question_url!, { approve: "No", notes: "Wait for the next release" });
    expect(answerResponse.status).toBe(200);
    await answerResponse.text();

    const responses = await Promise.all([first, second]);
    for (const response of responses) {
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        status: "answered",
        answers: { approve: "No", notes: "Wait for the next release" }
      });
    }
  });

  it("keeps the first answer across repeated status reads and rejects duplicates", async () => {
    const { data } = await create();
    const firstAnswer = await answer(data.question_url!);
    expect(firstAnswer.status).toBe(200);
    await firstAnswer.text();

    const duplicate = await answer(data.question_url!, { approve: "No", notes: "Second answer" });
    expect(duplicate.status).toBe(409);
    await duplicate.text();

    for (let index = 0; index < 2; index += 1) {
      const response = await status(data.status_url!);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        status: "answered",
        answers: { approve: "Yes", notes: "Looks good" }
      });
    }
  });

  it("accepts exactly one of two simultaneous answers and preserves its winner", async () => {
    const { data } = await create();
    const first = answer(data.question_url!, { approve: "Yes", notes: "First simultaneous answer" });
    const second = answer(data.question_url!, { approve: "No", notes: "Second simultaneous answer" });
    const [firstResponse, secondResponse] = await Promise.all([first, second]);

    expect([firstResponse.status, secondResponse.status].sort()).toEqual([200, 409]);
    await firstResponse.text();
    await secondResponse.text();

    const response = await status(data.status_url!);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      status: "answered",
      answers: firstResponse.status === 200
        ? { approve: "Yes", notes: "First simultaneous answer" }
        : { approve: "No", notes: "Second simultaneous answer" }
    });
  });

  it("renders an escaped question form and rejects GET after answering", async () => {
    const { data } = await create({
      title: 'Review <release> & "approval"',
      fields: [
        { id: "approve", label: "Continue <now> & verify", type: "choice", options: ["Yes", "No"] },
        { id: "notes", label: "Notes", type: "text" }
      ]
    });
    const questionPath = new URL(data.question_url!).pathname;
    const beforeAnswer = await SELF.fetch(new Request(data.question_url!));
    const beforeAnswerBody = await beforeAnswer.text();

    expect(beforeAnswer.status).toBe(200);
    expect(beforeAnswerBody).toContain('<body class="windows-31">');
    expect(beforeAnswerBody).toContain("Review &lt;release&gt; &amp; &quot;approval&quot;");
    expect(beforeAnswerBody).toContain("Continue &lt;now&gt; &amp; verify");
    expect(beforeAnswerBody).toContain(`<form method="post" action="${questionPath}">`);
    expect(beforeAnswerBody).toMatch(/link expires in \d{2}:\d{2}/);

    const answerResponse = await answer(data.question_url!);
    expect(answerResponse.status).toBe(200);
    await answerResponse.text();

    const afterAnswer = await SELF.fetch(new Request(data.question_url!));
    expect(afterAnswer.status).toBe(409);
    await afterAnswer.text();
  });

  it("rejects invalid choices while preserving and escaping submitted fields", async () => {
    const { data } = await create();
    const notes = `Keep <this> & \"safe\"`;
    const invalidChoice = await answer(data.question_url!, { approve: "Maybe", notes });
    expect(invalidChoice.status).toBe(400);
    const invalidChoiceBody = await invalidChoice.text();
    expect(invalidChoiceBody).toContain("Please provide a valid answer for every field.");
    expect(invalidChoiceBody).toContain(">Keep &lt;this&gt; &amp; &quot;safe&quot;</textarea>");
    expect(invalidChoiceBody).not.toContain(notes);

    const missingText = await answer(data.question_url!, { approve: "Yes" });
    expect(missingText.status).toBe(400);
    const missingTextBody = await missingText.text();
    expect(missingTextBody).toContain('value="Yes" checked required');

    const stillPending = await status(data.status_url!, "0");
    expect(stillPending.status).toBe(202);
    await stillPending.text();
  });

  it("expires question and status links before alarm cleanup and wakes registered polls", async () => {
    const { data } = await create();
    const waiting = status(data.status_url!, "25");
    await waitForWaiters(data.status_url!, 1);
    const expiresAt = new Date(data.expires_at!).getTime();
    vi.setSystemTime(expiresAt + 1);

    try {
      const beforeQuestion = await SELF.fetch(new Request(data.question_url!));
      expect(beforeQuestion.status).toBe(410);
      expect(await beforeQuestion.text()).toContain("This question link has expired.");

      const beforeAnswer = await answer(data.question_url!);
      expect(beforeAnswer.status).toBe(410);
      expect(await beforeAnswer.text()).toContain("This question link has expired.");

      const beforeStatus = await status(data.status_url!);
      expect(beforeStatus.status).toBe(410);
      expect(await beforeStatus.json()).toEqual({ status: "expired" });

      expect(await runDurableObjectAlarm(objectStub(data.status_url!))).toBe(true);

      const woken = await waiting;
      expect(woken.status).toBe(404);
      await woken.text();

      const afterQuestion = await SELF.fetch(new Request(data.question_url!));
      expect(afterQuestion.status).toBe(404);
      await afterQuestion.text();

      const afterStatus = await status(data.status_url!);
      expect(afterStatus.status).toBe(404);
      await afterStatus.text();
    } finally {
      vi.useRealTimers();
    }
  });

  it("redirects public HTTP and sends focused security headers", async () => {
    const redirect = await SELF.fetch(new Request("http://public.example/", { redirect: "manual" }));
    expect(redirect.status).toBe(307);
    expect(redirect.headers.get("Location")).toBe("https://public.example/");
    expect(redirect.headers.get("Strict-Transport-Security")).toBe("max-age=31536000");
    await redirect.text();

    const page = await SELF.fetch(new Request(`https://public.example/q/${"a".repeat(11)}`));
    expect(page.status).toBe(404);
    expect(page.headers.get("Strict-Transport-Security")).toBe("max-age=31536000");
    expect(page.headers.get("Content-Security-Policy")).toBe("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    await page.text();
  });

  it("rejects oversized streamed JSON without Content-Length", async () => {
    const body = JSON.stringify({ ...questionBody(), ignored: "x".repeat(17_000) });
    const requestBody = streamed(body);
    const requestWithStream = request("/questions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: requestBody
    });

    expect(requestWithStream.headers.has("Content-Length")).toBe(false);
    const response = await SELF.fetch(requestWithStream);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "request too large" });
  });

  it("rejects oversized streamed form data without Content-Length", async () => {
    const { data } = await create();
    const form = new URLSearchParams({
      field_approve: "Yes",
      field_notes: "Looks good",
      ignored: "x".repeat(17_000)
    });
    const requestBody = streamed(form.toString());
    const requestWithStream = new Request(data.question_url!, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: requestBody
    });

    expect(requestWithStream.headers.has("Content-Length")).toBe(false);
    const response = await SELF.fetch(requestWithStream);
    expect(response.status).toBe(400);
    expect(await response.text()).toContain("That answer is too large.");
  });
});

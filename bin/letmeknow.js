#!/usr/bin/env node

import { createServer } from "vite";
import { existsSync, readFileSync, statSync, writeSync } from "node:fs";
import { extname, relative, resolve, sep } from "node:path";

const MAX_SUBMISSION_BYTES = 1024 * 1024;
const localClient = String.raw`
const hot = import.meta.hot;
const stateKey = (control, index) => control.id ? "#" + control.id : (control.form?.id ?? "") + ":" + control.name + ":" + control.type + ":" + index;
const controls = root => [...root.querySelectorAll("input,select,textarea")];
const snapshot = () => {
  const state = new Map();
  let activeKey;
  for (const [index, control] of controls(document).entries()) {
    const key = stateKey(control, index);
    state.set(key, {
      value: control.value,
      checked: control.checked,
      selected: control instanceof HTMLSelectElement ? [...control.options].filter(option => option.selected).map(option => option.value) : undefined,
      start: typeof control.selectionStart === "number" ? control.selectionStart : undefined,
      end: typeof control.selectionEnd === "number" ? control.selectionEnd : undefined
    });
    if (control === document.activeElement) activeKey = key;
  }
  return { state, activeKey, x: scrollX, y: scrollY };
};
const restore = saved => {
  let active;
  for (const [index, control] of controls(document).entries()) {
    const state = saved.state.get(stateKey(control, index));
    if (!state) continue;
    if (control instanceof HTMLSelectElement && state.selected) {
      for (const option of control.options) option.selected = state.selected.includes(option.value);
    } else if (control.type === "checkbox" || control.type === "radio") {
      control.checked = state.checked;
    } else {
      control.value = state.value;
      if (typeof state.start === "number" && typeof control.setSelectionRange === "function") control.setSelectionRange(state.start, state.end);
    }
    if (stateKey(control, index) === saved.activeKey) active = control;
  }
  active?.focus();
  scrollTo(saved.x, saved.y);
};
const status = message => {
  const element = document.querySelector("[data-letmeknow-status]");
  if (element) element.textContent = message;
};
const replacePage = async () => {
  const saved = snapshot();
  const response = await fetch(location.href, { cache: "no-store", headers: { Accept: "text/html" } });
  if (!response.ok) throw new Error("page refresh failed");
  const next = new DOMParser().parseFromString(await response.text(), "text/html");
  document.title = next.title;
  document.body.replaceChildren(...[...next.body.childNodes].filter(node => !(node instanceof HTMLScriptElement && node.hasAttribute("data-letmeknow-client"))));
  restore(saved);
};
hot?.on("letmeknow:html-update", message => {
  const current = location.pathname.endsWith("/") ? location.pathname + "index.html" : location.pathname;
  if (message?.path !== current) return;
  replacePage().catch(() => status("The page could not be refreshed"));
});
document.addEventListener("submit", async event => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  event.preventDefault();
  const submitter = event.submitter;
  const method = (submitter?.getAttribute("formmethod") ?? form.getAttribute("method") ?? "get").toLowerCase();
  if (method !== "get" && method !== "post") {
    status("Only GET and POST forms are supported");
    return;
  }
  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }
  const rawAction = submitter?.getAttribute("formaction") ?? form.getAttribute("action") ?? location.href;
  const target = new URL(rawAction || location.href, location.href);
  if (target.origin !== location.origin) {
    status("Form actions must stay on this site");
    return;
  }
  const values = new URLSearchParams();
  for (const [name, value] of new FormData(form, submitter)) {
    if (typeof value !== "string") {
      status("File inputs are not supported");
      return;
    }
    values.append(name, value);
  }
  const metadata = {
    id: crypto.randomUUID(),
    form_id: form.id || null,
    action: target.pathname + target.search,
    trigger: {
      id: submitter?.id || null,
      name: submitter?.getAttribute("name"),
      value: submitter?.getAttribute("value")
    }
  };
  const headers = {
    "X-LetMeKnow-Submission": "1",
    "X-LetMeKnow-ID": encodeURIComponent(metadata.id),
    "X-LetMeKnow-Form-ID": encodeURIComponent(metadata.form_id ?? ""),
    "X-LetMeKnow-Action": encodeURIComponent(metadata.action),
    "X-LetMeKnow-Trigger-ID": encodeURIComponent(metadata.trigger.id ?? ""),
    "X-LetMeKnow-Trigger-Name": encodeURIComponent(metadata.trigger.name ?? ""),
    "X-LetMeKnow-Trigger-Value": encodeURIComponent(metadata.trigger.value ?? "")
  };
  if (method === "get") {
    for (const [name, value] of values) target.searchParams.append(name, value);
  }
  try {
    const response = await fetch(target, {
      method: method.toUpperCase(),
      headers,
      ...(method === "post" ? { body: values } : {})
    });
    if (!response.ok) throw new Error();
    status("Submitted");
  } catch {
    status("The submission failed");
  }
});
`;

function encodedHeader(request, name) {
  const value = request.headers[name];
  if (typeof value !== "string" || value === "") return null;
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

function addValue(values, name, value) {
  if (Object.prototype.hasOwnProperty.call(values, name)) {
    values[name] = Array.isArray(values[name]) ? [...values[name], value] : [values[name], value];
  } else {
    values[name] = value;
  }
}

function readBody(request) {
  return new Promise((resolveBody, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    request.on("data", chunk => {
      if (tooLarge) return;
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.byteLength;
      if (size > MAX_SUBMISSION_BYTES) {
        tooLarge = true;
        request.resume();
        reject(new Error("submission is too large"));
        return;
      }
      chunks.push(buffer);
    });
    request.on("end", () => resolveBody(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

async function submission(request, response) {
  const url = new URL(request.url || "/", "http://localhost");
  const method = (request.method || "GET").toUpperCase();
  const values = Object.create(null);
  if (method === "GET") {
    for (const [name, value] of url.searchParams) addValue(values, name, value);
  } else if (method === "POST") {
    const body = await readBody(request);
    const contentType = request.headers["content-type"]?.split(";", 1)[0].trim();
    if (contentType !== "application/x-www-form-urlencoded") throw new Error("unsupported submission encoding");
    for (const [name, value] of new URLSearchParams(body.toString("utf8"))) addValue(values, name, value);
  } else {
    throw new Error("unsupported submission method");
  }
  const event = {
    type: "submit",
    id: encodedHeader(request, "x-letmeknow-id"),
    method,
    action: encodedHeader(request, "x-letmeknow-action") || url.pathname,
    form_id: encodedHeader(request, "x-letmeknow-form-id"),
    trigger: {
      id: encodedHeader(request, "x-letmeknow-trigger-id"),
      name: encodedHeader(request, "x-letmeknow-trigger-name"),
      value: encodedHeader(request, "x-letmeknow-trigger-value")
    },
    values
  };
  process.stdout.write(`${JSON.stringify(event)}\n`);
  response.statusCode = 204;
  response.setHeader("Cache-Control", "no-store");
  response.end();
}

function localPlugin(root) {
  const htmlReloads = new Set();
  const clientPath = "/__letmeknow_client.js";
  const clientId = "\0letmeknow-client";
  return {
    name: "letmeknow-local",
    resolveId(id) {
      return id === clientPath ? clientId : undefined;
    },
    load(id) {
      return id === clientId ? localClient : undefined;
    },
    configureServer(server) {
      const send = server.ws.send.bind(server.ws);
      server.ws.send = payload => {
        if (payload.type === "full-reload" && (htmlReloads.has(payload.path) || htmlReloads.has("*"))) {
          htmlReloads.clear();
          return;
        }
        send(payload);
      };
      server.middlewares.use((request, response, next) => {
        if (request.headers["x-letmeknow-submission"] !== "1") {
          next();
          return;
        }
        submission(request, response).catch(cause => {
          response.statusCode = cause instanceof Error && cause.message === "submission is too large" ? 413 : 400;
          response.setHeader("Content-Type", "text/plain; charset=utf-8");
          response.end(cause instanceof Error ? cause.message : "invalid submission");
        });
      });
    },
    transformIndexHtml(html) {
      const script = `<script type="module" src="${clientPath}" data-letmeknow-client></script>`;
      return html.includes("</body>") ? html.replace("</body>", `${script}</body>`) : `${html}${script}`;
    },
    handleHotUpdate({ file, server }) {
      if (extname(file).toLowerCase() !== ".html") return;
      const path = "/" + relative(root, file).split(sep).join("/");
      htmlReloads.add(path);
      htmlReloads.add("*");
      server.ws.send({ type: "custom", event: "letmeknow:html-update", data: { path } });
      return [];
    }
  };
}

function localOptions(args) {
  let root;
  let host = process.env.LETMEKNOW_HOST || "127.0.0.1";
  let port = Number(process.env.LETMEKNOW_PORT || 5173);
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === "--host") host = args[++index] || "0.0.0.0";
    else if (argument.startsWith("--host=")) host = argument.slice("--host=".length);
    else if (argument === "--port") port = Number(args[++index]);
    else if (argument.startsWith("--port=")) port = Number(argument.slice("--port=".length));
    else if (argument.startsWith("-")) throw new Error(`unknown option: ${argument}`);
    else if (root === undefined) root = resolve(argument);
    else throw new Error("only one directory may be provided");
  }
  root = root || process.cwd();
  root = resolve(root);
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`directory does not exist: ${root}`);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("port must be between 0 and 65535");
  return { root, host, port };
}

async function startLocal(args) {
  const options = localOptions(args);
  const server = await createServer({
    root: options.root,
    logLevel: "silent",
    plugins: [localPlugin(options.root)],
    server: { host: options.host, port: options.port, strictPort: true }
  });
  process.once("SIGINT", () => process.exit(0));
  process.once("SIGTERM", () => process.exit(0));
  await server.listen();
  const address = server.httpServer?.address();
  const port = typeof address === "object" && address ? address.port : options.port;
  const url = new URL(server.resolvedUrls?.local?.[0] || `http://localhost:${port}/`);
  if (options.port === 0) url.port = String(port);
  process.stdout.write(`${JSON.stringify({ type: "ready", url: url.toString() })}\n`);
  await new Promise(() => {});
}

if (process.argv[2] === "--skill") {
  if (process.argv.length !== 3) {
    process.stderr.write("Usage: npx letmeknow-cli --skill\n");
    process.exit(1);
  }
  writeSync(1, readFileSync(new URL("../SKILL.md", import.meta.url)));
} else if (process.env.LETMEKNOW_URL) {
  await import("./remote.js");
} else if (process.argv.slice(2).includes("--help") || process.argv.slice(2).includes("-h")) {
  process.stdout.write("Usage: npx letmeknow-cli [directory] [--host host] [--port port]\n\nServe a folder with Vite. Form submissions are JSON lines on stdout.\n");
} else {
  try {
    await startLocal(process.argv.slice(2));
  } catch (cause) {
    process.stderr.write(`letmeknow: ${cause instanceof Error ? cause.message : "server failed"}\n`);
    process.exitCode = 1;
  }
}

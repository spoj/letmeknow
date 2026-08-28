import { createServer } from "vite";
import { existsSync, statSync } from "node:fs";
import { extname, relative, resolve, sep } from "node:path";
import { Readable, Writable } from "node:stream";

const MAX_BODY_BYTES = 1024 * 1024;
const GRACE_SECONDS = 10 * 60;
const CONNECTION_TIMEOUT = 10_000;
const MAX_RETRY_DELAY = 5_000;
const credentialPattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const clientPath = "/__letmeknow_client.js";
const clientId = "\0letmeknow-client";
const client = String.raw`
const key="letmeknow-client:"+location.host+location.pathname;
const draftKey="letmeknow-draft:"+location.host+location.pathname;
let credential=sessionStorage.getItem(key);
let socket;
let retryTimer;
let terminal=false;
const stateKey=(control,index)=>control.id?"#"+control.id:(control.form?.id??"")+":"+control.name+":"+control.type+":"+index;
const controls=root=>[...root.querySelectorAll("input,select,textarea")];
const snapshot=()=>{
  const state=new Map();
  let activeKey;
  for(const [index,control] of controls(document).entries()){
    const key=stateKey(control,index);
    state.set(key,{value:control.value,checked:control.checked,selected:control instanceof HTMLSelectElement?[...control.options].filter(option=>option.selected).map(option=>option.value):undefined,start:typeof control.selectionStart==="number"?control.selectionStart:undefined,end:typeof control.selectionEnd==="number"?control.selectionEnd:undefined});
    if(control===document.activeElement)activeKey=key;
  }
  return {state,activeKey,x:scrollX,y:scrollY};
};
const restore=saved=>{
  let active;
  for(const [index,control] of controls(document).entries()){
    const state=saved.state.get(stateKey(control,index));
    if(!state)continue;
    if(control instanceof HTMLSelectElement&&state.selected)for(const option of control.options)option.selected=state.selected.includes(option.value);
    else if(control.type==="checkbox"||control.type==="radio")control.checked=state.checked;
    else{control.value=state.value;if(typeof state.start==="number"&&typeof control.setSelectionRange==="function")control.setSelectionRange(state.start,state.end)}
    if(stateKey(control,index)===saved.activeKey)active=control;
  }
  active?.focus();
  scrollTo(saved.x,saved.y);
};
const status=message=>{const element=document.querySelector("[data-letmeknow-status]");if(element)element.textContent=message};
const sessionPrefix=location.pathname.match(/^\/s\/[a-f0-9]{20}\//)?.[0];
const currentPath=()=>{const path=sessionPrefix?location.pathname.slice(sessionPrefix.length-1)||"/":location.pathname;return path.endsWith("/")?path+"index.html":path};
const refresh=async()=>{
  const saved=snapshot();
  const response=await fetch(location.href,{cache:"no-store",headers:{Accept:"text/html"}});
  if(!response.ok)throw new Error("page refresh failed");
  const next=new DOMParser().parseFromString(await response.text(),"text/html");
  document.title=next.title;
  document.body.replaceChildren(...[...next.body.childNodes].filter(node=>!(node instanceof HTMLScriptElement&&node.hasAttribute("data-letmeknow-client"))));
  const links=[...document.head.querySelectorAll("link[rel=stylesheet]")];
  for(const link of links){const url=new URL(link.href);url.searchParams.set("_letmeknow",crypto.randomUUID());link.href=url}
  restore(saved);
};
const update=path=>{if(path===currentPath()||path?.endsWith(".css"))refresh().catch(()=>status("The page could not be refreshed"))};
const connect=()=>{
  clearTimeout(retryTimer);retryTimer=undefined;
  const url=new URL("_letmeknow/client",location.href);url.protocol=url.protocol==="https:"?"wss:":"ws:";
  socket=credential?new WebSocket(url,credential):new WebSocket(url);
  socket.onmessage=event=>{
    const message=JSON.parse(event.data);
    if(message.type==="credential"){credential=message.credential;sessionStorage.setItem(key,credential);return}
    if(message.type==="challenge"){socket.send(JSON.stringify({type:"alive",nonce:message.nonce}));return}
    if(message.type==="busy"){status("This session is open elsewhere");retryTimer=setTimeout(connect,message.retry_after*1000);return}
    if(message.type==="file_update"){update(message.path);return}
    if(message.type==="closed"){terminal=true;sessionStorage.removeItem(key);sessionStorage.removeItem(draftKey);status(message.message)}
  };
  socket.onclose=()=>{if(!terminal&&!retryTimer){status("Reconnecting…");retryTimer=setTimeout(connect,1000)}};
  socket.onerror=()=>{};
};
document.addEventListener("submit",async event=>{
  const form=event.target;
  if(!(form instanceof HTMLFormElement))return;
  event.preventDefault();
  const submitter=event.submitter;
  const method=(submitter?.getAttribute("formmethod")??form.getAttribute("method")??"get").toLowerCase();
  if(method!=="get"&&method!=="post"){status("Only GET and POST forms are supported");return}
  if(!form.checkValidity()){form.reportValidity();return}
  let target;
  try{target=new URL(submitter?.getAttribute("formaction")??form.getAttribute("action")??location.href,location.href)}catch{status("Invalid form action");return}
  if(target.origin!==location.origin){status("Form actions must stay on this site");return}
  if(sessionPrefix&&!target.pathname.startsWith(sessionPrefix))target.pathname=sessionPrefix+target.pathname;
  const values=new URLSearchParams();
  for(const [name,value] of new FormData(form,submitter)){if(typeof value!=="string"){status("File inputs are not supported");return}values.append(name,value)}
  const metadata={id:crypto.randomUUID(),form_id:form.id||null,action:target.pathname+target.search,trigger:{id:submitter?.id||null,name:submitter?.getAttribute("name"),value:submitter?.getAttribute("value")}};
  const headers={"X-LetMeKnow-Submission":"1","X-LetMeKnow-ID":encodeURIComponent(metadata.id),"X-LetMeKnow-Form-ID":encodeURIComponent(metadata.form_id??""),"X-LetMeKnow-Action":encodeURIComponent(metadata.action),"X-LetMeKnow-Trigger-ID":encodeURIComponent(metadata.trigger.id??""),"X-LetMeKnow-Trigger-Name":encodeURIComponent(metadata.trigger.name??""),"X-LetMeKnow-Trigger-Value":encodeURIComponent(metadata.trigger.value??"")};
  if(method==="get")for(const [name,value] of values)target.searchParams.append(name,value);
  try{const response=await fetch(target,{method:method.toUpperCase(),headers,...(method==="post"?{body:values}:{})});if(!response.ok)throw new Error();status("Submitted")}catch{status("The submission failed")}
});
connect();
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
      if (size > MAX_BODY_BYTES) {
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

class RelayRequest extends Readable {
  constructor(packet) {
    super();
    this.method = packet.method;
    this.url = packet.path;
    this.originalUrl = packet.path;
    this.headers = packet.headers || {};
    this.httpVersion = "1.1";
    this.httpVersionMajor = 1;
    this.httpVersionMinor = 1;
    this.socket = { encrypted: false, remoteAddress: "127.0.0.1" };
    this.body = Buffer.from(packet.body || "", "base64");
    this.sent = false;
  }

  _read() {
    if (this.sent) return;
    this.sent = true;
    this.push(this.body);
    this.push(null);
  }
}

class RelayResponse extends Writable {
  constructor() {
    super();
    this.statusCode = 200;
    this.headers = new Map();
    this.chunks = [];
  }

  setHeader(name, value) {
    this.headers.set(name.toLowerCase(), Array.isArray(value) ? value.join(", ") : String(value));
    return this;
  }

  getHeader(name) {
    return this.headers.get(name.toLowerCase());
  }

  getHeaders() {
    return Object.fromEntries(this.headers);
  }

  hasHeader(name) {
    return this.headers.has(name.toLowerCase());
  }

  removeHeader(name) {
    this.headers.delete(name.toLowerCase());
  }

  writeHead(status, headers) {
    this.statusCode = status;
    if (headers) for (const [name, value] of Object.entries(headers)) this.setHeader(name, value);
    return this;
  }

  flushHeaders() {}

  _write(chunk, _encoding, callback) {
    this.chunks.push(Buffer.from(chunk));
    callback();
  }

  body() {
    return Buffer.concat(this.chunks);
  }
}

function middlewareResponse(response) {
  const body = response.body();
  if (body.byteLength > MAX_BODY_BYTES) throw new Error("response body is too large");
  return {
    type: "http_response",
    request_id: response.requestId,
    status: response.statusCode,
    headers: response.getHeaders(),
    body: body.toString("base64")
  };
}

async function handleRequest(server, packet, send) {
  const request = new RelayRequest(packet);
  const response = new RelayResponse();
  response.requestId = packet.request_id;
  await new Promise((resolveRequest, rejectRequest) => {
    response.once("finish", resolveRequest);
    response.once("error", rejectRequest);
    try {
      server.middlewares(request, response, () => {
        if (!response.writableEnded) {
          response.statusCode = 404;
          response.end("Not found");
        }
      });
    } catch (cause) {
      rejectRequest(cause);
    }
  });
  send(middlewareResponse(response));
}

function options(args) {
  let root;
  for (const argument of args) {
    if (argument.startsWith("-")) throw new Error(`unknown option: ${argument}`);
    if (root !== undefined) throw new Error("only one directory may be provided");
    root = resolve(argument);
  }
  root = root || process.cwd();
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`directory does not exist: ${root}`);
  return { root };
}

function endpoint(control, credential, sessionUrl) {
  const url = new URL(control);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/v1/connect";
  url.search = "";
  url.hash = "";
  if (credential && sessionUrl) {
    const publicUrl = new URL(sessionUrl);
    const hostCode = publicUrl.hostname.match(/^([a-f0-9]{20})\.letmeknow\.dev$/);
    const pathCode = publicUrl.pathname.match(/^\/s\/([a-f0-9]{20})(?:\/|$)/);
    const code = hostCode?.[1] || pathCode?.[1];
    if (code) url.searchParams.set("code", code);
  }
  return url;
}

function validSessionUrl(value) {
  if (typeof value !== "string") return false;
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  if (/^[a-f0-9]{20}\.letmeknow\.dev$/.test(url.hostname)) return true;
  return /^\/s\/[a-f0-9]{20}(?:\/|$)/.test(url.pathname);
}

async function start(args) {
  const { root } = options(args);
  const control = process.env.LETMEKNOW_URL || "https://letmeknow.dev";
  let send = () => false;
  const vite = await createServer({
    root,
    configFile: false,
    appType: "spa",
    css: { postcss: false },
    logLevel: "silent",
    server: { middlewareMode: true, hmr: false, ws: false, fs: { strict: true, allow: [root], deny: ["**/.env", "**/.env.*", "**/.git/**", "**/*.key", "**/*.pem", "**/*.p12", "**/*.sqlite", "**/*.db"] } },
    plugins: [{
      name: "letmeknow-relay",
      resolveId(id) { return id === clientPath ? clientId : undefined; },
      load(id) { return id === clientId ? client : undefined; },
      configureServer(server) {
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
        const update = file => send({ type: "file_update", path: "/" + relative(root, file).split(sep).join("/") });
        server.watcher.on("change", update);
        server.watcher.on("add", update);
        server.watcher.on("unlink", update);
      },
      transformIndexHtml(html) {
        const script = `<script type="module" src="${clientPath}" data-letmeknow-client></script>`;
        return html.includes("</body>") ? html.replace("</body>", `${script}</body>`) : `${html}${script}`;
      }
    }]
  });

  let socket;
  let credential;
  let sessionUrl;
  let retryTimer;
  let connectionTimer;
  let retryDelay = 100;
  let retryUntil = 0;
  let stopped = false;
  let ready = false;
  const stop = async code => {
    if (stopped) return;
    stopped = true;
    clearTimeout(retryTimer);
    clearTimeout(connectionTimer);
    try { socket?.close(); } catch {}
    await vite.close();
    process.exit(code);
  };
  process.once("SIGINT", () => void stop(0));
  process.once("SIGTERM", () => void stop(0));

  const retry = () => {
    if (stopped || Date.now() >= retryUntil) return void stop(1);
    retryTimer = setTimeout(() => {
      retryTimer = undefined;
      connect();
    }, retryDelay);
    retryDelay = Math.min(retryDelay * 2, MAX_RETRY_DELAY);
  };

  const connect = () => {
    if (stopped) return;
    const reconnecting = Boolean(credential && sessionUrl);
    const current = socket = reconnecting ? new WebSocket(endpoint(control, credential, sessionUrl), credential) : new WebSocket(endpoint(control));
    connectionTimer = setTimeout(() => {
      if (socket !== current || current.readyState === WebSocket.OPEN || stopped) return;
      try { current.close(); } catch {}
      if (reconnecting) retry(); else void stop(1);
    }, CONNECTION_TIMEOUT);
    current.addEventListener("open", () => {
      if (socket !== current || stopped) return;
      clearTimeout(connectionTimer);
      retryDelay = 100;
      if (reconnecting) retryUntil = 0;
      send = packet => {
        if (current.readyState !== WebSocket.OPEN) return false;
        try { current.send(JSON.stringify(packet)); return true; } catch { return false; }
      };
      if (!reconnecting) send({ type: "open", mode: "proxy" });
    });
    current.addEventListener("message", event => {
      if (typeof event.data !== "string") return;
      let packet;
      try { packet = JSON.parse(event.data); } catch { return; }
      if (packet.type === "credential") {
        if (typeof packet.credential !== "string" || !credentialPattern.test(packet.credential)) return void stop(1);
        credential = packet.credential;
      } else if (packet.type === "session") {
        if (!validSessionUrl(packet.url)) return void stop(1);
        sessionUrl = packet.url;
        retryDelay = 100;
        if (!ready) {
          ready = true;
          process.stdout.write(`${JSON.stringify({ type: "ready", url: sessionUrl })}\n`);
        }
      } else if (packet.type === "http_request") {
        void handleRequest(vite, packet, response => send(response)).catch(() => send({ type: "http_response", request_id: packet.request_id, status: 500, headers: { "Content-Type": "text/plain; charset=utf-8" }, body: Buffer.from("preview request failed").toString("base64") }));
      } else if (packet.type === "closed") {
        void stop(0);
      }
    });
    current.addEventListener("error", () => {});
    current.addEventListener("close", () => {
      if (socket !== current || stopped) return;
      clearTimeout(connectionTimer);
      send = () => false;
      socket = undefined;
      if (!credential || !sessionUrl) return void stop(1);
      if (!retryUntil) retryUntil = Date.now() + GRACE_SECONDS * 1_000;
      retry();
    });
  };

  connect();
  await new Promise(() => {});
}

await start(process.argv.slice(2));

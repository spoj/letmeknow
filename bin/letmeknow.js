#!/usr/bin/env node

import { existsSync, readFileSync, statSync, writeSync } from "node:fs";
import { readFile, realpath, stat } from "node:fs/promises";
import { dirname, extname, relative, resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import chokidar from "chokidar";
import ignore from "ignore";
import { lookup } from "mrmime";

const MAX_BODY_BYTES = 1024 * 1024;
const GRACE_SECONDS = 10 * 60;
const CONNECTION_TIMEOUT = 10_000;
const MAX_RETRY_DELAY = 5_000;
const credentialPattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const ig = ignore().add([".env", ".env.*", ".git", ".ssh", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "*.key", "*.pem", "*.p12", "*.ppk", "*.p8", "*.sqlite", "*.db"]);
const privateFilePattern = /\.(?:key|pem|p12|ppk|p8|sqlite|db)$/i;

function getMimeType(filename) {
  const type = lookup(filename);
  if (!type) return "application/octet-stream";
  return type.startsWith("text/") || type === "application/json" || type === "application/xml" || type === "application/manifest+json"
    ? `${type}; charset=utf-8`
    : type;
}
const client = String.raw`
const sessionMatch=location.pathname.match(/^\/s\/[a-f0-9]{20}(?:\/|$)/);
const sessionBase=sessionMatch?(sessionMatch[0].endsWith("/")?sessionMatch[0]:sessionMatch[0]+"/"):"/";
const credentialKey="letmeknow-credential:"+location.origin+sessionBase;
const snapshotKey=()=>credentialKey+":state:"+pageIdentity();
let credential;
try{credential=sessionStorage.getItem(credentialKey)}catch{}
let socket;
let retryTimer;
let updateTimer;
let reloadTimer;
let terminal=false;
const controls=()=>[...document.querySelectorAll("button,input,select,textarea")];
const details=()=>[...document.querySelectorAll("details")];
const uniqueId=(element,all)=>element.id&&all.filter(candidate=>candidate.id===element.id).length===1?element.id:null;
const formIdentity=form=>form?.id||form?.getAttribute("name")||form?.getAttribute("action")||"document";
const controlKey=(control,index,all=controls())=>{const id=uniqueId(control,all);if(id)return"id:"+id;const form=control.form;const identity=formIdentity(form)+":"+(control.type||control.localName)+":"+(control.name||"");const occurrence=all.slice(0,index).filter(candidate=>!uniqueId(candidate,all)&&formIdentity(candidate.form)+":"+(candidate.type||candidate.localName)+":"+(candidate.name||"")===identity).length;return"control:"+identity+":"+occurrence};
const detailKey=(element,index,all=details())=>{const id=uniqueId(element,all);return id?"id:"+id:"detail:"+index};
const pageIdentity=()=>location.pathname+location.search+location.hash;
const snapshot=()=>{const all=controls();return{version:1,page:pageIdentity(),controls:all.map((control,index)=>({key:controlKey(control,index,all),value:control.value,checked:control.checked,indeterminate:control.indeterminate,selected:control instanceof HTMLSelectElement?[...control.options].map((option,optionIndex,options)=>option.selected?[option.value,options.slice(0,optionIndex).filter(candidate=>candidate.value===option.value).length]:null).filter(Boolean):undefined,start:typeof control.selectionStart==="number"?control.selectionStart:undefined,end:typeof control.selectionEnd==="number"?control.selectionEnd:undefined,direction:control.selectionDirection||undefined})),active:document.activeElement instanceof Element?controlKey(document.activeElement,all.indexOf(document.activeElement),all):undefined,details:details().map((element,index)=>({key:detailKey(element,index),open:element.open})),x:scrollX,y:scrollY}};
const status=message=>{const element=document.querySelector("[data-letmeknow-status]");if(element)element.textContent=message};
const stripSessionPath=path=>{if(sessionBase==="/")return path;if(path===sessionBase.slice(0,-1))return "/";return path.startsWith(sessionBase)?"/"+path.slice(sessionBase.length):path};
const routePath=()=>{let path=stripSessionPath(location.pathname);return path.endsWith("/")?path+"index.html":path};
const pagePath=path=>{path=path.split("?",1)[0];return stripSessionPath(path)||"/"};
const save=()=>{try{sessionStorage.setItem(snapshotKey(),JSON.stringify(snapshot()))}catch{}};
const restore=()=>{let raw;try{raw=sessionStorage.getItem(snapshotKey())}catch{return}if(!raw)return;let saved;try{saved=JSON.parse(raw)}catch{return}if(saved.version!==1||saved.page!==pageIdentity())return;const all=controls();const savedControls=new Map((Array.isArray(saved.controls)?saved.controls:[]).map(state=>[state.key,state]));let active;for(const [index,control] of all.entries()){const state=savedControls.get(controlKey(control,index,all));if(!state)continue;if(control instanceof HTMLSelectElement&&Array.isArray(state.selected)){const selectedIndexes=new Set(state.selected.filter(Number.isInteger));const selectedValues=new Set(state.selected.filter(Array.isArray).map(entry=>entry.join("\u0000")));for(const [optionIndex,option] of [...control.options].entries()){const occurrence=[...control.options].slice(0,optionIndex).filter(candidate=>candidate.value===option.value).length;option.selected=selectedIndexes.has(optionIndex)||selectedValues.has([option.value,occurrence].join("\u0000"))}}else if(control.type==="checkbox"||control.type==="radio"){control.checked=state.checked;control.indeterminate=state.indeterminate}else{control.value=state.value;if(typeof state.start==="number"&&typeof control.setSelectionRange==="function")control.setSelectionRange(state.start,state.end,state.direction||"none")}if(controlKey(control,index,all)===saved.active)active=control}const savedDetails=new Map((Array.isArray(saved.details)?saved.details:[]).map(state=>[state.key,state]));for(const [index,element] of details().entries()){const state=savedDetails.get(detailKey(element,index));if(state)element.open=state.open}active?.focus({preventScroll:true});scrollTo(saved.x||0,saved.y||0)};
const reload=()=>{if(reloadTimer)return;reloadTimer=setTimeout(()=>{save();location.reload()},75)};
const linkedStylesheet=path=>{for(const link of document.querySelectorAll('link[rel~="stylesheet"]')){let url;try{url=new URL(link.href,location.href)}catch{continue}if(url.origin!==location.origin)continue;if(sessionBase!=="/"&&!url.pathname.startsWith(sessionBase))continue;if(pagePath(url.pathname)===path)return link}return null};
const refreshStylesheet=link=>{const url=new URL(link.href,location.href);url.searchParams.set("_letmeknow",crypto.randomUUID());link.href=url.href};
const flushUpdates=()=>{updateTimer=undefined;const paths=[...pendingUpdates];pendingUpdates.clear();let shouldReload=false;const styles=[];for(const path of paths){if(/\.html?$/i.test(path)){if(path===routePath())shouldReload=true}else if(/\.css$/i.test(path)){const link=linkedStylesheet(path);if(link)styles.push([path,link]);else shouldReload=true}else shouldReload=true}if(shouldReload){reload();return}for(const [,link] of styles)refreshStylesheet(link)};
const pendingUpdates=new Set();
const update=path=>{if(typeof path!=="string")return;path=pagePath(path);pendingUpdates.add(path);if(!updateTimer)updateTimer=setTimeout(flushUpdates,75)};
let saveTimer;
const scheduleSave=()=>{if(!saveTimer)saveTimer=setTimeout(()=>{saveTimer=undefined;save()},100)};
addEventListener("input",scheduleSave,true);
addEventListener("change",scheduleSave,true);
addEventListener("toggle",scheduleSave,true);
addEventListener("focusin",scheduleSave,true);
addEventListener("selectionchange",scheduleSave,true);
addEventListener("scroll",scheduleSave,{passive:true});
addEventListener("pagehide",save);
addEventListener("load",()=>requestAnimationFrame(restore),{once:true});
document.addEventListener("reset",()=>setTimeout(save));
const connect=()=>{
  clearTimeout(retryTimer);retryTimer=undefined;
  const url=new URL(sessionBase+"_letmeknow/client",location.href);url.protocol=url.protocol==="https:"?"wss:":"ws:";
  const current=credential?new WebSocket(url,credential):new WebSocket(url);
  socket=current;
  current.onmessage=event=>{
    if(socket!==current||typeof event.data!=="string")return;
    let message;try{message=JSON.parse(event.data)}catch{return}
    if(message.type==="credential"){credential=message.credential;try{sessionStorage.setItem(credentialKey,credential)}catch{}return}
    if(message.type==="challenge"){if(current.readyState===WebSocket.OPEN)try{current.send(JSON.stringify({type:"alive",nonce:message.nonce}))}catch{}return}
    if(message.type==="busy"){status("This session is open elsewhere");retryTimer=setTimeout(connect,message.retry_after*1000);return}
    if(message.type==="file_update"){update(message.path);return}
    if(message.type==="closed"){terminal=true;try{sessionStorage.removeItem(credentialKey)}catch{}status(message.message)}
  };
  current.onclose=()=>{if(socket!==current||terminal)return;if(!retryTimer){status("Reconnecting…");retryTimer=setTimeout(connect,1000)}};
  current.onerror=()=>{};
};
document.addEventListener("submit",async event=>{
  const form=event.target;
  if(!(form instanceof HTMLFormElement))return;
  event.preventDefault();
  const submitter=event.submitter;
  const method=(submitter?.getAttribute("formmethod")??form.getAttribute("method")??"get").toLowerCase()||"get";
  if(method!=="get"&&method!=="post"){status("Only GET and POST forms are supported");return}
  if(!form.noValidate&&!submitter?.formNoValidate&&!form.checkValidity()){form.reportValidity();return}
  let target;
  try{const action=submitter?.getAttribute("formaction")??form.getAttribute("action")??location.href;const base=sessionBase!=="/"&&location.pathname===sessionBase.slice(0,-1)&&!document.querySelector("base")?new URL(sessionBase,location.href):document.baseURI;target=new URL(action,base)}catch{status("Invalid form action");return}
  if(target.origin!==location.origin){status("Form actions must stay on this site");return}
  if(sessionBase!=="/"){
    const sessionPath=sessionBase.slice(0,-1);
    if(target.pathname===sessionPath)target.pathname=sessionBase;
    else if(!target.pathname.startsWith(sessionBase))target.pathname=sessionBase+target.pathname.replace(/^\//,"");
  }
  const values=new URLSearchParams();
  for(const [name,value] of new FormData(form,submitter)){if(typeof value!=="string"){status("File inputs are not supported");return}values.append(name,value)}
  const actionPath=sessionBase!=="/"?target.pathname.slice(sessionBase.length-1)||"/":target.pathname;
  const metadata={id:crypto.randomUUID(),form_id:form.id||null,action:actionPath+target.search,trigger:{id:submitter?.id||null,name:submitter?.getAttribute("name"),value:submitter?.getAttribute("value")}};
  const headers={"X-LetMeKnow-Submission":"1","X-LetMeKnow-ID":encodeURIComponent(metadata.id),"X-LetMeKnow-Form-ID":encodeURIComponent(metadata.form_id??""),"X-LetMeKnow-Action":encodeURIComponent(metadata.action),"X-LetMeKnow-Trigger-ID":encodeURIComponent(metadata.trigger.id??""),"X-LetMeKnow-Trigger-Name":encodeURIComponent(metadata.trigger.name??""),"X-LetMeKnow-Trigger-Value":encodeURIComponent(metadata.trigger.value??"")};
  if(method==="get")for(const [name,value] of values)target.searchParams.append(name,value);
  try{const response=await fetch(target,{method:method.toUpperCase(),headers,...(method==="post"?{body:values}:{})});if(!response.ok)throw new Error();status("Submitted")}catch{status("The submission failed")}
});
connect();
`;

function header(packet, name) {
  const entry = Object.entries(packet.headers || {}).find(([key]) => key.toLowerCase() === name);
  return typeof entry?.[1] === "string" && entry[1] !== "" ? entry[1] : null;
}

function encodedHeader(packet, name) {
  const value = header(packet, name);
  if (value === null) return null;
  try { return decodeURIComponent(value); } catch { return null; }
}

function addValue(values, name, value) {
  if (Object.prototype.hasOwnProperty.call(values, name)) values[name] = Array.isArray(values[name]) ? [...values[name], value] : [values[name], value];
  else values[name] = value;
}

function response(packet, status, body = Buffer.alloc(0), headers = {}) {
  if (body.byteLength > MAX_BODY_BYTES) return response(packet, 413, Buffer.from("response body is too large"), { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
  const outputHeaders = { "Cache-Control": "no-store", ...headers };
  if (!Object.keys(outputHeaders).some(name => name.toLowerCase() === "content-length")) outputHeaders["Content-Length"] = String(body.byteLength);
  const method = typeof packet.method === "string" ? packet.method.toUpperCase() : "";
  return { type: "http_response", request_id: packet.request_id, status, headers: outputHeaders, body: method === "HEAD" ? "" : body.toString("base64") };
}

function errorResponse(packet, status, message) {
  return response(packet, status, Buffer.from(message), { "Content-Type": "text/plain; charset=utf-8" });
}

function deniedPath(pathname) {
  const normalized = pathname.replace(/^\/+/, "");
  return normalized !== "" && (ig.ignores(normalized) || pathname.split("/").filter(Boolean).some(part => ig.ignores(part) || privateFilePattern.test(part)));
}

function inside(root, target) {
  const path = relative(root, target);
  return path === "" || (path !== ".." && !path.startsWith(".." + sep));
}

async function safeRealpath(root, candidate) {
  try {
    const target = await realpath(candidate);
    return inside(root, target) ? target : null;
  } catch (cause) {
    if (cause?.code === "EACCES" || cause?.code === "EPERM") return null;
    if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") {
      try {
        const parent = await realpath(dirname(candidate));
        if (!inside(root, parent)) return null;
      } catch {}
      return undefined;
    }
    throw cause;
  }
}

function requestUrl(packet) {
  if (typeof packet.path !== "string" || !packet.path.startsWith("/")) throw new Error("invalid request path");
  const url = new URL(packet.path, "http://letmeknow.local");
  if (url.origin !== "http://letmeknow.local") throw new Error("invalid request path");
  let pathname;
  try { pathname = decodeURIComponent(url.pathname); } catch { throw new Error("invalid request path"); }
  if (pathname.includes("\0") || pathname.includes("\\")) throw new Error("invalid request path");
  return { pathname, encodedPathname: url.pathname, search: url.search };
}

function htmlWithClient(body, sessionBase) {
  const text = body.toString("utf8");
  const base = typeof sessionBase === "string" && /^\/s\/[a-f0-9]{20}\/$/.test(sessionBase) ? sessionBase : "/";
  const script = `<script type="module" src="${base}_letmeknow/client.js" data-letmeknow-client></script>`;
  return Buffer.from(text + script, "utf8");
}

async function staticResponse(root, packet) {
  const method = typeof packet.method === "string" ? packet.method.toUpperCase() : "";
  if (method !== "GET" && method !== "HEAD") return errorResponse(packet, 405, "method not allowed");
  let request;
  try { request = requestUrl(packet); } catch { return errorResponse(packet, 400, "bad request"); }
  if (request.pathname === "/_letmeknow/client.js") return response(packet, 200, Buffer.from(client), { "Content-Type": "text/javascript; charset=utf-8" });
  if (deniedPath(request.pathname)) return errorResponse(packet, 403, "forbidden");
  const candidate = resolve(root, "." + request.pathname);
  if (!inside(root, candidate)) return errorResponse(packet, 403, "forbidden");
  let target;
  try { target = await safeRealpath(root, candidate); } catch { return errorResponse(packet, 500, "preview request failed"); }
  if (target === null) return errorResponse(packet, 403, "forbidden");
  if (target === undefined) return errorResponse(packet, 404, "not found");
  if (deniedPath("/" + relative(root, target).split(sep).join("/"))) return errorResponse(packet, 403, "forbidden");
  let info;
  try { info = await stat(target); } catch (cause) {
    if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") return errorResponse(packet, 404, "not found");
    if (cause?.code === "EACCES" || cause?.code === "EPERM") return errorResponse(packet, 403, "forbidden");
    return errorResponse(packet, 500, "preview request failed");
  }
  if (info.isDirectory()) {
    if (!request.encodedPathname.endsWith("/")) {
      const location = request.encodedPathname.slice(request.encodedPathname.lastIndexOf("/") + 1) + "/" + request.search;
      return response(packet, 301, Buffer.from(`Redirecting to ${location}`), { Location: location, "Content-Type": "text/plain; charset=utf-8" });
    }
    const index = resolve(target, "index.html");
    try { target = await realpath(index); } catch (cause) {
      if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") return errorResponse(packet, 404, "not found");
      return errorResponse(packet, 500, "preview request failed");
    }
    if (!inside(root, target)) return errorResponse(packet, 403, "forbidden");
    if (deniedPath("/" + relative(root, target).split(sep).join("/"))) return errorResponse(packet, 403, "forbidden");
    try { info = await stat(target); } catch (cause) {
      if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") return errorResponse(packet, 404, "not found");
      if (cause?.code === "EACCES" || cause?.code === "EPERM") return errorResponse(packet, 403, "forbidden");
      return errorResponse(packet, 500, "preview request failed");
    }
  } else if (request.pathname.endsWith("/")) return errorResponse(packet, 404, "not found");
  if (info.size > MAX_BODY_BYTES) return errorResponse(packet, 413, "response body is too large");
  let body;
  try { body = await readFile(target); } catch (cause) {
    if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") return errorResponse(packet, 404, "not found");
    if (cause?.code === "EACCES" || cause?.code === "EPERM") return errorResponse(packet, 403, "forbidden");
    return errorResponse(packet, 500, "preview request failed");
  }
  if (body.byteLength > MAX_BODY_BYTES) return errorResponse(packet, 413, "response body is too large");
  if (extname(target).toLowerCase() === ".html") body = htmlWithClient(body, header(packet, "x-letmeknow-session-base"));
  if (body.byteLength > MAX_BODY_BYTES) return errorResponse(packet, 413, "response body is too large");
  return response(packet, 200, body, { "Content-Type": getMimeType(target) });
}

async function submission(packet) {
  const url = requestUrl(packet);
  const method = typeof packet.method === "string" ? packet.method.toUpperCase() : "";
  const values = Object.create(null);
  if (method === "GET") {
    for (const [name, value] of new URLSearchParams(url.search)) addValue(values, name, value);
  } else if (method === "POST") {
    const body = Buffer.from(typeof packet.body === "string" ? packet.body : "", "base64");
    if (body.byteLength > MAX_BODY_BYTES) throw new Error("submission is too large");
    const contentType = header(packet, "content-type")?.split(";", 1)[0].trim().toLowerCase();
    if (contentType !== "application/x-www-form-urlencoded") throw new Error("unsupported submission encoding");
    for (const [name, value] of new URLSearchParams(body.toString("utf8"))) addValue(values, name, value);
  } else throw new Error("unsupported submission method");
  const event = {
    type: "submit",
    id: encodedHeader(packet, "x-letmeknow-id"),
    method,
    action: encodedHeader(packet, "x-letmeknow-action") || url.pathname,
    form_id: encodedHeader(packet, "x-letmeknow-form-id"),
    trigger: { id: encodedHeader(packet, "x-letmeknow-trigger-id"), name: encodedHeader(packet, "x-letmeknow-trigger-name"), value: encodedHeader(packet, "x-letmeknow-trigger-value") },
    values
  };
  process.stdout.write(`${JSON.stringify(event)}\n`);
  return response(packet, 204);
}

async function handleRequest(root, packet) {
  if (header(packet, "x-letmeknow-submission") === "1") {
    try { return await submission(packet); } catch (cause) { return errorResponse(packet, cause?.message === "submission is too large" ? 413 : 400, cause instanceof Error ? cause.message : "invalid submission"); }
  }
  return staticResponse(root, packet);
}

function options(directory) {
  const root = resolve(directory || process.cwd());
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`directory does not exist: ${root}`);
  return realpath(root).then(root => ({ root }));
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
  try { url = new URL(value); } catch { return false; }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  if (/^[a-f0-9]{20}\.letmeknow\.dev$/.test(url.hostname)) return true;
  return /^\/s\/[a-f0-9]{20}(?:\/|$)/.test(url.pathname);
}

async function start(directory) {
  const { root } = await options(directory);
  const control = process.env.LETMEKNOW_URL || "https://letmeknow.dev";
  let send = () => false;
  const watcher = chokidar.watch(root, { ignoreInitial: true });
  watcher.on("all", (_event, filename) => {
    if (!filename) { send({ type: "file_update", path: "/" }); return; }
    const file = resolve(root, String(filename));
    const path = relative(root, file).split(sep).join("/");
    if (!path || path.startsWith("../") || path === ".." || deniedPath("/" + path)) return;
    send({ type: "file_update", path: "/" + path.split("/").map(encodeURIComponent).join("/") });
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
    await watcher.close();
    process.exit(code);
  };
  process.once("SIGINT", () => void stop(0));
  process.once("SIGTERM", () => void stop(0));

  const retry = () => {
    if (stopped || Date.now() >= retryUntil) return void stop(1);
    retryTimer = setTimeout(() => { retryTimer = undefined; connect(); }, retryDelay);
    retryDelay = Math.min(retryDelay * 2, MAX_RETRY_DELAY);
  };

  const connect = () => {
    if (stopped) return;
    const reconnecting = Boolean(credential && sessionUrl);
    const current = socket = reconnecting ? new WebSocket(endpoint(control, credential, sessionUrl), credential) : new WebSocket(endpoint(control));
    connectionTimer = setTimeout(() => {
      if (socket !== current || current.readyState === WebSocket.OPEN || stopped) return;
      try { current.close(); } catch {}
      if (!reconnecting) void stop(1);
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
      if (!reconnecting) send({ type: "open" });
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
        if (!ready) { ready = true; process.stdout.write(`${JSON.stringify({ type: "ready", url: sessionUrl })}\n`); }
      } else if (packet.type === "http_request") {
        void handleRequest(root, packet).then(result => send(result)).catch(() => send(errorResponse(packet, 500, "preview request failed")));
      } else if (packet.type === "closed") {
        void stop(0);
      } else if (packet.type === "error") {
        void stop(1);
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

let parsed;
try {
  parsed = parseArgs({
    args: process.argv.slice(2),
    options: {
      skill: { type: "boolean" },
      help: { type: "boolean", short: "h" }
    },
    allowPositionals: true
  });
} catch (cause) {
  process.stderr.write(`letmeknow: ${cause instanceof Error ? cause.message : "invalid arguments"}\n`);
  process.exit(1);
}

if (parsed.values.skill) {
  if (parsed.positionals.length > 0) { process.stderr.write("Usage: npx letmeknow-cli --skill\n"); process.exit(1); }
  writeSync(1, readFileSync(new URL("../SKILL.md", import.meta.url)));
} else if (parsed.values.help) {
  process.stdout.write("Usage: npx letmeknow-cli [directory]\n\nServe a folder through the hosted LetMeKnow relay. The CLI does not listen on a network port. Form submissions are JSON lines on stdout.\n");
} else if (parsed.positionals.length > 1) {
  process.stderr.write("letmeknow: only one directory may be provided\n");
  process.exit(1);
} else {
  try { await start(parsed.positionals[0]); } catch (cause) { process.stderr.write(`letmeknow: ${cause instanceof Error ? cause.message : "server failed"}\n`); process.exitCode = 1; }
}

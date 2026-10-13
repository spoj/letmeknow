import { readFileSync } from "node:fs";

export function readBackend(path = process.env.LMK_FRONTEND_CONFIG ?? new URL("backend.json", import.meta.url)) {
  const backend = JSON.parse(readFileSync(path, "utf8"));
  const { domain, directory } = backend;
  if (!/^[0-9a-f]{64}$/.test(directory.key)) throw new Error("Set backend.json directory.key to the reviewed fresh authority's PUBLIC key before release");
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*(:[1-9][0-9]*)?$/.test(domain)) throw new Error("Backend domain must be a canonical host or host:port");
  for (const relay of [directory.relay, ...directory.relays]) {
    const url = new URL(relay);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") throw new Error("Backend relay must be an HTTPS origin");
  }
  return backend;
}

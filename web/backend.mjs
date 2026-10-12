import { readFileSync } from "node:fs";

export function readBackend(path = process.env.LMK_FRONTEND_CONFIG ?? new URL("backend.json", import.meta.url)) {
  const backend = JSON.parse(readFileSync(path, "utf8"));
  if (!/^[0-9a-f]{64}$/.test(backend.membershipKey)) throw new Error("Set backend.json membershipKey to the reviewed fresh authority's PUBLIC key before release");
  const relay = new URL(backend.relay);
  if (relay.protocol !== "https:" || relay.username || relay.password || relay.search || relay.hash || relay.pathname !== "/") throw new Error("Backend relay must be an HTTPS origin");
  return { membershipKey: backend.membershipKey, relay: relay.origin };
}

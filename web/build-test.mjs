import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const good = { domain: "relay.letmeknow.dev", directory: { key: "11".repeat(32), relay: "https://relay.letmeknow.dev", relays: ["https://relay.letmeknow.dev"] } };
const with_ = (domain, directory) => ({ domain, directory: { ...good.directory, ...directory } });
for (const [backend, message] of [
  [with_(good.domain, { key: null }), /reviewed fresh authority/],
  [with_(good.domain, { key: "old-key-placeholder" }), /reviewed fresh authority/],
  [{ ...good, domain: "Relay.Example" }, /canonical host/],
  [{ ...good, domain: "https://relay.example" }, /canonical host/],
  [with_(good.domain, { relay: "http://backend.example" }), /HTTPS origin/],
  [with_(good.domain, { relay: "https://user@backend.example" }), /HTTPS origin/],
  [with_(good.domain, { relays: ["https://backend.example/config"] }), /HTTPS origin/],
  [with_(good.domain, { relays: ["https://backend.example/?key=x"] }), /HTTPS origin/],
  [with_(good.domain, { relays: ["https://backend.example/#x"] }), /HTTPS origin/]
]) test(`reject unconfigured or unsafe build: ${JSON.stringify(backend)}`, () => {
  const tmp = mkdtempSync(join(tmpdir(), "lmk-build-test-"));
  try {
    const config = join(tmp, "backend.json");
    writeFileSync(config, JSON.stringify(backend));
    const result = spawnSync(process.execPath, ["build.mjs"], { env: { ...process.env, LMK_FRONTEND_CONFIG: config }, encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, message);
  } finally {
    rmSync(tmp, { recursive: true });
  }
});

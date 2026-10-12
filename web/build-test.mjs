import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

for (const backend of [
  { membershipKey: null, relay: "https://relay.letmeknow.dev" },
  { membershipKey: "old-key-placeholder", relay: "https://relay.letmeknow.dev" },
  ...["http://backend.example", "https://user@backend.example", "https://backend.example/config", "https://backend.example/?key=x", "https://backend.example/#x"]
    .map(relay => ({ membershipKey: "11".repeat(32), relay }))
]) test(`reject unconfigured or unsafe build: ${JSON.stringify(backend)}`, () => {
  const tmp = mkdtempSync(join(tmpdir(), "lmk-build-test-"));
  try {
    const config = join(tmp, "backend.json");
    writeFileSync(config, JSON.stringify(backend));
    const result = spawnSync(process.execPath, ["build.mjs"], { env: { ...process.env, LMK_FRONTEND_CONFIG: config }, encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /reviewed fresh authority|Backend relay must be an HTTPS origin/);
  } finally {
    rmSync(tmp, { recursive: true });
  }
});

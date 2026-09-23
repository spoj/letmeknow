#!/usr/bin/env node
const { spawn } = require("node:child_process");
const fs = require("node:fs");

const target = `${process.platform}-${process.arch}`;
let binary;
try {
  binary = require.resolve(`@letmeknow/${target}/bin/letmeknow${process.platform === "win32" ? ".exe" : ""}`);
} catch {
  console.error(`letmeknow: no prebuilt binary for ${target}; see https://github.com/spoj/letmeknow`);
  process.exit(1);
}
try {
  fs.accessSync(binary, fs.constants.X_OK);
} catch {
  fs.chmodSync(binary, 0o755);
}

const child = spawn(binary, process.argv.slice(2), { stdio: "inherit" });
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, () => child.kill(signal));
child.on("error", error => {
  console.error(`letmeknow: ${error.message}`);
  process.exit(1);
});
child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));

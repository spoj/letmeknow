const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

/** Runs one of the prebuilt executables of this platform's package: `letmeknow`, or git's remote helper `git-remote-lmk`. */
module.exports = name => {
  const target = `${process.platform}-${process.arch}`;
  let binary;
  try {
    binary = require.resolve(`@letmeknow/${target}/bin/${name}${process.platform === "win32" ? ".exe" : ""}`);
  } catch {
    console.error(`${name}: no prebuilt binary for ${target}; see https://github.com/spoj/letmeknow`);
    process.exit(1);
  }
  // The binary and the plugins beside it, which it runs, must be executable.
  const bin = path.dirname(binary);
  for (const file of fs.readdirSync(bin)) {
    try {
      fs.accessSync(path.join(bin, file), fs.constants.X_OK);
    } catch {
      fs.chmodSync(path.join(bin, file), 0o755);
    }
  }

  const child = spawn(binary, process.argv.slice(2), { stdio: "inherit" });
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, () => child.kill(signal));
  child.on("error", error => {
    console.error(`${name}: ${error.message}`);
    process.exit(1);
  });
  child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
};

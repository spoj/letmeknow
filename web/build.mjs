// Builds the browser client into relay/public/assets, where the relay serves it: the client's library compiled to
// WebAssembly, and the app bundled. app.js and app.css keep their names; the WebAssembly file carries a hash.
import { execFileSync } from "node:child_process";
import { rmSync } from "node:fs";
import { build } from "esbuild";

const client = new URL("../client/", import.meta.url).pathname;
const out = new URL("../relay/public/assets/", import.meta.url).pathname;
execFileSync("cargo", ["rustc", "--lib", "--release", "--target", "wasm32-unknown-unknown", "--crate-type", "cdylib"], { cwd: client, stdio: "inherit" });
execFileSync("wasm-bindgen", ["--target", "web", "--out-dir", "pkg", `${client}target/wasm32-unknown-unknown/release/letmeknow.wasm`], { cwd: new URL(".", import.meta.url).pathname, stdio: "inherit" });
rmSync(out, { recursive: true, force: true });
await build({
  entryPoints: { app: "src/main.ts" },
  assetNames: "[name]-[hash]",
  loader: { ".wasm": "file" },
  publicPath: "/assets",
  bundle: true,
  minify: true,
  format: "esm",
  target: "es2022",
  outdir: out
});

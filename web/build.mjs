// Builds the browser client into relay/public/assets, where the relay serves it: the client's library compiled to
// WebAssembly, and the app bundled. app.js and app.css keep their names; the WebAssembly file and the chunks loaded
// later (the editor, the QR code) carry a hash.
import { execFileSync } from "node:child_process";
import { rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const web = fileURLToPath(new URL(".", import.meta.url));
const client = fileURLToPath(new URL("../client/", import.meta.url));
const out = fileURLToPath(new URL("../relay/public/assets/", import.meta.url));
execFileSync("cargo", ["rustc", "--lib", "--profile", "wasm", "--target", "wasm32-unknown-unknown", "--crate-type", "cdylib"], { cwd: client, stdio: "inherit" });
execFileSync("wasm-bindgen", ["--target", "web", "--out-dir", "pkg", `${client}target/wasm32-unknown-unknown/wasm/letmeknow.wasm`], { cwd: web, stdio: "inherit" });
rmSync(out, { recursive: true, force: true });
await build({
  entryPoints: { app: `${web}src/main.ts` },
  assetNames: "[name]-[hash]",
  chunkNames: "[name]-[hash]",
  splitting: true,
  loader: { ".wasm": "file" },
  publicPath: "/assets",
  bundle: true,
  minify: true,
  format: "esm",
  target: "es2022",
  outdir: out
});

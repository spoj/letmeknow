// Builds the browser client into dist/, which `letmeknow serve --web web/dist` serves: crates/web compiled to
// WebAssembly with the workspace's `wasm` profile, the app bundled, and a service worker that caches exactly these files.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { copyFileSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const web = fileURLToPath(new URL(".", import.meta.url));
const root = fileURLToPath(new URL("..", import.meta.url));
const out = `${web}dist/`;
execFileSync("cargo", ["build", "-p", "lmk-web", "--profile", "wasm", "--target", "wasm32-unknown-unknown"], { cwd: root, stdio: "inherit" });
execFileSync("wasm-bindgen", ["--target", "web", "--out-dir", "pkg", `${root}target/wasm32-unknown-unknown/wasm/lmk_web.wasm`], { cwd: web, stdio: "inherit" });
rmSync(out, { recursive: true, force: true });
await build({
  entryPoints: { app: `${web}src/main.ts` },
  assetNames: "[name]-[hash]",
  chunkNames: "[name]-[hash]",
  splitting: true,
  loader: { ".wasm": "file" },
  publicPath: "/",
  bundle: true,
  minify: true,
  format: "esm",
  target: "es2022",
  outdir: out
});
for (const file of ["index.html", "manifest.webmanifest", "icon.svg"]) copyFileSync(`${web}src/${file}`, out + file);
const files = readdirSync(out).sort();
const version = createHash("sha256");
for (const file of files) version.update(file).update(readFileSync(out + file));
await build({
  entryPoints: [`${web}src/sw.ts`],
  define: { FILES: JSON.stringify(files.map(file => `/${file}`)), VERSION: JSON.stringify(version.digest("hex").slice(0, 16)) },
  bundle: true,
  minify: true,
  target: "es2022",
  outfile: `${out}sw.js`
});

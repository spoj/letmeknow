// Builds the complete static frontend; no configuration is fetched from the backend.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { build } from "esbuild";
import { readBackend } from "./backend.mjs";

const web = fileURLToPath(new URL(".", import.meta.url));
const root = fileURLToPath(new URL("..", import.meta.url));
const out = resolve(web, process.env.LMK_FRONTEND_OUT ?? "dist");
const backend = readBackend();
execFileSync("cargo", ["build", "-p", "lmk-web", "--profile", "wasm", "--target", "wasm32-unknown-unknown", ...(process.env.LMK_TEST_WITNESS ? ["--features", "test-witness"] : [])], { cwd: root, stdio: "inherit" });
execFileSync("wasm-bindgen", ["--target", "web", "--out-dir", "pkg", resolve(root, process.env.CARGO_TARGET_DIR ?? "target", "wasm32-unknown-unknown/wasm/lmk_web.wasm")], { cwd: web, stdio: "inherit" });
rmSync(out, { recursive: true, force: true });
await build({
  entryPoints: { app: `${web}src/main.ts` },
  define: { BACKEND: JSON.stringify(backend) },
  assetNames: "[name]-[hash]",
  chunkNames: "[name]-[hash]",
  splitting: true,
  loader: { ".wasm": "file", ".woff": "file", ".woff2": "file" },
  publicPath: "/",
  bundle: true,
  minify: true,
  format: "esm",
  target: "es2022",
  outdir: out
});
for (const file of ["index.html", "manifest.webmanifest", "icon.svg", "icon-180.png", "icon-192.png", "icon-512.png"]) copyFileSync(`${web}src/${file}`, `${out}/${file}`);
// Pages has no SPA rewrite: the invite entry point must exist on a first visit.
mkdirSync(`${out}/i`);
copyFileSync(`${out}/index.html`, `${out}/i/index.html`);
writeFileSync(`${out}/.nojekyll`, "");
writeFileSync(`${out}/backend.json`, JSON.stringify(backend) + "\n");
const files = readdirSync(out).filter(file => !["i", ".nojekyll"].includes(file)).sort();
const version = createHash("sha256");
for (const file of files) version.update(file).update(readFileSync(`${out}/${file}`));
await build({
  entryPoints: [`${web}src/sw.ts`],
  define: { FILES: JSON.stringify(files.map(file => `/${file}`)), VERSION: JSON.stringify(version.digest("hex").slice(0, 16)) },
  bundle: true,
  minify: true,
  target: "es2022",
  outfile: `${out}/sw.js`
});

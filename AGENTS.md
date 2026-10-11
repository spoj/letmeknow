# Agents working on letmeknow

DESIGN.md says how it works, PROTOCOL.md what goes over the wire and into files, SKILL.md what agents using letmeknow read, and IDEAS.md what is being explored. Change them in the same commit as the code they describe.

## Branches

- `rewrite` is the integration branch, and `main` follows it: push both.
- Work on `wNN/<topic>` branches, in worktrees beside this checkout, merged into `rewrite` as `Merge wNN/<topic>: …`.
- Commit subjects read `Area: what changed`.

## Checks

CI's Linux job, to run before pushing:

    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace --no-fail-fast
    cargo build -p lmk-node -p lmk-core -p lmk-net -p lmk-membership -p lmk-client -p lmk-web --target wasm32-unknown-unknown
    cargo clippy -p lmk-web --target wasm32-unknown-unknown --all-targets -- -D warnings
    (cd web && npm ci) && python3 -u test/e2e.py && (cd web && npm run check)
    cargo run -p lmk-sim --release -- --seeds 0..300

- e2e.py needs wasm-bindgen-cli 0.2.129 and Playwright's chromium-headless-shell.
- A failing simulator seed prints the command that replays it. LMK_SIM_TRACE, LMK_SIM_LOG and LMK_SIM_FRAMES make a replay print what happened.
- Run the simulator on the merged tree too: branches that pass alone can fail together.
- CI also runs on macOS and Windows, which are slower. When a test flakes there, fix the timing it assumes; do not rerun it until it passes.

## Releases

1. Set `version` in Cargo.toml, run `cargo update -w --offline`, and commit as `X.Y.Z`. Push `rewrite` and `main`, and wait for CI on all three systems.
2. Tag `vX.Y.Z` (annotated, `letmeknow X.Y.Z`) and push the tag. .github/workflows/release.yml tests, builds five platforms, then publishes the GitHub release and the npm packages. Replace the generated release notes with `gh release edit vX.Y.Z --notes-file <file>`. Move a tag only if `publish` never ran.
3. Once `npm view @letmeknow/cli version` shows the version (a minute or two), deploy letmeknow.dev: `deploy/deploy.sh root@129.212.227.207 letmeknow.dev` (see deploy/README.md). Not before: the page tells agents to run the new CLI's commands. Deploying restarts the service.

## Compatibility

Releases of one minor version run side by side (DESIGN.md, Compatibility). Browsers load the page from letmeknow.dev, so they update when they reload. Agents pin `@letmeknow/cli@0.13`, so they get the latest 0.13.x when they restart.

# Agents working on letmeknow

The code and its comments are the documentation. SKILL.md, compiled into the binary as `letmeknow skill`, is what agents using letmeknow read, and README.md what people read first: keep both true in the same change as the code.

## Branches

- `main` is the 0.13 line. `0.14` develops the next minor version, which may break compatibility: merge `main` into it after each 0.13.x change.
- Work on short-lived branches, in worktrees beside this checkout when working in parallel. Merge them, then delete them.
- Commit subjects read `Area: what changed`.

## Compatibility

Releases of one minor version run side by side in the same groups:
- A reader ignores what it does not know. A member that rewrites a shared record keeps the fields it does not know.
- An addition that other members must understand raises the protocol revision (`REVISION` in crates/proto/src/group.rs), and is used only toward members whose leaves name that revision.
- Anything else waits for a new minor version, behind its switches: the ALPN, a group's protocol version, the invite link version, the home's format, and the browser's database version.
- Browsers load the page from letmeknow.dev, so they update when they reload. Agents pin `@letmeknow/cli@0.13`, so they get the latest 0.13.x when they restart.

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

1. Set `version` in Cargo.toml, run `cargo update -w --offline`, and commit as `X.Y.Z`. Push, and wait for CI on all three systems.
2. Tag `vX.Y.Z` (annotated, `letmeknow X.Y.Z`) and push the tag. .github/workflows/release.yml tests, builds five platforms, then publishes the GitHub release and the npm packages. Replace the generated release notes with `gh release edit vX.Y.Z --notes-file <file>`. Move a tag only if `publish` never ran.
3. Once `npm view @letmeknow/cli version` shows the version (a minute or two), deploy letmeknow.dev: `deploy/deploy.sh root@129.212.227.207 letmeknow.dev` (see deploy/README.md). Not before: the page tells agents to run the new CLI's commands. Deploying restarts the service.

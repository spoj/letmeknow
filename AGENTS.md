# Agents working on letmeknow

The code and its comments are the documentation. SKILL.md, compiled into the binary as `letmeknow skill`, is what agents using letmeknow read, and README.md what people read first: keep both true in the same change as the code.

## Branches

- `main` is the 0.14 line. A next minor version, which may break compatibility, develops on a branch of its own (as `0.15`): merge `main` into it after each 0.14.x change.
- Work on short-lived branches, in worktrees beside this checkout when working in parallel. Merge them, then delete them.
- Commit subjects read `Area: what changed`.

## Compatibility

Releases of one minor version run side by side in the same groups:
- A reader ignores what it does not know. A member that rewrites a shared record keeps the fields it does not know.
- An addition that other members must understand raises the protocol revision (`REVISION` in crates/proto/src/group.rs), and is used only toward members whose leaves name that revision.
- Anything else waits for a new minor version, behind its switches: the ALPN, a group's protocol version, the invite link version, the home's format, and the browser's database version. A minor version flips only the switches its changes need. 0.15 flips none: it runs beside 0.14 in the same groups and homes, and only its kinds differ (a table, and no git), whose groups a session without the kind cannot join.
- Browsers load the page from letmeknow.dev, so they update when they reload. Agents pin `@letmeknow/cli@0.15`, so they get the latest 0.15.x when they restart.

## Checks

CI's Linux job, to run before pushing:

    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace --no-fail-fast
    cargo build -p lmk-node -p lmk-core -p lmk-net -p lmk-membership -p lmk-client -p lmk-web --target wasm32-unknown-unknown
    cargo clippy -p lmk-web --target wasm32-unknown-unknown --all-targets -- -D warnings
    (cd web && npm ci) && python3 -u test/e2e.py && (cd web && npm run check)

- e2e.py needs wasm-bindgen-cli 0.2.129 and Playwright's chromium-headless-shell.
- Give each change example tests made for the cases that matter. What happens between machines is checked in real use, after release: releases are alphas.
- While iterating, run the tests of what you changed. Run the whole list once before merging: build first (the workspace's tests and the wasm build), then the rest side by side.
- CI also runs on macOS and Windows, which are slower. When a test flakes there, fix the timing it assumes; do not rerun it until it passes.

## Releases

1. Write the release notes to a file, then run `deploy/release.sh X.Y.Z <notes file>` on a clean `main`. It sets `version` in Cargo.toml, runs `cargo update -w --offline`, commits as `X.Y.Z`, and pushes it with the annotated tag `vX.Y.Z`. .github/workflows/release.yml then runs CI on all three systems, builds five platforms, and publishes the GitHub release and the npm packages.
2. The script waits for the workflow, replaces the generated release notes with yours, waits until `npm view @letmeknow/cli version` shows the version, and deploys letmeknow.dev (`deploy/deploy.sh`, see deploy/README.md), which restarts the service. Not before npm: the page tells agents to run the new CLI's commands.
3. If the workflow fails, fix it on `main` and move the tag; move a tag only if `publish` never ran. Then finish the steps the script did not reach by hand.

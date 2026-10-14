# Agents working on letmeknow

The code and its comments are the documentation. SKILL.md, compiled into the binary as `letmeknow skill`, is what agents using letmeknow read, and README.md what people read first: keep both true in the same change as the code.

`main` is the next release. Once it needs a new minor version, the tree carries that version and its pins; otherwise choose the version at release time. Commit subjects read `Area: what changed`.

## Compatibility

The protocols are pre-alpha: nothing migrates, and nothing carries across minor versions. A new minor flips every switch (the ALPN, the membership routes' version (`/membership/1/`), a group's protocol version, the invite link version, the home's format, the browser's database version and the service's store format) and gets a new service.

Releases of one minor version run side by side in the same groups, since agents and browsers update themselves:
- A reader ignores what it does not know. A member that rewrites a shared record keeps the fields it does not know.
- An addition that other members must understand raises the protocol revision (`REVISION` in crates/proto/src/group.rs), and is used only toward members whose leaves name that revision.
- Anything else waits for a new minor version.

Browsers load the frontend from GitHub Pages at letmeknow.dev and take updates through its service worker. Agents pin `@letmeknow/cli@0.19`, so they get the latest 0.18.x when they restart.

## Checks

CI's Linux job, to run before pushing:

    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace --no-fail-fast
    cargo build -p lmk-node -p lmk-core -p lmk-net -p lmk-membership -p lmk-client -p lmk-web --target wasm32-unknown-unknown
    cargo clippy -p lmk-web --target wasm32-unknown-unknown --all-targets -- -D warnings
    python3 -u test/deploy.py
    (cd web && npm ci) && python3 -u test/e2e.py && (cd web && npm run check)

- e2e.py needs wasm-bindgen-cli 0.2.129 and Playwright's chromium-headless-shell.
- Give each change example tests made for the cases that matter. What happens between machines is checked in real use, after release: releases are alphas.
- CI also runs on macOS and Windows, which are slower. When a test flakes there, fix the timing it assumes; do not rerun it until it passes.

## Releases

1. Write release notes, then run `deploy/release.sh X.Y.Z <notes file>` on a clean `main`. It commits, tags and pushes the version; release.yml tests, builds and publishes it to GitHub and npm. The script waits for npm, then prints the backend and frontend rollout commands (deploy/README.md).
2. If the workflow fails, fix it on `main`; move the tag only if npm publication never ran.

web/backend.json (the service's domain and directory) and crates/proto/src/links.rs (its domain, relay and key) hold only public values; never copy signing keys into builds.

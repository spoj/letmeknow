# Agents working on letmeknow

The code and its comments are the documentation. SKILL.md, compiled into the binary as `letmeknow skill`, is what agents using letmeknow read, and README.md what people read first: keep both true in the same change as the code.

## Branches

- `main` is the next release, whether patch or minor. Choose the version at release time; minor releases need no long-lived branch.
- Work on short-lived branches, in worktrees beside this checkout when working in parallel. Merge them, then delete them.
- Commit subjects read `Area: what changed`.

## Compatibility

Releases of one minor version run side by side in the same groups:
- A reader ignores what it does not know. A member that rewrites a shared record keeps the fields it does not know.
- An addition that other members must understand raises the protocol revision (`REVISION` in crates/proto/src/group.rs), and is used only toward members whose leaves name that revision.
- Anything else waits for a new minor version, behind its switches: the ALPN, a group's protocol version, the invite link version, the home's format, and the browser's database version. A minor version flips only the switches its changes need. Test the chosen contract: supported versions coexist; incompatible versions refuse without changing newer state.
- Browsers load the entire frontend from GitHub Pages at letmeknow.dev, independently of relay.letmeknow.dev. A service worker normally offers a waiting update; this is not cryptographic pinning, and the same-origin host still controls code. Agents pin `@letmeknow/cli@0.15`, so they get the latest 0.15.x when they restart.

## Checks

CI's Linux job, to run before pushing:

    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace --no-fail-fast
    cargo build -p lmk-node -p lmk-core -p lmk-net -p lmk-membership -p lmk-client -p lmk-web --target wasm32-unknown-unknown
    cargo clippy -p lmk-web --target wasm32-unknown-unknown --all-targets -- -D warnings
    python3 deploy/version-pins.py check
    python3 -u test/release.py
    python3 -u test/deploy.py
    (cd web && npm ci) && python3 -u test/e2e.py && (cd web && npm run check)

- e2e.py needs wasm-bindgen-cli 0.2.129 and Playwright's chromium-headless-shell. It builds a test-key frontend and serves it on a separate HTTPS origin from the real backend; it exercises cross-origin iroh-over-WSS, not WebRTC. Its script-free `blank.html` seeds old databases before the app loads. `web/backend.json` stages the production public key; never discover it from the backend or replace it with the old authority just to pass a build.
- Give each change example tests made for the cases that matter. What happens between machines is checked in real use, after release: releases are alphas.
- While iterating, run the tests of what you changed. Run the whole list once before merging: build first (the workspace's tests and the wasm build), then the rest side by side.
- CI also runs on macOS and Windows, which are slower. When a test flakes there, fix the timing it assumes; do not rerun it until it passes.

## Releases

1. Complete the security/protocol gates in PLAN-0.16.md and the fresh public-key configuration in web/backend.json before release. Never copy signing keys into builds. This frontend work does not implement the other 0.16 protocols or compatibility namespaces.
2. For X.Y.0, configure `LETMEKNOW_PI_REPO` to a reviewed clean local pi-letmeknow `main` with its pin action and dependencies already present (deploy/README.md). Write release notes, then run `deploy/release.sh X.Y.Z <notes file>` on clean `main`. It commits/tags/pushes the version; release.yml runs all-platform CI, builds five native platforms plus the whole production frontend, tests artifacts, and publishes only after all gates pass. The Linux release executable gets native E2E; the exact production frontend gets an offline startup/service-worker smoke test, while full browser/native E2E uses test configuration.
3. The script rewrites all CLI minor pins with the Cargo version, waits for verified publication/exact npm availability, then tests/commits/pushes the Pi minor pin for X.Y.0 and prints rollout commands. Backend deployment and Pages rollout are separate operator-reviewed actions (deploy/README.md), consuming the successful release run's artifacts without rebuilding. Pages dispatch runs from main and requires the github-pages environment approval configured by the operator.
4. If the workflow fails, fix it on main; move the tag only if npm publication never ran. Never deploy a partial/failed release or silently substitute a local build. No script performs destructive cutover, backup restore, or client-state deletion.

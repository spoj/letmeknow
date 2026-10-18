# Agents working on letmeknow

Before pushing, run CI's Linux checks:

    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace --no-fail-fast
    python3 -u test/deploy.py
    python3 -u test/pins.py
    python3 -u test/e2e.py

Release with `deploy/release.sh X.Y.Z <notes file>` on a clean `main` (deploy/README.md). deploy/backend.json and crates/proto/src/links.rs hold only public values; never copy signing keys into builds.

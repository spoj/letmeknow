# Identity minimization implementation

- Worktree: `/home/spoj/src/letmeknow-identity-minimal`
- Branch: `feat-private-identity-claims`
- Baseline: `f1efafbbff04add2c6d11e182d02da29952e52a2` (`f1efafb`).
- Design: `/tmp/lmk-implement-Rj5c/identity-minimization-design.md`, approved by parent.
- `web/node_modules` is a supplied untracked symlink, excluded from commits and patch.
- Private build directory: `target/private`; four Cargo jobs.

This baseline predates sealed epochs: its tests cannot establish private epoch-envelope confidentiality. No epoch/membership namespace or topology change is part of this patch.

## Implementation checkpoint

Keys-only v2 bodies, strict Ed25519 checks, canonical device-signed private names, same-ID/device certificate updates, private UTC-day maintenance, installed-roster-only durable bindings, coalesced session refresh, native evidence and browser persistent People warnings/accessor barriers are implemented. The ledger is `node/identity-bindings`, per saved provider, and survives group deletion/revocation. Directory hints never seed it. Names remain claims; no operator-verification record exists.

Passed so far: native and wasm compilation; native and wasm clippy; 32 core tests; 43 node integration tests including the new identity flows; all 9 client integration tests; the native multi-device/chat/doc/table/offline-resume/takeover regression. The first workspace run had one extra timeout warning on an unchanged-certificate refresh during a loss test. Fixed by checking no-op before network work, retaining the commit-closure recheck; that exact loss test passes. Browser tests already pass the new open-People/form-preservation, name-change, toast lifetime, held/aborted observation transaction, accessor withholding, recovery, and existing phone-to-pocket checks. Full browser run is still in progress: a removal Heard invalidation discarded the old group title before Removed; skip presentation invalidation when removed (Removed is already the invalidation). Do not count a partial browser run as a pass.

Next checkpoint will record full checks, negative controls, uncovered cases and detailed merge boundaries. All logs are under `target/private/identity-*.log`; initial setup failures and obsolete expected `unknown` assertions were corrected, not counted as passes.

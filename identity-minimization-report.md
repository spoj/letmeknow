# F27 + #55 implementation

## Source and artifacts

- Worktree: `/home/spoj/src/letmeknow-identity-minimal`; branch `feat-private-identity-claims`.
- Recorded baseline: **`f1efafbbff04add2c6d11e182d02da29952e52a2`** (`f1efafb`).
- Approved contract: `/tmp/lmk-implement-Rj5c/identity-minimization-design.md`, read completely along with AGENTS/README/SKILL/PLAN/EPOCH.
- Implementation checkpoint: `449742d` (`Identity: minimize directories and remember signed private claims`); subsequent local commit contains the final regressions, lifecycle fix and this report.
- Export: `identity-minimization.patch`, a complete binary-capable diff from the recorded baseline, including new files and this report. The patch itself is not recursively included.
- `web/node_modules` remains the supplied **untracked symlink**, never staged or included in the patch. No installs, subagents, push, release, deployment, production access or other-worktree source changes.
- Builds used only `target/private`, `CARGO_BUILD_JOBS=4`; every synchronous test command was bounded by shell `timeout 20m` and tool timeout 1500s. Recursive searches were bounded, starting at 5s.

**This baseline precedes sealed epochs. These results do not prove confidentiality of private enclosing membership/commit/Welcome envelopes.** No in-progress epoch source was imported or copied. Membership/service/epoch namespaces and frontend/backend topology/defaults are unchanged.

## Implemented contract

1. Public directory `Body` is keys-only: `prev`, `writers: Vec<Bytes>`, genesis-only `membership`. Deleted `Listed`, public names and writer timestamps. Genesis derives its sole writer from the fresh per-identity seed; generated successors sort/deduplicate keys. v2 signatures cover exact body bytes; predecessor succession, closure, dropped keys and genesis authority remain. Continuation service fields and malformed/weak writer keys fail. Directory ID/address/sealing derivations remain unchanged.
2. Required certificate `name`/`device_name` claims are signed with the v2 domain and fixed session/identity/device keys plus u64 big-endian **UTF-8 byte** lengths. Strict Ed25519 verification is shared by directory authorization, MLS refresh rules and local recertification. Route hints remain unsigned bootstrap hints; successful claims expose the authenticated genesis service, not the hint. No service-trusted names or peer-hint pins.
3. `Change.certificate` only refreshes the installed same-session/same-ID/same-device tuple. API and raw MLS rules reject forged claims and rebinding; ordinary name-only updates remain. Untargeted initial invalid certificates remain MLS members but confer no identity labels, observation, peer-service permission or targeted admission. `Authorized` is independent of observation state.
4. `Identity::certify` signs one locked snapshot of committed private settings/own credential, not desired device-file labels or Presence. `Node::recertify` checks before network work (no-op refresh does not wait on unavailable history) and rechecks inside the existing commit closure. It commits existing leaves, not just the future-membership credential.
5. `Client::refresh_identity` retains leave behavior, coalesces passes with `try_lock`, gets its fresh certificate after acquiring the lock, and continues after per-group errors/timeouts. Startup and private Settings/Heard trigger background passes. Native owner/non-owner sessions and browsers retry every ten seconds; errors are visible warnings. Background identity duties report errors while their group still exists; a duty overtaken by deletion is obsolete, not retried against a nonexistent group.
6. Private `Rec.publication_day` schedules keys-only restatement after 182 UTC days; create initializes it, join starts at zero, only successful local publication advances it. Rename alone does not append. It is retention bookkeeping, neither name freshness nor revocation freshness.
7. `node/identity-bindings` is an insertion-ordered, append-only provider record of full-ID/exact-name pairs, per saved native session or browser profile. Observation occurs only at installed-group, accepted-commit and authoritative-directory replay boundaries, over active roster credentials whose embedded key equals the actual MLS leaf key and whose complete certificate is authorized. Lookups, departed rosters, live profile payloads, historical descriptions and invalid certificates cannot seed it. Group deletion/revocation never deletes it.
8. New pairs are persisted before queuing warnings through the existing post-durability outbox. A process-local notified set avoids repeated notices; authenticated changed/colliding pairs produce restart reminders, covering commit-before-output crashes without a new alert-acknowledgement protocol. Invalid current claims reveal neither remembered names nor observation standing.
9. Native warnings are immediate and carry full IDs; `members` retains structured evidence and per-group `status.identity_warnings` uses strings that survive compaction/filtering. Browser People retains original/other names, full copyable IDs and persistent change/collision indicators, updates while open without rebuilding its form, and disambiguates colliding identities with short display suffixes. There is no trust badge or verification button. `groups()` and `items()` capture a snapshot, await storage, then return it; failed storage releases neither snapshot.

## Checks actually run

All following final commands passed, using the environment/bounds above:

- `cargo build -p lmk-kinds -p letmeknow --offline` (plugins required by native session tests).
- `cargo test --workspace --no-fail-fast --offline -- --test-threads=4`: **215 executed tests**, zero failures/ignored. Log: `target/private/identity-workspace-final.log`.
- `cargo build -p lmk-node -p lmk-core -p lmk-net -p lmk-membership -p lmk-client -p lmk-web --target wasm32-unknown-unknown --offline`.
- `cargo clippy --workspace --all-targets --offline -- -D warnings`.
- `cargo clippy -p lmk-web --target wasm32-unknown-unknown --all-targets --offline -- -D warnings`.
- `(cd web && npm run check)`. The preceding build/clippy/typecheck log is `target/private/identity-checks-final.log`.
- `python3 -u test/e2e.py`: complete native + Chromium browser run, ending **`browser ok` / `all ok`**, including the existing storage/file/plugin/admission/recovery/service-worker cases. Log: `target/private/identity-e2e-final.log`. Uses supplied dependencies and wasm-bindgen-cli 0.2.129; **npm ci was not run** because installs were forbidden.
- `git diff --check`.

Zero-test auxiliary binaries/doctest targets are not counted as evidence. No macOS/Windows or power-loss run is claimed.

### Discriminating coverage

- `core/public.rs`: succession/unlisted/dropped writers, wrong predecessor/branch/service/hash, permanent closure, explicit reauthorization, weak/malformed keys, old domain/schema rejection; canonical empty/multibyte/ambiguous-concatenation claims and independent mutation of labels, keys, ID, signature/domain/lengths. Changing only the hint deliberately does not invalidate the device signature.
- `core/group_tests.rs::private_certificates_refresh_but_cannot_rebind_a_membership`: real continuing/later-joining MLS readers, both signed labels, unchanged handle/key, API rejection with byte-for-byte provider-state comparison, anonymous-to-certified refusal, a losing refresh against a competing name commit and successful retry, and raw-wire certificate removal/unsigned-name rejection by all readers. Existing name-only and initial-claim-not-enforced tests retained.
- `node/tests/identity/claims.rs::every_public_body_is_keys_only_through_rename_restatement_removal_and_closure`: real device create/add/remove/both renames/restart/maintenance/closure, independent directory client, decrypts **every** envelope and checks exact raw JSON keys and string writers. Canary labels/precise clock are absent; rename and non-due restart do not grow the directory; day 182 does; an ID retained before removal still opens closure.
- `installed_bindings_survive_refresh_collision_restart_and_group_deletion`: SQLite first binding, no pin from standalone lookup, no-op epoch stability, signed rename/device-only update, no descriptive directory growth, restart reminder, revocation and leaving all groups, case-variant collision after restart with both full IDs, and separate observer scope for a new handle.
- `invalid_installed_claims_cannot_supply_names_or_poison_observations_or_targeted_admission`: real forged/stolen/unlisted/malformed claims, targeted rejection versus untargeted initial admission, no names/observations, byte-identical original ledger, then legitimate rename compared with that original. Even an authorized peer's real encrypted live Presence/profile payload cannot append a binding.
- `a_late_directory_response_cannot_observe_a_roster_that_was_left`: real gated service response arrives after the installed group was left; no binding is created. Existing stale-mirror/failed-first-route tests now also install actual claims and inspect the durable binding record. Subsequent legitimate lookup/restart works.
- `observation_events_wait_for_storage_and_failure_never_releases_them`: actual installed credential refresh behind held/failed durability; staged record exists but no corresponding event escapes. Existing publication-after-persistence-failure test uses a real writer-set change and independent head comparison, not a now-no-op rename.
- All C1 peer-entry authority, C2 route-authority, F8 expired-history preservation, targeted admission, offline revocation and existing C3/C4 regressions ran in the full suite.
- Client tests install two already-authorized colliding identities in one Welcome, keep both full IDs/history regardless of order, reject ambiguous name addressing, retain status evidence; another test proves an unavailable group's refresh cannot starve a reachable group and reports failure.
- `session/identity_tests.rs`: real native device owner + non-owner + another device in existing chat/doc/table groups; non-owner device rename and remote identity rename; immediate hour-held observer warning with full ID; full members/status evidence; both native sessions/device manager stop, remote rename leaves offline leaves unchanged, owner takeover/resume updates the same fingerprints, observer restart preserves first names. The old non-owner studio rename test remains.
- Browser tests preserve phone -> pocket and add native rename across existing chat/doc/table leaves, open People form preservation, full-ID/name history, warning beyond eight-second toast lifetime, real held/aborted binding-record transactions with **both accessors pending/rejected**, explicit recovery retaining first bindings, reload/tab takeover, case-insensitive collision/disambiguation/ambiguous addressing, and persistent People evidence. No unhandled browser errors in the final run.

### Negative controls (all restored, then positive suites rerun)

Each command selected and executed exactly one real test, exited 101 with an assertion failure, not a build error or zero-test result:

| Temporary regression | Detector / observed failure | Log under `target/private/` |
|---|---|---|
| Inject `name` into signed public body serialization | Raw decrypted key set contains unexpected `name` | `identity-negative-public-leak.log` |
| Bypass certificate signature checking in directory authorization | Mutated unsigned name redeems an identity-targeted invite | `identity-negative-unsigned-claim.log` |
| Bypass node outbox durability wait | `observation escaped held storage` | `identity-negative-early-output.log` |
| Disable existing-leaf recertification commits | Existing client device rename cannot reach its peer; bounded polling assertion fails | `identity-negative-no-leaf-refresh.log` |

The final native suite reran these positive tests after restoration. Browser storage tests ran positively; there was not a separate wasm accessor-bypass mutation run.

### Failures found and corrected during iteration

- Missing test temporary directories and obsolete successful `unknown` assertions: fixed fixture setup/expected new standing.
- Unchanged-certificate refresh unnecessarily waited for catch-up, waking a loss-recovery test with a timeout: added preflight no-op check, retaining transactional recheck. The original loss test and entire workspace then passed.
- New Heard invalidation on removal erased the group's display title before Removed: emit it only for continuing memberships; Removed handles deletion. The original Team removal wording assertion remains.
- A background identity duty overtaken by leaving its group now terminates as obsolete, while failures for extant groups remain warnings.
- Full-ID copy controls exposed tests selecting the first arbitrary copy control instead of the invite; selectors now require `.invite .copy code`. Browser send ambiguity test uses the actual `send` API, not a nonexistent request variant. Asynchronous description access exposed a navigation timing assumption; the test waits for the selected Notes heading before clicking Settings.
- Old C4 tests intentionally read in-memory descriptions during failed storage. That is forbidden by the adopted accessor contract: they now assert rejection, use the sender's genuine attachment link, and still assert the actual intervening messages/file bytes after recovery/reload (including with the peer offline). No failed durability assertion was removed to make a pass. Two existing recovery-race tests allow 1s for an incoming peer mutation; they still require dirty-retry refusal and verify all data after reload.

## Merge boundaries and remaining gates

- **Core:** apply only the `Certificate` import, `Change.certificate`, installed-credential construction/preflight, and narrow credential rule to the epoch worker's already guarded/sealed `Group::commit`. Keep its savepoint, sealing/size checks, exact package binding and identity-service-key restriction. Do not replace its whole commit implementation with this pre-epoch one.
- **Node:** small hooks in `State::add_group`, accepted `reading::apply`, authoritative `logs::replayed`, startup binding loading, and identity API publication/recertification. Move them to the worker's final accepted/install transaction boundaries, preserving rollback of staged state and its durable outbox. No opened-but-unjudged observation. Keep the removal invalidation distinction. `logs.rs` otherwise retains the C2 lookup path; no old log/history/runtime module was copied over epoch work.
- **Directory service addressing:** this tree uses the baseline capability/head API. Parent must retain the worker's `C = public::address(ID)` versus authenticated `D = head::reference(S,C)` routing. Directory capabilities do not rotate with private groups. Do not change membership/service/head schemas on this patch's behalf.
- **Cutover:** parent owns coordinated ALPN/group/invite/home/browser switches. v1 domain/body/certificate checks are tested here; a complete published-0.15 versus final-0.16 namespace/store matrix is **not** proven by this baseline. No compatibility shim or old-data deletion was introduced.
- **Frontend:** this baseline serves the browser from its backend. Merge only identity types/UI/accessor changes onto the parent's separately validated origin-separated frontend; no origin/default/build/deployment changes here.
- **Still to run after epoch merge:** actual epoch-zero/Welcome/commit envelope decryption/privacy negatives and exporter rotation, a refresh racing removal under the sealed epoch state machine, and epoch persistence/uncertain-append recovery around these hooks. The real-MLS competing-commit refresh test here is not a substitute.
- **Additional proposed cases not separately implemented:** a malicious *authoritative* service withholding an authentic old prefix from a fresh network reader (the authentic stale-prefix authorization limit is characterized in the public/C2 fixtures, not a new end-to-end withholding server); browser-only malformed-certificate injection; forced browser refresh network failure followed specifically by the ten-second successful retry; and an identity-specific lost-public-append-reply maintenance test. The browser storage-failure/reload flow and native unavailable-group warning are tested, but are not claimed as those cases.

## Deliberate tradeoffs

Authorization is only as fresh as the authenticated directory view held here. A fresh reader can accept an authentic stale prefix; retained checkpoints resist rollback, but observations add no freshness or privilege. Directory-ID holders retain key/revocation visibility; service/head timing and traffic remain visible. Members may retain/share private claims; no anonymity or global newest-name order is promised. Offline leaves keep old valid labels until resumed and refreshed. Observations are per saved session/profile, not home/account-wide contacts; first bindings never expire automatically. Independent verification remains the operator's separate act. Binding-history exhaustion must fail storage, not evict/re-pin; broader malicious-authorized-peer quotas remain outside this change.

# Published native compatibility (Linux x64)

`compatibility.py` resolves authoritative npm CLI **and** platform metadata, downloads exact packages with `npm pack --ignore-scripts` (no install/scripts), verifies SHA-512 integrity before safe extraction, checks package/platform/version and the executable's version, and preserves the entire adjacent plugin layout. It records metadata bytes/digests, tarball URLs/integrity/SHA-256, package trees and binary SHA-256 in `baselines.json`. The runner verifies them again. No PATH, npx, debug-tree, rebuilt-old-source or error-based fallback exists.

Python 3.12+, npm/Node and openssl must already be available. Native processes use isolated HOME/XDG directories, explicit binary/session/home/local relay/membership/CA, and no inherited application/proxy/plugin configuration. Temporary self-signed localhost certificates are generated, never production keys. Commands/events/service startup have deadlines; the work deadline leaves three minutes within the 20-minute CI bound for cleanup. Linux process groups plus subreaping clean up listeners, services and plugins, including failed constructors. `e2e.py` shares the bounded process/listener primitives.

## Gate

Build the candidate normally, with both plugins adjacent, and the separate direct-ALPN fixture:

```
cargo build -p letmeknow -p lmk-kinds --bins --example compatibility_alpn
python3 test/compatibility_test.py
python3 test/compatibility.py resolve --candidate-version X.Y.Z --out /absolute/artifacts/baselines.json
python3 test/compatibility.py old-writer --baselines /absolute/artifacts/baselines.json
python3 test/compatibility.py run --bin /absolute/target/debug/letmeknow --alpn-probe /absolute/target/debug/examples/compatibility_alpn --baselines /absolute/artifacts/baselines.json
```

`X.Y.Z` must be the actual Cargo/binary version; it is not an executable version override. CI supplies Cargo's version; release uses its tag and exact release executable. Both retain artifacts even on failure. The separate `old-writer` command explicitly runs `cargo test -p lmk-membership --test old_writer -- --ignored` with `LMK_0_15_BIN` set to the verified manifest path. Ordinary workspace tests ignore this regression. Its test target is supplied by the membership integration, not reimplemented here.

`compatibility-contract.json` declares candidate 0.16, previous 0.15 **incompatible**, explicit new-service initialization, default-home names and ALPNs. It intentionally fails on the pre-integration Cargo 0.15.1 tree. `--contract` on resolve accepts a deliberately reviewed different contract: a future compatible minor sets `previous_policy: compatible`, not an automatic reset (and can explicitly set `old_writer_minor: null` when the separate 0.15 service-writer fixture is no longer applicable). Namespace/ALPN changes are not inferred from Cargo's version. Protocol unknown-field/shared-record/revision and wrong-group-protocol unit tests remain part of ordinary workspace tests; native success is not proof of those fixtures.

Selection uses numeric stable versions, excluding prereleases and ignoring dist-tags. The highest same-minor release is selected **including equality with Cargo**. Previous means the highest stable release in the newest lower major/minor, which must match the declared previous minor. A first X.Y.0 can record `absent-first-release` only after both metadata responses succeeded; candidate/candidate and previous-minor coverage remain mandatory. A patch without a same-minor baseline fails. HTTP errors/404, timeout, malformed metadata, missing integrity, partial platform publication, corrupt extraction and wrong binary versions fail, never become absence.

## Cases and evidence

Every positive pairing runs both creator/version orders:

- Chat messages, replies, committed IDs/global positions and attachments both ways, checking decrypted/fetched bytes. Pending sends must produce their actual committed ID/position before comparison.
- Doc initial text, edits and file links both ways, exact convergence and restart/offline catchup.
- Rename settings and Add/remove/leave from both versions in chat and doc; continued use across commits. Wait for admitted plugin snapshots before removal, not a timing sleep.
- The **same handle and home**, A→B→A and B→A→B, retaining fingerprints/device/identity, groups, docs and file bytes.
- Distinct sessions sharing a home with each device-owner order, follower identity operations, SIGKILL owner takeover, exactly one kernel device-lock owner, unchanged device identity, resumed chat/doc and exact per-handle multi-device group presence. A second remote session makes remote start/stop/takeover observable in both directions.
- Targeted unsupported-doc refusal, unchanged real executable copied without its plugin, no PATH plugin discovery; no membership/epoch change or warning to an unrelated member of the same doc.

Previous-incompatible cases populate real old/new homes using their own services, then test reciprocal refused opens with exact complete tree equality (paths/types/modes/bytes, including unknown sentinels, native blobs and plugin state); own-version reopening; both directions of command/Stop and group/device invite rejection; default-home isolation in both boot orders; and cross-service refusal plus direct TLS ALPN acceptance/rejection controls against actual service/application endpoints. A cross-service command timeout is recorded as **uncertain**, never as rejection evidence or a skip: the case still requires every preservation assertion and both directions of direct ALPN controls. The direct fixture requires TLS `no_application_protocol` (0x178), not just any connection failure.

Raw home snapshots cover every file, type, mode and modification/change timestamp (not access time). Live snapshots retain raw inventories but compare every SQLite table/schema/value (including duplicate rows) and non-SQLite file byte, rather than WAL/checkpoint representation. Session `groups.json` is compared as a complete logical group index. Cross-service calls use separately populated anonymous chat/doc/blob clients, keeping unrelated identity-presence traffic from being confused with data loss; both original identity homes also remain quiescent and byte-checked. Uncertain attempts can add records and extend `node/groups`, `node/logs` and session group indexes, never delete previous entries, duplicate IDs or rewrite other pre-existing values. No cleanup erases pending attempts to make comparisons pass. Unexplained changes fail the gate, with before/after evidence retained for integration review.

`run/results.json`, process logs/events, command results, candidate/ALPN-fixture identity and snapshots are inspectable. Provenance also retains the exact Python runner sources and invocation; restart events append rather than overwrite earlier observations. Fail-fast stops at a failed case; absence of later results is **not** a pass. The intended 0.16 matrix requires the separately integrated native-home/IPC and epoch protocol changes; this harness does not implement or waive them. Parent owns full browser database/store/lock/channel preservation. No 0.15 frontend archive was published; neither this runner nor source-behavior browser fixtures are a published-browser baseline.

## Optional published positive control

```
python3 test/compatibility.py positive-control --out /absolute/new-control-directory
```

This downloads and runs actual 0.15.0/0.15.1, not a candidate 0.16. `--artifacts /absolute/control-manifest.json` explicitly reuses verified control packages for harness iteration; CI resolve never falls back to a cache. Published 0.15.0 predates `ready.bin`: only its verified control digest permits that field's absence. Every command/restart still uses its fixed manifest executable. Both older array-form and newer object-form `npm pack --json` reports are accepted; package identity and integrity checks are identical.

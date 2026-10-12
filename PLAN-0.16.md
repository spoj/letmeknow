# 0.16: trust the published client, not the service

Implementation plan, not a description of the released software. Based on the adversarial review of `5f714da` and the owner's subsequent decisions.

## Contract

- Clean break from 0.15 is acceptable, including new groups and identities. No preserving migration or mixed-version activation path.
- Clients trust the project's GitHub/npm distribution. The backend must neither supply their code nor authorize deletion of their local state.
- The entire static frontend, including HTML and service worker, comes from GitHub Pages. Hosts: `letmeknow.dev` for the frontend, `relay.letmeknow.dev` for membership/relay. DNS and release administration remain trusted.
- New group logs are independently named and sealed from epoch zero, rotating on every MLS commit. Log capabilities and sealing keys use separate exporters.
- Modest size-bucket padding. Counts, coarse activity and residual size-class inference remain visible; no cover traffic or anonymity claim.
- Public stats contain completed-day site-wide totals, not per-log rows, current online counts or live traffic.
- Identity directories retain minimum authorization/revocation and authenticated service-routing information. Unnecessary descriptive metadata stays private; identity-ID holders keep directory read access.
- Disposable service for now: no remote replicas or automated disaster recovery. Catastrophic loss may require explicit service/group recreation, never silent signed-history rollback or client erasure. Normal restarts still require durable storage.
- The owner authorized release and deployment after passing review/tests, confirmed the frontend/backend hosts, and explicitly approved deleting the old server database and Litestream/Spaces backups at cutover. The owner has created the relay DNS records. Do not erase client-local data or waive a security/test blocker. The frontend DNS switch still needs verified administrative access.

## Known limit: directory freshness

Authentic directory history is not proof of the latest history. The authoritative service can withhold a revocation from a fresh reader. Persisted checkpoints prevent rollback behind known state; peer evidence can reveal omitted or conflicting history when it arrives. Instant revocation for isolated/offline readers is not promised.

Expiring device authorizations renewed by a separate owner-controlled authority would bound stale acceptance, at a renewal/availability cost. That is a separate identity-design decision, not implicit approval from the metadata or disposable-service choices.

## Work

- [x] #68: warn about secrets and deletion in Docs and Tables.
- [x] #70: develop the next release on main, with short-lived change branches.
- [ ] #64: compatibility matrix and published baselines, including first-minor-release handling.
- [x] F8: preserve local state when the service refuses history as expired.
- [x] C1: bind peer entries to the destination log and its service authority.
- [x] C2: authenticate identity-directory authority before caching a claimant's route or accepting verification.
- [ ] C3: power-loss-durable native/service commits before external effects.
- [ ] C4: retain failed browser writes and withhold dependent output until durable.
- [x] F26: bind pi-letmeknow sessions to immutable full-version/platform installations (`pi-letmeknow` commit `757e27a`; typecheck and 12 focused tests pass).
- [ ] #72: specify cross-epoch transition witnesses, ancestry comparison, global bases and peer-only catch-up; then implement sealed/padded epoch logs.
- [ ] #73/#74: fresh incompatible store with hashed capabilities and day-based expiry metadata; reject old writers and unsafe reuse.
- [ ] F15/F21/F32: audit diagnostic capability/metadata leaks and bound append/read/subscription/storage work.
- [ ] #67: bounded health checks and completed-day public totals without blocking appends on scans.
- [ ] F6/F22: implementation staged: whole static frontend/Pages artifacts, compiled backend public-key configuration, independent HTTPS/WSS E2E and trusted-origin invite presentation. Release remains blocked on the fresh public key, native-default coordination, workflow/environment review and actual operator cutover; provenance does not prove harmlessness or reproducibility.
- [ ] F27: minimize the public identity-directory payload.
- [ ] #55: first-seen identity bindings and change warnings; distinguish observations from operator verification.
- [ ] #69/#71: automated pins, gated artifact rollout, bounded newer-minor notice visible through pi-letmeknow.
- [ ] Replication/restore provisioning removed from deployment; explicit loss -> fresh authority/groups documented. Service-loss/refusal protocol tests and operator-reviewed removal of actual old state/replicas remain separate gates.
- [ ] Full checks and an operator-reviewed cutover inventory covering old processes, storage, replicas, service workers and diagnostic histories.

Update code, README.md, SKILL.md, AGENTS.md, deploy/README.md and relevant tests together. Do not retain claims of harmless publication, legacy compatibility or recoverability that this contract rejects.

## Acceptance matrix

| Boundary | Expected result |
|---|---|
| 0.15 client and 0.16 service/group | Explicit incompatibility; no writes to new state. |
| 0.15 process/tab and 0.16 local storage | Separate namespaces or enforced refusal, never concurrent interpretation of incompatible state. |
| Old service executable and new store | Refusal before reading, expiring or appending under old semantics. |
| Supported patches of the same minor | Group, identity and local-state coexistence according to the supported contract. |
| First release of a minor | Test available published baselines; never fetch its own unpublished npm version. |
| Service refusal/loss/fork | Preserve client data and evidence; report unavailable/conflicting history. |
| Persistence failure | No dependent acknowledgement, Welcome or peer output; recovery cannot silently omit a failed write batch. |

## #72 design gate

The adopted implementation contract is [EPOCH-LOGS.md](EPOCH-LOGS.md), refined by separate cryptographic and simplicity reviews. Its transition witness binds the predecessor commit, terminal local position, cumulative base/history, and covering signed-chain evidence. Keep enough ancestry to compare histories across multiple moves even when current heads match. Do not reveal old capabilities to joiners or new ones to removed members.

Test competing commits; the same commit after different prefixes; a page with an ignored post-transition suffix; admission at a nonzero base; lost append/Welcome replies and retry through another admitter; two-move peer-only catch-up without the service, including restart; sends racing a move; self-update after capability disclosure; removed members holding all old secrets; doc/table cursors; and failed persistence.

## Review evidence

The review produced 34 held concerns and four refuted findings. Completed reviews used GPT-6 Astra only, not cross-model validation. Findings are code/design review results, not a substitute for regression tests.

Full original evidence and owner-updated synthesis: `/tmp/workflow-37gM/`. This checklist preserves the adopted decisions independently of those temporary review artifacts.

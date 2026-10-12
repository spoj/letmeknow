# 0.16: trust the published client, not the service

Implementation plan, not a description of the released software. Based on the adversarial review of `5f714da` and the owner's subsequent decisions.

## Contract

- Clean break from 0.15 is acceptable, including new groups and identities. No preserving migration or mixed-version activation path.
- Clients trust the project's GitHub/npm distribution. The backend must neither supply their code nor authorize deletion of their local state.
- The entire static frontend, including HTML and service worker, comes from GitHub Pages. Proposed hosts: `letmeknow.dev` for the frontend, `relay.letmeknow.dev` for membership/relay. DNS and release administration remain trusted.
- New group logs are independently named and sealed from epoch zero, rotating on every MLS commit. Log capabilities and sealing keys use separate exporters.
- Modest size-bucket padding. Counts, coarse activity and residual size-class inference remain visible; no cover traffic or anonymity claim.
- Public stats contain completed-day site-wide totals, not per-log rows, current online counts or live traffic.
- Identity directories retain minimum authorization/revocation and authenticated service-routing information. Unnecessary descriptive metadata stays private; identity-ID holders keep directory read access.
- Disposable service for now: no remote replicas or automated disaster recovery. Catastrophic loss may require explicit service/group recreation, never silent signed-history rollback or client erasure. Normal restarts still require durable storage.
- No production reset, DNS change, deletion of backups or release is authorized by this implementation checklist alone.

## Work

- [x] #68: warn about secrets and deletion in Docs and Tables.
- [x] #70: develop the next release on main, with short-lived change branches.
- [ ] #64: compatibility matrix and published baselines, including first-minor-release handling.
- [ ] F8: preserve local state when the service refuses history as expired.
- [ ] C1: bind peer entries to the destination log and its service authority.
- [ ] C2: authenticate identity-directory authority before caching a claimant's route or accepting verification.
- [ ] C3: power-loss-durable native/service commits before external effects.
- [ ] C4: retain failed browser writes and withhold dependent output until durable.
- [ ] F26: bind pi-letmeknow sessions to immutable full-version/platform installations.
- [ ] #72: specify cross-epoch transition witnesses, ancestry comparison, global bases and peer-only catch-up; then implement sealed/padded epoch logs.
- [ ] #73/#74: fresh incompatible store with hashed capabilities and day-based expiry metadata; reject old writers and unsafe reuse.
- [ ] F15/F21/F32: audit diagnostic capability/metadata leaks and bound append/read/subscription/storage work.
- [ ] #67: bounded health checks and completed-day public totals without blocking appends on scans.
- [ ] F6/F22: GitHub-built whole frontend, independent backend configuration, trusted invite presentation and provenance documentation.
- [ ] F27: minimize the public identity-directory payload.
- [ ] #55: first-seen identity bindings and change warnings; distinguish observations from operator verification.
- [ ] #69/#71: automated pins, gated artifact rollout, bounded newer-minor notice visible through pi-letmeknow.
- [ ] Remove replication/restore provisioning; document and test explicit service-loss behavior.
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

Specify the transition witness before implementation. It binds the predecessor commit, terminal local position, cumulative base/history, and covering signed-chain evidence. Keep enough ancestry to compare histories across multiple moves even when current heads match. Do not reveal old capabilities to joiners or new ones to removed members.

Test competing commits; the same commit after different prefixes; a page with an ignored post-transition suffix; admission at a nonzero base; lost append/Welcome replies and retry through another admitter; two-move peer-only catch-up without the service, including restart; sends racing a move; self-update after capability disclosure; removed members holding all old secrets; doc/table cursors; and failed persistence.

## Review evidence

The review produced 34 held concerns and four refuted findings. Completed reviews used GPT-6 Astra only, not cross-model validation. Findings are code/design review results, not a substitute for regression tests.

Full original evidence and owner-updated synthesis: `/tmp/workflow-37gM/`. This checklist preserves the adopted decisions independently of those temporary review artifacts.

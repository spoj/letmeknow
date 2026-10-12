# 0.16 epoch logs

Implementation contract for PLAN-0.16.md, not a claim that implementation/tests are complete. Protect honest members from the log operator; do not promise delivery, global freshness, automatic fork repair, or protection from a colluding authorized member.

## Cryptography and addressing

For group G (16 bytes), epoch e (u64 big-endian), and the authenticated membership-service verification key S (32 bytes):

```
ctx = G || e || S
C = MLS-Exporter("letmeknow epoch log address v1", ctx, 32)
K = MLS-Exporter("letmeknow epoch log sealing v1", ctx, 32)
D = SHA256("letmeknow log reference v1\0" || S || C)
h0 = SHA256("letmeknow log v2\0" || S || D)
di = SHA256(exact_wire_entry_i)
hi = SHA256(h_(i-1) || di)
```

Requests use the bearer capability C. Storage and heads use D. There is no service lookup-by-D bypass; supplying D as a capability hashes it again. Public identity-directory request capabilities stay derivable from identity IDs, but use the same reference/head convention. A head contains D, length, hash, time_ms, signature. Its signed bytes are `"letmeknow head v2\0" || S || D || length:u64 || hash || time_ms:u64`. An empty local chain has h0 and no service signature; it is not a fabricated signed head.

Private groups are protected at creation. Every accepted MLS commit, including update/rename/settings commits, closes the source epoch log. Leave requests alone do not. Changing an identity group's service signing authority is forbidden: it would reinterpret an unchanged public identity elsewhere. A private chat's authorized service change binds both old and new authorities; route changes are not authority changes.

Seal the complete existing encoded Entry, retaining its inner author signature and message-ID MAC:

```
wire = 0x01 || random_nonce[24] || XChaCha20Poly1305(K, nonce, plaintext, aad)
plaintext = inner_length:u32 || encoded_inner_entry || zero_padding
aad = "letmeknow epoch envelope v1\0" || G || e || S || D || bucket:u32
bucket = max(1024, next_power_of_two(inner_length + 45))
```

Total binary length equals bucket, at most 1 MiB; maximum inner length is 1,048,531 bytes. Reject unsupported version/bucket, invalid AEAD, impossible inner length or nonzero padding. Reject oversize staged commits without changing persistent or in-memory MLS/pending state. Nonces are random, not shared counters/positions. A retry uses persisted identical wire bytes. Store both pending inner Entry and sealed wire: MLS own-pending recognition uses inner equality even if that same signed inner Entry was re-enveloped with another nonce. The actually accepted wire digest determines its physical history.

The 1-KiB floor costs about 16x for a formerly 65-byte log marker, not for the separate message payload. It obscures some type/size distinctions, not all; counts, ordering, traffic and larger size classes remain visible. Measure real Add/update/remove sizes in tests.

## Positions and accepted history

Keep group IDs and all application/plugin cursors global. A physical position p belongs to global B+p. Invalid entries before the first valid commit count; an ignored suffix after it does not. Use checked arithmetic.

For the first accepted commit at local cut c, a fixed-size canonical transition W contains, in order:

```
"letmeknow transition v1\0", G,
source_epoch:u64, source_S[32], source_D[32],
base:u64, parent_history[32], cut:u64, cut_hash[32],
terminal_wire_digest[32], inner_entry_digest[32],
successor_S[32], successor_D[32]
```

`inner_entry_digest` hashes the entire opened encoded Entry, including the signed commit/Welcome wrapper. `next_epoch=e+1`, `next_base=B+c`, `next_history=SHA256(W)` are derived and checked, not independent fields. Genesis is `SHA256("letmeknow history genesis v1\0" || G || 0:u64 || S0 || D0 || 0:u64)`. Links between transitions must match epoch, authority/reference, base and parent hash. Source/destination references already commit to their MLS epoch exporters; no separate epoch-authenticator commitment is needed.

Cover length, time, observer signatures and ignored suffix are excluded from W. Different accepted prefixes produce different cumulative roots even when the commit, successor MLS state and latest head match. Multiple equal later moves cannot erase an earlier difference.

Keep the substantive crash boundary as an optional durable cut in active metadata, not duplicated Open/Closing/Closed records. On discovering c in a fully verified page, persist the cut and necessary raw prefix/proof, then stop source subscription/reads. Until merge, current MLS still derives K, so the fixed commit can be reopened after restart. Continue the existing wait/recovery policy for older *application-message* ciphertexts independently of the outer exporter.

In one transaction: capture needed opened/counting/admission data; merge the accepted commit; save W, proof and caches; retire the source; delete old capability/exporter copies; create the successor at h0; advance B/R/active mapping. Only then release effects through C3/C4. A removed observer does not invent successor exports; retain its source evidence outside live-group deletion. A late source response cannot alter a replacement attempt or reopen a retired log.

## Proofs, storage and peer authorization

A signed head at N >= c needs a complete verified path to N, including ignored suffix digests. Keep the longest compatible coverage accepted; a later shorter proof must not discard it. Prefix hashes or `{hash_at_cut, latest_head}` alone are not extension proofs. Unequal-length paths may be compatible; malformed bytes reaching no signed head are not service equivocation. Two valid same-length heads with different hashes already prove equivocation. More generally, a signed shorter head contradicts a different hash at that position in an independently verified longer path; no preimages for the shorter branch are needed. Always bind the common S/D to the local group first.

Retain observer-held complete digest evidence for the lifetime of the local group/evidence record. Store packed immutable bounded digest chunks and small head/segment records, not growing JSON vectors copied on every append. Historical chunks load on demand. Distinguish verified digest coverage, stored raw prefix and globally applied position. Keep the active epoch's complete raw replay prefix independently of application expiry, then retain it for H after local closure, extended by admission pins below; never apply/serve post-cut raw suffix as group history. Keep old reader endpoints only with raw replay. Current C/K derive from current MLS; do not archive old exporters/keys.

Use two bounded peer jobs: hash-linked transition/history navigation, and segment transfer (digests, or authorized raw entries plus necessary proof). Service gap pages must be fully verified/retained before any entry reaches apply; individual notices from an unverified longer page are insufficient. Peer replay can verify digests first, then stream raw bytes matching them, avoiding an unbounded raw staging buffer. Initialize successors locally, without a service RPC or arbitrary latest-head anchor. Receiver-at-L0/holder-at-L2 must progressively replay both moves with the service off, including restart.

Normal payloads/state/files require current authorization plus position-appropriate compatible ancestry. Sealed historical replay requires the requester's authenticated endpoint in that segment's saved reader list; a removed reader may fetch its removal cut, not its successor. Evidence-only records disclose commitments/linkage/counts, not C/K, plaintext, Welcome or file keys. Recheck the actual category/authorization as queued frames leave.

Accept proof data only for a requested destination/target/cursor. Verify expected authority/reference and signature first. One in-flight target per authenticated endpoint, accounting across its streams/replacement connections; contiguous pages; checked cursors; bounded rows and at most 4 MiB encoded per response. The 8-MiB per-endpoint and 32-MiB global limits bound resident unverified buffers, NOT total proof length. Stream into separately quota-accounted untrusted temporary chunks. Reserve the target's total temporary/promotion budget before accepting it; supported temporary capacity must accommodate the implementation's supported accepted archives. Never allocate a whole vector from a claimed length. Verify the final signed endpoint before promotion/application; bad proof, cancellation or restart may discard temporary chunks without touching accepted records. Accepted streaming must not rewrite earlier chunks.

Reserve memory/temp/work capacity for locally anchored foreground replay. Background/speculative reservations are reclaimable; fairly schedule eligible foreground jobs and bound target lifetime/total work, not just idle time. Aggregate accounting survives endpoint reconnection. Budget exhaustion cancels/defers candidates, never consumes accepted-history reserves or sets conflict. This is bounded-work isolation, not unlimited availability under Sybil/network flooding. A background auditor must reserve its *eventual retention* allowance too: do not automatically chase/retain arbitrarily longer compatible post-cut suffixes or let them consume required foreground-evidence reserves. Deferring an optional audit is incomplete accountability, not a fork. Preserve previously accepted covers and actual established contradictions.

Define separate total temporary, accepted-evidence and raw-storage quotas before implementation acceptance, including foreground reserves. Real storage exhaustion reports unavailability with state preserved; never prune required evidence/replay while claiming the same guarantee. Test a sole-final-head proof just over 8 MiB with service off and adequate total quota, bounded resident memory, wrong final hash, interrupted download, and later smaller target. Also test stalled/drip-fed/reconnecting background endpoints exhausting their allowance while honest foreground replay still completes, and increasing valid closed-log suffixes that cannot consume its reserves.

A peer label or self-consistent foreign history does not associate a log with G. Association comes from local creation, accepted replay, or the authenticated admission checkpoint. Follow ancestor bodies backward from a pinned hash; divergent candidate branches can demonstrate a contradiction only at a locally associated source. An unproved root mismatch excludes that peer from synchronization/state exchange, not the whole group. Persist a group conflict only on verified incompatible service-signed paths for that group. Preserve local data; no automatic branch choice.

Ordinary `Synced` means agreement on accepted lineage and current applied frontier: equal authenticated epoch/destination/B/R, equal verified current head (or both local-empty), application through it, no proven conflict. It does not mean a pre-join forensic archive has been downloaded or that the service is globally fresh. A joiner may synchronize from its signed checkpoint. Fetch missing ancestors/proofs on demand, never replace that checkpoint with a claim.

Preserve the conservative physical-equivocation policy separately: bounded background descriptor/proof comparisons of locally retained old segments can expose ignored-suffix forks even when R matches. They do not gate ordinary `Synced`; no inventory-hash field is needed. Compatible covers are benign. A proven suffix-only fork stops protocol progress and is labelled as physical equivocation after the accepted cut, not as changed application contents. Missing pre-join archives mean incomplete historical accountability, not a proven fork.

## Admission and uncertain operations

Use the native RFC/OpenMLS KeyPackageRef consistently, not a custom bare SHA-256 digest or the outer MlsMessage hash. Cache/compare the exact validated package reference, not just its signing/leaf keys. Ensure Welcome processing consumed the intended saved package, including cases with multiple outstanding packages and identical leaf/signing keys but different init keys.

For accepted Adds only, continuing observers sign a checkpoint:

```
"letmeknow admission checkpoint v1\0" || SHA256(W) || SHA256(Welcome)
    || KeyPackageRef[32] || added_signature_key[32]
```

The response contains W, Welcome, signer key and signature. Verify the signer's actual key in the validated Welcome roster, own requested-package binding, and derived group/epoch/service/reference. Preserve the original invite-named authenticated peer/channel relationship: an arbitrary valid Welcome for an attacker-created group is not admission authority. The member attests to pre-join semantics/base; the service does not. No signatures on non-Add transitions or variable Add lists in every W are needed.

Start a provider savepoint before OpenMLS Welcome processing consumes keys. Invalid checkpoint/Welcome restores all provider state and registers no live group. Successful installation atomically pins MLS+B/R and the empty successor; restart does not consume the Welcome twice. Pre-join evidence need not accompany admission; keep the authenticated checkpoint even when old forensic material is unavailable.

Every continuing observer saves accepted `(invite_hash, exact package ref)` recovery data and its original Welcome/checkpoint before output. Recovery lookup precedes live-invite lookup, expiry and used checks. An original named admitter that missed the Add must replay it; a later-joined member is not a recovery oracle. Keep recovery caches while the accepted leaf remains unchanged, even past invite expiry/H. Install these caches and pins atomically before exporter loss or expiry decisions. Derive the earliest required successor epoch from durable caches before restart expiry, and pin raw successor prefixes/readership until that particular leaf's update/removal; another leaf's change releases nothing. This deliberately retains the conservative unbounded-time recovery promise: an unchanged offline leaf can consume storage beyond H. Quotas stop progress rather than silently drop that promise. No protocol for proving Welcome receipt is added.

Uncertain refusal is not non-inclusion, for messages or commits. Preserve exact pending bytes, payloads and Joining keys after a possibly accepted attempt. Capture `(epoch,S,D,wire_digest)` per asynchronous attempt; old success/refusal/transport callbacks cannot mutate a new attempt. Reconcile accepted pre-cut entries versus ignored post-cut ones; rebuild losing intents only after rule rechecking. Keep counted-ID dedup through the whole epoch even if H expires. Explicit cancellation/deletion may abandon recovery; automatic service-error cleanup may not.

## Acceptance

Run real-MLS and integrated regressions for all PLAN-0.16.md design-gate cases. Include foreign signed histories/garbage proofs that cannot freeze G; different-length and same-length prefixes followed by multiple identical moves; unequal covers and suffix-only forks; another admitter after lost Welcome and expiry; exact package/ref and savepoint rollback; re-enveloped own pending commits; uncertain message refusal; stale callbacks; historical reader send-time gates; bounded proof/storage work; preserved doc/table/global cursors; and C3/C4 failures around every transition/admission boundary. The design reviews/model checks are not implementation validation.

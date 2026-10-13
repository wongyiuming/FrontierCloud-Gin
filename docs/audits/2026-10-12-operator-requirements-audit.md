# Operator requirements 1–4 audit

Audit date: 2026-10-12. Branch: `dev`; base HEAD:
`0fb4a9a9b9717c2f7892c3cb63465633c62ee7af`. Implementation remains uncommitted.
The logs cover identified working snapshots and private fixture image IDs.
They are **not** exact-source CI for a new commit or public release proof.
Final whole-source integration is recorded in the
[completion audit](2026-10-13-completion-audit.md). This document retains the
original evidence snapshot and its verification boundaries.

| Requirement | Implementation and evidence | Boundary |
| --- | --- | --- |
| Published-image installation without build tools | `scripts/get-fc.sh` extracts the prebuilt operator bundle from one immutable public image without starting it. Storage uses the same `fc install storage` entrypoint. Runtime images include Compose, examples, manuals and `fc`. | No new release was published. Public availability requires the reviewed publication workflow; private fixture evidence is not public release proof. |
| Simple first selection, immutable later operations | Install discovers latest once, binds reviewed main/exact-source CI, and resolves all FrontierCloud components against that same revision. Receipt/image locks retain platform, config/image digests, schema, configuration and mount identity. Restart uses `--no-build --pull never`. | The per-installation immutable component lock is the recorded manifest. There is no additional independent release-manifest digest field or new protocol. Configuration hash is not described as an image digest. |
| Distinct image failures | Registry proof and Docker classification distinguish missing image, denied access, platform, integrity and network errors. Install now preserves the safe category through failed pulls. | [Race evidence](2026-10-12-operator-pull-diagnostics.txt) covers actual subprocess stderr redaction and Install propagation, and rejects initialization/build after failure. |
| Thin CLI and readonly doctor | `cmd/fc` covers the requested operations. Doctor inventories Docker/Compose, architecture, DNS, ports, mounts, free space, declared state and configuration without data initialization, image pulls or write probes. Human and JSON reports use stable exits. | Public inbound reachability, runtime write permission and unsafe offline database inspection remain explicitly unverified. Local outbound access is never inbound proof. |
| Existing-state protection | `Deployment.Empty` rejects receipts, existing named/external volumes, nonempty writable mounts, retained default data roots and containers bound to the same working directory even after project renaming. Guards repeat after network work. | Separate installation acceptance owns native first-install tests. Environment changes are never treated as migration/takeover. |
| Useful private diagnostics | Status combines binding, expected services, readiness, certificates, schema/role, maintenance and relationship health. Diagnose uses bounded facts; logs allowlist fields and omit arbitrary messages/errors/URLs. | Playback remains an explicit unverified item in routine readonly status; recovery acceptance performs managed reads and HTTP Range. |
| Real backup consistency | Native offline leases plus stopped deployment writers cover capture. Cold SQLite includes WAL/SHM; MySQL uses a consistent logical dump and explicit external-writer attestation. Logical-idle checks reject incomplete resource/file transactions. Manifests retain classes, identity/version/schema, hashes/sizes, key references and missing peers. | Built-in business backups remain separate. Unknown mounts or missing peers cannot become complete cluster recovery points; MySQL data directories are never copied hot. |
| Confirmed restoration and truthful failures | Check is readonly; apply requires an absent target and exact original identity. Activation requires source-offline approval and validates native identity, schema and managed reads before opening. Failure now verifies all non-MySQL writers stopped and native closure, independently of caller cancellation. | [Fault/cancellation race evidence](2026-10-12-restore-failure-fence.txt) validates `failed_fence_unverified`, retained archives and rejected reopening when Docker cleanup cannot be confirmed. |
| Actual backup → restore → business validation | Actual [SQLite](2026-10-12-upgrade-6to7-sqlite.json) and [MySQL](2026-10-12-upgrade-6to7-mysql.json) runs cover upgrade, subsequent backup/restoration/opening, stable NodeID/media ID/priority and HTTP Range. | Publication proof is injected and clearly marked. Synthetic fixture source revisions are not exact-commit public provenance. |
| Complete coordinated recovery set | All listed local node leases are held together through capture. Omitted Storage is rejected; archive set IDs prevent mixing capture intervals. Preparation and activation cover the complete reciprocal graph; Master opens last. [Native two-node evidence](2026-10-12-recovery-set-native-final.json) verifies original keys/sealed credentials, media identity/Range and a second complete backup of restored nodes. | One local Docker engine. Cross-host writers need independent coordinated shutdown/validation; separate node archives cannot be advertised as one consistent set. Fixture pairing uses native stores after real startup and private static TLS material; it does not certify network pairing/reconnect or automatic CA issuance. |
| Approved upgrade ordering | Explicit target and digest-approved plan bind source identity/receipt and exact image proofs. Apply rechecks, pulls before disruption, freezes, creates/verifies recovery, prepares compatible schema and validates managed reads. Opening is separate approval. | Actual generation 6 → 7 succeeds for SQLite/MySQL. [Injected preparation failure](2026-10-12-upgrade-6to7-failure.json) preserves recovery and native closure without automatic rollback. Unknown transitions are rejected. |

## Evidence privacy

A scoped development-host scan compared 36 retained private fixture secret files
with 59 public native/upgrade reports. No raw matching fixture secret or
private-key PEM block occurred. Private fixture logs had no group/other permission
bits. The scan emitted counts and violations only. Source/recovery data and
volumes remain preserved; only named fixture containers and verified empty
project networks were removed.

## Remaining validation boundaries

- Parent integration must test the final stable whole-source snapshot. The latest
  diagnostic and failure-cleanup changes have operator/CLI race evidence, not a
  repeated full topology native run.
- Public bootstrap/release proof and public ACME reachability cannot be inferred
  from a private acceptance adapter. No publication was authorized.
- Cross-host orchestration, independent external MySQL writers and automatic
  rollback are outside the local-engine workflow. These limits are explicit.

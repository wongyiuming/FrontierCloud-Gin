# Storage architecture regression changes

Retirements are explicit feature removals, not substitutes for passing tests.
Cross-node release convergence (`internal/release/converge*`,
`manifest_converge*`, `manifest_control*`) and the cluster-release CLI are
removed because appliances have no updater. The two updater RPCs are removed
from the native route inventory and replaced by authenticated absence checks
in `internal/httpapi/nodes_admin_test.go` and storage route absence tests.
The real whole-fleet release fixture (`native_matrix_release_real_test.go`) and
the whole-manifest branch of `stack_real_test.go` are retired as that feature no
longer exists. Native five-node business acceptance remains, using one business
Master and four storage-only appliances. Master self-upgrade/handoff/rollback
remains a separate real Engine gate on both supported Master databases.

Replacement coverage:

- `internal/release/coordinator_test.go`: local Master-only authorization,
  no repository enumeration of storage, identity race, policy/busy/CI guards,
  exact historical rollback and offline local rollback.
- `internal/release/history_test.go`: bounded same-repository discovery,
  text-size limits, cache isolation and API backoff.
- `internal/config/storage_test.go`: SQLite/TLS/high-port constraints.
- `cmd/frontiercloud/storage_test.go`: stable identity, storage-only routes,
  no business dependencies, signed one-use package.
- `internal/store/business/backup_files_test.go`: file-backed payload,
  idempotency, interrupted receives, retention, partial reads and corruption.
- Existing updater health/Nginx failure restores and immutable runtime
  handoff tests remain. Historical local manifest compatibility tests now
  assert that no remote release command executes.

Count discovered, executed, passed and skipped separately in final release
evidence. External database, Redis, Engine, fleet and browser gates may be
skipped by a unit run; a green unit run alone does not certify a release.

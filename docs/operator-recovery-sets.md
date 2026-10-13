# Coordinated recovery sets

An individual deployment backup retains its original `complete_cluster: false`
and lists missing related-node state. Merely collecting several independently
created archives cannot establish a shared consistent recovery point.

`fc backup set-create` currently coordinates multiple explicit deployments on
**one local Linux Docker engine**. It is an opt-in offline operation. Supply the
entire reciprocal Master/Storage roster, including Backup-only nodes:

```sh
./fc backup set-create \
  --deployment /srv/master \
  --deployment /srv/storage-direct \
  --deployment /srv/storage-relay \
  --confirm-master-id EXACT_MASTER_NODE_ID \
  --freeze-all --output /private/new-recovery-set
```

MySQL requires `--confirm-external-writers-stopped`. The tool checks exact
NodeIDs and mutual active protocol-2 relationships before freezing anything.
Missing, duplicate, foreign and pending relationships block the operation.
It then freezes the Master first, stops every member's deployment writers, and
holds **all** native control/runtime leases simultaneously. Identity, schema,
transaction state and the complete relationship roster are checked again while
those leases remain held. Only then are member archives captured and the final
`recovery-set.json` published. All members remain offline afterward.

The set manifest records original versions, schema generations, roles, NodeIDs,
relationship projections, archive sizes and SHA-256 digests. Each archive also
contains the same random recovery-set ID. A hash-valid archive from another
capture interval cannot substitute for one of these members. Every member keeps
its own identity, signing and encryption recovery materials. Nothing copies a
source node's identity onto another existing node.

Unclassified volumes or bind mounts block complete-set publication. Partial
output and closed native fences are retained on failure; no recursive cleanup
or automatic reopening occurs. The common lease interval covers native writers
on this engine, not unrelated external MySQL writers. The explicit MySQL
confirmation remains necessary.

Verification and material extraction are separate:

```sh
./fc backup set-verify --file /private/new-recovery-set
./fc restore set-check --file /private/new-recovery-set \
  --sha256 APPROVED_SET_MANIFEST_SHA256 --target /private/restored-cluster
./fc restore set-apply --file /private/new-recovery-set \
  --sha256 APPROVED_SET_MANIFEST_SHA256 --confirm-master-id EXACT_MASTER_NODE_ID \
  --target /private/restored-cluster
```

Check is read-only and verifies every archive, graph, set identity and available
target capacity. Apply requires an absent target, stages all members under a
private parent, verifies the actual extracted bytes through the existing archive
reader, preserves native offline flags, and publishes the parent only after
every member is extracted. It does not start containers or claim restored
business validation. Each member has a `.fc-recovery-set.json` guard preventing
ordinary independent activation or opening.

The coordinator then prepares a new distinct Compose project for every member.
It checks all extracted files against their source archives before changing any
member receipt, including rejecting extra database/WAL files. Preparation holds
all native target leases simultaneously and starts no containers.

```sh
./fc restore set-prepare --file /private/new-recovery-set \
  --target /private/restored-cluster --project-prefix recovered \
  --sha256 APPROVED_SET_MANIFEST_SHA256 --confirm-master-id EXACT_MASTER_NODE_ID
./fc restore set-activate --target /private/restored-cluster \
  --sha256 APPROVED_SET_MANIFEST_SHA256 --confirm-master-id EXACT_MASTER_NODE_ID \
  --confirm-all-sources-offline
./fc restore set-open --target /private/restored-cluster \
  --sha256 APPROVED_SET_MANIFEST_SHA256 --confirm-master-id EXACT_MASTER_NODE_ID
```

Activation starts followers before the Master under public manual maintenance.
Every node must retain its own NodeID and schema generation, have no pending
native transactions, pass native managed-resource reads and health checks, and
retain the complete reciprocal protocol-2 relationship graph. Any activation
or opening failure refences every prepared member and retains all journals and
archives. Single-deployment activation also verifies the native gate and all
deployment writers after a failure, independently of caller cancellation. An unverified fence is reported explicitly; automatic rollback is not
attempted. Opening requires another whole-set check and opens the Master last.
Marker cleanup has a durable phase and can be retried with the same approval.

A recovered deployment can itself be backed up and recovered again. Its exact
runtime-secrets, certificate-state, published-certificate and Redis binds map to
the original state classes. Unmounted historical volume declarations are not
used as substitute state. An arbitrary bind with a familiar target name still
blocks completeness; the generated recovery path must also match. A second
recovery relocates those verified classes into another absent target and refuses
an already prepared target journal.

The isolated two-node SQLite Compose acceptance in
[`2026-10-12-recovery-set-native-final.json`](audits/2026-10-12-recovery-set-native-final.json)
exercises the entire reciprocal Master/Storage set, including rejecting an
omitted Storage before freezing. It completes real native startup, captures and
restores both nodes, independently decrypts each original identity and sealed
relationship credential, checks HTTP Range and the same managed media ID, and
creates and verifies a second complete backup set from the restored deployments.
All source and recovery material remains retained. Each Web is limited to one
CPU and 512 MiB without swap; five post-business Master CPU samples are below
the existing 20 percent gate. The driver is
`tests/operator_recovery_set_acceptance.py`; its opt-in native-store fixture
setup is unavailable in the production CLI.

That fixture uses a static private test certificate and native-store pairing
setup after actual startup. It does not certify public image delivery, automatic
certificate issuance, live pairing/reconnect, five-node topology, playlist or
browser behavior. Those remain separate acceptance evidence. A persisted graph
alone is never substituted for network or business verification.

Cross-host coordination and archive transport are outside this local-engine
entrypoint. Operators must coordinate stopped writers across all involved hosts
and validate their recovery procedure independently. Distinct hosts cannot be
passed as local paths or replaced by manually assembled timestamps; separate
single-node archives cannot be claimed as a complete consistent recovery set.

An interrupted `set-open` with a durable `opening` journal is retryable with the
same set checksum and MasterID. Members already opened are reconciled using
their retained restore journals; remaining followers open before the Master.
Failures during resumed set validation refence all prepared members. Review any
interrupted operation lock separately before retrying; locks are never stolen.

Repeat the same `set-prepare` after `preparing_fenced` interruption with the exact
source directory, set checksum, MasterID and project prefix. It rechecks all
original data/key material, allows only the recorded rewritten deployment
metadata, and reconciles each same-intent member checkpoint. Unknown extras,
changed resources, projects or receipts remain blocked. `set-activate` also
admits `activating_fenced`: already verified followers are reconciled and the
remaining members start behind maintenance, with Master last. Failures retain
the entire set and attempt to refence every prepared member.

Same-intent preparation recovery also admits retained regular atomic-write
siblings of the known mutable metadata files (`.next`/`.next-*`). It preserves
those files unchanged for inspection; links, unknown files and extra resource
material remain blocked.

Successful set capture reports member-specific `cleanup_warnings`, including
retained generated scratch locations. These operational warnings are separate
from archive integrity and complete-cluster proof; they must not hide private
plaintext scratch requiring cleanup.

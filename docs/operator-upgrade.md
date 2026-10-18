# Approved operator upgrades

`foc upgrade` is a short-lived host-side Compose operation. After the Compose
installer registers the deployment, run it from any host directory. It does not add an agent,
Docker socket access to Web, a business upgrade API, or a fleet rollout.

The deployment must already have an immutable `.fc-deployment.json` receipt,
its recorded project/mount/database/role selection, and a running native release
with `operator-status`. Keep the installed deployment's Compose files and
configuration. This entry
updates component images only. Configuration changes require their own reviewed
procedure; an environment edit is not a database or disk migration.

## One-command upgrade

Run `foc upgrade` from any host directory. No revision, plan file, hash or NodeID
is required. It selects the newest successfully published main release, proves
the merged source tree and exact-source CI, and pins its immutable revision.
When main is still building or publication failed, it explains that state and
uses the last verified published alias; it never falls back after a network,
permission or integrity failure. It refuses an implicit downgrade. An unfinished
upgrade always keeps its recorded target, even when a newer release appears.

If necessary, the command refreshes its host backend with the existing bounded
Compose installer and continues automatically using the same pinned revision.
A newer installed tool is retained. Tool installation failure stops before the
business upgrade; a failed business upgrade retains its journal and recovery
point. There is still one business-upgrade confirmation. Existing tools released
before this entry was added need one explicit verified `foc self-update --revision
FULL_PUBLISHED_MAIN_SHA` to obtain it; this cannot retroactively alter old binaries.

The Compose installer retains one owned backend per observed database generation
before replacing the global executable. If another deployment has an unfinished
upgrade for an older generation, `foc upgrade` automatically delegates that
recorded target to its matching retained backend. That backend verifies the full
original journal and cannot refresh or downgrade the newer global tool while
finishing the pending operation. Missing or mismatched retained executables stop
without changing the pending deployment. These small recovery executables are
retained by generation, not by release; do not remove them during pending work.

To deliberately select an exact release, use
`foc upgrade --revision FULL_PUBLISHED_MAIN_SHA`.
The tool verifies the selected public release and deployment, displays version,
database generation and state-backup capacity, and asks for one confirmation.
After the capacity scan, it refreshes the release plan before requesting consent,
so a long MySQL dump estimate does not consume the plan's one-hour validity.
It manages the private plan and recovery archive in the registered deployment
directory, invokes the existing apply checks, and opens only after preparation
and managed read verification succeed. No plan filename, hash or NodeID needs
to be copied by the operator. Existing Compose selection and media mounts remain
bound to the receipt. `foc self-update` remains available for tool-only refresh.

Release readiness is reported separately from registry access:

| Stage | Meaning |
| --- | --- |
| `main_ci_waiting` / `main_ci_running` / `main_ci_failed` | Exact main CI is absent, pending or failed |
| `image_publication_waiting` | Main CI passed; publisher has not started |
| `image_build_running` | A component compile job is running |
| `image_publish_running` | A component image publisher is running |
| `image_alias_promotion_running` | Verified default aliases are being promoted |
| `image_build_or_publication_running` | Publisher active; no specific running job observed |
| `image_publication_failed` | Newest exact publisher attempt did not succeed |
| Publication succeeded but image verification failed | Successful publication does not prove that an image remains accessible; underlying missing, network, permission, platform or integrity error is retained |

For MySQL, the interactive confirmation explicitly attests that external writers
are stopped. Noninteractive use requires `--yes` and, for MySQL, the separate
`--confirm-external-writers-stopped` attestation. The tool cannot infer external
writer ownership. Declining confirmation leaves the upgrade unstarted.

Repeating the command with the same target detects a recorded resumable stage
and requests consent to finish it using its existing plan and recovery point.
A different target, failed phase, controlled recovery, changed receipt, or
interrupted operation lock is refused. An already current ready deployment is
reported without another upgrade, after retrying any recorded generated-stage
cleanup through the same guarded opening path. The command never silently restores a database
or opens a failed upgrade. Keep managed plan, backup and journal evidence.

## Detailed preparation and opening

The following subcommands remain available for deliberate staged operations.

Upgrade recovery always uses `upgrade-state`: SQLite database/WAL/SHM or a
consistent MySQL dump, deployment configuration, identity keys, certificates,
Redis and native lifecycle state. Media, lyrics and recording files remain in
their original mounts and are never copied into the upgrade recovery point.
The plan binds this scope into its approval digest; no media-exclusion flag is
required. `foc backup plan` estimates this same upgrade scope.

The archive explicitly records the excluded business files and is not a complete
data restore for a new machine. Original media mounts must be retained. The
upgrade verifies managed reads against these retained files before opening.
Database rollback still requires controlled recovery; no DDL rollback is implied.

For a `failed_fenced` preparation which has never begun public activation,
`foc upgrade recover-state` restores the verified pre-upgrade database and state
into the same retained mounts. It requires the original plan digest, exact NodeID,
original archive SHA and a new private recovery directory. Current failed state
is retained there before any restoration; no media bytes are captured. SQLite
restores the archived database/WAL/SHM, and MySQL requires external-writer
confirmation, retains a logical dump of the failed database, then explicitly
recreates only the recorded database from the verified dump. Identity keys,
including `data/media-keys/media-premaster.key`, configuration and certificate
state are restored without replacing native lifecycle/control lease files.

Before a MySQL database is dropped, recovery checks its server data volume's
free space against the source table/index storage estimate recorded in the
archive, an expansion allowance and remaining reserve. Historical state archives
without that estimate cannot authorize destructive MySQL restoration. This
estimate is independent of the compressed dump size and archive destination.
On a continuing recovery, allocated private `.ibd` files in the recorded database
directory can count as space reclaimed by the explicit database drop. Shared
tablespaces and hard-linked files never count as reclaimed space.
Recovery checks both root and application MySQL credentials against the archive
and refuses drift before replacing any live state. Password
rotation or loss of the server credential requires separately coordinated MySQL
credential recovery; an application dump cannot restore server account state.

Recovery validates the source generation, identity and original managed files
and remains `prepared_fenced`. Its returned plan records `recovery_of` and a new
approval digest. Use that returned digest with `foc upgrade open` to separately
confirm opening the restored source. Recovery refuses any upgrade which began
activation or accepted new writes; it never silently discards post-opening data.
An interrupted `restoring_state` operation can be retried with the same original
approval, archive SHA and recorded recovery directory. Failed capture materials
are retained and a capture error makes no database restoration.
Recovery inventories all captured state classes, retains target-created files,
and removes target-only state before restoring archived files. The original
native/runtime/site lease files remain pinned. Recovery destinations require a
real parent with no symlink ancestors and cannot lie inside any retained root.
Destination capacity includes cumulative positive file-size growth across all
state roots sharing a filesystem, peak temporary copies and remaining reserve.

Use an explicit published main commit for an existing installation. `latest`
is accepted by initial installation only. A plan performs read-only Docker
inspection and public registry/reviewed-source verification; it does not pull
images, reserve capacity, create a lock, stop services, or enter maintenance.

```sh
./fc --directory /srv/frontiercloud upgrade plan \
  --revision FULL_PUBLISHED_MAIN_SHA > /private/upgrade-plan.json
```

Review `from_revision`, `target_revision`, `node_id`, `project`, `database`,
`from_schema_generation`, `schema_generation`, all component image digests, and
`plan_sha256`. The plan
expires after one hour. Infrastructure image digests remain fixed. Every
FrontierCloud component in this deployment is resolved from the same explicit
release and architecture. Apply repeats the identity, configuration and remote
image proof checks, rejecting drift before stopping the source.

```sh
./fc --directory /srv/frontiercloud upgrade apply \
  --plan /private/upgrade-plan.json \
  --approve-plan-sha256 REVIEWED_PLAN_SHA256 \
  --confirm-node-id SOURCE_NODE_ID \
  --backup-output /private/new-pre-upgrade-recovery.tar
```

MySQL additionally requires `--confirm-external-writers-stopped`. This is an
operator attestation about writers outside FrontierCloud's native gate; the
tool does not infer it from stopping Web. The archive path must be new and on
an accessible local filesystem outside the captured state roots.

Apply pulls approved digest references before taking the site offline. It then
uses the existing native lifecycle freeze, stops this deployment's writers,
creates and independently verifies a real recovery archive, records its checksum,
and only then publishes the new image lock and receipt. The target runs
`prepare-release` behind the closed native fence and verifies the original
identity, schema, idle transaction state and representative managed reads.

Successful apply ends at **`prepared_fenced`**. Services remain stopped. Opening
is a second explicit action, so preparing images cannot accidentally reopen a
site that needs operator review:

```sh
./fc --directory /srv/frontiercloud upgrade open \
  --approve-plan-sha256 REVIEWED_PLAN_SHA256 \
  --confirm-node-id SOURCE_NODE_ID
```

Open starts the recorded resident services under public maintenance, verifies
readiness and actual managed business reads, then removes only its own public
maintenance flag. A preexisting administrator maintenance flag is preserved and
blocks this operation. Container health is not claimed to prove browser playback,
cross-node Range routing or every object in a large catalog.

An `opening` intent is durable before public maintenance is removed. If a
process or host stops during activation/opening or between journal and ready
receipt updates, repeat the same explicitly approved `upgrade open` after
reviewing any interrupted operation lock. The retry restores owned public
maintenance before archive hashing/runtime checks, revalidates the original
recovery point and target business reads, then finishes journal/receipt updates
idempotently. It does not steal an operation lock, reopen failed phases, remove
new unowned administrator maintenance, or resume an independent native fence.
The receipt also binds effective Compose execution/isolation fields, including
commands, entrypoint, user, capabilities, privileged/read-only state and network
mode. Those edits require their own reviewed configuration procedure.

## Resume an interrupted approved switch

If `.fc-upgrade.json` records `backed_up_fenced`, `switching_fenced`,
`preparing_fenced` or `prepared_fenced`, use the existing plan and original
NodeID to reconcile an interrupted image-lock/receipt switch:

```sh
./fc --directory /srv/frontiercloud upgrade resume \
  --approve-plan-sha256 REVIEWED_PLAN_SHA256 \
  --confirm-node-id SOURCE_NODE_ID
```

MySQL also requires `--external-writers-stopped`. Resume admits only the recorded
old/target receipt and approved image pins. It restores the native fence, verifies
the original recovery archive and public target proof, then prepares the target.
An already completed additive migration is inspected rather than replayed as an
old generation. Success remains `prepared_fenced`; opening is still explicit.
A failed phase, changed configuration or unknown image-lock field is rejected.
Review interrupted operation locks separately; resume does not steal them.

## Failure and recovery boundary

`.fc-upgrade.json` records phases, the previous receipt, the approved plan,
recovery archive location and checksum. Previous successful journals are retained
under their plan digest before a later upgrade. These files contain no runtime
secrets; the recovery archive does contain private recovery material and remains
mode 0600. Preserve all of them. The normal restart command rejects a receipt
which is not ready.

After a failure during the fenced operation, the tool attempts to keep the native
gate closed and all deployment writers stopped. `failed_fenced` means that check
succeeded; `failed_fence_unverified` requires immediate operator investigation
because stopping the process or inspecting its fence could not be confirmed.
Neither state can be opened by `upgrade open`. An interrupted lock is not stolen
automatically. The old image receipt, new image receipt, backup and journal are
recovery evidence, not permission to delete the current database.

The admitted paths are same-generation preparation and the explicit generation
6 → 7 forward migration. Unknown generations and other transitions are refused.
Existing generation-4/5 deployments without operator receipts use the separately
approved maintainer path: preserve their original Compose/project/mount selection,
close the native gate and stop all writers, verify a complete cold recovery point,
then invoke the published generation-7 runtime's `prepare-release` with the exact
`--from-generation 4` (or `5`), original `--confirm-node-id`,
`--confirm-generation 7` and verified `--backup-sha256`. That command checks the
exact source generation's complete transaction roster before the retained
additive DDL, then checks generation-7 idleness and identity. It keeps the gate
closed. This does not grant `fc backup/restore/upgrade` generation-4/5 receipt
compatibility or authorize initialization of an existing deployment. Generation
3, absent/malformed tables, unknown journals and unfinished writes are refused.
For 6 → 7, the source generation-6 image supplies the quiescent runtime facts;
the archive retains `schema_generation: 6`. The generation-7 target independently
checks the original identity and generation-6 transaction roster before applying
the defined additive DDL, and then validates the generation-7 state. The receipt
keeps the generation-6 recovery image set. No failure restores old images
automatically or claims to undo DDL. Restoring a backup requires the matching
recorded release and explicit source-offline/target-empty recovery controls. Any
writes made after a successful opening are outside the earlier backup's recovery
point and require an explicit preservation decision before restoration.

The backup is for **this deployment**. It includes its local state classes and
records related-node state as missing. Its `complete_cluster` flag is not promoted
by upgrading one Master or Storage. A coordinated local-engine cluster recovery
point uses the explicit [recovery-set workflow](operator-recovery-sets.md);
ordinary single-deployment recovery cannot safely substitute for that proof.

## Validation scope

The upgrade unit tests use an isolated temporary directory, real archive bytes,
hash verification and archive extraction with an injected Docker runner. They
exercise stale/mismatched approvals, image proof drift, existing backup protection,
configuration drift, preparation/read failures, retained backup bytes, maintenance
ownership and explicit reopening. They do not represent a real released-image
upgrade, schema rollback, TLS deployment, external MySQL coordination, five-node
recovery or browser acceptance. Those require the separate development-host
Compose acceptance gate. The optional native adapter in
`tests/operator_recovery_acceptance.py` performs actual Compose switching,
freeze, snapshot/dump, recovery, managed reads and HTTP Range checks using
explicit private image IDs. Its publication proof is injected; it cannot certify
public releases. The generation-6 → 7 native gates are recorded for
[SQLite](audits/2026-10-12-upgrade-6to7-sqlite.json) and
[MySQL](audits/2026-10-12-upgrade-6to7-mysql.json).
Each uses the actual generation-6 source and rebuilt generation-7 target,
validates forward preparation and opening, then captures and restores the upgraded
state. The [preparation-failure gate](audits/2026-10-12-upgrade-6to7-failure.json)
verifies the retained recovery point, native closed fence and absence of automatic
rollback. These gates do not grant schema rollback authority.

An interrupted `backup_pending` upgrade uses the same approved `upgrade resume`
command and original source receipt. Resume first restores the native fence.
It independently verifies an existing complete archive against the original
identity/revision/generation. A missing archive is captured again; a regular
partial archive is preserved unchanged beside the recorded output with an
`.interrupted-<timestamp>` suffix before a new capture. Symlinks/nonregular
outputs, changed source image locks and mismatching verified archives are
refused. A fresh verified recovery point is durably recorded before switching.

Upgrade activation/opening also retains a generated staged marker inode before
public marker publication. A manual marker written by an administrator after
intent persistence has a different inode and is never adopted or removed. The
staged ownership file is removed only after durable successful ready publication.
A verified backup with a scratch-cleanup warning remains a valid recovery point;
its warning and retained scratch location are recorded in the upgrade journal.

Prior completed upgrade journals can be archived again only when the existing
history file is byte-identical. Conflicting history remains blocked. Generated
upgrade marker staging uses the approved plan's digest in its filename, so
retained prior staging does not obstruct another plan. Cleanup failure is
persisted as `stage_cleanup_warning`; repeating the same target with the
one-command entry or repeating the same completed `upgrade open`
retries only that recorded generated stage, preserving administrator maintenance.

The host-side `fc` verifier may use an optional read-only `GITHUB_API_TOKEN`
for GitHub API rate limits. Do not pass it to Web or certificate containers.
Business configuration has no release branch, CD or GitHub credential fields.

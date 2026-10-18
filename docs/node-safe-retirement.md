# Safe node retirement

The expanded Nodes details and `foc node retire` use the same Master service.
Retirement applies to one exact downstream Storage NodeID. It retains the node
identity, database, audit history, containers and volumes. It never uninstalls a
node, wipes storage, reassigns a backup or rotates the local identity.

## Operator workflow

1. Complete or cancel migrations through their ordinary task controls. Resolve
   uploads, recordings, migration workers, reservations and active read dependencies.
2. Run the node card's read-only retirement check, or:

   ```text
   fc --json node retire check NODE_ID --master https://master.example --credential-stdin
   ```

   Supply the existing Admin or temporary credential through standard input.
   `--ca-file FILE` adds an explicit trusted public CA; TLS verification remains
   enabled. Credentials and private keys are never command arguments.
3. Inspect every reported blocker. Unknown files require investigation, not
   manual deletion just to make the report pass. Backup generations, chunks and
   placement remain blockers: an observed backup checksum alone does not prove
   that replacement and retention requirements have been met.
4. Use the safe retirement confirmation button and enter the exact source NodeID, or:

   ```text
   fc --json node retire apply NODE_ID --confirm-node-id NODE_ID --master https://master.example --credential-stdin
   ```

   The server performs a fresh observation. A previous report is not an approval
   token and is never accepted as physical clearance.

Apply exits `0` only for a completed, identity-bound retirement receipt. Exit `1`
means the operation is blocked or incomplete; any established fence remains in
place. Exit `2` means invalid input, authentication, transport or an invalid
response. The GUI shows a retry action for a fenced relationship. Use the same
Master, relationship and NodeID to retry. A lost response does not authorize
resetting, re-pairing or clearing the fence.

## Durable protocol

`POST /api/v1/media/admin/nodes/{relationship_id}/retire/apply` accepts exactly
`member_id` and `confirm_member_id`, which must match. Existing HTTPS, Admin
session, CSRF and request bounds apply. The ordinary active-node revoke action
cannot bypass retirement. Pending pairing cancellation and legacy tombstone
notifications retain their separate behavior.

After a fresh clear check, the Master transaction changes the relationship to
`retiring` and sets the storage member non-writable. It holds the existing node
writer lock while repeating the ledger checks. The peer performs its own fenced
transition using authenticated `POST /internal/v1/retirement` with action `begin`
and the same exact `confirm_member_id`. Ordinary relationship authentication and
durable resource admission reject this state. Failed observations leave the
fence in SQL; neither a timeout nor a restart reopens it.

The peer's `complete` action joins all previously admitted internal HTTP work
and queued native migration jobs through a pinned OS request lease. It then
holds the native media and recording mutation barriers while scanning the real
data/media/recording roots and rechecking the database under the writer
transaction. Native readers and writers must finish before completion. Owned
upload admission runs before any temporary upload file is created. A request
that authenticated before fencing cannot create a new stage after completion.

Completion stores a durable `revoked` tombstone with `fenced_at`, `completed_at`,
Master, member and relationship identities. The Master commits its corresponding
tombstone only after verifying the peer's authenticated receipt. The old
credential cannot resume heartbeat, uploads, recordings, migration or other
ordinary work. Its narrowly scoped retirement authentication can retrieve or
replay the existing receipt after a lost acknowledgement. Nonces still prevent
request replay; retries sign fresh requests. Repeated completion does not create
a second completion audit event or change the receipt. Identity reset is blocked
while any retirement is incomplete.

The request lease and native barriers provide live exclusion. The SQL state
provides durability across restart. The retirement route bypasses the ordinary
request lease only so that it can acquire the exclusive lease itself. Final
inspection is local and does not recursively issue inventory RPCs.

## Retained state and blocked observations

The report retains only verified native state, including the selected SQLite
database and existing sidecars, the configured node vault whose identity still
matches the process, the media premaster matching durable key metadata, known
idle coordination files and the exact built-in default lyric. Files must remain
the selected native inodes; a copied filename is not sufficient. Missing keys,
changed inodes, corrupt bytes, unknown siblings and busy leases block completion.
Inspection does not regenerate missing keys.

Native startup provenance is retained only when its store binding matches the
actual configured database and its sealed startup receipt binds that selection
to the current NodeID. Both files are pinned after successful native admission,
before inventory routes are registered. Startup admission and store-selection
locks must be idle. The long-lived node control lock is recognized only when
this service holds the exact scanned inode; foreign lock owners, changed bytes,
replacement inodes and a missing held filename remain blockers.

Terminal migration checkpoints additionally require strict native journal
decoding, idle blob leases, absent staging leftovers and matching durable
task/unit/object receipts. Published checkpoints must have retired their private
anchor after the configured grace. Cancellation-only receipts cannot be used as
publication evidence. Merely setting a task's label to completed or cancelled
does not satisfy these checks.

Generation-seven migration history is reconciled in bounded pages. Admitted
plan headers, immutable bindings, object and proof digests, unit counts, bytes
and terminal checkpoints must agree with the task. Orphan headers, bindings or
path indexes block retirement. Preview caches have no migration authority and
may remain after expiry; valid terminal bindings remain as audit history.

The three inventory roots are the actual runtime mounts. Old copies left behind
after a mount change remain visible blockers. Filesystem free-space observations
may share one underlying device and must not be added together. Retained bytes
remain counted; a clear report is never permission to erase a volume.

Certificate-controller private, published and runtime volumes are separate from
the business inventory roots. Retirement preserves these volumes and their
controller; it does not claim to inspect or authorize removal of their contents.
Native disk wiping and infrastructure teardown require a separate operator
decision after retirement and retention obligations have been resolved.

Nginx-served media is rejected by final retirement because its readers do not
participate in the native service barriers. Offline peers and older peers that
cannot produce the required inventory or retirement receipt cannot complete.

## Validation evidence

The isolated development run in
[the joint race log](audits/2026-10-12-paged-migration-second.txt) passed the
actual HMAC handler test that pauses after authorization, persists the fence,
refuses completion while the handler is active, and rejects its subsequently
created unknown file during the final scan. It also passed independent-runtime
lease exclusion, changed-inode rejection, held native readers, lost peer commit
acknowledgement, retained key tampering and the already-admitted upload test that
checks for zero new stage files after retirement. Native upload recovery and
cancellation regressions ran in the same batch.

[The client and CLI race log](audits/2026-10-12-parallel-retirement-second.txt)
covers TLS/cookie/CSRF use, exact NodeID confirmation, valid completed-history
retries and rejection of foreign, future or unfinished receipts. The local
`node tests/node_retirement_ui_smoke.mjs` DOM fixture exercises confirmation,
the shared apply API, persisted-fence retry and the completed history display.
That fixture does not constitute native browser acceptance.

[The subsequent TLS and Redis integration log](audits/2026-10-12-paged-cli-retirement-tls.txt)
records the Admin retirement tests against actual Redis, including anonymous and
CSRF rejection, exact confirmation, bounded requests and shared busy admission.
It also records the generation-seven plan-history test: preview caches remain
legal, corrupted admitted manifests and orphaned rows block, and valid terminal
bindings remain retained. Native fleet acceptance is recorded separately by the
integration run.

[The retained-native marker tests](audits/2026-10-12-retirement-native-markers.txt)
and [the held-control-lock regression](audits/2026-10-12-retirement-native-markers-second.txt)
verify actual vault-sealed startup provenance and fixed file identities, including
same-byte replacements, foreign NodeIDs, busy startup locks and disappearance of
the scheduler's held lock. Native receipt recording precedes HTTP registration,
so legitimate startup files are pinned without accepting arbitrary filenames.

# Legacy placement writer lock audit

This is a development audit, not an activation authorization. The encrypted
tree and public-ingress production gates remain closed. Legacy paths, journals,
stages and global catalog rows contain business names and must not be used as
the final encrypted-tree write path. Local owner locks protect only cooperating
processes sharing the same verified lock and database marker; they do not
protect another host or an old writer that ignores the marker.

The intended global acquisition order for a short authorization or mutation
is owner control, tree fence, ingress fence and media volume; release is in
reverse. A writer with an exclusive owner lock may serialize cooperating
readers before taking a volume lock, but that alone does not update the sealed
tree or make a plaintext publication safe. Never hold these global locks over
remote HTTP, S3 calls, or an unbounded body read. The table records observed
legacy call order, not a claim that all call sites have been fenced.

| Path | Observed acquisition and write | Required boundary before activation |
| --- | --- | --- |
| MasterLocal upload reservation | `ReserveMasterEncryptedUpload` takes the media exclusive lease before `ReserveUpload`/`ReserveEncryptedUpload`. | Reorder or deny the old reservation under the persistent tree gate; avoid volume-to-owner/ingress inversion. |
| MasterLocal upload publication | `UploadMasterBytes` reads and stages the body without the owner lock; its local publication candidate then takes owner exclusive before volume and `finishUpload`/`CompleteMasterUpload`. The repository must enforce the same private owner lease and marker in the SQL transaction. | Validate failure recovery and all same-database callers. Replace the path-bearing stage, journal and target with the authenticated random-blob/tree protocol, or persistently reject this legacy path when the tree is active. |
| MasterLocal upload recovery | `recoverUploads` is called from startup recovery while the media volume is exclusive; it verifies a journal and calls `finishUpload`. `reconcileExpiredUpload` also holds the volume for local absence checks and reservation release. | Recovery must acquire compatible owner/tree authority before volume, without holding it over unbounded hashing, and preserve unknown intents and bytes. Startup/restore cannot bypass a missing or changed marker. |
| Remote native upload completion | `UploadMasterBytes` and `FinalizeMasterUpload` hold an upload-session lease across remote upload/stat and then call `FinalizeUpload`; `reconcileExpiredUpload` performs remote stat/absence work before `FinalizeRecoveredUpload`. | Retain the intent and session serialization, perform network work without global owner/tree/ingress locks, then reacquire in the agreed order and atomically recheck exact receipt, owner, reservation and revision before publication or recovery. |
| Global deletion | `DeleteGlobal` calls `PrepareGlobalDelete` under a media shared lease. MasterLocal deletion calls `PrepareMasterDelete` and `CommitMasterDelete` while media is exclusive. Remote retry holds an operation/object lease across HTTPS and `CompleteGlobalDelete`. | Do not turn these SQL calls into ingress writes under an already-held volume. Persist a revocation intent, perform peer work without global locks, then acquire the required fences in order and recheck the exact owner acknowledgement, version, authorization and accounting before each durable transition. |
| Global rename | `prepareGlobalRename` holds media exclusive while preparing SQL. Retry holds an operation lease across owner requests; local movement uses a media exclusive lease that is released before `CompleteGlobalRename`. | Coordinate each durable phase with the same tree/owner generation and short ordered fences; do not hold global locks during remote work. Recovery must prove which operation owns the observed state. |
| S3 completion, deletion and recovery | `media.S3CompleteUpload` and recovery hold the S3 admission lease; `s3media` holds per-upload or per-object operation leases around provider calls and repository start/finish transitions. | Keep existing provider keys and objects intact. Separate intent/CAS, provider I/O and proof-verified completion; use current authenticated member/vault configuration and ordered short fences. S3/native migration is not reintroduced. |

Do not mechanically change these repository transactions to `ingressWrite`:
where a caller already owns the media volume this can deadlock against a reader
holding ingress while waiting for that volume. Complete the per-path writer,
recovery, cross-process and marker coverage with fault-injection tests before
using these fences to claim final authorization or enabling either gate.

## Legacy read and grant boundaries

The required `MediaRepository.CheckLegacyPhysicalWritesAllowed` check rejects
an existing durable tree root, missing schema, database error or cancellation.
It is a point-in-time defense only: the native runtime and offline initializer
must hold the same maintenance fence, and old processes, independent stores,
remote hosts and rollback still require separate proof. `media.NewContext`
currently rejects a durable root before recovery or default-lyric creation;
the tree-native service construction and its unified runtime activation are
not installed.

* Public `stream` → `deliver` → `media.Delivery`, direct `media.Stream`,
  Admin `cryptoBytes` / `downloadPlanBytes` / download → `media.Download`,
  and public `CryptoObject` now check the durable marker. Public stream and
  the Admin crypto/download/plan handlers also explicitly reject a partially
  configured `Public.opaqueTree`. They remain legacy paths; actual tree-native
  playback, downloads and key handling must replace them before activation.
  An in-memory `Public.opaqueTree` is not a durable-root check or atomic
  activation, and does not by itself configure the separate relay handlers.
* Master and Follower Local/Direct/Relay legacy grant issuance and legacy
  Master Direct/Relay/lyric and Follower Relay bearer reopening check the
  Master's durable marker. Follower owner endpoints still accept their own
  legacy v2/v3 capabilities without knowing the Master's marker. Authenticated
  owner revocation or proven drain of every previously issued grant, plus a
  single atomic installation of all public, Master and Follower handlers, is
  required before activation. A TTL or configuring one handler is not proof.
* S3 control, upload grants, source grants and background reconciliation check
  the marker before provider requests. Existing S3 must remain available with
  the tree disabled. A sealed S3 placement, current configuration lease, owner
  proof, existing object/version inventory and backup/restore, and authorized
  direct reads are mandatory before the new tree may activate; this temporary
  legacy refusal does not meet the S3 compatibility requirement.
* Legacy local/owned rename and delete, global retry, and native migration
  receiver, publication, cleanup and unpublish check the local marker before
  physical changes. Unknown journals, anchors, targets and reservations are
  preserved when blocked. These checks do not propagate the Master's marker to
  a Follower; the tree-native migration protocol and owner authorization,
  including prior operation settlement, remain activation requirements.

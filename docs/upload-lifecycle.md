# Upload lifecycle and abandoned-browser recovery

An upload is a reservation, a byte transfer and a confirmed publication, not
one database INSERT. Refresh/close can interrupt transfer or lose finalize.
Browser `finally` is best-effort only; it is not run reliably on page teardown.

## Recovery rules

The Master retains the existing 30-minute reservation deadline. A background
sweep runs immediately at startup, then waits a full 30 seconds after each
sweep finishes before starting another. Each sweep examines at most 50 expired
reservations serially. A long sweep cannot accumulate timer ticks and cause
continuous verification work without a cooldown. Checks start with ten seconds and allow one additional
second per 16 MiB, capped at 180 seconds; a sweep is capped at 180 seconds.
Storage digest verification uses a separate one-connection pool, so hashing
large files does not consume the ten-second heartbeat pool. Failed checks
rotate without renewing expiry or refunding quota.
Expiry permits investigation; it is **never evidence to delete media**.

- Master-local: acquire the same cross-process session lease as transfer,
  finalize and cancel; take the volume mutation lease. If a committed media
  identity, unknown file, recovery journal or active writer exists, defer.
  Only confirmed absence permits atomic reservation/quota release.
- Direct/Relay: query the currently paired, verified HTTPS storage node.
  A complete matching object/size/SHA-256/ETag receipt repairs the lost
  Master finalize. The file is preserved. A not-found response must additionally
  pass the signed, **non-destructive** `storage-control/upload-absence` operation
  before refunding capacity. It checks identity, path, pending stages and journals
  under the same exclusive cross-process volume lease as publication, then
  durably fences that upload generation. It never calls ordinary media delete.
- Offline, authentication failure, generic HTTP failure, invalid receipt or
  cancellation keeps the reservation; retry later. Completed catalog entries
  do not enter this expiry sweep.
- Storage appliances also reconcile abandoned stage reservations during
  normal service, using their stage OS lease. They do not discard live streams
  or publication journals. Quota release and audit remain transactional.

Direct browser upload capabilities expire after five minutes and are issued
with the initial reservation; the thirty-minute Master deadline does not
renew them. An admitted long upload still holds its storage stage lease.
Server-relayed transfers hold the Master session lease. Timeout cannot race
these live writers. No unload beacon is trusted as physical cleanup proof.

## Atomic absence and storage upgrade boundary

An old `stat -> delete -> refund` sequence was unsafe: a direct PUT could commit
between the stat's 404 and delete. The deletion endpoint is intentionally allowed
to delete committed media for ordinary admin deletion, so using it for upload
recovery or cancellation could remove a valid file without publishing it on the
Master. A second stat would merely move, not close, this race window.

The new paired absence operation returns a receipt matching the exact
`upload_id`, `object_id`, path and `durable-generation-v1` fence. A committed row,
unknown file, pending reservation or unassociated private stage/journal causes
deferral, without changing bytes or either node's quota. The signed upload token
now carries its reservation generation. PUT checks its expiry and generation
fence **again inside the exclusive lease immediately before ReserveOwnedUpload**;
a request authenticated earlier but still queued cannot start writing after the
absence receipt. A fresh reservation has a different generation and can upload
the same path. Explicit cancellation uses the same non-destructive operation.

Storage nodes must be manually upgraded to implement this capability. Existing
nodes (including the old 8a runtime) still support complete-object stat/finalize
recovery, but cannot automatically release absent uploads: missing API, auth,
network errors or invalid receipts retain the reservation. There is deliberately
**no fallback to the legacy destructive endpoint**, and no automatic storage
version synchronization or production storage update.

Small private `.storage-abort-<upload_id>` metadata files persist with the media
root, not the SQL database; keep them in filesystem/migration backups. A separate
`.storage-legacy-fence-<object_id>` marker rejects only old generation-less
capabilities for that object; new signed generations remain writable. These
markers are not media or catalog entries and must not be age-pruned while a late
admitted worker may exist. They consume one small filesystem allocation each per
aborted generation/object, so monitor inode and disk use. Publication writes a
bounded 2 KiB maximum temporary file, fsyncs it, hard-links it atomically without
overwrite and fsyncs the directory. Normal failure removes only its unpublished
temporary name; a hard crash can leave a private `.storage-fence-tmp-*` artifact
which is not an authorization fence. Offline maintenance may remove those exact
temporary artifacts after all writers stop; never remove final fences by age or
mistake them for cache. Missing media-root metadata backups weaken admission
fencing and must not be presented as lossless restoration.

## 2026-10-09 production incident

Read-only checks found exactly two expired reservations for Beyond CD1/CD2
in `vido/大型演出`, occupying 354,081,484 bytes on EVOXT. The storage node had
neither published identities, corresponding files nor partial stages.
Two existing Gin `DELETE /api/v1/media/admin/upload/session/{id}` calls
returned 200; read-only postchecks proved both reservations gone, reserved
capacity reduced by exactly that amount and used capacity unchanged. No
direct SQL writes or media deletions were performed.

Reservations also enforce directory placement affinity. A stale Direct
reservation can block other filenames in that directory when a different
site type is selected; a hash blacklist is not required to cause the symptom.
Historical completed session rows without a live global placement are not
the proof of that affinity and were not deleted in this repair.

MP3 under `vido/` is a separate type/path rejection, not a stale reservation:
audio belongs under `music/`. Do not weaken category validation or silently
move an operator's file while repairing reservations.

## Regression coverage

Tests cover abandoned retry, live lease, unknown bytes, completed placement,
unexpired reservation, audit rollback, periodic dead-stage cleanup without
restart, Direct/Relay lost-finalize preservation, offline deferral and wrong
receipt rejection. Real TLS tests distinguish 404 from 401/403/409/5xx.
Race tests publish after a stat 404 and prove that absence conflicts while media
bytes, storage catalog and quota survive; they also cover late admitted PUT,
legacy unsupported API, live writer/journal rejection and fresh same-path retry.
Controlled-clock scheduler tests execute the production scheduling function
with short and long sweeps, proving a full completion-relative cooldown and
parent cancellation during work, waiting, and before the first sweep. They do
not sleep for 30 seconds or change the system clock.
Business repository tests run against both SQLite and MySQL on the bounded
development host, not production fixtures or the three-minute hosted test CI.

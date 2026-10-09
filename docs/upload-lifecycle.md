# Upload lifecycle and abandoned-browser recovery

An upload is a reservation, a byte transfer and a confirmed publication, not
one database INSERT. Refresh/close can interrupt transfer or lose finalize.
Browser `finally` is best-effort only; it is not run reliably on page teardown.

## Recovery rules

The Master retains the existing 30-minute reservation deadline. A background
sweep runs at startup and every 30 seconds, examines at most 50 expired
reservations serially, bounds individual checks to 10 seconds and a sweep to
30 seconds. Failed checks rotate without renewing expiry or refunding quota.
Expiry permits investigation; it is **never evidence to delete media**.

- Master-local: acquire the same cross-process session lease as transfer,
  finalize and cancel; take the volume mutation lease. If a committed media
  identity, unknown file, recovery journal or active writer exists, defer.
  Only confirmed absence permits atomic reservation/quota release.
- Direct/Relay: query the currently paired, verified HTTPS storage node.
  A complete matching object/size/SHA-256/ETag receipt repairs the lost
  Master finalize. The file is preserved. A not-found response must additionally
  pass the paired deletion/absence workflow, which refuses live partial
  stages and unknown objects, before refunding capacity.
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
Business repository tests run against both SQLite and MySQL on the bounded
development host, not production fixtures or the three-minute hosted test CI.

# Business backup transfer compatibility contract

This documents the existing v2 cold-artifact transport, not a new recovery
format. An accepted artifact is not proof that its business rows can safely be
restored. Snapshot consistency, schema validation, ownership adoption and
maintenance/restore remain separate acceptance gates.

All four routes are HTTPS POST requests with the ordinary v2 exact-raw-body
relationship HMAC and durable nonce checks. Only a Follower's active upstream
may write backups. The receiver derives the Master identity from that
relationship, never from a caller-supplied body field. Online catalog/account
reads must never use these cold artifacts as a replacement database.

`generation` is a positive signed 64-bit JSON integer. Preserve its exact
integer value: nanosecond generations exceed float64's exact integer range.
Responses contain no database identifiers, dialects or connection details.

## Messages

| Route suffix | Required body fields | Successful response |
| --- | --- | --- |
| `begin` | `generation` | `{"status":"receiving"}` |
| `chunk` | `generation`, `chunk_index`, `chunk` | `{"status":"receiving","bytes":N}` |
| `commit` | `generation`, `checksum` | `{"status":"ready","bytes":N}` |
| `abort` | `generation` | `{"status":"failed","generation":G,"aborted_generations":N}` (or `"clean"`) |

Each route is under `/internal/v1/backup/`. `chunk` is standard padded base64
without whitespace, encoding at most 192 KiB. `chunk_index` is an integer from
0 through 10,000,000 inclusive. Control bodies remain bounded separately from
decoded bytes. No compression or payload-sized in-memory artifact is required.

Commit requires at least one received chunk, an uninterrupted index sequence
starting at zero, and the exact lowercase 64-hex SHA-256 of all decoded chunks
concatenated in index order. Validation failure must not mark a generation ready
or discard bytes needed for retry. Receivers retain the newest two verified
generations for a Master; the chunks of discarded generations are removed too.

Abort intentionally cleans **all receiving generations of that paired Master**,
not just the generation echoed in the response. It never deletes ready
generations or another Master's artifacts. `failed` means partial generations
were aborted; `clean` means there were none. Repeating abort is safe.

## Replay and implementation safeguards

Older receivers reject duplicate chunks. A receiver may accept a byte-identical
chunk replay after a lost acknowledgement; it must never replace an existing
index with different bytes. Senders cannot assume duplicate acceptance from
all v2 peers. The native receiver also accepts an identical ready-commit replay
without duplicating its success audit, and rejects `begin` for an already ready
generation so a late request cannot erase the verified artifact.

The native receiver rechecks current role/upstream in the same SQL transaction
as each write. Ready state, byte/chunk totals, retention and success audit commit
atomically. A failed audit leaves the generation receiving with its chunks
intact. Out-of-order completion cannot move the member's latest-generation
pointer backwards. These safeguards do not add runtime-specific wire fields.

The existing compatibility artifact and native export/scheduling boundaries are
documented in [`business-backup.md`](business-backup.md).

Invalid messages/checksums/sequences return 400; invalid authentication returns
401; an authenticated request in the wrong role/direction returns 403. A role
or relationship change discovered at the write boundary returns 409. No such
failure is reported as a successful ready generation.

## Native ready-byte observation

`POST /internal/v1/backup-observation` independently re-reads a known ready
generation through one bounded asynchronous worker. The request binds an
observation ID, member/Master/relationship IDs, `scope=data`,
`resource_kind=backup`, a canonical positive decimal generation string in
`object_id`, the ready manifest's metadata digest, and its exact expected byte
count. No filesystem path, fetch URL or decryption key is accepted. The normal
HTTPS, exact-body HMAC, nonce and current Follower/upstream checks apply to
`start`, `status` and `cancel`; status/cancel also require the returned process
incarnation and the identical request. Unknown fields are rejected.

The worker uses the existing cold reader and a 64 KiB hash buffer, requires
full EOF and checks actual length/SHA-256. It repeats the live identity-bound
manifest lookup after reading; a historical read snapshot that survived
retention does not prove that the generation is still retained. The worker
expires after five minutes, cancels on shutdown, and is joined before its
borrowed roots close. Inspection opens the existing coordination lock and
never recreates a missing one. A busy worker rejects additional observations.

The Master `ObserveBackup` client pins the current relationship, exact request,
incarnation and fixed expiry, checks the resulting generation/length/hash,
and requests bounded cancellation on exit. The virtual observation path is
`backup/GENERATION`; it is not a caller-controlled filesystem locator.

This is an integrity observation only. It neither validates the package's
business restore semantics nor pins a generation against future retention.
Backup replacement, durable retention holds and authorized source purge remain
separate work; a successful observation alone cannot authorize retirement or
delete the sole recovery point. Ordinary v2 delivery compatibility is unchanged.

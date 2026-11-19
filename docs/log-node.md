# Encrypted project logs

Status: connected to Master/resource-node startup; development acceptance and
staging delivery are in progress. This document replaces the manual-delete design.

## Scope and activation

Only project-produced application, access/error, audit, node, security,
WebRTC, certificate, job and browser diagnostic events are in scope. Host,
provider and unrelated application logs are excluded. No new container, ELK,
agent service, compression or full-text index is permitted. Collection and
archive work run in existing Go services.

Activation is an explicit Admin action selecting one healthy, authenticated,
native Direct storage member. S3, Relay, inactive relationships, unavailable
Direct endpoints and an unverified transport transition cannot be selected.
The Master and ingress remain separate from the archive owner. Changing
ingress does not change the log destination. A log member cannot be changed
to Relay, revoked or removed while live archives or transfer intent remain.

Before activation, current retention policies remain in effect. After activation,
the Master keeps the recent 12 hours and the complete log lifecycle is 35 days.
Only lifecycle expiry deletes logs; there is no manual/date-based deletion UI
or endpoint. Failed archive upload is not authority to remove the local source.
Disabling admission stops new archive work, not preservation of existing logs.

The SQLite implementation stores encrypted capture buffers, manifests and jobs
inside the existing Master database, so normal recovery points retain their key
bindings. It reserves a 128 MiB log budget and 1 GiB physical business headroom.
Resource producers hold a bounded 16 MiB public-key encrypted outbox; heartbeat
acknowledgements follow Master commit. Archive replicas have a separate bounded
namespace. Exhaustion is reported and never authorizes deleting unexpired logs.
An audit required by a business transaction still fails atomically if it cannot
be persisted. Best-effort runtime/browser event loss is exposed as a counter.

Master runtime captures are encrypted every second and coalesced into immutable
blocks within five minutes or on explicit query. Resource runtime captures use
bounded five-second batches and the existing authenticated heartbeat. A process
crash can lose the current in-memory batch, not already persisted encrypted jobs.
Nginx and certificate-agent messages use a dedicated RAM-backed Unix socket
volume with no extra container; existing traffic-counter mounts stay read-only.

## Bounded archive lifecycle

Seal bounded blocks before any file/SQL persistence. Keep logical event identity
separate from the random physical archive name. No plaintext journal, spill,
temporary file or retry payload is allowed. Rotation by size/time is bounded;
do not encrypt or scan an entire day's logs in one request.

The durable job queue records upload, verification, acknowledged placement,
local release and expiry. Work waits for the existing business-idle admission,
uses bounded chunks and yields when business traffic resumes. It cannot make
business admission wait for an archive. Retry verifies the exact ciphertext
hash and transaction before advancing; elapsed time is not proof of success.

Moving the log destination first admits a Direct target, copies ciphertext
and verifies receipts, commits placement, then releases old owned copies.
Keep both copies until that commit is proven. New capture and retries remain
bound to their recorded destination generation. No dual business writer or
resource exchange is introduced. Capacity exhaustion must be visible; it must
not silently delete an unarchived block or extend the Master's retention forever.

## Key and read boundaries

Use a fresh AES-256-GCM data key per bounded block. The existing Master vault
wraps that data key and its manifest binding. Only the Master retains wrapped
keys and the key authority. The archive node receives ciphertext and a narrow
upload/read/expiry capability, never the block key, Master vault key or a
decryption endpoint. This applies even if the selected node is untrusted.

An authenticated Admin query obtains a short-lived, exact-block grant and
data key from the Master over verified TLS. The browser downloads ciphertext
directly from the Direct node, verifies it and decrypts/filters it locally in
a bounded Web Worker. No plaintext or keys enter localStorage, IndexedDB,
download files, query strings or service-worker caches. Responses use no-store.
Keys expire out of the Master grant authority; previously delivered plaintext
cannot be revoked from a browser and must not be advertised as revocable.

Master Bash uses the existing authenticated operator context to fetch exact
blocks and decrypt to the terminal. Keys are not command arguments and no
plaintext scratch file is created. Nothing is decrypted on the archive node.

## Queries and diagnostics

No log data is fetched until Query is pressed. Presets are recent 6 hours,
1 day, 3 days and 7 days (four presets). Custom dates select complete days in
an explicit timezone; internal request boundaries are unambiguous instants.
Types are enumerated. Keyword filtering requires a selected type and a window
strictly shorter than 12 hours; it is performed in the browser, never sent to
the Master as a server search request. Bound selected bytes and request count
and show partial/bounded retrieval clearly; never silently label a truncated
result as complete. Cancel terminates download/decryption work and clears keys.

Browser diagnostics start only with log-node activation. Reuse bounded report
sanitization and admission; never accept arbitrary console dumps, cookies,
bearer URLs, credentials or request bodies. Apply rate and byte budgets and
report diagnostic loss without blocking playback. Existing retired temporary
diagnostic endpoints must not be silently re-enabled.

## Acceptance before staging

Verify Direct-only eligibility, restart/resume and lost acknowledgements,
read-only/full disk, interrupted upload/move, expired grants, ciphertext/key
swapping and lifecycle boundaries on the development host. GUI acceptance must
cover activation, explicit query, presets, keyword restrictions, direct browser
download/decryption, cancellation, destination move and honest error states.
Confirm no archive-node key/plaintext persistence and no Master media relay.
Update staging only after these checks; production follows the existing user
acceptance, review and source-release workflow.

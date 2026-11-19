# Encrypted native media tree — development contract

Status: **under development**. The empty SQLite Master can prepare its
authenticated namespace in maintenance. Normal startup and the complete
upload, read and recovery paths still require acceptance before deployment.

The in-memory migration path preflight is bounded and detects ambiguous exact
paths without returning names. It is not connected to a complete, reconciled,
fenced source snapshot and cannot authorize a migration. Master process memory
may reach swap, crash dumps or diagnostic captures; deployment must account for
those destinations rather than claiming that a Go memory-only value can never
reach disk or can be reliably erased from memory.

## Security objective and trust boundary

The Master remains the sole business authority and keeps the tree key. Native
resource nodes receive independent random blob identifiers and scoped read/write
capabilities, never a plaintext business name/path or the Master tree key.
All new uploads use encrypted content and opaque physical names, including
Master-owned resources. A change of ingress or transport leaves that format
intact. Existing media is carried forward by download and reupload using the
normal business workflow.

On disk, filesystem locations are derived only from a fresh 256-bit random blob
identifier. A Master metadata row encrypts each logical parent ID, object ID,
type and component name. Its placement record separately encrypts owner, blob
identifier, independent random public read alias, content length, byte digest,
and any original media-encryption
descriptor. An old object ID can itself be an unsalted path hash: raw legacy
IDs must not be copied into a visible index or used as a physical filename.
Stable, domain-separated keyed tags allow lookup without unkeyed hashes of
names or IDs. Tags, blob IDs and operation IDs must never be generated from a
logical name or user path.
`PrepareFileWithFreshLocators` generates the blob and alias inside the trusted
Master and reserves both keyed tags transactionally in a common permanent
namespace. The caller-supplied-locator preparation path is limited to the
isolated synthetic prototype. Full comparison against historic identifiers and
trustworthy source/node binding still precede any real import.
The dormant schema also contains a unique keyed alias-to-keyed-object index.
It is committed atomically with each visible placement and is rechecked against
the encrypted placement on every alias lookup. A shared tree lease must span
alias lookup and the independent authorization decision; absent or altered
mappings fail closed. It reveals grouping/counts but no raw alias or object ID
to a database observer. It is not yet connected to production routing.

The experimental visible-directory index separates keyed visible and hidden
groups, with authenticated rows and counts. A bounded page contains only
visible entries; its encrypted continuation is bound to the visible directory
revision and authenticated ancestor revisions. Visible child changes and
ancestor changes require restarting pagination; unrelated directories and
hidden-only changes do not reveal themselves by invalidating the cursor. Its explicit,
resumable rebuild blocks indexed reads and writers until complete. The current
list verifies the group's row count and the rows it returns, not the integrity
of every row beyond that page; group counting also scans the group. Page rows
and their facts, reservations and revocation states are read in a bounded batch.
Recovery,
all mutation paths, large-directory cost and cross-process fencing remain
activation gates. In particular, authenticated rows do not prevent whole-store
rollback or a non-cooperating database writer. No public handler may rely on
this index until these boundaries are addressed and independently validated.
The separately selected existing `include_hidden=true` catalog scope merges
both keyed groups and binds both revisions and the scope into its cursor. It
is display metadata. An exact media address can open a hidden category and
play its audio or video through the normal encrypted delivery path. The scope
of a catalog response carries no playback or lyric credential. Neither scope is
in product order. The catalog adapter applies the existing category presence
rules and preference/name ordering.

Each name/placement revision has an independent random 256-bit encryption
identity and 96-bit AES-GCM nonce; the identity selects a domain-separated
per-record key. Fixed-size padded payloads hide the name length and type in the
encrypted row. Persisted encryption identities and blob IDs require durable,
non-reusable reservations, including versions retained after replacement or
deletion. Concurrent writers, retry, database crash and restoration must never
silently reuse an identity. The caller must atomically compare the durable
revision and must not treat an entire older database snapshot as current merely
because its ciphertext authenticates.

Name records written by the experimental v2 format use fixed 4096-byte
component padding and accept up to 1024 Unicode scalar values; v1 records
remain readable with their original 1024-byte envelope. The version and its
coarse padding bucket are observable. Complete-path and subtree move limits,
the source's MySQL character-count semantics and old-record recovery must be
verified before migration; supporting a component in isolation is not proof
that every historical path can be imported.

This design **does not hide** record counts, same-parent grouping and number of
siblings, change timing, byte sizes observable on a node, or access patterns.
It does not protect the Master from a fully compromised Master process or hide
bytes a client has legitimately received. The actual storage integration must
also protect plaintext from SQL/WAL/journals, node databases, temporary files,
search indexes, crash logs, access/error logs, diagnostics, backups, migration
manifests and retained old snapshots. Adding one encrypted table while leaving
those old rows or copies in place is not completion.

Each environment needs its own random, dedicated Master tree root secret and
public per-installation salt. The tree secret must never be derived from the
media premaster: preproduction needs access to keys for historical encrypted
media, and salt alone cannot prevent a holder of a shared premaster deriving a
production tree key. A separate scoped per-object key-transfer prototype is
under development; it is not connected or approved for real exports. A
missing/mismatched key or salt for an existing namespace must fail closed,
never regenerate silently. The tree secret must stay on its own trusted Master,
with protected durable storage and independently recoverable encrypted backups;
neither the tree secret nor media premaster belongs on resource nodes. An
isolated Linux key-file prototype uses a private, Master-owned directory,
exclusive creation and fsync, and refuses missing, partial or insecure keys;
it assumes the directory is trusted and exclusively controlled and is not
connected to runtime initialization. No encrypted key backup, escrow, or
cross-environment migration implementation is provided yet.
The v2 business exporter refuses any nonempty sealed-tree table before emitting
rows, and the operator's idle diagnostic blocks ordinary offline capture when
it observes such rows. Existing empty-tree backups remain supported. The legacy
archive reader/writer also refuses an explicit `runtime_secrets/tree-master.key`
key reference; an absent or forged reference proves nothing about a database or
an alternative key location. Historical archive formats lack a trustworthy tree
marker, and these checks do not cover noncooperating writers, unopened old
backups or keys at other paths. Do not activate the real tree until every
capture and restore path has authenticated tree state, a protected key backup,
and the same exclusive fence; incomplete checks must never be used to allow it.
Preproduction must also use independent node/vault identities. Existing
full-state backups and any transfer of media keys require a documented trust
and recovery procedure before any real deployment.

The existing business repository exposes an explicit, Master-only read-only
inventory of one database snapshot. It returns aggregate counts rather than
names, raw IDs, hashes or keys and is not scheduled or exposed as a public
endpoint. It has a five-second context deadline and a shared 25,000 matched-row
budget, rejecting an incomplete result. SQL engines may still inspect more rows
than they return, so an operator must additionally schedule any invocation at
an appropriate idle point. It includes selected legacy path/hash/descriptor,
visibility, audit/journal and quota indicators; it does not verify actual
payloads, remote nodes, authorization closure, old log content or backup
copies, does not fence subsequent writes, and always reports runtime not ready.
Large datasets require a separate resumable, fenced inventory design rather
than raising the cap blindly. The explicit local command is
`frontiercloud sealed-tree-inventory`; it opens an existing SQLite store in
read-only mode or uses read-only MySQL queries/transactions, validates the
existing Master/Standalone identity, and does not initialize a
database or tree. It must be invoked at an appropriate idle point and its
result is informational only; it does not hold a migration fence after return.
The same snapshot checks local `media_objects` for exact path/tree conflicts
and reports only a failure flag and an aggregate node count. A failure may
also mean the bounded preflight could not process that source. This single
local-table result excludes global and remote catalogs, visibility-only paths,
source reconciliation and bytes, and cannot establish migration readiness.

## Required lifecycle before activation

1. Prepare the new tree on an empty deployment with the current schema and
   a clean data directory. Verify a separate business API download of the
   media and lyrics and record associations and ordering first.
2. Reserve each new random blob ID and revision before publishing bytes. Use
   the same content format for Master Local, Direct and Relay uploads. Check
   bytes and ownership, sync required files and directories, and commit
   catalog visibility atomically. Retry and cancellation must preserve the
   identity and distinguish unpublished stages from committed files.
3. Exercise normal new-format reads, lyric association, ordering, mutation,
   authorization and recovery end to end. Reupload old content through the
   same business flow and compare the restored associations and ordering with
   the recorded source. Keep the verified download through this check.

Audit URL paths as well as query strings in every application and proxy log:
removing the query and masking known relay routes does not prove arbitrary
path segments are free of names. Route-template logging and error handling need
their own coverage, including older log archives and resource-node output.

The public ingress prerequisite lease is not installed. An isolated Linux
`TreeFence` uses a private Master directory, stable-inode flock and a keyed SQL
binding to the fence's random identity, device and inode. Its shared lease
checks the file and tree write generation; its current SQLStore mutations take
an exclusive lock. Copying the fence file to a new inode is refused, including
after restart. A separately reviewed offline rebind and key/backup recovery
procedure is still required for a legitimate filesystem move or restore.
Initialization must durably create the private directory before initializing
the fence, and an interrupted initialization retains its file rather than
regenerating it. Leases are not reentrant: never try to upgrade a held read
lease to a write lease; release it and start a new checked operation instead.

Before activation every cooperating tree writer, key rotation, restore,
database replacement, and admission reader must use the same fence. Admission
holds its read fence, obtains the ingress lease after it, and retains both
through authorization or selection commit. A failed check aborts the commit.
The isolated revocation path first commits an encrypted pending intent and
keyed recovery index under an exclusive tree fence, then blocks new Master
reads and conservatively blocks tree Moves. Owner-signed revoke and delete
receipts are independently checked against the current paired owner key and
encrypted into the intent; neither receipt clears the pending operation or
deletes Master data. Pending operations can be found by object or operation ID
or listed in bounded indexed pages. An absent index or an older valid database
snapshot is not proof that no prior operation existed: a rollback anchor and
complete owner/key/backup reconciliation are still required.
In particular, restoring an owner registry or vault snapshot from before a
revocation can make an unexpired Direct grant valid again. Owner recovery or
database replacement must start with opaque reads disabled and authenticate
the current Master pending/version state before any future enablement; an old
valid ciphertext or owner signature alone cannot establish freshness.
The directory must be durable, private, trusted and on a filesystem with
coherent locks, and every writer must obey the protocol: flock cannot stop a
privileged bypass and is not a distributed fence across separate hosts. Process
death releases OS locks but recovery must revalidate state. The old runtime,
restore paths and ingress have not yet been integrated; no fallback is safe.

## Current isolated primitives

`sealedtree.Tree` seals and opens records, derives parent/name/object indexes,
and generates random blob identifiers. `sealedtree.SQLStore` deliberately
initializes only an otherwise empty SQLite database and provides bounded,
authenticated lookup and enumeration, atomic metadata+placement insertion,
revision-checked directory rename/move with cycle detection, and integrity
checks. Fixed-size encrypted facts can preserve optional visibility, playback,
object timestamps and lyric references; the isolated file publication flow can
bind facts, name and placement in one SQL commit, and directory creation can
bind its facts atomically. An isolated shared-lease reader now checks hidden
ancestors and reads the authenticated entry, facts and opaque placement while
the lease is held; it is not user authorization and depends on all writers
using the same fence. Actual authorization, audit/quota transactions, orphaned
legacy visibility paths and full product migration remain unimplemented. The
isolated `BlobPublisher` validates a bounded synthetic byte stream,
uses independent opaque operation/blob IDs, fsyncs stage and directories, and
publishes by a no-replace hard link on Linux. Replaying an existing complete
stage verifies and syncs it again; an incomplete stage fails closed. It retains
stages and requires exclusive trusted control of its root. The SQLite prototype
also reserves a pending file with sealed name and placement rows, publishes its
bytes, then commits visibility and removes the pending row in one transaction;
it can replay a complete stage after interruption before commit. The same
transaction records an authenticated historical completion receipt so a retry
after a lost response can acknowledge the prior commit; that receipt does not
assert the object still exists after a later change. There is no implemented
stage cleanup. `RecoverPendingWithLease` can reopen bounded pages of the
persisted intents and return their authenticated IDs, metadata and blob
placement to trusted Master memory. Each page requires a held read fence; it
does not prove the original source, remote ownership, quota or completeness,
and pages from separate leases are not an atomic snapshot. Writers must release
the read fence and reauthenticate each intent when publishing. Other platforms
fail closed; filesystem or node compromise can invalidate any later read. This
single-filesystem experiment does not establish remote-node receipts, ownership
or authorization, quota, or clustered durability, and must not be enabled in
the application. The product's SQLite and MySQL schemas have dormant, checked
tree tables, but startup rejects nonempty tree state; the prototype itself has
no MySQL runtime store, product route, eviction or backup format. Synthetic tests exercise
tampering, binary Unicode distinctions, fixed-size records, concurrent writers,
crash rollback and scanning synthetic SQLite/WAL files for plaintext.

Passing those tests means only that the isolated primitive behaved as tested.
It is not evidence that the running product or real data has an encrypted tree.

## Lock ordering and activation boundary

The application startup currently installs none of the tree admission,
owner-control, owner-request, or deletion readiness callbacks. In particular,
the owner-control paths described below are isolated code and fixture behavior,
not evidence that a running node has that fence. An unconfigured repository
with no owner marker uses the existing ingress SQL/OS lock path.

The implementation has these distinct local orders:

* A configured business `ingressWrite` takes the owner-control exclusive fence
  before the ingress write fence. The node promotion/revocation paths similarly
  take owner control before the volume operation and subsequent repository write.
* The isolated composite public admission takes owner control before tree and
  ingress. Older raw-tree fixture paths and isolated preproduction source/key
  coordinators can still start with a tree lease before acquiring ingress;
  they are not a production lock-order proof.
* Isolated owner revocation first reads the pending intent under a tree lease,
  releases it, then holds an owner-control prerequisite through the network
  operation and the later exclusive tree ACK transaction. The short ingress
  relationship lease acquired for the request is released before that ACK.
  The prerequisite has not been connected to a production lock.
* Owner-side control handlers require their configured shared owner fence
  before the protected volume operation and signing. Their production readiness
  callback is not installed.

These orders do not yet form an activation contract. In particular, taking an
owner-control shared fence after ingress while a writer holds owner-control and
waits for ingress is an ABBA deadlock; taking owner control after tree also
conflicts with a control-held tree ACK. A candidate Master-local order is
owner-control, then tree, then ingress, with reverse-order release. It must
first be enforced and fault-tested for every admission, tree writer, S3/member
and source/vault update, promotion and offline recovery. Remote owner protocols
must not be treated as the same local lock. Until then, a catalog consistency
proof or an isolated successful test is not permission to install the gate.

The existing-business SQLite initializer remains unconditionally closed at
its public entry point. Its package-private maintenance experiment checks the
existing deployment binding, Master identity and vault, database and lock file
identities, schema generation and dormant tree structure, and outstanding
legacy journals before creating a root. It does not yet establish a durable
gate for every legacy writer or offline command. If the root commits but its
private identity binding or tree fence is missing, the experiment refuses to
recreate them and maintenance must remain enabled; no automatic crash repair
journal exists. Whole-database rollback, non-cooperating path ABA and writers
on other hosts remain outside that local maintenance proof. MySQL tree runtime
and its cross-host fence are not implemented.

The unpublished SQLite transaction experiment can verify a pinned owner
receipt and finalize a tree pending row together with reserved-to-used
accounting. Its test-only same-database fixture uses synthetic owner evidence
and explicitly bypasses the closed legacy-writer gate. It does not verify a
real source plan or key grant across databases, prove owner file publication,
or provide a product activation path. Recorded signed cleanup is terminal but
does not by itself release capacity. Historical ledger retries do not replace
the tree's authenticated completion check or fresh owner authorization.

Generic `SetFacts` and `Move` are still isolated primitives: they can change
visibility or paths without completing every owner's authorization revocation.
No new authorization may be issued after an effective hide/move; already signed
S3 provider URLs retain the existing expiry semantics and cannot be recalled by
the tree alone. Migration, application writers, old processes, recovery, audit,
and the S3 member/credential leases must be made consistent before activation.

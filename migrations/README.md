# Shared database schema

The current schema generation is 7 (`migrations/schema.go`). Both backends
embed their `0007-schema.json` snapshot. The operator archive/upgrade path accepts
source generation 6 or 7; the lower-level release-preparation command also has
explicit 4/5-to-7 migration logic. That does not make those generations supported
by `foc upgrade`. See [upgrade boundaries](../docs/operator-upgrade.md).

Historical generation 6 has one logical model and two physical snapshots:

- `mysql/0006-schema.json`: existing InnoDB DDL, including binary media paths,
  generated active-ban uniqueness, indexes, and preference constraints.
- `sqlite/0006-schema.json`: corresponding SQLite DDL and indexes. Audit keys
  use `INTEGER PRIMARY KEY`, dates use UTC ISO text, and backup chunks use BLOB.

Each JSON array entry is one SQL statement. There is no runtime SQL translation.
Go embeds these exact files into its binary; Retired Python application markers are removed; migration data and Go migration code remain authoritative. A schema
change must update both backends and advance the same migration generation.
Business identifiers and node protocol values never depend on physical row IDs.

Generation 1 -> 2 introduces the migration journal. Its name and checksum retain
the existing MySQL migration identity, including when SQLite applies the equivalent
physical operation. SQLite runs initialization and upgrade inside `BEGIN IMMEDIATE`;
MySQL uses a connection-scoped migration lock, with resumable DDL and an atomic
generation/journal update. Both reject future generations, incomplete schemas,
and nonempty databases without a generation marker.

Changing `DB_TYPE` selects a database; it does not copy or migrate business data.
Generation 2 -> 3 creates `media_encryption`, whose immutable descriptors follow
stable media identities through upload, rename and crash recovery. Deletion or
abandoned-upload cleanup retains a small file-ID tombstone, preventing reuse of
a prepared AES key/nonce pair. Historical plaintext objects have no descriptor.
The `media_crypto_keys` singleton preserves a public premaster fingerprint. The
persistent premaster is a separately protected secret and must accompany data
recovery; business backup artifacts contain descriptors and the verifier, never
that secret. Startup rejects a missing verifier for encrypted data and a restored
key that does not match it.
SQLite databases belong to a single host and must not be shared over NFS.

Generation 3 -> 4 widens directory and media priorities to -7..500000. SQLite
rebuilds only `media_playback_stats` inside the existing migration transaction,
preserving its columns, rows, indexes and triggers. MySQL uses one atomic ALTER
to replace the range CHECK and widen SMALLINT to INT; re-running after a crash
before the journal/marker update is safe. No stored priority or playback value
is reset or scaled. The historical generation-2/3 snapshots remain immutable.
Older generation-3 binaries refuse a generation-4 database. Back up the database
before first activation; code rollback does not reverse the database migration.

## Resource migration generations and native validation

Generation 4 -> 5 adds the durable Storage resource migration ledger: tasks,
immediate-parent ownership units, source versions and disk-checksum checkpoints,
capacity reservations, independent draining causes, scope locks, fenced runner
epochs, Storage publication/deletion journals and read leases. It does not change
existing media IDs, owners, paths, priorities, encryption descriptors or keys.
Current runtime execution, the independent migration Admin module and safe
retirement are implemented separately from these schema assets; table creation
alone is not feature or acceptance proof. Master Local remains outside the
Storage-to-Storage execution scope. See [migration](../docs/resource-migration-planning.md)
and [retirement](../docs/node-safe-retirement.md).

SQLite rolls additive DDL and the journal/marker update back together. MySQL DDL
commits independently, so table creation is replayable and the generation remains
4 until the journal and marker commit together. A journal failure therefore
requires retry, not an assertion that MySQL DDL was rolled back. The new snapshots
preserve all generation-4 statements; historical snapshots remain immutable.
Generation-4 runtimes refuse this database. Use matching generation-5 images after
approved offline migration; returning to generation 4 requires its own matching
recovery point and explicit handling of later writes.

`scripts/test-resource-schema.sh` creates new private SQLite/MySQL fixtures,
injects journal failure, retries incomplete MySQL DDL, verifies historical facts
and tests future-generation refusal. It is development acceptance outside CI.
Pending migration tasks, reservations, scope locks or Storage journals block both
native full-deployment capture and journal-free business snapshot export.

Generation 5 -> 6 adds `migration_peer_bindings`, a bounded resource-only object
description plus its SHA-256, committed with each follower object registration.
This preserves kind, parent/path mapping and encryption descriptors across
requests/restarts. It contains no node private keys, credentials or media keys.
Changing a registered description is rejected even if its byte count and path
are unchanged. The generation-5 snapshots and release vectors remain immutable.
Generation-5 binaries refuse this database; matching generation-6 image labels,
release manifests and recovery records are required. Code rollback does not
reverse the DDL. SQLite migration is atomic; MySQL creation is resumable before
the generation-6 journal/marker commit. Both failure windows are tested outside
hosted CI. Pre-existing generation-5 peer journals have no inferred binding:
authenticated re-registration from the original Master plan is required before
data actions are admitted. Unknown state remains fenced.

Generation 6 -> 7 adds `migration_plan_headers`, `migration_plan_bindings` and
`migration_plan_paths`. Plan observations and admitted object bindings are paged
durably instead of requiring one large in-memory plan. A page is not an ownership
unit: copying remains bounded while cutover still commits a complete immediate
parent. Preview creation does not drain nodes, reserve capacity or change owners.
Historical task representations remain readable; SQL snapshots, journal identity
and forward-only generation checks remain authoritative. See the
[paged planning contract](../docs/resource-migration-planning.md).

Gin/Go implements business repositories, independent migration/health commands,
and both database dialects. Default deployment is Gin + SQLite; the optional
MySQL overlay selects the same logical schema on MySQL. Python deployment and
live Python/Go database interoperability are no longer supported.

Run scripts/test-go-business.sh for real SQLite/MySQL transaction and schema
coverage and scripts/test-native-api.sh for Python-driven Gin HTTP behavior.
Five-node native fleet validation runs on the development host only; hosted CI
checks canonical schema assets in-memory and stays within three minutes.

Historical IDs, serialization and existing-state migration checks remain
mandatory; removing a runtime does not permit resetting a production store.

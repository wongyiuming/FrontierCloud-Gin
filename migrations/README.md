# Shared database schema

Schema generation 3 has one logical model and two reviewed physical snapshots:

- `mysql/0003-schema.json`: existing InnoDB DDL, including binary media paths,
  generated active-ban uniqueness, indexes, and preference constraints.
- `sqlite/0003-schema.json`: corresponding SQLite DDL and indexes. Audit keys
  use `INTEGER PRIMARY KEY`, dates use UTC ISO text, and backup chunks use BLOB.

Each JSON array entry is one SQL statement. There is no runtime SQL translation.
Go embeds these exact files into its binary; Python files are retained as syntax references only. A schema
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

## Native validation

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

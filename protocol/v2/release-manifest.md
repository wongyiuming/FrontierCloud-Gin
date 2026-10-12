# Historical release manifest v1

Protocol v2 retains the bounded manifest parser and canonical vectors for local
operator/recovery tooling. Online Admin status/history/upgrade/rollback APIs and
whole-cluster release dispatch are retired. Ordinary business deployments do not
mount manifest metadata, launch an updater or distribute release jobs to storage.
See [operator-managed releases](../../docs/master-self-release.md).

The current native schema gate is generation **6**. The unchanged
vectors/release-manifest.json is the generation-2 historical fixture, and
vectors/release-manifest-generation3.json, generation4.json and generation5.json retain historical data.
vectors/release-manifest-generation6.json defines current acceptance, together
with schemas/release-manifest.json. Current tooling rejects old generations
and future generation 7. Protocol 2 is not a promise of database compatibility
across generations, and historical digests do not authorize reverse migrations.

The retained manifest has a common release_version, protocol,
schema_generation and main/gin_main historical publication profiles. Each
artifact binds an immutable Git archive's production commit, reviewed source
commit and tree SHA. SQLite/MySQL does not enter wire identity. A canonical
SHA-256 covers the complete manifest; it is not publication evidence by itself.

Manifests are at most 8192 bytes. Unknown/duplicate fields or profiles, trailing
input, malformed SHAs, boolean/floating version numbers, missing artifacts and
unsupported generations are rejected. Selected artifacts still need exact
reviewed-source, successful source-push CI and provenance proof. Authentication,
network or image-proof failure cannot be treated as a missing published image.

Operators deploy reviewed current-generation images through Compose. Schema
3 -> 4 needs a consistent independent database backup and supported offline
migration; older binaries refuse the new database. Code rollback cannot reverse
DDL. Preserve identities, media metadata and secrets; see
[physical schema migration](../../migrations/README.md). Native development
acceptance and successful CI do not imply a completed production deployment.

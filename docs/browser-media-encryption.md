# Browser media encryption contract

Every file or folder selection requires a new explicit `plain` or `encrypted`
decision. Closing the choice cancels that selection. Missing modes, changed
descriptors and invalid preparation tokens are rejected by the server. Crypto
errors never select plaintext, and previously selected modes are not persisted.

## Data and key paths

The browser encrypts each complete upload into private temporary ciphertext
storage before reserving its storage destination. It reads at most one 1 MiB
plaintext chunk at a time; the temporary file is removed after completion or
failure. Master and storage receive ciphertext. Master-managed lyrics use the
same format without moving lyric relations to storage nodes. Existing plaintext
objects remain plaintext.

Version 1 uses AES-256-GCM with independent 1 MiB chunks and 128-bit tags. A file
descriptor contains a random 128-bit `file_id`, random 64-bit `nonce_prefix`,
plaintext size, ciphertext size, chunk size, version and algorithm. Chunk IVs
are `nonce_prefix || uint32_be(chunk_index)`; additional authenticated data is
`frontiercloud:chunk:v1:<file_id>:<plaintext_size>:<chunk_index>`. Ciphertext size
is `plaintext_size + 16 * ceil(plaintext_size / 1048576)`. Descriptors are checked
at every persistence, signed capability and restore boundary.

Each file key is HMAC-SHA-256 of an independently generated persistent 256-bit
premaster, with message `frontiercloud:file-key:v1:<file_id>`. Unique file IDs
and retained small tombstones prevent reusing a key/nonce pair after canceled
or deleted uploads. A storage retry may resume the same authorized object and
identical descriptor; it cannot attach that descriptor to a different object.

A browser and Master establish ephemeral P-256 ECDH once per authorization
session. HKDF-SHA-256 uses a random 32-byte salt and
`frontiercloud:browser-wrap:v1:<session_id>` to derive an AES-256 wrapping key.
Master returns each authorized file key as an AES-GCM envelope with random
96-bit IV and AAD `frontiercloud:key-envelope:v1:<session_id>:<file_id>`.
Master computes these small envelopes, permissions and byte hashes; it does
not encrypt, decrypt, transcode or compress ordinary media content.

Algorithms and nonce requirements follow
[Web Cryptography](https://www.w3.org/TR/WebCryptoAPI/) and
[NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
[Build-time obfuscation](browser-crypto-assets.md) adds bounded reading effort
without replacing those algorithms or adding expensive playback transformations.

## Authorization consumption and expiration

An authorization is bound to either the authenticated Admin session or an
HttpOnly same-site browser cookie. Key endpoints require same-origin requests
and HTTPS, with a loopback-only development exception. Public authorization
rechecks current visibility and object ownership for each envelope. A session
cannot grant Admin access, grant hidden content, or transfer to another cookie.

The session has a fixed 15-minute lifetime. Multiple files, Range requests,
seeks and continuous playback reuse its wrapping key; file requests do not
extend its deadline. “One-time” means one ephemeral handshake and one bounded
authorization session, not one file or one HTTP request. The server bounds its
in-memory session registry to 4096 entries. Restart, explicit browser revoke,
Admin logout or timeout invalidates further envelope issuance. Upload preparation
tokens are independently signed, bound to the Admin session and descriptor, and
expire after 15 minutes; reservations still follow the upload lifecycle.

The browser keeps non-extractable CryptoKey objects in memory and obtains a new
authorization when needed after expiration or worker restart. Decryption tag
failure or identity mismatch is terminal: no plaintext fallback or unverified
chunk is delivered. This controls this application's behavior. An authorized
browser user can preserve keys or plaintext; revocation cannot erase already
received bytes and this feature provides no DRM guarantee.

## Playback, downloads and durable lifecycle

A same-origin service-worker URL represents plaintext. It maps plaintext HTTP
Range requests to whole ciphertext chunks, authenticates before exposing each
chunk, trims the requested range and returns plaintext-sized headers. Native
video and the existing continuous MP3 MediaSource path use the same adapter.
Interrupted network reads retry from the delivered offset. Local, Direct and
Relay storage still transport opaque ciphertext through existing capabilities.

Single-file downloads decrypt in the browser. Mixed folders use a bounded
download plan and browser-streamed ZIP64 with CRC32, including plaintext and
encrypted objects. Plaintext is not cached by the worker. Renames preserve file
identity and descriptors; delete/recovery journals and backup validation include
the metadata. Karaoke decrypts lyrics in the browser and submits a bounded
snapshot for recording replay; ordinary lyrics remain server-authoritative.

The premaster lives at `DATA_ROOT/media-keys/media-premaster.key`, separate from
node signing credentials, and requires regular-file ownership/permissions.
It must be backed up independently into operator-controlled offline recovery
material. Business backups sent to storage contain metadata, not this secret;
encrypted recovery requires a separate key proof. Missing key material with
encrypted objects fails startup instead of generating a replacement. A durable,
domain-separated public key fingerprint in SQL is included in business backups;
startup rejects a different valid-length key, a missing registered key, and
encrypted metadata without that fingerprint. Storage nodes do not load the
Master premaster or issue browser key envelopes. Losing
the premaster makes existing encrypted media unrecoverable.

The database also preserves a public, domain-separated HMAC fingerprint in
`media_crypto_keys`; business backups include this verifier. Startup compares
the restored premaster against it and rejects even a structurally valid 32-byte
key that belongs to another installation. Active encrypted metadata without its
verifier is rejected as incomplete recovery. Storage Followers do not initialize
or load a premaster; a promotion to Master requires restoring and proving the
original key before starting its browser key service.

Schema generation 3 stores the descriptors and is forward-only from generation
2. The first schema-3 runtime switch requires operator maintenance, independent
backups and stopping database/filesystem writers. See
[release migration boundaries](master-self-release.md#browser-encryption-and-schema-generation-3)
and [abandoned-upload recovery](upload-lifecycle.md). Production Master upgrades
remain manual.

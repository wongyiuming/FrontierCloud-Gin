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
rechecks current visibility and object ownership for each envelope. A public session
cannot grant Admin access, grant hidden content, or transfer to another cookie.

The session has a fixed 15-minute lifetime. Multiple files, Range requests,
seeks and continuous playback reuse its wrapping key; file requests do not
extend its deadline. The server returns a conservative `expires_in` of 1–900
seconds. Page and service worker use a shared monotonic countdown starting
before the handshake request, so client clock offsets and wall-clock changes
cannot renew authorization. Envelopes retain the original server `expires_at`.
“One-time” means one ephemeral handshake and one bounded
authorization session, not one file or one HTTP request. The server bounds its
in-memory session registry to 4096 entries. Master process restart, explicit server
revocation through `/crypto/revoke`,
Admin logout or timeout invalidates further envelope issuance. Upload preparation
tokens are independently signed, bound to the Admin session and descriptor, and
expire after 15 minutes; reservations still follow the upload lifecycle.

The browser keeps non-extractable CryptoKey objects in memory and obtains a new
authorization when needed after expiration. A restarted worker re-registers the
live page and retrieves its still-valid in-memory keys without another ECDH
handshake or an extended deadline. Page exit clears that page's and worker's
in-memory access; it does not call the server revocation endpoint. Decryption tag
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
the metadata. Admin trees and search results carry the same descriptor, so
encrypted media and lyrics retain their status after rename.

Virtual encrypted downloads and ZIP downloads use attachment navigation and the
worker's `Content-Disposition` filename. They omit the link's `download`
attribute so Chromium dispatches the worker fetch; the live page remains open
to provide its existing keys.

Karaoke decrypts lyrics in the browser. Saving an account recording with
encrypted source lyrics creates an independent encrypted snapshot of its lyric
entries. The browser encrypts their JSON with a fresh file ID, key and nonce;
the ticket, recording footer, SQL metadata and storage receipts contain only
the descriptor and ciphertext. The preparation token is account-, browser-
and source-bound and is never persisted in the footer or database. Plaintext
lyric entries cannot replace a reserved encrypted snapshot.

Snapshots are limited to 1400 KiB of plaintext JSON within the existing 2 MiB
recording-metadata limit. Direct and Relay signed upload capabilities carry
only the descriptor and canonical metadata SHA-256; the recording footer
transports the ciphertext. Storage validates that footer against the durable
reservation before publication. Snapshot file IDs share the global uniqueness
registry with media file IDs, using a separate `recording_lyric` object namespace.
Cancel and delete retain consumed IDs as tombstones.

History replay obtains the snapshot key only for the current authenticated
recording owner, reusing the existing fixed-lifetime browser authorization.
It remains available after the original lyric is renamed or deleted. Guest
recordings keep encrypted-source lyric entries only in browser memory until
account save; their audio preview and download do not embed plaintext lyrics.
Ordinary plaintext lyric snapshots retain the existing server-authoritative
behavior.

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

The public verifier is stored in `media_crypto_keys`. A Master restored from a
business backup must restore and prove the original premaster before starting
its browser key service. An existing Standalone promoted to Master continues
using its existing verified premaster.

Schema generation 3 stores the descriptors and is forward-only from generation
2. The first schema-3 runtime switch requires operator maintenance, independent
backups and stopping database/filesystem writers. See
[release migration boundaries](master-self-release.md#browser-encryption-and-schema-generation-3)
and [abandoned-upload recovery](upload-lifecycle.md). Production Master upgrades
remain manual.

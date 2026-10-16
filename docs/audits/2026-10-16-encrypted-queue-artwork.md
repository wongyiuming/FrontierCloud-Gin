# Encrypted queue artwork and browser cache acceptance

Candidate base: `29b1bedcc7e40cb5ba385390b46518f2be8abe14`.

The prior production diagnosis found twelve encrypted Relay tracks in one
album, but only the first received browser metadata. Manual MSE selection
bypassed the legacy metadata hook. Calling that existing hook in an isolated
diagnostic browser restored the second track's original cover. No production
file, deployment or encryption descriptor was changed during that diagnosis.

The fix adds metadata activation to the shared MSE business-track hook and
one background visible-queue read, with selection priority. Individual rows
are patched without rebuilding the queue. Original images are not resized,
recompressed or uploaded after decryption. Server decryption remains prohibited.

## Development and RN gates before the first push

- Source CI, source/compiled crypto smoke, metadata/parser smoke, visible-queue
  scheduling and manual/automatic MSE activation regressions passed.
- The complete HTTP API package passed Go race testing. Artwork conditional
  requests return 304, while deleted sources still return 404.
- A fresh native SQLite Master and four storage nodes completed pairing and
  heartbeat. Three distinct 28-second MP3s, each larger than one encryption
  chunk and carrying its own original PNG, were browser-encrypted and uploaded
  through real Relay reservations. Placement, each picture hash, manual
  selection 2/3/1, and two automatic MSE transitions passed in Chromium.
- The five native Web services each recovered below 20% of one CPU for five
  consecutive one-second samples. This focused browser gate does not claim to
  repeat the complete native matrix or migration acceptance.
- The same three-track MSE and picture test passed on the independent RN HTTPS
  staging site. Its Standalone role is recorded separately from the native
  Relay test. A new page obtained three fresh key grants and issued zero new
  ciphertext requests while restoring all three covers.
- A separate original JPEG remained 500 by 500 pixels with SHA-256
  `c0e26653bf5b8a0f6cf3fb80797cb26f40cb3bcdbd7af61eebc86c035661c7b0`.
  Server bytes matched the browser-produced ciphertext; browser decryption and
  a real 206 Range round-trip matched the original.

Observed Chromium HTTP cache traffic on RN:

| Original asset | Image bytes | Cold HTTP bytes including headers | Repeated HTTP bytes | Conditional response |
| --- | ---: | ---: | ---: | ---: |
| Versioned music logo | 11,228 | 11,699 | 0 | 304 |
| Plain album artwork | 60,596 | 61,118 | 0 | 304 |

The encrypted-byte cache is worker memory, bounded to 32 MiB with a five-minute
reuse window and LRU eviction. It requires valid page grants and fresh AES-GCM
verification; it persists neither plaintext covers nor keys. Worker termination
loses that cache. Versioned logos and plain artwork retain their HTTP caching
rules. No database generation or media format changes are required.

RN staging was stopped after acceptance, with its Compose/data retained and
host ports 80/443 released. The existing production containers' IDs, image IDs
and start times matched before/after; staging idle CPU samples were
0.69%, 0.55%, 0.68%, 0.68%, 0.45%.

Private input transcripts, screenshots, raw acceptance JSON and file hashes are
retained under the operator's local `encrypted-queue-delivery-20261016` evidence
directory. Production release and operator-command evidence must be recorded
separately after successful review, merge and anonymous public-image validation.

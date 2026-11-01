# Music directory artwork

MP3 uploads retain their original bytes. The player displays catalog filenames
and directory labels and does not load the artwork parser or request covers.
Only directory pages derive embedded pictures from ID3v2.2/v2.3/v2.4 tags.
Text frames and ID3v1 suffixes are ignored; they never change display names,
media identity, placement, managed paths or lyric relations.

Picture parsing reads at most 8 MiB of ID3 data and accepts at most 4 MiB of
JPEG, PNG, WebP or GIF artwork. It does not decode audio, transcode or execute
external tools. Storage-node reads fetch only the bounded tag prefix. Derived
pictures share a cache bounded to 256 entries and 32 MiB. File size/modification
time or remote object identity/ETag key the cache; cover requests revalidate the
source before serving cached artwork. Two non-queuing slots admit cold picture
reads; authorized warm-cache reads do not consume those slots. Saturation,
known-offline owners and propagated cancellation/deadline errors return HTTP 503
with a two-second Retry-After. The browser retries at most once within its
original fifteen-second deadline.

Encrypted and S3 MP3 pictures are read in the authorized browser through the
existing service-worker Range adapter. The Master and storage nodes never
decrypt encrypted media. At most two picture jobs run concurrently. Pictures
are deduplicated by SHA-256 in a page-local 32 MiB blob pool and revoked on page
exit; decrypted pictures never enter session storage, uploads, SQL or a
server-side cache. Existing encrypted files require no re-upload or migration.

Directory listings contain only an artwork endpoint URL per category; they do
not embed track descriptors. The browser requests that endpoint only for a
visible card, receiving at most eight visible MP3 candidates. Plain local and
storage-node candidates use the native metadata endpoint; encrypted and S3
candidates are read in the browser. Directory scans admit at most three visible
card jobs and reselect from the currently visible page after each phase. Paging
away cannot enqueue more old-page scans. Candidate queries have an eight-second
browser deadline and a two-second server lookup deadline. A lookup timeout
returns HTTP 503; the browser retries once after two seconds within the same
deadline. Browser Range reads have a fifteen-second per-read deadline and retain
their candidate for later retry on transient failure. A page-memory lookup cache
holds at most 32 entries for 30 seconds and clears when catalog structure changes,
access is refused or the page exits. Hidden/public scopes use distinct keys.
Directory covers retain their original bytes, dimensions and formats.

Original-image reuse has three scopes. Versioned brand logos retain their
one-year immutable browser cache. Plain artwork retains its five-minute private
HTTP cache and a SHA-256 ETag permits a bodyless 304 after revalidation. The
service worker keeps at most 32 MiB of authenticated ciphertext chunks in memory,
with a five-minute reuse window and least-recently-used eviction. Browser page
changes may reuse these encrypted bytes while the worker survives. Every read
still requires the current page capability/grant and verifies AES-GCM with its
authorized key. Every cached chunk first obtains a fresh server key decision,
so an earlier valid key cannot bypass a hidden/deleted/replaced source. Old
pages that cannot acknowledge this revalidation use normal source reads.
Replacement descriptors have distinct cache identities. Worker
restart discards this cache; no plaintext picture or key is persisted to disk.

Cover URLs identify the current managed music path and resource ID through
`/api/v1/media/cover`. Directories derive representative artwork from their
visible candidate tracks; a directory without embedded artwork uses a consistent
album placeholder. Directory candidates follow the catalog's hidden/public
scope and mutations; per-file plaintext URLs retain existing media-access
semantics. Encrypted key visibility checks remain mandatory. No separately
managed image files are introduced.

Frontier UI shows nine large album covers per horizontally snapped page. Native
touch scrolling, mouse drag, wheel and keyboard navigation share the
same ordered cards; reduced motion disables animated page changes. Vertical
wheel scroll remains available whenever large covers exceed the viewport.
The existing list layout retains its information sidebar while Frontier UI hides those
labels. No animation loop, frontend framework or rendering engine is introduced.

On secondary public pages, a leftward swipe from the right edge returns to the
server-rendered business parent, independent of browser history. Nested albums
return to their parent directory, top-level categories return to the media home,
and player pages return to their containing category. Interior cover paging,
player controls and vertical scrolling retain their existing gestures. Horizontal
trackpad scrolling uses the same parent only when a nested scroller cannot consume
the gesture; a short navigation cooldown prevents inertia skipping another level.

`scripts/ops/import_music.py` imports an artist/album/MP3 tree through normal
Standalone Admin uploads. Its resumable manifest records source hashes and
managed paths. A lost finalized-upload reply is reconciled only after downloading
and hashing existing album files; differing content is never overwritten.

`scripts/ops/audit_music_covers.py` is a historical operator-side source and
cover audit; it predates deferred directory candidate loading and must be updated
before use with the current artwork API. Its Mutagen and Pillow dependencies do
not enter the product image.

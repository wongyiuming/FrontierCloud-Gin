# Music metadata and directory artwork

Plain MP3 uploads retain their original bytes. Catalog responses retain filename
and default artwork; optional metadata requests derive title, artist, album and
embedded artwork from ID3v2.2/v2.3/v2.4 tags, with bounded ID3v1 tail reads for
local and remote files. Missing or malformed tags retain the catalog fallbacks.
These derived fields never change media identity,
placement, managed paths or explicit lyric relations.

Tag parsing reads at most 8 MiB of metadata and accepts at most 4 MiB of JPEG,
PNG, WebP or GIF artwork. It does not decode audio, transcode or execute external
tools. Storage-node reads fetch only the bounded tag prefix and, when needed,
the final 128 bytes. Derived metadata and images
share a cache bounded to 256 entries and 32 MiB. File size/modification time or
remote object identity/ETag key the cache; cover requests revalidate the source
before serving cached artwork. Non-MP3 audio formats retain their existing
playback behavior. Two non-queuing slots admit cold metadata reads; already
authorized warm-cache reads do not consume those slots. Temporary admission or
owner failures return HTTP 503 with a two-second Retry-After. The browser retries
at most once within its original fifteen-second metadata deadline.

Encrypted MP3 metadata is derived in the authorized browser through the existing
service-worker Range adapter. The Master and storage nodes never decrypt it.
ID3 tag reads are bounded to 8 MiB, pictures to 4 MiB, and at most two metadata
jobs run concurrently. Selection and MSE automatic transitions request the active
track's tags with priority. An IntersectionObserver also schedules one visible
queue track at a time, leaving another metadata slot for selection. Scrolling
away discards unstarted work; opening an album never queues its entire catalog.
Transient visible-row failures have at most three automatic attempts, separated
by ten seconds; selecting a track remains an explicit retry. Completed metadata
patches that row without replacing the queue or resetting its scroll position.
Covers are deduplicated by SHA-256 in a page-local 32 MiB
blob pool and revoked on page exit; decrypted tags/covers never enter session
storage, uploads, SQL, or a server-side cache. Directory listings contain only
an artwork endpoint URL per album; they do not embed track descriptors. The
browser requests that endpoint only for a visible card, receiving its plain
cover or at most eight visible encrypted track descriptors as candidates. Directory
scans admit at most three visible-card jobs and reselect from the currently
visible page after each phase; paging away cannot enqueue more old-page scans.
Candidate queries have an eight-second browser deadline and a two-second server
lookup deadline. A lookup timeout returns HTTP 503, never a successful empty
result; the browser retries once after two seconds within the same deadline.
Encrypted metadata Range reads
have a fifteen-second per-read deadline and retain their candidate for later
retry on transient failure. The existing two-job decryption limit is unchanged.
A page-memory lookup cache deduplicates candidate queries, holds at most 32
entries for 30 seconds, and clears when the catalog structure changes, access
is refused, or the page exits. Hidden/public scopes use distinct query keys.
It never persists decrypted tags or cover bytes. Large album/directory covers
retain their original bytes, dimensions and formats. The audio player's 50 CSS
pixel queue pictures alone use an opt-in browser Canvas view, bounded to 96
physical pixels on the longest edge without upscaling, encoded as WebP at 0.85
quality. Original cover URLs/blobs remain intact for large views and Media Session.
No server thumbnail conversion, source replacement, plaintext upload, key
persistence or server-side compression is introduced. At most 128 page-local
thumbnail blobs (64 KiB each) are admitted. The owner requires these small views
to be strictly best effort: unsupported browsers, exhausted admission, cold HTTP
cache, idle starvation and rendering failures retain a network-free music-note
placeholder. They never trigger an original-image fallback download. Large
original views and Media Session keep their existing original sources.
Thumbnail work has its own serial channel, preserving both encrypted-metadata
slots. It reuses a page-local decrypted Blob, or reads only the same-origin
browser HTTP cache (`only-if-cached`); a cache miss cannot start a network fetch.
Only visible queue rows request work. Audio-player tag reads and thumbnails
use a native browser idle callback with at least eight milliseconds available,
and either explicitly paused playback or at least twelve seconds buffered ahead
(a completely buffered final segment also qualifies). There is no forced start
after a buffering deadline. Without idle-callback support, admitted metadata may
use one cancellable 250ms delay; thumbnails retain their placeholder.
Falling below that playback-buffer threshold, waiting for media, seeking, switching tracks, backgrounding or leaving the page
cancels artwork work and in-flight tag Range requests. Thumbnail jobs have a
two-second total lifetime including queue waiting, and recheck visibility and
playback admission before decoding. Exit revokes blobs. Native bitmap decoding
already in progress cannot be interrupted; cancellation discards its result and
closes the bitmap. A cold encrypted tag read still authenticates and fetches
whole AES-GCM chunks after admission: resizing alone does not reduce those bytes.
Existing file-ID, visibility, replacement and authorization checks apply to every Range.
Metadata failures retain filename/default art and do not block playback. Already
uploaded encrypted files require no re-upload or database migration.

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
`/api/v1/media/cover`. Tracks without their own artwork may share another
visible track's cover in the same album and directory. Music directories derive
representative artwork from visible plain tracks; a directory without embedded
artwork uses a consistent album placeholder. Directory candidates follow the
catalog's explicit hidden/public scope and mutations; per-file plaintext URLs
retain the existing media-access semantics. Encrypted key visibility checks
remain mandatory. No separately managed image files are introduced.

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

`scripts/ops/audit_music_covers.py` independently inspects imported source tags
with Mutagen and verifies image decoding with Pillow on the operator/test host.
It checks every catalog cover response and directory cover against source image
hashes, including each track's own artwork when present. Missing source images,
invalid images, missing catalog artwork and incorrect cover bytes are reported
separately. These audit dependencies never enter the product image.

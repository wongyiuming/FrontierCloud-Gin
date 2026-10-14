# Music metadata and directory artwork

Plain MP3 uploads retain their original bytes. The first catalog read derives
title, artist, album and embedded artwork from ID3v2.2/v2.3/v2.4 tags, with
ID3v1 text fallback for local files. Missing or malformed tags retain the
filename and default artwork. These derived fields never change media identity,
placement, managed paths or explicit lyric relations.

Tag parsing reads at most 8 MiB of metadata and accepts at most 4 MiB of JPEG,
PNG, WebP or GIF artwork. It does not decode audio, transcode or execute external
tools. Storage-node reads stop after the tag prefix. Derived metadata and images
share a cache bounded to 256 entries and 32 MiB. File size/modification time or
remote object identity/ETag key the cache; cover requests revalidate the source
before serving cached artwork. Encrypted objects remain opaque and use fallback
display metadata. Non-MP3 audio formats retain their existing playback behavior.

Cover URLs identify the current managed music path and resource ID through
`/api/v1/media/cover`. Tracks without their own artwork may share another
visible track's cover in the same album and directory. Music directories derive
representative artwork from visible plain tracks; a directory without embedded
artwork uses a consistent album placeholder. Artwork follows catalog visibility
and mutations; it does not introduce separately managed image files.

The directory globe uses perspective, GPU card transforms and precomputed
latitude/longitude geometry. Pointer and wheel input interpolate toward a target,
with time-based inertia and damping. Rendering stops when movement settles or
the document is hidden. Keyboard navigation, a cover-grid alternative and reduced
motion remain available.

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

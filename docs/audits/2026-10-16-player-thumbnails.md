# Small player artwork acceptance

The audio player's 50 CSS pixel queue artwork now uses a browser-generated WebP
view, at most 96 pixels on its longest edge without upscaling. The existing
original cover URL/blob remains unchanged for directory cards and Media Session.
Only visible queue rows request thumbnail work. The final owner requirement makes
small artwork optional: cached sources only, native idle time, sufficient playback
buffer and no original-download fallback. Browser Canvas
is the only rendering implementation; no package, decoder, server transformer,
runtime dependency, database migration or media rewrite is introduced.

Development acceptance used the existing isolated preview with Web limited to
one CPU and 512 MiB. RN acceptance used only the independent `fc-rn-preprod`
Compose project. Before the first push, development and RN Chromium checks passed
three distinct encrypted MP3 covers, manual MSE selection, automatic MSE
continuation, ciphertext reuse with fresh authorization, hidden-source refusal
and explicit recovery after unhiding. A fresh native five-node SQLite fleet also
passed the same browser cases with Relay placement. Source CI and JavaScript
metadata/player/MSE regressions passed on the development host.

The large encrypted directory card retained its original 500 by 500 JPEG,
60,596 bytes, SHA-256
`c0e26653bf5b8a0f6cf3fb80797cb26f40cb3bcdbd7af61eebc86c035661c7b0`.
The player view was 96 by 96 WebP, 3,518 bytes. The three distinct 64 pixel test
covers were not upscaled; their original PNG hashes were independently checked
alongside three distinct WebP views.

Initial source `afad559` cold-start comparison used new browser contexts and the same application/media.
The baseline replaced only the two browser scripts with release `b7be3fd` bytes
in the test browser. No server route or application source was substituted.
Neither run used artificial network throttling. Measured seconds from navigation
until active MSE playback passed 0.1 seconds:

| Environment | Round | Before | After |
| --- | --- | --- | --- |
| Development LAN | 1 | 0.368 | 0.390 |
| Development LAN | 2 | 0.412 | 0.380 |
| Development LAN | 3 | 0.395 | 0.379 |
| RN public HTTPS | 1 | 3.088 | 4.502 |
| RN public HTTPS | 2 | 3.110 | 2.828 |
| RN public HTTPS | 3 | 5.010 | 2.712 |

Medians were 0.395 to 0.380 seconds locally and 3.110 to 2.828 seconds on RN.
These small samples include substantial public-network variation and one slower
candidate run; they do not establish a stable speedup. Local ciphertext requests
started before first playback fell from seven to six. The 3,518-byte WebP figure
is the generated display object, not a claim that a cold encrypted source needs
only that many network bytes. AES-GCM still authenticates complete chunks.
Decrypted pictures, thumbnails and keys are not persisted to browser disk.

Development idle CPU samples were 0.35, 0.41, 0.25, 0.14 and 0.16 percent.
RN samples were 0.64, 0.55, 0.38, 9.36 and 0.99 percent. RN staging was stopped
after acceptance; its Compose/data were retained, ports 80/443 were free, and
pre-existing production container IDs/images/start times were unchanged.

## Separate production video diagnosis

Read-only inspection reproduced silent video for the existing *For the People*
concert, whose MP4 has H.264 video and E-AC-3 (`ec-3`) six-channel audio. Tested
Chromium 151 reported no `audio/mp4; codecs="ec-3"` support. Both the application
player and a plain native video element decoded video while audio decoded bytes
remained zero. The same native-element test decoded Opus audio normally. This is
a demonstrated codec compatibility failure on the tested browser/platform, not
a claim about every browser or the owner's previous device configuration.

The native media/audio/video player class block is byte-identical between
production releases `bb1b1430` and `b7be3fd` (SHA-256
`63060190bf0a58b6828c63ebc28ff1925929dc467f92e87674f9337eff45aa44`).
The affected video is plaintext and does not use the encrypted worker path.
No production file was rewritten and no compatibility decoder/transcoder was
added. Codec support varies by browser and operating system; adding any heavy
compatibility component requires a separate owner decision.

Raw browser evidence and actual SSH/script inputs are retained privately under
`player-thumbnails-delivery-20261016` on the operator workstation. Production
upgrades are a later, separately recorded `foc` phase.

## Earlier review follow-up (source 78a0784)

Two P2 findings were accepted: missing thumbnail capabilities could delay the
legacy original source, and two slow thumbnails could occupy both tag-reading
slots. The player now checks bitmap/encoder/2D-canvas capabilities before
suppressing the original source. Thumbnail rendering uses its own serial channel
and cannot take either encrypted-metadata slot. Unit cases hold two thumbnail
requests while requiring selected metadata to finish; a real Chromium case
disables OffscreenCanvas and checks the original source and 500-pixel image.
Development source checks, encrypted MSE cases and the fresh native Relay fleet
and isolated RN checks were repeated after these changes. Initial timing samples above remain attributed
to their original source rather than being relabeled as post-review results.

Post-review RN first-play samples were 3.514/2.838, 3.258/2.894 and
2.807/3.075 seconds (before/after); medians were 3.258/2.894 seconds. The
development medians were 0.395/0.392 seconds. These remain small, variable
samples. Original dimensions/hashes and the 3,518-byte player view were unchanged.

An independent persistent-profile browser restart check confirmed versioned
logos were disk-cache hits with zero response wire bytes. The encrypted music
still requested ciphertext after browser restart, matching the worker-memory
cache contract. A two-second, read-only source-audio sample at 60 seconds in the
E-AC-3 concert measured mean -22.5 dB and peak -2.6 dB using the development
host's existing test tools; no production tool was installed.

## Playback-first revision

The owner subsequently required small covers to be expendable. This supersedes
the original-image fallback and three-second forced start described for earlier
sources above. Audio queue rows now immediately show a local SVG placeholder.
They can use an existing decrypted Blob or a same-origin HTTP cache hit, but
never fetch an original over the network to fill this small view. Other large
cover surfaces retain their original sources and quality.

Artwork and audio-player tag reads require a browser idle callback with at least
eight milliseconds remaining and twelve seconds buffered ahead, or a fully
buffered final segment. Explicitly paused playback also permits idle work.
Buffering, seeking, track changes and backgrounding cancel work; tag Range
requests receive the cancellation signal. Thumbnail lifetime is two seconds
including queue age, not fifteen seconds for each predecessor. Admission and
row visibility are rechecked after idle waiting. Unsupported APIs, cache misses,
failures and idle starvation keep the placeholder without playback recovery or
original-image retries. In-progress native bitmap decoding cannot be forcibly
interrupted; its result is discarded and bitmap closed after cancellation.

Regression cases cover low-buffer refusal, queued cancellation before a stalled
predecessor completes, total queue lifetime, cache-only requests, missing encoder,
decoder failure and no idle callback execution. Real encrypted MSE playback and
manual switching must continue in all three browser artwork failure modes.
No codec library, framework, server transformation or persistent plaintext cache
is introduced. Latest-source measurements and input records remain separate from
the historical samples above.

Continuous MSE business activation also rotates the artwork controller before
loading the next track's tags. Browser acceptance checks the old signal is
aborted at each automatic boundary while retaining the same media element and
MSE source. Queue image assertions permit placeholders; original tag/image
verification is explicit and runs after mandatory manual/automatic playback
checks. A no-idle variant requires zero displayed thumbnails while still passing
those playback checks, then independently verifies the original decrypted bytes.

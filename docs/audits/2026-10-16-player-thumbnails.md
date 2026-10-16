# Small player artwork acceptance

The audio player's 50 CSS pixel queue artwork now uses a browser-generated WebP
view, at most 96 pixels on its longest edge without upscaling. The existing
original cover URL/blob remains unchanged for directory cards and Media Session.
Only visible queue rows request thumbnail work. Encrypted metadata and artwork
give initial audio buffering up to three seconds before starting. Browser Canvas
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

Cold-start comparison used new browser contexts and the same application/media.
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

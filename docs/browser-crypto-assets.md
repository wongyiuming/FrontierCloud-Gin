# Build-time obfuscation for browser media encryption

Browser encryption modules keep reviewable source and ship three generated
modules under `static/js/compiled/`. Obfuscation increases the effort required
to read code; AES-GCM, ECDH and HKDF provide encryption and key envelopes. Users
who receive keys or plaintext can retain them, and the public repository exposes
source. Obfuscation is not DRM or a guarantee against saving content.

The build tool is npm `javascript-obfuscator` **5.9.0**, with every transitive
dependency and package integrity digest pinned in `package-lock.json`. Only its
local offline `obfuscate` API is called; no Pro/cloud service is used. Node and
the obfuscator are development tools. The container build context excludes npm
packages and dependency directories; runtime images ship generated assets.

Options use source-hash seeds, hexadecimal local identifier renaming, string
arrays, index shifts and shuffling, while retaining public API properties and
global interfaces. `browser-no-eval` output introduces no eval or dynamic
Function. Control-flow flattening, dead-code injection, RC4/Base64 string
decoding, anti-debugging, self-defending transformations and property renaming
are disabled. Each output is bounded to 256 KiB. These settings preserve the
streaming decryption control path instead of adding heavy runtime transformations.
Options follow the [upstream documentation](https://github.com/javascript-obfuscator/javascript-obfuscator/blob/master/README.md);
the lockfile identifies the actual build version.

```sh
npm ci --ignore-scripts --no-fund --no-audit
npm run build:media-crypto
node scripts/obfuscate-media-crypto.mjs --check
node tests/media_crypto_build_smoke.mjs
node tests/media_crypto_smoke.mjs
FC_CRYPTO_COMPILED=1 node tests/media_crypto_smoke.mjs
```

The build manifest records source/output SHA-256 and byte sizes, plus hashes of
the configuration, build script and lockfile. The service worker imports the
compiled common module with its output hash as a version parameter. There are
no timestamps or random build seeds: identical inputs must generate identical
bytes. Unbuilt source, output or lockfile changes fail `--check`. That check
uses Node built-ins; lightweight CI downloads no npm dependency and does not
run the obfuscator.

The root worker script has its own response CSP: only same-origin script imports
and same-origin or HTTPS connections are allowed. HTTPS connections support the
existing Direct and Relay storage URLs. APIs and other static assets use the
restrictive default policy. Browser acceptance registers this worker through real Nginx/TLS
and executes its imports and encrypted data requests; a Node VM does not enforce
worker response CSP.

The 2026-10-10 development-workspace checks ran the same real-WebCrypto,
service-worker Range/authorization-expiry and ZIP64 regressions against source
and compiled modules. Both passed; two consecutive builds produced identical
output SHA-256 values. The 129 build dependency packages occupied approximately
41.5 MiB, and that npm audit reported no known vulnerabilities. The three
delivered scripts occupied approximately 45.0 KiB. These are local build and
behavior checks, not development-host database, real-browser or staging
acceptance evidence. No production node was deployed by this step.

`TestBrowserEncryptedHTTPClusterPrimaryDirectRelayLifecycle` subsequently passed
against the current compiled modules in the Windows development workspace. It
connects Node real-WebCrypto page/worker adapters to real Gin TLS endpoints and
tests two encrypted files per Primary, Direct and Relay placement. Each pair
reuses one ECDH session, receives wrapped grants, decrypts complete downloads and
seeks across authenticated chunk boundaries, then preserves ciphertext hashes,
descriptors and stable IDs through rename. Audit-failed local and offline remote
deletion retain ciphertext/quota until recovery; Direct lost-finalize recovery
publishes the existing storage receipt. Disk/SQL checks verify nonce tombstones
and both nodes' quota. DOM/OPFS, the signed cluster transport and the Nginx
X-Accel relay remain test adapters. This is HTTP/WebCrypto interoperability
evidence, not real-browser, real-Nginx or deployment acceptance; tests skip when
Node is unavailable, and such a skip is not interoperability evidence.

# Current capabilities and limits

This page tracks the current source. It describes implementation, not a fresh
production inspection or a new execution of every acceptance gate.

| Feature | Current behavior | Limit |
| --- | --- | --- |
| Roles | Standalone, one Master, Direct / Relay storage | No independent storage business site, multi-Master or automatic failover. |
| Nodes | Compact summaries; manually expand resource, certificate, backup and retirement details | Data refresh preserves expansion only for the current page session. |
| Node resource migration | Independent planning/task/progress/control module | Whole-parent cutover; no Master data relay or Master Local endpoint. |
| Continuous audio | Compatible MP3 uses one MSE session, rolling buffering and interrupted-read retry | No 128 MiB total-track cap; other formats retain browser/single-track limits. |
| Artwork | Visible queue metadata on demand; best-effort small player thumbnails | Pictures must not block playback; large covers keep original image quality. |
| Encryption | Browser chunked AES-GCM; server permissions, descriptors and small key envelopes | No server decryption of ordinary media and no DRM guarantee. |
| Upload reclamation | Leases, journals and physical-presence proofs | Refresh/offline alone never permits deletion; unknown bytes and pending work remain blocking. |
| TLS | Go issuance/renewal; Admin status and audited certificate/key export | Certificate agent has no project-upgrade responsibility. |
| Releases | Registered hosts run `foc upgrade`, with one confirmation | Per host; no automatic new service, mount or environment deployment. |
| Upgrade recovery | Database, configuration, identity, certificates and control state | Excludes media, lyrics and recording content; not fresh-machine disaster recovery. |

## Cache lifetimes

- Versioned Logo: one-year browser HTTP cache, subject to browser eviction.
- Plain artwork: five-minute private HTTP cache; ETag revalidation may return 304.
- Decrypted metadata, artwork and thumbnails: page memory, without plaintext/key
  persistence. The service worker separately caches at most 32 MiB of authenticated
  ciphertext for five minutes; worker restart discards it. Reuse still checks
  current authorization and authenticates GCM chunks.
- Catalog and artwork-candidate caches have separate bounds; neither may bypass
  hidden, deleted, replaced or no-longer-authorized object checks.

Reload may reuse HTTP cache or a surviving worker's ciphertext. Restarting a
browser does not guarantee encrypted covers avoid another download. See
[metadata/artwork](music-metadata.md), [encryption](browser-media-encryption.md)
and [continuous playback](audio-continuous-stream.md).

## Removed and unshipped features

Updater, Admin release/rollback controls, the external CD receiver, Compute Worker,
format conversion and its deployment controller are removed. Video uses browser
decoding without automatic repair of incompatible audio. Voice control has only
been evaluated; it is not implemented.

`fc` remains the operator bundle/backend name. The host-global launcher is `foc`
to avoid replacing Bash's builtin. Default Compose requires `foc-host-init`
before application initialization. First use verifies/registers the running
deployment. A separately pinned published bootstrap backend may precede the
application version; normal upgrade refreshes it when needed. Older deployments
retain the separate Compose installer; see [daily operation](foc-quickstart.md).

Persisted `Follower`, `only_stroge`, historical schema snapshots, recovery journals
and absence regressions retain compatibility/recovery value. Old names alone
are not grounds for deletion. Dated audits prove only their recorded source/scope.

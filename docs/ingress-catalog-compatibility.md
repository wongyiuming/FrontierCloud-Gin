# Public catalog compatibility for the encrypted tree

This matrix records the existing behavior that the new catalog must preserve.
It is not an authorization decision, an implementation claim, or permission to
activate a non-Master public ingress. The Master remains the sole authority.

| Surface | Existing scope and selection | Existing order |
| --- | --- | --- |
| Public categories, default | Active media beneath the requested parent, excluding paths hidden directly or by an ancestor. A child category appears only when it contains matching media. | Directory preference descending; Unicode case-folded child name ascending; original child name ascending for ties. |
| Public categories, `include_hidden=true` | Existing public route explicitly includes hidden categories; the parameter is not an Admin login or a user identity. | The same directory ordering. |
| Public media catalog | Active media that are direct children of the requested category. Ordinary category lists filter hidden entries. An exact address opens its hidden category, and the existing reveal gesture opens the expanded lists. | Media preference descending; full media path ascending under Go string comparison; media ID ascending for ties. |
| Single-object media and lyrics | Hiding a category controls discovery. Playback of an exact audio or video still uses the active ingress, current object and placement, and normal browser key session. Linked lyrics use their own association and access checks. Preserve the internal default-lyric fallback without presenting it as a user-managed lyric. | Not a catalog ordering rule. |
| Karaoke recordings | Authenticated account session and user ID scope recordings separately from the public media catalog. | Existing recording-list contract, not a public media-tree cursor. |

The public catalog has no per-user media ACL. `include_hidden` controls which
entries are displayed. Playback is available through an exact address and
follows the same object authorization checks regardless of listing visibility.
A continuation cursor carries no user privileges.

Directory preference comes from directory objects and
`media_playback_stats.preference`; media preference comes from the same stats
by media ID. Preference is bounded by the existing -7..500000 rule. Playback
score is returned but does **not** participate in `sortTracks`. Existing
priority edits, drag ordering, path moves, insertion, removal, visibility changes
and ancestor changes must atomically update or invalidate the relevant sorted
index and continuation state. Playback accounting still needs a consistent
snapshot of its returned value, without invalidating sorted order solely because
the score changed.

Relevant regression baselines include `TestPublicPagesAndCatalogContract`,
`TestDirectoryCaseFoldTiesMatchPublicAdminAndDrag`, and
`TestEqualPriorityCatalogStableAcrossSessionsAndCache`. The old path and audit
tables contain plaintext names: a production encrypted-tree implementation must
replace or protect those records and coordinate all writers and recovery.

The present tree listing is an isolated primitive, not a product catalog. Its
keyed order is not the product order. Production still needs bounded resumable
sorted indices for both display ranges, atomic mutation/recovery, authenticated
scope-bound cursors, and one-core/memory validation on large directories. It
must not silently truncate entries or treat a scan budget as a permanent empty
directory. Tree-mode legacy catalog and artwork readers remain fail closed until
their replacements meet these conditions.

# Preproduction feature ledger (2026-11-13)

Baseline: production is deployed from Gin `main`, as confirmed by the owner.
Remote main was verified as `64901e2f2d66a125fceb401c934ebc24be44b05d`
(PR #41, 2026-10-28). Current staging receipt:
`preprod-0296ecb32e15375ea4c8c555`.

Count one independently observable capability or defect once. Do not count
files, commits, deployments, iterations, multiple screen sizes or three links
affected by the same defect as additional updates. These are verified items,
not a claim that every historical patch has been audited or the release is ready.

## Confirmed staging lead: 23 items

### 8 new capabilities

1. Explicit public ingress selection independent of the sole Master and object
   ownership, including confirmation before changing ingress.
2. Encrypted logical file tree and random physical object names, with the same
   encrypted resource format on Master and resource nodes.
3. Upload explicitly selects a destination node address/identity; no silent
   switch to another placement when the chosen target cannot accept it.
4. Existing node communication reports simple host CPU and memory observations.
5. Node inventory searches names/addresses/IDs and filters type and status.
6. Node operations split into inventory, public routing/transport, backup
   recovery points and node settings navigation.
7. Encrypted business recovery-point capture, verified archive receipts and
   visible backup health on the two retained staging storage nodes.
8. Distinct low-saturation Direct and Relay status colors.

### 15 corrected defects

1. An S3 status failure no longer empties the native node-management module.
2. Business recovery-point backup can complete instead of repeatedly failing.
3. Admin directory download no longer fails with resource unavailable.
4. Lyrics can be selected before selecting a song, preserving the intended flow.
5. Lyric track/file/relation totals load correctly instead of zero/blank.
6. Same-name automatic lyric association control becomes usable after loading.
7. The three homepage brand logos survive ingress changes.
8. Fullscreen lyrics no longer show the unintended outer scrollbar.
9. Versioned static/crypto resources reuse browser cache on warm navigation.
10. Node disclosure works from the complete header, not only its small button.
11. Focusing a node button no longer stalls automatic telemetry refresh.
12. The separate backup module's single card no longer occupies a narrow column.
13. SQLite IP security UI no longer instructs the operator to query MySQL.
14. Admin public-view/return links follow the selected ingress, not stale Master.
15. Narrow K歌 layouts no longer overflow or overlap header controls.

Evidence for these counts is the completed staging image receipts and browser
acceptance records, not draft source or total diff size. In particular the
November 12 cache/lyrics receipt records warm crypto transfer bytes = 0 and a
474ms warm music DOM; the November 13 browser runs cover ingress round trips,
logos, lyrics, directory ZIP CRC, disclosure/polling, and five K歌 widths.

## Not counted as delivered functionality

- The misleading legacy retirement report is now refused. This is a safety
  mitigation; complete sealed-tree retirement inventory is not restored.
- Sealed-tree native resource migration is not connected to the GUI/runtime.
- cc Relay-to-Direct deployment/application readiness remains incomplete.
- S3 remains deferred and unavailable; it is not counted as a working addition.
- Real microphone recording/upload and full disaster-restore drills are not
  certified by a working Start button or a healthy backup badge.
- Log-node management is newly resumed development, not a staging capability.
- Long-stall timeout recovery and S3 migration were canceled; do not count them.
- IPv6 `.env` bind settings already exist in baseline main and are not counted
  as a new capability merely because they were discussed in this chat.
- Historical parser, hidden-video and resource-label patches need their own
  exact acceptance ledger before adding them to this confirmed total.

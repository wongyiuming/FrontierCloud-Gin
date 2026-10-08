# Directory rename recovery and first-load diagnostics

## Confirmed directory failure

The Master had one durable `rename_pending` operation for `music/黄耀明CD`
to `music/黄耀明`, containing 495 Master-local objects. All source files
existed with their recorded sizes. The destination contained only four empty
subdirectories, but no registered destination resources.

SQL admitted the operation because it checked registered destination objects,
not the physical empty directory. The subsequent exclusive filesystem rename
correctly refused to overwrite an existing directory. Public active-only
catalogs excluded fenced records; the management tree incorrectly did the same.
This was an admission/management bug, not deletion of 495 files.

Recovery first took a consistent SQLite database-only snapshot. Five empty
directories (four children and the destination itself) were removed with
`rmdir`, which refuses to delete files. The existing native worker resumed the
original operation and committed its catalog/path changes transactionally.
No manual SQL writes or file re-imports were used. All 495 files and object IDs,
priority/playback metadata, lyric links and visibility metadata were verified.

The fix checks the local destination under the same filesystem mutation lease
as uploads before committing a new intent. Existing intents remain replayable.
Pending remote/partial moves remain fenced from public playback, but are now
visible in the authenticated management tree/search with their operation and
destination, instead of escaping administrator visibility. Pending objects are
not eligible for download/delete/hide until reconciliation completes. This
does not authorize overwriting a remote destination or guessing a rollback.

Regression coverage includes an existing empty destination, pending operation
visibility versus public exclusion, and identity-preserving roll-forward.

## First-load evidence boundary

Only 2026-10-08 16:29–17:30 Asia/Shanghai was inspected for the reported car
browser visit. Nginx and Web logs did not retain User-Agent; the audit tables
with UA did not identify Tesla/QtCar in that interval. Consequently there is no
reliable historical car IP/carrier identification or proved incident root cause.

A separate confirmed startup dependency has been fixed: the category page no
longer waits for a synchronously downloaded network-observation script before
rendering its embedded catalog. An isolated browser test keeps observation
download pending while verifying that category cards still appear. This is not
mainland-carrier testing and must not be represented as a Tesla reproduction.

Nginx now records escaped UA and upstream timing segments, but still omits
credential-bearing query strings. UA can be spoofed, and HTTP access logs
cannot diagnose requests that fail before HTTP during DNS/TLS setup. A trusted
car source IP/carrier or a user-provided probe on that carrier is still required
for the requested mainland network acceptance.

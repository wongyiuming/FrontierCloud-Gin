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
with UA did not identify Tesla/QtCar in that interval. The subsequent IP-based
correlation found one sustained business visitor, consistent with the user's
report that only their car was browsing continuously. This is a candidate
identification, not a recovered UA or a proved incident root cause.

The candidate made 228 requests: 147 HTTP 200, 44 HTTP 204, 25 HTTP 307,
eight HTTP 429, three HTTP 303 and one HTTP 499. Official
[APNIC ASN registration](https://rdap.apnic.net/autnum/56041) identifies its
exit network as China Mobile Zhejiang (`CMNET-Zhejiang-AP`, AS56041).
This establishes the network registration, not the physical vehicle location
or absence of an intermediate proxy. Other visitors' addresses are omitted.

The first home request was 16:32:09, followed by directory fetch at 16:32:14
and observation POST at 16:32:15. The 429 responses were observation requests,
not playback or directory throttling. The 303 responses were explicit cache
refreshes; 307 responses were root/icon-version redirects, not a media loop.
The 17:26:08 category request was cancelled by the client (499), followed by a
successful retry at 17:26:10 and key scripts at 17:26:11. There was no 504 or
minute-long HTTP processing evidence. Large icons remain a cold-load cost,
but the existing log does not prove that they caused the reported delay.

A separate confirmed startup dependency has been fixed: the category page no
longer waits for a synchronously downloaded network-observation script before
rendering its embedded catalog. An isolated browser test keeps observation
download pending while verifying that category cards still appear. This is not
mainland-carrier testing and must not be represented as a Tesla reproduction.

Nginx now records escaped UA and upstream timing segments, but still omits
credential-bearing query strings. UA can be spoofed, and HTTP access logs
cannot diagnose requests that fail before HTTP during DNS/TLS setup. A trusted
mainland probe on the identified carrier and a client performance timeline are
still required for the requested network reproduction. No such probe was
available during this inspection.

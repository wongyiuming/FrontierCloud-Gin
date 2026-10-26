"""Fast schema/protocol asset checks, not a substitute for real-driver acceptance."""
import json
import hashlib
import re
from pathlib import Path
import sqlite3

from check_ci_budget import check_workflows


root = Path(__file__).resolve().parents[1]
issues = check_workflows(root / ".github/workflows")
if issues:
    raise SystemExit("\n".join(issues))
for path in (root / "protocol").rglob("*.json"):
    json.loads(path.read_text(encoding="utf-8"))
for generation, tables in ((2, 34), (3, 36), (4, 36), (5, 45), (6, 46), (7, 49), (8, 54)):
    documents = [json.loads((root / "migrations" / kind / f"{generation:04d}-schema.json").read_text(encoding="utf-8"))
                 for kind in ("sqlite", "mysql")]
    assert all(document["generation"] == generation for document in documents)
    with sqlite3.connect(":memory:") as database:
        for statement in documents[0]["statements"]:
            database.execute(statement)
        assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert database.execute("SELECT COUNT(*) FROM sqlite_schema WHERE type='table'").fetchone()[0] == tables
additions = []
for kind in ("sqlite", "mysql"):
    old = json.loads((root / "migrations" / kind / "0004-schema.json").read_text(encoding="utf-8"))["statements"]
    current = json.loads((root / "migrations" / kind / "0005-schema.json").read_text(encoding="utf-8"))["statements"]
    assert current[:len(old)] == old, "Resource migration must preserve the historical schema"
    additions.append(current[len(old):])
    names = {re.match(r"CREATE TABLE IF NOT EXISTS (\w+)", item).group(1)
             for item in additions[-1] if item.startswith("CREATE TABLE")}
    if kind == "sqlite":
        sqlite_names = names
    else:
        assert names == sqlite_names and len(names) == 9, "Both backends need the same task model"
checksum = hashlib.sha256("\n".join(additions[0]).encode()).hexdigest()
constant = re.search(r'const ResourceMigrationChecksum = "([a-f0-9]{64})"',
                     (root / "migrations/schema.go").read_text(encoding="utf-8")).group(1)
assert checksum == constant, "Resource migration journal checksum differs from canonical DDL"
for kind in ("sqlite", "mysql"):
    old = json.loads((root / "migrations" / kind / "0005-schema.json").read_text())["statements"]
    current = json.loads((root / "migrations" / kind / "0006-schema.json").read_text())["statements"]
    assert current[:-1] == old and current[-1].startswith("CREATE TABLE IF NOT EXISTS migration_peer_bindings")
    if kind == "sqlite":
        digest = hashlib.sha256(current[-1].encode()).hexdigest()
        constant = re.search(r'const PeerBindingsChecksum = "([a-f0-9]{64})"', (root / "migrations/schema.go").read_text()).group(1)
        assert digest == constant
s3_additive = {}
for kind in ("sqlite", "mysql"):
    previous = json.loads((root / "migrations" / kind / "0007-schema.json").read_text(encoding="utf-8"))["statements"]
    current = json.loads((root / "migrations" / kind / "0008-schema.json").read_text(encoding="utf-8"))["statements"]
    assert current[:len(previous)] == previous, "S3 migration must preserve every generation-7 statement"
    additions = current[len(previous):]
    names = {re.match(r"CREATE TABLE IF NOT EXISTS (\w+)", value).group(1)
             for value in additions if value.startswith("CREATE TABLE")}
    assert names == {"s3_members", "s3_uploads", "s3_upload_parts", "s3_objects", "s3_probe_journal"}
    s3_additive[kind] = "\n".join(additions)
    if kind == "mysql":
        probe = next(value for value in additions if value.startswith("CREATE TABLE IF NOT EXISTS s3_probe_journal "))
        part = next(value for value in additions if value.startswith("CREATE TABLE IF NOT EXISTS s3_upload_parts "))
        catalog = next(value for value in current if value.startswith("CREATE TABLE IF NOT EXISTS global_media_objects "))
        assert "etag VARCHAR(512) NOT NULL" in probe, "probe cleanup must preserve provider ETags"
        assert "etag VARCHAR(128) NOT NULL" in part and "etag VARCHAR(128) NOT NULL" in catalog
digest = hashlib.sha256(("sqlite\n" + s3_additive["sqlite"] + "\nmysql\n" + s3_additive["mysql"]).encode()).hexdigest()
constant = re.search(r'const S3Checksum = "([a-f0-9]{64})"',
                     (root / "migrations/schema.go").read_text(encoding="utf-8")).group(1)
assert digest == constant, "S3 journal checksum differs from canonical backend DDL"
print("Protocol JSON and canonical SQLite schema assets passed; full acceptance remains external")

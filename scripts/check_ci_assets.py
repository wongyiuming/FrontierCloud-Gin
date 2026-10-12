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
for generation, tables in ((2, 34), (3, 36), (4, 36), (5, 45)):
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
print("Protocol JSON and canonical SQLite schema assets passed; full acceptance remains external")

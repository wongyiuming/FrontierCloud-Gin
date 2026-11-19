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
for generation, tables in ((2, 34), (3, 36), (4, 36), (5, 45), (6, 46), (7, 49), (8, 54), (9, 56), (10, 77)):
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
public_routing = {}
for kind in ("sqlite", "mysql"):
    previous = json.loads((root / "migrations" / kind / "0008-schema.json").read_text(encoding="utf-8"))["statements"]
    current = json.loads((root / "migrations" / kind / "0009-schema.json").read_text(encoding="utf-8"))["statements"]
    assert current[:len(previous)] == previous, "Public routing must preserve generation-8 statements"
    additions = current[len(previous):]
    names = {re.match(r"CREATE TABLE IF NOT EXISTS (\w+)", value).group(1) for value in additions}
    assert names == {"public_ingress_config", "native_transport_policy"}
    public_routing[kind] = "\n".join(additions)
digest = hashlib.sha256(("sqlite\n" + public_routing["sqlite"] + "\nmysql\n" + public_routing["mysql"]).encode()).hexdigest()
constant = re.search(r'const PublicRoutingChecksum = "([a-f0-9]{64})"',
                     (root / "migrations/schema.go").read_text(encoding="utf-8")).group(1)
assert digest == constant, "Public routing journal checksum differs from canonical backend DDL"
sealed_tree = {}
for kind in ("sqlite", "mysql"):
    previous = json.loads((root / "migrations" / kind / "0009-schema.json").read_text(encoding="utf-8"))["statements"]
    current = json.loads((root / "migrations" / kind / "0010-schema.json").read_text(encoding="utf-8"))["statements"]
    assert current[:len(previous)] == previous, "Sealed tree schema must preserve generation-9 statements"
    additions = current[len(previous):]
    names = {re.match(r"CREATE TABLE IF NOT EXISTS (\w+)", value).group(1)
             for value in additions if value.startswith("CREATE TABLE")}
    assert names == {"sealed_tree_meta", "sealed_tree_records", "sealed_tree_encryption_ids",
                     "sealed_tree_blob_ids", "sealed_tree_placements", "sealed_tree_aliases", "sealed_tree_revocations", "sealed_tree_facts", "sealed_tree_operation_ids",
                     "sealed_tree_pending_files", "sealed_tree_pending_facts", "sealed_tree_fence", "sealed_tree_owner_fence", "sealed_tree_capacity_intents", "sealed_tree_capacity_meta", "sealed_tree_capacity_accounts", "sealed_tree_capacity_ids", "sealed_tree_source_pin", "sealed_tree_capacity_scopes", "sealed_tree_listing_meta", "sealed_tree_listing"}
    sealed_tree[kind] = "\n".join(additions)
digest = hashlib.sha256(("sqlite\n" + sealed_tree["sqlite"] + "\nmysql\n" + sealed_tree["mysql"]).encode()).hexdigest()
constant = re.search(r'const SealedTreeChecksum = "([a-f0-9]{64})"',
                     (root / "migrations/schema.go").read_text(encoding="utf-8")).group(1)
assert digest == constant, "Sealed tree journal checksum differs from canonical backend DDL"
legacy_intent = {}
for kind in ("sqlite", "mysql"):
    previous = json.loads((root / "migrations" / kind / "0010-schema.json").read_text(encoding="utf-8"))["statements"]
    document = json.loads((root / "migrations" / kind / "0011-schema.json").read_text(encoding="utf-8"))
    assert document["generation"] == 11
    current = document["statements"]
    assert current[:len(previous)] == previous, "Enrollment schema must preserve generation-10 statements"
    additions = current[len(previous):]
    names = {re.match(r"CREATE TABLE IF NOT EXISTS (\w+)", value).group(1)
             for value in additions if value.startswith("CREATE TABLE")}
    assert names == {"legacy_read_control_intents"}
    legacy_intent[kind] = "\n".join(additions)
digest = hashlib.sha256(("sqlite\n" + legacy_intent["sqlite"] + "\nmysql\n" + legacy_intent["mysql"]).encode()).hexdigest()
constant = re.search(r'const LegacyReadIntentChecksum = "([a-f0-9]{64})"',
                     (root / "migrations/schema.go").read_text(encoding="utf-8")).group(1)
assert digest == constant, "Enrollment intent journal checksum differs from canonical backend DDL"
selected_upload = {}
for kind in ("sqlite", "mysql"):
    previous = json.loads((root / "migrations" / kind / "0011-schema.json").read_text(encoding="utf-8"))["statements"]
    document = json.loads((root / "migrations" / kind / "0012-schema.json").read_text(encoding="utf-8"))
    assert document["generation"] == 12
    current = document["statements"]
    assert current[:len(previous)] == previous, "Selected uploads must preserve generation-11 statements"
    additions = current[len(previous):]
    names = {re.match(r"CREATE TABLE IF NOT EXISTS (\w+)", value).group(1)
             for value in additions if value.startswith("CREATE TABLE")}
    assert names == {"selected_upload_intents", "selected_upload_parent_scopes", "selected_upload_cancellations",
                     "selected_s3_uploads", "selected_s3_parts", "sealed_recording_audio"}
    selected_upload[kind] = "\n".join(additions)
digest = hashlib.sha256(("sqlite\n" + selected_upload["sqlite"] + "\nmysql\n" + selected_upload["mysql"]).encode()).hexdigest()
constant = re.search(r'const SelectedUploadIntentChecksum = "([a-f0-9]{64})"',
                     (root / "migrations/schema.go").read_text(encoding="utf-8")).group(1)
assert digest == constant, "Selected upload journal checksum differs from canonical backend DDL"
opaque_migration = {}
for kind in ("sqlite", "mysql"):
    previous = json.loads((root / "migrations" / kind / "0012-schema.json").read_text(encoding="utf-8"))["statements"]
    document = json.loads((root / "migrations" / kind / "0013-schema.json").read_text(encoding="utf-8"))
    assert document["generation"] == 13
    current = document["statements"]
    assert current[:len(previous)] == previous, "Opaque migrations must preserve generation-12 statements"
    additions = current[len(previous):]
    names = {re.match(r"CREATE TABLE IF NOT EXISTS (\w+)", value).group(1)
             for value in additions if value.startswith("CREATE TABLE")}
    assert names == {"opaque_migration_tasks", "opaque_migration_units", "opaque_migration_objects"}
    opaque_migration[kind] = "\n".join(additions)
digest = hashlib.sha256(("sqlite\n" + opaque_migration["sqlite"] + "\nmysql\n" + opaque_migration["mysql"]).encode()).hexdigest()
constant = re.search(r'const OpaqueMigrationChecksum = "([a-f0-9]{64})"',
                     (root / "migrations/schema.go").read_text(encoding="utf-8")).group(1)
assert digest == constant, "Opaque migration journal checksum differs from canonical backend DDL"
print("Protocol JSON and canonical SQLite schema assets passed; full acceptance remains external")

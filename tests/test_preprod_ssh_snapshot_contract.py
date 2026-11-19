"""Linux-only synthetic checks for the unregistered read-only SSH collector."""
import ast
import hashlib
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]


def remote_program(name="_REMOTE"):
    tree = ast.parse((ROOT / "scripts/preprod_ssh_snapshot.py").read_text(encoding="utf-8"))
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {name, "_REMOTE_CPU"} and isinstance(node.value, ast.Constant):
                    values[target.id] = ast.literal_eval(node.value)
    return values[name].replace("# CPU_BUDGET_HELPER", values["_REMOTE_CPU"])


@unittest.skipUnless(sys.platform == "linux", "requires Linux process and cgroup semantics")
class SnapshotCollectorContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dbpath = pathlib.Path(self.tmp.name) / "frontiercloud.db"
        self.db = sqlite3.connect(self.dbpath)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE node_identity(singleton INTEGER,node_id TEXT,role TEXT)")
        self.db.execute("INSERT INTO node_identity VALUES(1,?, 'Master')", ("a" * 32,))
        tables = {
            "media_objects": "media_id object_kind media_path path_locator created_at updated_at",
            "global_media_objects": "media_id storage_member_id object_id media_path object_kind size_bytes etag state created_at updated_at path_locator",
            "media_visibility": "relative_path hidden updated_at",
            "media_playback_stats": "media_id media_path preference play_score created_at updated_at",
            "media_lyric_links": "media_id media_path lyric_id lyric_path created_at updated_at",
            "media_encryption": "object_kind object_id file_id descriptor_json created_at",
            "cluster_storage_members": "member_id relationship_id member_kind transport storage_enabled allocated_bytes used_bytes reserved_bytes physical_free_bytes health writable updated_at",
            "node_relationships": "relationship_id peer_id peer_endpoint peer_key direction mode state created_at",
            "media_crypto_keys": "singleton key_id created_at",
        }
        for table, columns in tables.items():
            self.db.execute("CREATE TABLE " + table + " (" + ",".join(c + " TEXT" for c in columns.split()) + ")")
        self.db.execute("INSERT INTO media_crypto_keys VALUES('1',?,'1')", ("b" * 64,))
        self.db.commit()
        self.cgroup = pathlib.Path(self.tmp.name) / "cgroup"
        (self.cgroup / "group").mkdir(parents=True)
        self.cpu = self.cgroup / "group/cpu.max"
        self.self_cgroup = pathlib.Path(self.tmp.name) / "self.cgroup"
        self.self_cgroup.write_text("0::/group\n")
        self.pressure = pathlib.Path(self.tmp.name) / "io.pressure"
        self.cpu.write_text("max 100000\n")
        self.pressure.write_text("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def launch(self, *, max_io_psi=1e9, program="_REMOTE", query=None):
        script = (remote_program(program)
                  .replace("'/opt/frontiercloud/data/frontiercloud.db'", repr(str(self.dbpath)))
                  .replace("'/sys/fs/cgroup'", repr(str(self.cgroup)))
                  .replace("'/proc/self/cgroup'", repr(str(self.self_cgroup)))
                  .replace("'/proc/pressure/io'", repr(str(self.pressure))))
        p = subprocess.Popen([sys.executable, "-B", "-c", script], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        budget = {"max_load_ratio": 1e9, "max_io_psi": max_io_psi, "bytes_per_second": 1024 * 1024}
        budget.update(query or {})
        p.stdin.write((json.dumps(budget) + "\n").encode())
        p.stdin.flush()
        return p

    def test_read_only_transaction_returns_all_fixed_sections(self):
        p = self.launch()
        raw = p.stdout.read()
        error = p.stderr.read()
        self.assertEqual(p.wait(timeout=10), 0, error.decode(errors="replace"))
        p.stdin.close()
        p.stdout.close()
        p.stderr.close()
        result = json.loads(raw)
        self.assertEqual(result["node"], "a" * 32)
        self.assertEqual(len(result["sections"]), 9)
        self.assertEqual(self.db.execute("SELECT role FROM node_identity").fetchone(), ("Master",))

    def test_pressure_limit_fails_before_snapshot_output(self):
        self.pressure.write_text("some avg10=20.00 avg60=0.00 avg300=0.00 total=0\n")
        p = self.launch(max_io_psi=1)
        raw = p.stdout.read()
        p.stderr.read()
        self.assertNotEqual(p.wait(timeout=10), 0)
        p.stdin.close()
        p.stdout.close()
        p.stderr.close()
        self.assertEqual(raw, b"")

    def test_root_cgroup_without_cpu_max_is_valid(self):
        self.self_cgroup.write_text("0::/\n")
        p = self.launch()
        raw, error = p.stdout.read(), p.stderr.read()
        self.assertEqual(p.wait(timeout=10), 0, error.decode(errors="replace"))
        p.stdin.close(); p.stdout.close(); p.stderr.close()
        self.assertEqual(json.loads(raw)["node"], "a" * 32)

    def test_object_facts_respects_pressure_budget(self):
        media_id, owner_id = "b" * 64, "a" * 32
        name = "music/album/song.mp3"
        self.db.execute("INSERT INTO global_media_objects VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (media_id, owner_id, "c" * 64, name, "audio", "3", "weak", "active", "1", "1", hashlib.sha256(name.encode()).hexdigest()))
        self.db.execute("INSERT INTO cluster_storage_members VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (owner_id, None, "MasterLocal", "Local", "1", "0", "0", "0", "0", "online", "1", "1"))
        self.db.commit()
        query = {"media_id": media_id, "owner_id": owner_id}
        p = self.launch(program="_REMOTE_FACTS", query=query)
        raw, error = p.stdout.read(), p.stderr.read()
        self.assertEqual(p.wait(timeout=10), 0, error.decode(errors="replace"))
        p.stdin.close(); p.stdout.close(); p.stderr.close()
        self.assertEqual(json.loads(raw)["facts"]["placement"][0], media_id)
        self.db.execute("UPDATE global_media_objects SET path_locator='invalid' WHERE media_id=?", (media_id,))
        self.db.commit()
        p = self.launch(program="_REMOTE_FACTS", query=query)
        raw = p.stdout.read(); p.stderr.read()
        self.assertNotEqual(p.wait(timeout=10), 0)
        p.stdin.close(); p.stdout.close(); p.stderr.close()
        self.assertEqual(raw, b"")
        self.db.execute("UPDATE global_media_objects SET path_locator=? WHERE media_id=?", (hashlib.sha256(name.encode()).hexdigest(),media_id))
        self.db.commit()
        self.pressure.write_text("some avg10=20.00 avg60=0.00 avg300=0.00 total=0\n")
        p = self.launch(program="_REMOTE_FACTS", query=query, max_io_psi=1)
        raw = p.stdout.read(); p.stderr.read()
        self.assertNotEqual(p.wait(timeout=10), 0)
        p.stdin.close(); p.stdout.close(); p.stderr.close()
        self.assertEqual(raw, b"")

    def test_long_unicode_path_is_collected_without_byte_truncation(self):
        media_id, owner_id = "d" * 64, "a" * 32
        name = "music/" + "🧪" * 300 + "/" + "中" * 200 + "/song.mp3"
        self.assertGreater(len(name.encode()), 1024)
        self.db.execute("INSERT INTO global_media_objects VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (media_id, owner_id, "e" * 64, name, "audio", "3", "weak", "active", "1", "1", hashlib.sha256(name.encode()).hexdigest()))
        self.db.execute("INSERT INTO cluster_storage_members VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (owner_id, None, "MasterLocal", "Local", "1", "0", "0", "0", "0", "online", "1", "1"))
        self.db.commit()
        p = self.launch(program="_REMOTE_FACTS", query={"media_id":media_id,"owner_id":owner_id})
        raw, error = p.stdout.read(), p.stderr.read()
        self.assertEqual(p.wait(timeout=10), 0, error.decode(errors="replace"))
        p.stdin.close(); p.stdout.close(); p.stderr.close()
        self.assertEqual(json.loads(raw)["path"], name)

    def test_disconnect_cancels_during_bounded_stream(self):
        name = "music/" + "a" * 980 + ".mp3"
        self.db.executemany("INSERT INTO media_objects VALUES(?,?,?,?,?,?)", [
            (f"{i:064x}", "audio", name, hashlib.sha256(name.encode()).hexdigest(), "1", "1") for i in range(200)
        ])
        self.db.commit()
        p = self.launch()
        try:
            first = p.stdout.read(1)
            if not first:
                self.fail(p.stderr.read().decode(errors="replace"))
            checkpoint = self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            self.assertEqual(checkpoint[0], 0, "streaming must not hold the source SQLite read snapshot")
            p.stdin.close()
            p.stdout.read()
            p.stderr.read()
            self.assertNotEqual(p.wait(timeout=10), 0)
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
            if not p.stdin.closed:
                p.stdin.close()
            p.stdout.close()
            p.stderr.close()

    def test_cooperating_process_lock_and_replaced_inode_fail_closed(self):
        tree = ast.parse((ROOT / "scripts/preprod_ssh_snapshot.py").read_text(encoding="utf-8"))
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_single_collector")
        snippet = ast.unparse(function)
        namespace = {"os": os, "pathlib": pathlib, "stat": __import__("stat"),
                     "threading": threading, "contextmanager": contextmanager,
                     "_PROCESS_BUDGET": threading.Lock()}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "lock-fixture", "exec"), namespace)
        child = ("import os,pathlib,stat,threading\nfrom contextlib import contextmanager\n"
                 "_PROCESS_BUDGET=threading.Lock()\n" + snippet +
                 "\nwith _single_collector(): print('acquired')\n")
        with patch.object(pathlib.Path, "home", return_value=pathlib.Path(self.tmp.name)):
            with self.assertRaisesRegex(ValueError, "lock identity"):
                with namespace["_single_collector"]():
                    env = dict(os.environ, HOME=self.tmp.name)
                    result = subprocess.run([sys.executable, "-B", "-c", child], env=env,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn(b"acquired", result.stdout)
                    lock = pathlib.Path(self.tmp.name) / ".codex/tmp/preproduction-clone-20261104/.source-collector-budget.lock"
                    lock.unlink()
                    lock.write_bytes(b"1")


if __name__ == "__main__":
    unittest.main()

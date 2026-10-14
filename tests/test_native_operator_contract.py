"""Source and isolated API-driver contracts; never operate Docker hosts."""
from __future__ import annotations

import ast
from pathlib import Path
import unittest
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


class NativeOperatorTests(unittest.TestCase):
    def test_inventory_has_exact_native_five_nodes(self):
        source = (ROOT / "internal/nativeacceptance/native_matrix_real_test.go").read_text()
        self.assertIn("const fleetNodeCount = 5", source)
        self.assertIn('"go-sqlite"', source)
        self.assertIn('"go-mysql"', source)
        self.assertNotIn("UPDATER_PROJECT", source)
        self.assertNotIn("updater-control", source)

    def test_chaos_resource_driver_uses_native_tree_contract(self):
        source = (ROOT / "scripts/ops/dev_chaos.py").read_text(encoding="utf-8")
        function = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "resources")
        calls = []

        class FixtureClient:
            def __init__(self, node):
                assert node == "master"

            def api(self, url):
                calls.append(url)
                if url == "/api/v1/media/admin/tree?path=music":
                    return {"items": [{"kind": "directory", "path": "music/歌手"}]}
                return {"items": [
                    {"kind": "file", "media": True, "media_id": "id", "path": "music/歌手/song.mp3",
                     "size": 123, "storage_member_id": "member"},
                    {"kind": "file", "media": False, "size": None},
                ]}

        namespace = {"Client": FixtureClient, "quote": quote}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "resources", "exec"), namespace)
        self.assertEqual(namespace["resources"](), [{"resource_id": "id", "path": "music/歌手/song.mp3",
                                                     "size": 123, "member": "member"}])
        self.assertEqual(calls[-1], "/api/v1/media/admin/tree?path=music%2F%E6%AD%8C%E6%89%8B")

    def test_operator_python_never_executes_inside_web(self):
        source = (ROOT / "scripts/ops/dev_control.py").read_text(encoding="utf-8")
        self.assertIn('"web", "sh", "-c"', source)
        self.assertNotIn('"web", "python"', source)
        self.assertIn('len(inventory["nodes"]) != 5', source)

    def test_import_preserves_album_site_affinity(self):
        source = (ROOT / "scripts/ops/dev_import_media.py").read_text(encoding="utf-8")
        self.assertIn('hashlib.sha256(target_dir.encode())', source)
        self.assertNotIn('site_type = ("primary", "direct", "relay")[index % 3]', source)

    def test_retired_cd_units_and_dispatcher_are_not_distributed(self):
        self.assertFalse((ROOT / "ops/frontiercloud-dev-cd.timer").exists())
        self.assertFalse((ROOT / "ops/frontiercloud-dev-cd.service").exists())
        source = (ROOT / "scripts/ops/dev_control.py").read_text(encoding="utf-8")
        guard = next(n for n in ast.parse(source).body if isinstance(n, ast.If)
                     and ast.unparse(n.test) == "__name__ == '__main__'")
        self.assertIsInstance(guard.body[0], ast.Raise)
        self.assertIn("Legacy development CD is retired", ast.unparse(guard))


if __name__ == "__main__":
    unittest.main()

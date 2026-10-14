"""Keep the owner-approved native frontend dependency boundary explicit."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = {"react", "react-dom", "vue", "@vue/runtime-core", "@angular/core",
             "svelte", "solid-js", "next", "nuxt", "three"}


class FrontendBaselineTests(unittest.TestCase):
    def test_browser_dependencies_do_not_introduce_frontend_frameworks(self):
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        dependencies = set(package.get("dependencies", {})) | set(package.get("devDependencies", {}))
        self.assertFalse(dependencies & FORBIDDEN)
        lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
        for name in FORBIDDEN:
            self.assertNotIn("node_modules/" + name, lock.get("packages", {}))

    def test_shipped_frontend_sources_remain_native_browser_assets(self):
        forbidden_suffixes = {".jsx", ".tsx", ".vue", ".svelte"}
        for path in (ROOT / "static").rglob("*"):
            self.assertNotIn(path.suffix.lower(), forbidden_suffixes, str(path))

    def test_policy_and_agent_instructions_cover_future_frontend_work(self):
        for name in ("ARCHITECTURE.md", "CONTRIBUTING.md", "AGENTS.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("HTML, CSS and native JavaScript", text)
            self.assertIn("MUST", text)


if __name__ == "__main__":
    unittest.main()

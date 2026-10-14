from pathlib import Path
import unittest

import json


ROOT = Path(__file__).resolve().parents[1]


class AdminSystemModulesContractTests(unittest.TestCase):
    def read(self, path: str) -> str:
        return (ROOT / path).read_text(encoding="utf-8")

    def test_release_management_is_removed_from_product(self):
        page = self.read("internal/httpapi/admin.go")
        runtime = self.read("cmd/frontiercloud/http.go")
        schema = json.loads(self.read("protocol/v2/openapi.json"))
        for filename in ("static/js/release-admin.js", "static/js/release-version-ui.js", "internal/httpapi/release.go"):
            self.assertFalse((ROOT / filename).exists())
        self.assertNotIn("js/release-admin.js", page)
        self.assertNotIn("RegisterReleaseAdmin", runtime)
        self.assertNotIn("SocketAgent", runtime)
        self.assertFalse(any(path.startswith("/api/v1/media/admin/nodes/release") for path in schema["paths"]))
        for compose in ("docker-compose.yaml", "docker-compose.gin.yaml"):
            value = self.read(compose)
            for forbidden in ("  updater:", "docker.sock", "updater_control", "maintenance_state"):
                self.assertNotIn(forbidden, value)

    def test_expanded_admin_module_owns_the_viewport(self):
        css = self.read("static/css/admin-system-modules.css")
        focus = self.read("static/js/admin-focus.js")
        self.assertIn("min-height: calc(100dvh - 28px)", css)
        self.assertIn("flex-basis: calc(100dvh - 28px)", css)
        self.assertIn("scrollIntoView", focus)

    def test_site_maintenance_is_independently_visible_and_controllable(self):
        api = self.read("internal/httpapi/site.go")
        service = self.read("internal/sitecontrol/service.go")
        client = self.read("static/js/maintenance-admin.js")
        maintenance = json.loads(self.read("protocol/v2/openapi.json"))["paths"]["/api/v1/media/admin/site/maintenance"]
        self.assertIn('group.GET("/maintenance"', api)
        self.assertIn('group.POST("/maintenance"', api)
        self.assertIn("get", maintenance)
        self.assertIn("post", maintenance)
        self.assertIn(".frontiercloud-force-open", service)
        self.assertNotIn("s.agent", service)
        self.assertNotIn("internal/release", service)
        self.assertIn("站点开放状态", client)
        self.assertIn("进入维护", client)
        self.assertIn("结束维护", client)

    def test_all_existing_brand_logo_management_is_preserved(self):
        brand = self.read("static/js/brand-admin.js")
        self.assertIn("前沿娱乐 / 前沿媒体 / 前沿音乐", brand)
        self.assertIn("state.items.map(card)", brand)


if __name__ == "__main__":
    unittest.main()

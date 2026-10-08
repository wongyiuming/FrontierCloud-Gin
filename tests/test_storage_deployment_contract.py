"""Lightweight architecture guards; real Compose/network proof is external."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StorageDeploymentContract(unittest.TestCase):
    def test_native_http_fixture_uses_the_new_repository_release_pair(self):
        text = (ROOT / "tests/test_gin_http.py").read_text(encoding="utf-8")
        self.assertIn('RELEASE_BRANCH="main", RELEASE_SOURCE_BRANCH="dev"', text)
        self.assertNotIn('RELEASE_BRANCH="gin_main"', text)

    def test_appliance_has_only_one_resident_service_and_exiting_initializers(self):
        text = (ROOT / "docker-compose.storage.yaml").read_text(encoding="utf-8")
        services = text.split("\nservices:\n", 1)[1].split("\nvolumes:\n", 1)[0]
        self.assertEqual(re.findall(r"^  ([a-z-]+):$", services, re.M),
                         ["secrets-init", "media-init", "web"])
        self.assertEqual(services.count('restart: "no"'), 2)
        self.assertEqual(services.count("restart: unless-stopped"), 1)
        for forbidden in ("docker.sock", "updater_control", "mysql:", "redis:", "nginx:", "coturn"):
            self.assertNotIn(forbidden, services)

    def test_storage_uses_high_port_tls_sqlite_and_no_proxy_acceleration(self):
        text = (ROOT / "docker-compose.storage.yaml").read_text(encoding="utf-8")
        for required in ("DEPLOYMENT_MODE: only_stroge", "DB_TYPE: sqlite", 'TLS_ENABLED: "true"',
                         'NGINX_MEDIA_ACCEL: "false"', 'HTTP_ADDR: :8443', '${STORAGE_PORT:-8443}:8443'):
            self.assertIn(required, text)
        self.assertNotRegex(text, r"(?m)^\s+- .*:(?:80|443)(?:\s|$)")

    def test_operator_builds_immutable_web_only_and_never_deletes_data(self):
        script = (ROOT / "scripts/deploy-storage.sh").read_text(encoding="utf-8")
        self.assertIn('build-native-images.sh "$revision" web-only', script)
        self.assertIn("up -d --no-build --wait", script)
        self.assertIn("storage-pair < /dev/null", script)
        self.assertNotIn("down", script)
        self.assertNotIn("prune", script)

    def test_storage_has_no_business_or_updater_route_registration(self):
        text = (ROOT / "cmd/frontiercloud/storage.go").read_text(encoding="utf-8")
        for forbidden in ("RegisterAdmin(", "RegisterPublic(", "RegisterSiteAdmin(",
                          "RegisterReleaseAdmin(", "RegisterNodeRelease("):
            self.assertNotIn(forbidden, text)
        self.assertIn("MinVersion: tls.VersionTLS12", text)
        self.assertNotIn("InsecureSkipVerify:", text)

    def test_history_is_master_only_and_untrusted_pr_text_is_not_html(self):
        text = (ROOT / "static/js/release-admin.js").read_text(encoding="utf-8")
        self.assertIn("refreshHistory", text)
        self.assertIn("version.title", text)
        self.assertIn("systemReleaseNotes').textContent", text)
        for forbidden in ("value.followers", "cluster_convergence_needed", "整个集群", "升级并分发"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()

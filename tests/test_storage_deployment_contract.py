"""Lightweight architecture guards; real Compose/network proof is external."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StorageDeploymentContract(unittest.TestCase):
    def test_certificate_services_are_compose_only_with_persistent_socket_volume(self):
        text = (ROOT / "docker-compose.storage.yaml").read_text(encoding="utf-8")
        for value in ("certificate-init:", "certificate-agent:", "command: [init-certificate]",
                      "build:", "cpus: 0.05", "mem_limit: 128m", "memswap_limit: 128m",
                      "cap_drop: [ALL]", "read_only: true", 'tmpfs: ["/tmp:size=16m,mode=1777"]',
                      "certificate_runtime:/run/frontiercloud-certificate:ro",
                      "certificate_published:/run/frontiercloud-tls:ro"):
            self.assertIn(value, text)
        controller = text.split("  certificate-agent:", 1)[1].split("  web:", 1)[0]
        for forbidden in ("systemctl", "sysusers", "docker.sock", "privileged:", "pid: host", "ports:", "/etc/systemd", "/usr/local/libexec"):
            self.assertNotIn(forbidden, controller)
        self.assertIn("network_mode: host", controller)
        self.assertIn("cap_add: [NET_BIND_SERVICE]", controller)
        for legacy in ("docker-compose.storage-certificate.yaml",
                       "docker-compose.storage-certificate-webroot.yaml",
                       "docker-compose.storage-certificate-temporary.yaml"):
            self.assertFalse((ROOT / legacy).exists(), legacy)
        self.assertNotIn("--http01-directory", controller)
        for path in (ROOT / "scripts/ops").glob("frontiercloud-certificate*"):
            self.fail(f"retired host certificate provision returned: {path}")
        code = (ROOT / "cmd/frontiercloud/certificate.go").read_text(encoding="utf-8")
        self.assertIn("requireCertificateVolumes()", code)
        self.assertNotIn('"os/exec"', code)

    def test_native_http_fixture_uses_the_new_repository_release_pair(self):
        text = (ROOT / "tests/test_gin_http.py").read_text(encoding="utf-8")
        self.assertIn('RELEASE_BRANCH="main", RELEASE_SOURCE_BRANCH="dev"', text)
        self.assertNotIn('RELEASE_BRANCH="gin_main"', text)

    def test_appliance_has_only_one_resident_service_and_exiting_initializers(self):
        text = (ROOT / "docker-compose.storage.yaml").read_text(encoding="utf-8")
        services = text.split("\nservices:\n", 1)[1].split("\nvolumes:\n", 1)[0]
        self.assertEqual(re.findall(r"^  ([a-z-]+):$", services, re.M),
                         ["secrets-init", "media-init", "certificate-init", "certificate-agent", "web"])
        self.assertEqual(services.count('restart: "no"'), 3)
        self.assertEqual(services.count("restart: unless-stopped"), 2)
        for forbidden in ("docker.sock", "updater_control", "mysql:", "redis:", "nginx:", "coturn"):
            self.assertNotIn(forbidden, services)

    def test_storage_uses_explicit_network_profile_sqlite_and_no_proxy_acceleration(self):
        text = (ROOT / "docker-compose.storage.yaml").read_text(encoding="utf-8")
        for required in ("DEPLOYMENT_MODE: only_stroge", "DB_TYPE: sqlite", 'TLS_ENABLED: ${TLS_ENABLED:-true}',
                         'NGINX_MEDIA_ACCEL: "false"', 'HTTP_ADDR: :${STORAGE_PORT:-443}',
                         'STORAGE_TRANSPORT: ${STORAGE_TRANSPORT:-direct}'):
            self.assertIn(required, text)
        for retired in ("STORAGE_TLS_CERT:", "STORAGE_TLS_KEY:", "SSL_CERT_PATH:", "SSL_KEY_PATH:"):
            self.assertNotIn(retired, text)
        config = (ROOT / "internal/config/config.go").read_text(encoding="utf-8")
        self.assertIn('value.StorageTransport == "direct" && value.StoragePort != 443', config)
        self.assertIn('"relay"', config)

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

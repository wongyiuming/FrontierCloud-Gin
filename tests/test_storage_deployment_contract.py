"""Lightweight architecture guards; real Compose/network proof is external."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StorageDeploymentContract(unittest.TestCase):
    def test_built_and_published_web_images_declare_the_same_tls_topology(self):
        # Operator image proof binds this capability to the release contract.
        for name in ("Dockerfile.gin", "ci/Dockerfile.web", "nginx/Dockerfile"):
            with self.subTest(dockerfile=name):
                source = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn('frontiercloud.automatic-tls="1"', source)

    def test_certificate_services_are_compose_only_with_persistent_socket_volume(self):
        text = (ROOT / "docker-compose.storage.yaml").read_text(encoding="utf-8")
        for value in ("certificate-init:", "certificate-agent:", "command: [init-certificate]",
                      "cpus: 0.05", "mem_limit: 128m", "memswap_limit: 128m",
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
                         ["foc-host-init", "secrets-init", "media-init", "certificate-init", "certificate-agent", "web"])
        self.assertEqual(services.count('restart: "no"'), 4)
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

    def test_operator_pulls_public_images_without_build_fallback_or_data_deletion(self):
        script = (ROOT / "scripts/deploy-storage.sh").read_text(encoding="utf-8")
        self.assertIn('exec "$client" install storage', script)
        self.assertNotIn('build-native-images', script)
        compose = (ROOT / "docker-compose.storage.yaml").read_text(encoding="utf-8")
        self.assertIn('ghcr.io/wongyiuming/frontiercloud-gin-web:${FRONTIERCLOUD_REVISION:-latest}', compose)
        self.assertNotIn('build:', compose)
        self.assertIn('FC_OPERATOR_CLIENT:-./fc', script)
        self.assertNotIn('storage-pair', script)
        self.assertNotIn("down", script)
        self.assertNotIn("prune", script)

    def test_storage_has_no_business_or_updater_route_registration(self):
        text = (ROOT / "cmd/frontiercloud/storage.go").read_text(encoding="utf-8")
        for forbidden in ("RegisterAdmin(", "RegisterPublic(", "RegisterSiteAdmin(",
                          "RegisterReleaseAdmin(", "RegisterNodeRelease("):
            self.assertNotIn(forbidden, text)
        self.assertIn("MinVersion: tls.VersionTLS12", text)
        self.assertNotIn("InsecureSkipVerify:", text)

    def test_business_also_has_no_online_upgrade_registration(self):
        text = (ROOT / "cmd/frontiercloud/http.go").read_text(encoding="utf-8")
        self.assertNotIn("RegisterReleaseAdmin", text)
        self.assertNotIn("release.Coordinator", text)


if __name__ == "__main__":
    unittest.main()

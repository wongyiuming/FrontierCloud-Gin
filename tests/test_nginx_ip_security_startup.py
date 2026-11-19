"""Exercise the actual entrypoint's initial policy render without Docker."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("sh") and shutil.which("awk"), "requires POSIX sh and awk")
class NginxIPSecurityStartupTest(unittest.TestCase):
    def run_startup(self, initial=None, appear=False, nginx_fails=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "active-bans.tsv"
            runtime = root / "runtime"
            sleeps = root / "sleeps"
            nginx_called = root / "nginx-called"
            if initial is not None:
                snapshot.write_text(initial, encoding="utf-8")
            script = (ROOT / "nginx/25-ip-security.sh").read_text(encoding="utf-8")
            self.assertEqual(script.count("watch_rules &"), 1)
            script = script.replace("watch_rules &", "# watcher excluded from initial-render test")
            script = script.replace("/app/data/.ip-security/active-bans.tsv", snapshot.as_posix())
            script = script.replace("/etc/nginx/runtime", runtime.as_posix())
            script = script.replace("/etc/nginx/render-security.awk", (ROOT / "nginx/render-security.awk").as_posix())
            script = script.replace("set -eu\n", """set -eu
sleep() {
    printf x >> "$FIXTURE_SLEEPS"
    if [ "$FIXTURE_APPEAR" = 1 ] && [ ! -e "$FIXTURE_SNAPSHOT" ]; then
        printf '# frontiercloud-ip-security-v1\\n192.0.2.1 0\\n' > "$FIXTURE_SNAPSHOT"
    fi
}
nginx() { : > "$FIXTURE_NGINX_CALLED"; return "$FIXTURE_NGINX_EXIT"; }
""", 1)
            fixture = root / "startup.sh"
            fixture.write_text(script, encoding="utf-8", newline="\n")
            env = dict(os.environ, FIXTURE_SLEEPS=sleeps.as_posix(), FIXTURE_NGINX_CALLED=nginx_called.as_posix(),
                       FIXTURE_APPEAR="1" if appear else "0", FIXTURE_SNAPSHOT=snapshot.as_posix(),
                       FIXTURE_NGINX_EXIT="1" if nginx_fails else "0")
            result = subprocess.run([shutil.which("sh"), fixture.as_posix()], env=env, capture_output=True,
                                    text=True, timeout=10)
            rules = runtime / "ip-security.conf"
            return (result.returncode, sleeps.read_text() if sleeps.exists() else "",
                    nginx_called.exists(), rules.read_text() if rules.exists() else "", result.stderr)

    def test_delayed_valid_snapshot_is_rendered(self):
        code, sleeps, checked, rules, _ = self.run_startup(appear=True)
        self.assertEqual((code, sleeps, checked, rules), (0, "x", True, "192.0.2.1 1;\n"))

    def test_existing_valid_snapshot_does_not_wait(self):
        code, sleeps, checked, rules, _ = self.run_startup("# frontiercloud-ip-security-v1\n192.0.2.1 0\n")
        self.assertEqual((code, sleeps, checked, rules), (0, "", True, "192.0.2.1 1;\n"))

    def test_absent_snapshot_times_out_closed(self):
        code, sleeps, checked, rules, stderr = self.run_startup()
        self.assertNotEqual(code, 0)
        self.assertEqual(len(sleeps), 30)
        self.assertFalse(checked)
        self.assertEqual(rules, "")
        self.assertIn("initial IP security snapshot unavailable", stderr)

    def test_present_malformed_snapshot_fails_without_wait(self):
        code, sleeps, checked, rules, _ = self.run_startup("# frontiercloud-ip-security-v1\n127.0.0.1; 0\n")
        self.assertNotEqual(code, 0)
        self.assertEqual(sleeps, "")
        self.assertFalse(checked)
        self.assertEqual(rules, "")

    def test_rejected_nginx_configuration_fails_closed(self):
        code, sleeps, checked, _, _ = self.run_startup("# frontiercloud-ip-security-v1\n192.0.2.999 0\n",
                                                       nginx_fails=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(sleeps, "")
        self.assertTrue(checked)


if __name__ == "__main__":
    unittest.main()

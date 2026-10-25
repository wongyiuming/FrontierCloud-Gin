"""Default deployment must install the bounded global entry before initialization."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RequiredFocComposeTests(unittest.TestCase):
    def test_root_entries_are_deployments_and_legacy_installer_still_ships(self):
        files = {p.name for p in ROOT.glob('*compose*.yaml')}
        self.assertEqual(files, {'docker-compose.yaml', 'docker-compose.gin-mysql.yaml',
                                 'docker-compose.storage.yaml'})
        self.assertTrue((ROOT / 'deploy/compose.foc.yaml').is_file())
        for name in ('Dockerfile', 'Dockerfile.gin', 'ci/Dockerfile.web'):
            text = (ROOT / name).read_text(encoding='utf-8')
            self.assertIn('COPY deploy/compose.foc.yaml /app/operator/', text)
            if name != 'ci/Dockerfile.web':
                self.assertIn('COPY deploy/compose.foc.yaml ./deploy/', text)

    def test_every_default_has_required_independently_pinned_installer(self):
        for name in ('docker-compose.yaml', 'docker-compose.storage.yaml'):
            with self.subTest(name=name):
                text = (ROOT / name).read_text(encoding='utf-8')
                installer = text.split('  foc-host-init:\n', 1)[1].split('  secrets-init:\n', 1)[0]
                self.assertRegex(installer, r'image: ghcr.io/wongyiuming/frontiercloud-gin-web@sha256:[0-9a-f]{64}')
                self.assertRegex(installer, r'FOC_OPERATOR_REVISION: [0-9a-f]{40}')
                for required in ('command: ["auto"]', 'FOC_COMPOSE_INSTALL: "1"', 'FOC_AUTOMATIC_PROJECT: "1"',
                                 'frontiercloud.foc-bootstrap: "1"', 'network_mode: none', 'cap_drop: [ALL]',
                                 'read_only: true', 'memswap_limit: 128m', 'restart: "no"'):
                    self.assertIn(required, installer)
                for forbidden in ('profiles:', 'docker.sock', 'privileged:', 'pid: host', 'env_file:', '${'):
                    self.assertNotIn(forbidden, installer)
                for name in ('secrets-init', 'media-init', 'certificate-init'):
                    # Inspect the complete indented service, stopping only at a sibling.
                    initializer = re.split(r'\n  [a-z][a-z-]*:', text.split('  ' + name + ':\n', 1)[1], 1)[0]
                    self.assertIn('foc-host-init: {condition: service_completed_successfully}', initializer)
                self.assertEqual(len(re.findall(r'type: bind', installer)), 5)

    def test_retired_bootstrap_files_are_absent(self):
        for name in ('.github/workflows/bootstrap-images.yml', 'scripts/bootstrap_native_publish.py',
                     'tests/test_bootstrap_native_publish.py'):
            self.assertFalse((ROOT / name).exists(), name)

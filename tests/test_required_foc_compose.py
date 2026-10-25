"""Business startup is independent of the explicitly selected host operator."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
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

    def test_host_installer_is_optional_and_independently_pinned(self):
        for name in ('docker-compose.yaml', 'docker-compose.storage.yaml'):
            with self.subTest(name=name):
                text = (ROOT / name).read_text(encoding='utf-8')
                installer = text.split('  foc-host-init:\n', 1)[1].split('  secrets-init:\n', 1)[0]
                self.assertRegex(installer, r'image: ghcr.io/wongyiuming/frontiercloud-gin-web@sha256:[0-9a-f]{64}')
                self.assertRegex(installer, r'FOC_OPERATOR_REVISION: [0-9a-f]{40}')
                for required in ('command: ["auto"]', 'FOC_COMPOSE_INSTALL: "1"', 'FOC_AUTOMATIC_PROJECT: "1"',
                                 'frontiercloud.foc-bootstrap: "1"', 'network_mode: none', 'cap_drop: [ALL]',
                                 'read_only: true', 'memswap_limit: 128m', 'restart: "no"',
                                 'profiles: [operator]'):
                    self.assertIn(required, installer)
                for forbidden in ('docker.sock', 'privileged:', 'pid: host', 'env_file:', '${'):
                    self.assertNotIn(forbidden, installer)
                # Every runtime service, including all initializer dependencies,
                # must be runnable without the operator or its host mounts.
                runtime = text.split('  secrets-init:\n', 1)[1]
                for forbidden in ('foc-host-init', 'source: /usr', 'target: /usr/local/bin',
                                  '/usr/local/bin:', '/usr/local/lib/frontiercloud',
                                  '/etc/frontiercloud', 'FOC_COMPOSE_INSTALL', 'profiles:'):
                    self.assertNotIn(forbidden, runtime)
                self.assertEqual(len(re.findall(r'type: bind', installer)), 5)

    def test_retired_bootstrap_files_are_absent(self):
        for name in ('.github/workflows/bootstrap-images.yml', 'scripts/bootstrap_native_publish.py',
                     'tests/test_bootstrap_native_publish.py'):
            self.assertFalse((ROOT / name).exists(), name)


@unittest.skipUnless(shutil.which('docker'), 'real Docker Compose parser unavailable')
class ActualOptionalOperatorGraphTests(unittest.TestCase):
    def test_all_runtime_selections_exclude_operator_until_profile_selected(self):
        probe = subprocess.run(['docker', 'compose', 'version'], capture_output=True, text=True, timeout=15)
        if probe.returncode:
            self.skipTest('real Docker Compose plugin unavailable')
        for transport, database in (('business', 'sqlite'), ('business', 'mysql'),
                                    ('direct', 'sqlite'), ('relay', 'sqlite')):
            with self.subTest(transport=transport, database=database), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                for name in ('docker-compose.yaml', 'docker-compose.gin-mysql.yaml', 'docker-compose.storage.yaml'):
                    shutil.copyfile(ROOT / name, directory / name)
                (directory / 'empty.env').write_text('')
                env = {key: value for key, value in os.environ.items()
                       if not key.startswith('COMPOSE_')}
                port = '8443' if transport == 'relay' else '443'
                env.update(FRONTIERCLOUD_REVISION='a' * 40, TLS_ENABLED='false',
                           DB_TYPE=database, SERVER_NAME='storage.fixture.invalid', STORAGE_TRANSPORT=transport,
                           STORAGE_PORT=port,
                           STORAGE_ENDPOINT='https://storage.fixture.invalid' + (':8443' if port == '8443' else ''))
                filename = 'docker-compose.yaml' if transport == 'business' else 'docker-compose.storage.yaml'
                command = ['docker', 'compose', '--project-directory', str(directory),
                           '--env-file', str(directory / 'empty.env'), '-f', str(directory / filename)]
                if database == 'mysql':
                    command += ['-f', str(directory / 'docker-compose.gin-mysql.yaml')]

                def config(*args):
                    return subprocess.check_output(command + list(args), text=True, env=env, timeout=30)

                names = set(config('config', '--services').splitlines())
                self.assertIn('web', names)
                self.assertNotIn('foc-host-init', names)
                default = json.loads(config('config', '--format', 'json'))['services']
                optional = json.loads(config('--profile', 'operator', 'config', '--format', 'json'))['services']
                self.assertEqual(set(default), names)
                self.assertEqual(set(optional), names | {'foc-host-init'})
                self.assertEqual(optional['foc-host-init']['profiles'], ['operator'])
                self.assertEqual(optional['foc-host-init'].get('depends_on', {}), {})
                for name, service in default.items():
                    self.assertEqual(service, optional[name], name)
                    self.assertNotIn('foc-host-init', service.get('depends_on', {}), name)
                    self.assertNotIn('profiles', service, name)
                    for mount in service.get('volumes', []):
                        self.assertNotIn(mount['target'], {'/host/usr', '/host/etc', '/usr/local/bin',
                                                         '/usr/local/lib/frontiercloud', '/etc/frontiercloud'}, name)
                for initializer in ('secrets-init', 'media-init', 'certificate-init'):
                    self.assertIn(initializer, names)
                if transport == 'business':
                    self.assertEqual('mysql' in names, database == 'mysql')

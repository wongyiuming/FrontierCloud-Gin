"""Exercise the actual POSIX entry in isolated directories, without Docker writes."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('sh'), 'POSIX shell required')
class HostEntryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backend = self.root / 'backend'
        self.calls = self.root / 'calls'
        self.registry = self.root / 'registry'
        self.labels = self.root / 'labels'
        self.labels.write_text('')
        self.backend.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CALLS"\nexit 0\n')
        self.backend.chmod(0o755)
        docker = self.root / 'docker'
        docker.write_text('#!/bin/sh\ncat "$LABELS"\nexit "${DOCKER_EXIT:-0}"\n')
        docker.chmod(0o755)
        source = (ROOT / 'scripts/foc').read_text()
        source = source.replace('backend=/usr/local/lib/frontiercloud/foc/fc', 'backend=' + shlex.quote(str(self.backend)))
        source = source.replace('registry=/etc/frontiercloud/foc-deployments', 'registry=' + shlex.quote(str(self.registry)))
        self.entry = self.root / 'foc'
        self.entry.write_text(source)
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ['PATH'],
                        CALLS=str(self.calls), LABELS=str(self.labels))

    def deployment(self, name):
        path = self.root / name
        path.mkdir()
        (path / '.fc-deployment.json').write_text('{}')
        return path

    def invoke(self, *args):
        return subprocess.run(['sh', str(self.entry), *args], cwd='/', env=self.env,
                              capture_output=True, text=True)

    def test_default_status_deduplicates_labels_and_registry(self):
        deployment = self.deployment('bundle with spaces')
        self.registry.write_text(str(deployment) + '\n')
        self.labels.write_text((str(deployment) + '\n') * 3)
        self.assertEqual(self.invoke().returncode, 0)
        self.assertEqual(self.calls.read_text().splitlines(), ['--directory', str(deployment), 'status'])

    def test_multiple_deployments_refuse_before_backend(self):
        a, b = self.deployment('master'), self.deployment('storage')
        self.labels.write_text(f'{a}\n{b}\n')
        result = self.invoke('restart')
        self.assertEqual(result.returncode, 2)
        self.assertIn('multiple deployments', result.stderr)
        self.assertFalse(self.calls.exists())

    def test_explicit_selection_preserves_arguments_without_discovery(self):
        self.env['DOCKER_EXIT'] = '1'
        args = ['upgrade', 'plan', '--directory', '/chosen path', '--revision', 'a' * 40]
        self.assertEqual(self.invoke(*args).returncode, 0)
        self.assertEqual(self.calls.read_text().splitlines(), args)

    def test_empty_explicit_selection_refuses(self):
        self.assertEqual(self.invoke('--directory=', 'restart').returncode, 2)
        self.assertFalse(self.calls.exists())

    def test_missing_registered_receipt_fails_closed(self):
        self.registry.write_text('/missing/deployment\n')
        self.labels.write_text(str(self.deployment('other')) + '\n')
        self.assertEqual(self.invoke('restart').returncode, 2)
        self.assertFalse(self.calls.exists())

    def test_discovery_failure_never_selects_registered_deployment(self):
        self.registry.write_text(str(self.deployment('master')) + '\n')
        self.env['DOCKER_EXIT'] = '1'
        self.assertEqual(self.invoke('restart').returncode, 2)
        self.assertFalse(self.calls.exists())

    def test_version_works_without_docker(self):
        self.env['DOCKER_EXIT'] = '1'
        self.assertEqual(self.invoke('version').returncode, 0)
        self.assertEqual(self.calls.read_text().splitlines(), ['version'])

    def test_unrelated_and_symlinked_receipts_are_not_selected(self):
        other = self.root / 'unrelated'
        other.mkdir()
        (other / '.fc-deployment.json').symlink_to(self.backend)
        self.labels.write_text(str(other) + '\n')
        self.assertEqual(self.invoke().returncode, 2)
        self.assertFalse(self.calls.exists())

    def test_installer_refuses_unmanaged_command_and_preserves_bytes(self):
        bundle = self.root / 'bundle'
        bundle.mkdir()
        binary = bundle / 'fc'
        binary.write_text('#!/bin/sh\nprintf "%s\\n" ' + 'a' * 40 + '\n')
        binary.chmod(0o755)
        (bundle / 'foc').write_text((ROOT / 'scripts/foc').read_text())
        installer = (ROOT / 'scripts/install-foc.sh').read_text()
        for prefix in ('/usr/local', '/etc/frontiercloud'):
            installer = installer.replace(prefix, str(self.root / prefix.lstrip('/')))
        installer = installer.replace('[ "$(id -u)" -eq 0 ]', '[ 0 -eq 0 ]')
        native = self.deployment('native')
        installer = installer.replace('receipt_directory=/deployment', 'receipt_directory=' + shlex.quote(str(native)))
        path = bundle / 'install-foc.sh'
        path.write_text(installer)
        collision = self.root / 'usr/local/bin/foc'
        collision.parent.mkdir(parents=True)
        collision.write_text('unrelated-program')
        env = dict(os.environ, FOC_COMPOSE_INSTALL='1', FOC_OPERATOR_REVISION='a' * 40)
        result = subprocess.run(['sh', str(path), str(native)], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(collision.read_text(), 'unrelated-program')

    def test_direct_host_installer_is_refused(self):
        env = dict(os.environ)
        env.pop('FOC_COMPOSE_INSTALL', None)
        result = subprocess.run(['sh', str(ROOT / 'scripts/install-foc.sh'), '/unused'],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('Compose foc installation', result.stderr)


if __name__ == '__main__':
    unittest.main()

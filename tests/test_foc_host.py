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
        self.web_labels = self.root / 'web-labels'
        self.web_labels.write_text('')
        self.scratch = self.root / 'scratch'
        self.scratch.mkdir()
        self.backend.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CALLS"\nexit 0\n')
        self.backend.chmod(0o755)
        docker = self.root / 'docker'
        docker.write_text('''#!/bin/sh
case "$*" in
  *"--filter label=com.docker.compose.service=web"*)
    case "$*" in *"--filter label=frontiercloud.runtime=go"*) ;; *) exit 97 ;; esac
    case "$*" in *"--filter label=frontiercloud.component=web"*) ;; *) exit 97 ;; esac
    cat "$WEB_LABELS" ;;
  *) cat "$LABELS" ;;
esac
exit "${DOCKER_EXIT:-0}"
''')
        docker.chmod(0o755)
        source = (ROOT / 'scripts/foc').read_text()
        source = source.replace('backend=/usr/local/lib/frontiercloud/foc/fc', 'backend=' + shlex.quote(str(self.backend)))
        source = source.replace('registry=/etc/frontiercloud/foc-deployments', 'registry=' + shlex.quote(str(self.registry)))
        self.entry = self.root / 'foc'
        self.entry.write_text(source)
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ['PATH'],
                        CALLS=str(self.calls), LABELS=str(self.labels), WEB_LABELS=str(self.web_labels),
                        TMPDIR=str(self.scratch),
                        XDG_STATE_HOME=str(self.root / 'user-state'))

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
        self.assertEqual(list(self.scratch.iterdir()), [])

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

    def test_sanitized_environment_bypasses_user_registry_for_explicit_commands(self):
        self.env.pop('HOME', None)
        self.env.pop('XDG_STATE_HOME', None)
        self.env['DOCKER_EXIT'] = '1'
        for args in (['--directory', '/chosen path', 'status'], ['version']):
            with self.subTest(args=args):
                result = self.invoke(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.calls.read_text().splitlines(), args)
        self.assertEqual(self.invoke('--help').returncode, 0)

    def test_sanitized_environment_still_discovers_system_registry(self):
        self.env.pop('HOME', None)
        self.env.pop('XDG_STATE_HOME', None)
        deployment = self.deployment('system-only')
        self.registry.write_text(str(deployment) + '\n')
        result = self.invoke('status')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls.read_text().splitlines(), ['--directory', str(deployment), 'status'])

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

    def test_user_registration_survives_container_removal(self):
        native=self.deployment('remembered')
        registry=self.root/'user-state/frontiercloud/foc-deployments'
        registry.parent.mkdir(parents=True)
        registry.write_text(str(native)+'\n')
        self.labels.write_text('')
        self.assertEqual(self.invoke('restart').returncode,0)
        self.assertEqual(self.calls.read_text().splitlines(),['--directory',str(native),'restart'])

    def test_version_works_without_docker(self):
        self.env['DOCKER_EXIT'] = '1'
        self.assertEqual(self.invoke('version').returncode, 0)
        self.assertEqual(self.calls.read_text().splitlines(), ['version'])

    def test_auto_discovery_does_not_register_existing_nonready_receipts(self):
        deployment = self.deployment('interrupted')
        self.registry.write_text('@compose\n')
        self.labels.write_text(str(deployment) + '\n')
        self.backend.write_text('#!/bin/sh\nfor arg do [ "$arg" != compose-register ] || exit 33; done\nprintf "%s\\n" "$@" > "$CALLS"\n')
        for state, args in [('prepared', ['install', 'resume']), ('upgrade_fenced', ['upgrade'])]:
            with self.subTest(state=state):
                (deployment / '.fc-deployment.json').write_text('{"state":"' + state + '"}')
                result = self.invoke(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.calls.read_text().splitlines(), ['--directory', str(deployment), *args])

    def test_help_needs_no_deployment_or_docker(self):
        self.env['DOCKER_EXIT'] = '1'
        result = self.invoke('--help')
        self.assertEqual(result.returncode, 0)
        self.assertIn('foc [--directory DIR]', result.stdout)
        self.assertFalse(self.calls.exists())

    def test_unrelated_and_symlinked_receipts_are_not_selected(self):
        other = self.root / 'unrelated'
        other.mkdir()
        (other / '.fc-deployment.json').symlink_to(self.backend)
        self.labels.write_text(str(other) + '\n')
        self.assertEqual(self.invoke().returncode, 2)
        self.assertFalse(self.calls.exists())

    def installer_fixture(self):
        bundle = self.root / 'bundle'
        bundle.mkdir()
        binary = bundle / 'fc'
        binary.write_text('#!/bin/sh\nif [ "${1:-}" = operator-generation ]; then echo 7; else printf "%s\\n" ' + 'a' * 40 + '; fi\n')
        binary.chmod(0o755)
        (bundle / 'foc').write_text((ROOT / 'scripts/foc').read_text())
        installer = (ROOT / 'scripts/install-foc.sh').read_text()
        for prefix in ('/usr/local', '/etc/frontiercloud'):
            installer = installer.replace(prefix, str(self.root / prefix.lstrip('/')))
        installer = installer.replace('host_root=/host', "host_root=''")
        installer = installer.replace('[ "$(id -u)" -eq 0 ]', '[ 0 -eq 0 ]')
        native = self.deployment('native')
        installer = installer.replace('receipt_directory=/deployment', 'receipt_directory=' + shlex.quote(str(native)))
        self.installer = bundle / 'install-foc.sh'
        self.installer.write_text(installer)
        self.native = native
        self.global_entry = self.root / 'usr/local/bin/foc'
        self.home = self.root / 'usr/local/lib/frontiercloud/foc'
        self.install_env = dict(self.env, FOC_COMPOSE_INSTALL='1', FOC_OPERATOR_REVISION='a' * 40)

    def install(self):
        return subprocess.run(['sh', str(self.installer), str(self.native)],
                              env=self.install_env, capture_output=True, text=True)

    def test_automatic_compose_install_needs_no_receipt_or_manual_registration(self):
        self.installer_fixture()
        (self.native / '.fc-deployment.json').unlink()
        self.install_env['FOC_AUTOMATIC_PROJECT'] = '1'
        self.install_env.pop('FOC_OPERATOR_REVISION')
        result = subprocess.run(['sh', str(self.installer), 'auto'], env=self.install_env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.global_entry.exists())
        self.assertIn('@compose', (self.root / 'etc/frontiercloud/foc-deployments').read_text())

    def test_web_discovery_ignores_unmarked_compose_deployments(self):
        native = self.deployment('managed')
        unrelated = self.root / 'other'
        unrelated.mkdir()
        self.registry.write_text('@compose\n' + str(native) + '\n')
        self.labels.write_text(str(unrelated) + '\n' + str(native) + '\n')
        self.web_labels.write_text(str(native) + '\n')
        self.assertEqual(self.invoke('status').returncode, 0)
        self.assertEqual(self.calls.read_text().splitlines(), ['--directory', str(native), 'status'])
        self.assertFalse((unrelated / '.fc-deployment.json').exists())

    def test_marked_running_web_can_register_without_installer_or_registry(self):
        native = self.root / 'running-native'
        native.mkdir()
        self.labels.write_text(str(native) + '\n')
        self.web_labels.write_text(str(native) + '\n')
        registration = self.root / 'registration'
        self.env['REGISTRATION'] = str(registration)
        self.backend.write_text('''#!/bin/sh
if [ "$3" = compose-register ]; then
  printf '%s\\n' "$2" > "$REGISTRATION"
  printf '{}' > "$2/.fc-deployment.json"
  exit 0
fi
printf '%s\\n' "$@" > "$CALLS"
''')
        result = self.invoke('status')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(registration.read_text().strip(), str(native))
        self.assertEqual(self.calls.read_text().splitlines(), ['--directory', str(native), 'status'])

    def test_marked_web_rejected_by_backend_does_not_become_registered(self):
        native = self.root / 'unproved-native'
        native.mkdir()
        self.labels.write_text(str(native) + '\n')
        self.web_labels.write_text(str(native) + '\n')
        self.backend.write_text('#!/bin/sh\n[ "$3" != compose-register ] || exit 33\nprintf "%s\\n" "$@" > "$CALLS"\n')
        self.assertNotEqual(self.invoke('status').returncode, 0)
        self.assertFalse((native / '.fc-deployment.json').exists())
        self.assertFalse(self.calls.exists())

    def test_multiple_marked_web_candidates_do_not_register_either(self):
        candidates = [self.root / name for name in ('first-native', 'second-native')]
        for directory in candidates:
            directory.mkdir()
        self.web_labels.write_text(''.join(str(directory) + '\n' for directory in candidates))
        result = self.invoke('status')
        self.assertEqual(result.returncode, 2)
        self.assertIn('multiple deployments', result.stderr)
        self.assertFalse(self.calls.exists())
        for directory in candidates:
            self.assertFalse((directory / '.fc-deployment.json').exists())

    def test_success_without_receipt_publication_still_refuses(self):
        native = self.root / 'missing-result'
        native.mkdir()
        self.web_labels.write_text(str(native) + '\n')
        self.assertEqual(self.invoke('status').returncode, 2)
        self.assertFalse((native / '.fc-deployment.json').exists())
        self.assertEqual(self.calls.read_text().splitlines(), ['--directory', str(native), 'compose-register'])

    def test_explicit_compose_install_retains_different_backend_at_same_generation(self):
        self.installer_fixture()
        self.assertEqual(self.install().returncode, 0)
        before = (self.home / 'fc').read_bytes()
        source = self.installer.parent / 'fc'
        source.write_text('#!/bin/sh\nif [ "${1:-}" = operator-generation ]; then echo 7; else echo ' + 'b' * 40 + '; fi\n')
        self.install_env['FOC_AUTOMATIC_PROJECT'] = '1'
        self.install_env.pop('FOC_OPERATOR_REVISION')
        result = subprocess.run(['sh', str(self.installer), 'auto'], env=self.install_env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.home / 'fc').read_bytes(), before)

    def test_installer_refuses_unmanaged_command_and_preserves_bytes(self):
        self.installer_fixture()
        self.global_entry.parent.mkdir(parents=True)
        self.global_entry.write_text('unrelated-program')
        self.assertEqual(self.install().returncode, 2)
        self.assertEqual(self.global_entry.read_text(), 'unrelated-program')

    def test_managed_marker_does_not_allow_changed_command_replacement(self):
        self.installer_fixture()
        self.assertEqual(self.install().returncode, 0)
        self.global_entry.write_text('administrator-replacement')
        self.assertEqual(self.install().returncode, 2)
        self.assertEqual(self.global_entry.read_text(), 'administrator-replacement')

    def test_refresh_retains_one_backend_per_generation_for_other_pending_nodes(self):
        self.installer_fixture()
        self.assertEqual(self.install().returncode, 0)
        pending = self.root / 'other-node-pending.json'
        pending.write_text('{"phase":"prepared_fenced","schema_generation":7}')
        original = pending.read_bytes()
        bundle = self.root / 'bundle'
        for generation, revision in ((8, 'b' * 40), (9, 'c' * 40)):
            (bundle / 'fc').write_text('#!/bin/sh\nif [ "${1:-}" = operator-generation ]; then echo ' + str(generation) + '; else echo ' + revision + '; fi\n')
            self.install_env['FOC_OPERATOR_REVISION'] = revision
            result = self.install()
            self.assertEqual(result.returncode, 0, result.stderr)
        retained = self.home / 'backends/g7/fc'
        self.assertEqual(subprocess.check_output([str(retained), 'operator-generation'], text=True).strip(), '7')
        self.assertEqual(subprocess.check_output([str(retained), 'version'], text=True).strip(), 'a' * 40)
        self.assertEqual(subprocess.check_output([str(self.home / 'backends/g8/fc'), 'version'], text=True).strip(), 'b' * 40)
        self.assertEqual(subprocess.check_output([str(self.home / 'fc'), 'version'], text=True).strip(), 'c' * 40)
        self.assertEqual(pending.read_bytes(), original)

    def test_refresh_refuses_symlinked_retained_backend_directory(self):
        self.installer_fixture()
        self.assertEqual(self.install().returncode, 0)
        other = self.root / 'unrelated-backends'
        other.mkdir()
        (self.home / 'backends').symlink_to(other, target_is_directory=True)
        self.assertEqual(self.install().returncode, 2)
        self.assertEqual(subprocess.check_output([str(self.home / 'fc'), 'version'], text=True).strip(), 'a' * 40)
        self.assertEqual(list(other.iterdir()), [])

    def test_interrupted_first_install_and_publication_are_retryable(self):
        self.installer_fixture()
        real_mv = shutil.which('mv')
        fake_mv = self.root / 'mv'
        # SIGTERM the installer before backend publication, then after launcher
        # publication (registry rename). No production test hook is required.
        fake_mv.write_text('#!/bin/sh\ncase "$*" in *"$FAIL_MATCH"*) kill -TERM "$PPID"; exit 1 ;; esac\nexec ' + shlex.quote(real_mv) + ' "$@"\n')
        fake_mv.chmod(0o755)
        for match in ('fc.new.', 'foc-deployments.new.'):
            with self.subTest(match=match):
                self.install_env['FAIL_MATCH'] = match
                self.assertNotEqual(self.install().returncode, 0)
                self.assertFalse((self.home / '.install-lock').exists())
                self.install_env['FAIL_MATCH'] = '__never__'
                self.assertEqual(self.install().returncode, 0)
                self.assertEqual(self.global_entry.read_bytes(), (self.home / 'launcher.current').read_bytes())
                self.assertFalse((self.home / 'launcher.pending').exists())
                self.global_entry.unlink()
                shutil.rmtree(self.home)

    def test_host_symlink_parent_refused(self):
        self.installer_fixture()
        actual = self.root / 'elsewhere'
        actual.mkdir()
        parent = self.root / 'usr/local'
        parent.parent.mkdir()
        parent.symlink_to(actual, target_is_directory=True)
        self.assertEqual(self.install().returncode, 2)
        self.assertEqual(list(actual.iterdir()), [])

    def test_global_options_without_command_default_to_status(self):
        native = self.deployment('master')
        self.labels.write_text(str(native) + '\n')
        for args in (['--json'], ['--directory', str(native)], ['--json', '--directory=' + str(native)]):
            with self.subTest(args=args):
                self.assertEqual(self.invoke(*args).returncode, 0)
                self.assertEqual(self.calls.read_text().splitlines()[-1], 'status')

    def test_independent_commands_work_during_docker_outage(self):
        self.env['DOCKER_EXIT'] = '1'
        for args in (['--json', 'version'], ['node', 'retire', 'check', 'node-id'],
                     ['backup', 'verify', '--file', '/archive'], ['backup', 'set-verify', '--file', '/set'],
                     ['restore', 'check', '--file', '/archive', '--target', '/target'],
                     ['restore', 'apply', '--file', '/archive', '--target', '/target'],
                     ['backup', 'set-create', '--spec', '/spec'], ['restore', 'set-check', '--spec', '/spec']):
            with self.subTest(args=args):
                self.assertEqual(self.invoke(*args).returncode, 0)
                self.assertEqual(self.calls.read_text().splitlines(), args)

    def test_restore_activation_and_open_discover_local_deployment(self):
        native = self.deployment('recovered')
        self.registry.write_text(str(native) + '\n')
        for action in ('activate', 'open'):
            args = ['restore', action, '--confirm-node-id', 'identity']
            with self.subTest(action=action):
                self.assertEqual(self.invoke(*args).returncode, 0)
                self.assertEqual(self.calls.read_text().splitlines(), ['--directory', str(native), *args])
                self.calls.unlink()
                self.env['DOCKER_EXIT'] = '1'
                self.assertEqual(self.invoke(*args).returncode, 2)
                self.assertFalse(self.calls.exists())
                explicit = ['--directory', str(native), *args]
                self.assertEqual(self.invoke(*explicit).returncode, 0)
                self.assertEqual(self.calls.read_text().splitlines(), explicit)
                self.env.pop('DOCKER_EXIT')

    def test_compose_parent_views_exclude_runtime_socket_roots(self):
        import yaml
        service = yaml.safe_load((ROOT / 'deploy/compose.foc.yaml').read_text())['services']['install']
        volumes = service['volumes']
        views = [v for v in volumes if v['target'].startswith('/host')]
        self.assertEqual({v['source'] for v in views}, {'/usr', '/etc'})
        self.assertTrue(all(v['read_only'] for v in views))
        self.assertFalse(any(v['source'] in ('/', '/run', '/var', '/var/run') or
                             'docker.sock' in v['source'] for v in volumes))
        self.assertEqual(len([v for v in volumes if not v.get('read_only')]), 3)

    def test_direct_host_installer_is_refused(self):
        env = dict(os.environ)
        env.pop('FOC_COMPOSE_INSTALL', None)
        result = subprocess.run(['sh', str(ROOT / 'scripts/install-foc.sh'), '/unused'],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('Compose foc installation', result.stderr)


if __name__ == '__main__':
    unittest.main()

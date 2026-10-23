"""Pure admission/layout checks for the real browser driver, without Chromium."""
import ast
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'tests/media_native_browser.py'


def definitions():
    # Extract the actual stdlib admission functions, keeping this source check
    # independent of test-only Playwright and all product application modules.
    tree = ast.parse(DRIVER.read_text(encoding='utf-8'))
    names = {'regular', 'read_fixture', 'check_geometry', 'digest'}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = dict(Path=Path, stat=stat, json=json, re=re, ipaddress=ipaddress,
                     FORMAT='frontiercloud-gin-native-media-browser-v1',
                     hashlib=__import__('hashlib'))
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(DRIVER), 'exec'), namespace)
    return namespace


class NativeMediaBrowserContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.workspace = Path(self.directory.name) / 'fc-native-matrix-example'
        root = self.workspace / 'go-sqlite'
        (root / 'site0/secrets').mkdir(parents=True)
        (root / 'certs').mkdir()
        self.key = root / 'site0/secrets/admin_key'
        self.key.write_text('disposable-test-key-123456')
        self.key.chmod(0o600)
        ca = root / 'certs/ca.pem'
        ca.write_bytes(b'-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n')
        self.path = root / 'media-browser-fixture.json'
        self.value = dict(format='frontiercloud-gin-native-media-browser-v1', database='go-sqlite', nonce='a' * 32,
            origin='https://site0.fleet.invalid', web_cpu_limit=1, web_memory_bytes=512 * 1024**2,
            hosts={f'site{i}.fleet.invalid': f'172.28.{i}.2' for i in range(5)},
            owners={f'{i:032x}': f'https://site{i}.fleet.invalid' + (':8443' if i > 2 else '') for i in range(5)},
            ca_file=str(ca), admin_key_file=str(self.key))
        self.functions = definitions()

    def read(self):
        self.path.write_text(json.dumps(self.value))
        if os.name != 'nt':
            return self.functions['read_fixture'](self.path, self.workspace)
        # Windows does not expose Linux 0600 through chmod/stat. Emulate only
        # this fixture inode's POSIX mode, keeping product admission unchanged;
        # the native Linux gate reads and checks the real mode.
        actual_stat = Path.stat
        def posix_mode(path, *args, **kwargs):
            result = actual_stat(path, *args, **kwargs)
            if path == self.key:
                fields = list(result)
                fields[0] = stat.S_IFREG | 0o600
                return os.stat_result(fields)
            return result
        with mock.patch.object(Path, 'stat', posix_mode):
            return self.functions['read_fixture'](self.path, self.workspace)

    def test_real_fixture_admission_keeps_exact_owner_and_ca(self):
        value, key, ca_hash = self.read()
        self.assertEqual(value['owners'], self.value['owners'])
        self.assertEqual(key, 'disposable-test-key-123456')
        self.assertRegex(ca_hash, '^[a-f0-9]{64}$')

    def test_foreign_origin_owner_or_ca_is_not_a_native_fixture(self):
        for field, replacement in (('origin', 'https://520mall.cc'), ('nonce', 'not-a-nonce'),
            ('ca_file', str(self.workspace / 'other.pem')), ('web_memory_bytes', 1024**3),
            ('owners', {'a' * 32: 'https://site0.fleet.invalid'})):
            with self.subTest(field=field):
                original = self.value[field]
                self.value[field] = replacement
                with self.assertRaises(ValueError):
                    self.read()
                self.value[field] = original

    def test_loopback_or_public_hosts_refused(self):
        for address in ('127.0.0.1', '8.8.8.8', '0.0.0.0', '224.0.0.1'):
            with self.subTest(address=address):
                self.value['hosts']['site1.fleet.invalid'] = address
                with self.assertRaises(ValueError):
                    self.read()

    def test_geometry_requires_wrapping_without_font_reduction_or_clipping(self):
        valid = dict(before='18px', after='18px', whiteSpace='normal', rows=3, glyphsInside=True,
            glyphsInsidePanel=True, scrollWidth=350, clientWidth=350, scrollHeight=64, clientHeight=64)
        self.functions['check_geometry'](valid)
        for change in (dict(after='14px'), dict(rows=1), dict(glyphsInside=False),
            dict(glyphsInsidePanel=False), dict(scrollWidth=400), dict(scrollHeight=100), dict(whiteSpace='nowrap')):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                self.functions['check_geometry']({**valid, **change})

    def test_additional_hook_does_not_replace_the_default_fleet(self):
        source = (ROOT / 'internal/nativeacceptance/native_matrix_real_test.go').read_text()
        hook = source.split('if os.Getenv("FRONTIERCLOUD_TEST_MEDIA_BROWSER") == "1" {', 1)[1].split('if os.Getenv("FRONTIERCLOUD_TEST_ENCRYPTED_QUEUE_BROWSER")', 1)[0]
        self.assertIn('fleetMediaBrowserGate(t, ctx, e, project, sites, perform)', hook)
        self.assertNotIn('return', hook)
        self.assertIn('kinds := []string{"go-sqlite", "go-mysql"}', source)
        self.assertIn('five Web services did not recover idle CPU within 30 seconds', source)
        # The TLS test driver must use normal contexts and an imported actual CA.
        tree = ast.parse(DRIVER.read_text())
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            for keyword in call.keywords:
                self.assertNotEqual(keyword.arg, 'ignore_https_errors')
        self.assertNotIn('--ignore-certificate-errors', DRIVER.read_text())


if __name__ == '__main__':
    unittest.main()

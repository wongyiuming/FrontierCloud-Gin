"""Registry proof/error classification; no network, daemon or application imports."""
import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import urllib.error

from scripts.registry_images import ImageUnavailable, resolve, ensure

SHA = 'a' * 40
ROOT = Path(__file__).resolve().parents[1]


def response(value, digest=None):
    body = json.dumps(value).encode()
    return 200, {'Docker-Content-Digest': digest or 'sha256:' + hashlib.sha256(body).hexdigest()}, body


class RegistryImagesTests(unittest.TestCase):
    def test_exact_digest_and_matching_platform_only(self):
        digest = 'sha256:' + 'b' * 64
        manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
                    'manifests': [{'digest': digest, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                                   'platform': {'os': 'linux', 'architecture': 'amd64'}}]}
        self.assertEqual(resolve(SHA, 'web', 'amd64', lambda *args: response(manifest)),
                         'ghcr.io/wongyiuming/frontiercloud-gin-web@' + digest)
        with self.assertRaises(ImageUnavailable):
            resolve(SHA, 'web', 'arm64', lambda *args: response(manifest))
        manifest['manifests'].append(manifest['manifests'][0])
        with self.assertRaises(ValueError):
            resolve(SHA, 'web', 'amd64', lambda *args: response(manifest))

    def test_only_manifest_unknown_not_auth_network_or_generic_404_is_absence(self):
        with self.assertRaises(ImageUnavailable):
            resolve(SHA, 'web', request=lambda *args: (404, {}, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}'))
        for code, body in ((403, b'{}'), (500, b'{}'), (404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}'),
                           (404, b'{"errors":[],"errors":[{"code":"MANIFEST_UNKNOWN"}]}'),
                           (404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"},{"code":"DENIED"}]}')):
            with self.assertRaises(ValueError):
                resolve(SHA, 'web', request=lambda *args: (code, {}, body))
        with self.assertRaises(urllib.error.URLError):
            resolve(SHA, 'web', request=lambda *args: (_ for _ in ()).throw(urllib.error.URLError('fixture')))

    def test_anonymous_token_scope_is_fixed_not_challenge_realm(self):
        calls = []
        manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json'}
        def request(path, token=''):
            calls.append((path, token))
            if path.startswith('/token?'):
                self.assertIn('repository%3Awongyiuming%2Ffrontiercloud-gin-updater%3Apull', path)
                return 200, {}, b'{"token":"public-read-only"}'
            if not token:
                return 401, {'WWW-Authenticate': 'Bearer realm="http://127.0.0.1/secret"'}, b'{}'
            return response(manifest)
        self.assertIn('frontiercloud-gin-updater@sha256:', resolve(SHA, 'updater', request=request))
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[-1][1], 'public-read-only')

    def test_bad_digest_type_and_duplicate_json_fail_closed(self):
        manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json'}
        with self.assertRaises(ValueError):
            resolve(SHA, 'web', request=lambda *args: response(manifest, 'sha256:' + '0' * 64))
        for kind in (None, 'evil.index.v1+json'):
            manifest['mediaType'] = kind
            with self.assertRaises(ValueError):
                resolve(SHA, 'web', request=lambda *args: response(manifest))
        body = b'{"schemaVersion":2,"schemaVersion":2}'
        with self.assertRaises(ValueError):
            resolve(SHA, 'web', request=lambda *args: (200, {'Docker-Content-Digest': 'sha256:' + hashlib.sha256(body).hexdigest()}, body))

    def test_pull_failure_never_tags_or_silently_compiles(self):
        with patch('scripts.registry_images.resolve', return_value='ghcr.io/fixture@sha256:' + 'b' * 64), \
             patch('scripts.registry_images.subprocess.run', return_value=subprocess.CompletedProcess([], 1)) as run:
            with self.assertRaises(ValueError):
                ensure(SHA, 'web')
            self.assertEqual(run.call_count, 1)

    def test_workflow_test_gate_precedes_checkout_and_compilation(self):
        workflow = (ROOT / '.github/workflows/publish-images.yml').read_text(encoding='utf-8')
        self.assertLess(workflow.index("newest.conclusion !== 'success'"), workflow.index('actions/checkout'))
        self.assertLess(workflow.index('actions/checkout'), workflow.index('go build'))
        self.assertNotIn('go test', workflow)
        self.assertIn('needs: publish', workflow)
        self.assertIn('registry_images.py --resolve', workflow)
        fallback = (ROOT / 'scripts/build-native-images.sh').read_text(encoding='utf-8')
        self.assertIn('if (( code != 3 )); then exit', fallback)
        self.assertIn('git archive --format=tar', fallback)
        self.assertNotIn('--force', fallback)


if __name__ == '__main__':
    unittest.main()

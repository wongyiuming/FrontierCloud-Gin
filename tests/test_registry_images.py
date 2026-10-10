"""Registry proof/error classification; no network, daemon or application imports."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch
import urllib.error

from scripts.registry_images import ImageUnavailable, ManifestUnknown, SOURCE, fetch, publication_plan, publication_probe, resolve, ensure

SHA = 'a' * 40
ROOT = Path(__file__).resolve().parents[1]


def response(value, digest=None):
    body = json.dumps(value).encode()
    return 200, {'Docker-Content-Digest': digest or 'sha256:' + hashlib.sha256(body).hexdigest()}, body


def publication_fixture(component='web', configuration=None):
    config = configuration or {'os': 'linux', 'architecture': 'amd64', 'config': {'Labels': {
        'frontiercloud.revision': SHA, 'frontiercloud.component': component,
        'frontiercloud.runtime': 'go', 'frontiercloud.schema-generation': '2',
        'frontiercloud.release-manifest-version': '1', 'org.opencontainers.image.source': SOURCE,
        'org.opencontainers.image.revision': SHA}}}
    raw = json.dumps(config).encode()
    config_digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': config_digest, 'size': len(raw)}, 'layers': []}
    runtime = response(manifest)
    index = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
             'manifests': [{'digest': runtime[1]['Docker-Content-Digest'], 'mediaType': manifest['mediaType'],
                            'platform': {'os': 'linux', 'architecture': 'amd64'}}]}
    tag = response(index)
    def request(path, token=''):
        if path.endswith('/' + SHA):
            return tag
        if '/blobs/' in path:
            return 200, {}, raw
        return runtime
    return request, tag, runtime, raw


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
        self.assertLess(workflow.index("github.event.workflow_run.conclusion == 'success'"), workflow.index('actions/checkout'))
        self.assertLess(workflow.index('Prove newest completed source CI'), workflow.index('  compile:'))
        compile_part = workflow.split('  compile:\n')[1].split('  publish:\n')[0]
        self.assertIn('needs: [plan]', compile_part)
        self.assertLess(compile_part.index('actions/checkout'), compile_part.index('go build'))
        self.assertNotIn('secrets.', compile_part)
        self.assertNotIn('go test', workflow)
        self.assertNotIn('STAGING_CD_SECRET', workflow.split('  notify-staging:\n')[0])
        self.assertIn('scripts/trusted_native_publish.py publish', workflow)
        fallback = (ROOT / 'scripts/build-native-images.sh').read_text(encoding='utf-8')
        self.assertIn('if (( code != 3 )); then exit', fallback)
        self.assertIn('git archive --format=tar', fallback)
        self.assertNotIn('--force', fallback)

    def test_publication_verifies_config_and_manifest_hash_platform_source_and_schema(self):
        request, tag, runtime, raw = publication_fixture()
        result = publication_probe(SHA, 'web', request)
        self.assertEqual(result['tag_digest'], tag[1]['Docker-Content-Digest'])
        self.assertEqual(result['image'].split('@')[1], runtime[1]['Docker-Content-Digest'])
        config = json.loads(raw)
        for field, value in [('os', 'windows'), ('architecture', 'arm64')]:
            changed = {**config, field: value}
            with self.assertRaises(ValueError):
                publication_probe(SHA, 'web', publication_fixture(configuration=changed)[0])
        for field in ('frontiercloud.revision', 'frontiercloud.component', 'frontiercloud.runtime',
                      'frontiercloud.schema-generation', 'frontiercloud.release-manifest-version',
                      'org.opencontainers.image.source', 'org.opencontainers.image.revision'):
            changed = json.loads(raw)
            changed['config']['Labels'][field] = 'wrong'
            with self.assertRaises(ValueError):
                publication_probe(SHA, 'web', publication_fixture(configuration=changed)[0])

    def test_publication_only_exact_manifest_unknown_allows_new_bytes(self):
        with self.assertRaises(ManifestUnknown):
            publication_probe(SHA, 'web', lambda *args: (404, {}, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}'))
        for code, body in ((404, b'{}'), (404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}'),
                           (404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"},{"code":"DENIED"}]}'),
                           (403, b'{}'), (500, b'{}'), (401, b'{}')):
            with self.assertRaises(ValueError):
                publication_probe(SHA, 'web', lambda *args: (code, {}, body))
        request, tag, runtime, raw = publication_fixture()
        invalid = json.loads(tag[2]);invalid['manifests'][0]['platform']['architecture'] = 'arm64'
        with self.assertRaises(ValueError):
            publication_probe(SHA, 'web', lambda path, token='': response(invalid) if path.endswith(SHA) else request(path, token))
        # Config/child absence is corruption of an existing publication, not a
        # missing tag: it must never grant a rebuild.
        for suffix in ('/blobs/', '/manifests/sha256:'):
            with self.assertRaises(ValueError):
                publication_probe(SHA, 'web', lambda path, token='': (404, {}, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}') if suffix in path else request(path, token))

    def test_publication_reads_all_components_and_resumes_valid_partial_release(self):
        calls = []
        fixtures = {c: publication_fixture(c)[0] for c in ('web', 'updater', 'nginx')}
        def request(path, token=''):
            component = next(c for c in fixtures if 'gin-' + c + '/' in path)
            calls.append(component)
            if component == 'updater':
                return 404, {}, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}'
            return fixtures[component](path, token)
        plan = publication_plan(SHA, request)
        self.assertEqual(set(calls), {'web', 'updater', 'nginx'})
        self.assertTrue(plan['components']['updater']['missing'])
        self.assertFalse(plan['components']['web']['missing'])
        self.assertFalse(plan['components']['nginx']['missing'])

    def test_config_digest_size_and_child_digest_fail_closed(self):
        request, tag, runtime, raw = publication_fixture()
        for suffix in ('/blobs/', '/manifests/sha256:'):
            with self.assertRaises(ValueError):
                publication_probe(SHA, 'web', lambda path, token='': (200, {}, b'{}') if suffix in path else request(path, token))
        child = json.loads(runtime[2]);child['config']['size'] += 1
        bad_runtime = response(child)
        index = json.loads(tag[2]);index['manifests'][0]['digest'] = bad_runtime[1]['Docker-Content-Digest']
        with self.assertRaises(ValueError):
            publication_probe(SHA, 'web', lambda path, token='': response(index) if path.endswith(SHA) else (200, {}, raw) if '/blobs/' in path else bad_runtime)

    def test_workflow_sha_serialization_reuse_precedes_any_build_or_login(self):
        text = (ROOT / '.github/workflows/publish-images.yml').read_text()
        group = next(line for line in text.splitlines() if 'group: native-images' in line)
        self.assertIn('needs.plan.outputs.revision', group)
        self.assertNotIn('github.ref', group)
        self.assertIn('cancel-in-progress: false', text)
        self.assertLess(text.index('scripts/trusted_native_publish.py plan'), text.index('actions/setup-go'))
        self.assertLess(text.index('scripts/trusted_native_publish.py plan'), text.index('docker/setup-buildx-action'))
        self.assertLess(text.index('scripts/trusted_native_publish.py plan'), text.index('packages: write'))
        self.assertEqual(text.count("if: steps.selection.outputs.missing == 'true'"), 6)
        self.assertIn('scripts/trusted_native_publish.py publish', text)
        self.assertNotIn('docker login', text)

    def test_blob_only_fixed_https_github_redirect_without_forwarding_auth(self):
        def reply(status, headers, raw):
            stream = io.BytesIO(raw)
            stream.status, stream.headers = status, headers
            return stream
        location = 'https://pkg-containers.githubusercontent.com/fixture?signature=public-fixture'
        opener = Mock()
        opener.open.side_effect = [reply(307, {'Location': location}, b''), reply(200, {}, b'config')]
        with patch('scripts.registry_images.urllib.request.build_opener', return_value=opener):
            self.assertEqual(fetch('/v2/wongyiuming/frontiercloud-gin-web/blobs/sha256:' + 'b' * 64, 'registry-secret')[2], b'config')
        self.assertEqual(opener.open.call_args_list[0].args[0].get_header('Authorization'), 'Bearer registry-secret')
        self.assertIsNone(opener.open.call_args_list[1].args[0].get_header('Authorization'))
        for location in ('http://pkg-containers.githubusercontent.com/fixture', 'https://evil.invalid/fixture',
                         'https://pkg-containers.githubusercontent.com:444/fixture',
                         'https://user@pkg-containers.githubusercontent.com/fixture'):
            opener = Mock();opener.open.return_value = reply(307, {'Location': location}, b'')
            with patch('scripts.registry_images.urllib.request.build_opener', return_value=opener), self.assertRaises(ValueError):
                fetch('/v2/wongyiuming/frontiercloud-gin-web/blobs/sha256:' + 'b' * 64, 'registry-secret')
            self.assertEqual(opener.open.call_count, 1)

    def test_publication_network_failure_never_becomes_missing_plan(self):
        with self.assertRaises(urllib.error.URLError):
            publication_plan(SHA, lambda *args: (_ for _ in ()).throw(urllib.error.URLError('fixture')))


if __name__ == '__main__':
    unittest.main()

"""Trusted writer boundary tests: synthetic OCI, no registry writes or credentials."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error
import zipfile

from scripts import trusted_native_publish as publisher

REVISION, TRUSTED = 'a' * 40, 'b' * 40


class Fixture:
    def __init__(self, branch='dev'):
        self.environ = {'GITHUB_EVENT_NAME': 'workflow_run', 'GITHUB_REPOSITORY': publisher.REPOSITORY,
                        'GITHUB_REF': 'refs/heads/main', 'GITHUB_WORKFLOW_REF': publisher.WORKFLOW_REFERENCE,
                        'GITHUB_WORKFLOW_SHA': TRUSTED, 'GITHUB_SHA': TRUSTED,
                        'GITHUB_RUN_ID': '2000', 'GITHUB_RUN_ATTEMPT': '2'}
        self.source = {'id': 1000, 'workflow_id': 9, 'name': publisher.SOURCE_NAME, 'run_number': 10,
                       'run_attempt': 3, 'path': '.github/workflows/docker.yml', 'head_sha': REVISION,
                       'head_branch': branch, 'event': 'push', 'status': 'completed', 'conclusion': 'success',
                       'head_repository': {'full_name': publisher.REPOSITORY}}
        self.event = {'action': 'completed', 'repository': {'full_name': publisher.REPOSITORY, 'default_branch': 'main'},
                      'workflow_run': copy.deepcopy(self.source)}
        self.runs = [self.source]
        self.head = REVISION
        self.record = {'id': 55, 'name': publisher.artifact_name(self.environ, 'web'), 'expired': False,
                       'size_in_bytes': 100, 'digest': 'sha256:' + 'd' * 64,
                       'workflow_run': {'id': 2000, 'head_branch': 'main', 'head_sha': TRUSTED}}
        self.artifacts = [self.record]

    def read(self, path):
        if path == '/actions/workflows/docker.yml':
            return {'id': 9, 'path': '.github/workflows/docker.yml', 'name': publisher.SOURCE_NAME}
        if path.startswith('/actions/workflows/9/runs?'):
            return {'total_count': len(self.runs), 'workflow_runs': copy.deepcopy(self.runs)}
        if path == '/actions/runs/1000': return copy.deepcopy(self.source)
        if path.startswith('/git/ref/heads/'): return {'object': {'type': 'commit', 'sha': self.head}}
        if path == '/actions/runs/2000/artifacts?per_page=100':
            return {'total_count': len(self.artifacts), 'artifacts': copy.deepcopy(self.artifacts)}
        raise AssertionError('Unexpected proof path ' + path)

    def proof(self, component='web'):
        return {'image': 'ghcr.io/wongyiuming/frontiercloud-gin-' + component + '@sha256:' + 'c' * 64,
                'tag_digest': 'sha256:' + 'c' * 64, 'config_digest': 'sha256:' + 'd' * 64}

    def plan(self, missing=False):
        def probe(_revision, component):
            if missing: raise publisher.registry_images.ManifestUnknown()
            return self.proof(component)
        return publisher.source_proof(self.event, self.environ, self.read, probe)


def oci_payload(component='web', revision=REVISION, mutate=None):
    def encoded(value): return json.dumps(value, separators=(',', ':')).encode()
    labels = {'org.opencontainers.image.source': publisher.registry_images.SOURCE,
              'org.opencontainers.image.revision': revision, 'frontiercloud.revision': revision,
              'frontiercloud.component': component, 'frontiercloud.runtime': 'go',
              'frontiercloud.schema-generation': '3', 'frontiercloud.release-manifest-version': '1'}
    configuration = {'os': 'linux', 'architecture': 'amd64', 'config': {'Labels': labels}}
    if mutate: mutate(configuration)
    config = encoded(configuration)
    layer = b'opaque fixture layer bytes, never executed'
    def descriptor(body, media):
        return {'digest': 'sha256:' + hashlib.sha256(body).hexdigest(), 'size': len(body), 'mediaType': media}
    manifest = encoded({'schemaVersion': 2, 'mediaType': publisher.OCI_MANIFEST,
                        'config': descriptor(config, 'application/vnd.oci.image.config.v1+json'),
                        'layers': [descriptor(layer, 'application/vnd.oci.image.layer.v1.tar')]})
    selected = descriptor(manifest, publisher.OCI_MANIFEST)
    selected['platform'] = {'os': 'linux', 'architecture': 'amd64'}
    entries = {'oci-layout': encoded({'imageLayoutVersion': '1.0.0'}),
               'index.json': encoded({'schemaVersion': 2, 'manifests': [selected]})}
    for body in (manifest, config, layer): entries['blobs/sha256/' + hashlib.sha256(body).hexdigest()] = body
    return entries, selected['digest']


def save_oci(directory, entries, extra=None):
    path = Path(directory) / 'fixture.oci.tar'
    with tarfile.open(path, 'w') as archive:
        for name, body in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
        if extra: extra(archive)
    return path


class TrustedNativePublishTests(unittest.TestCase):
    def test_main_code_and_original_source_identity_are_bound_for_dev_and_main(self):
        for branch in ('dev', 'main'):
            fixture = Fixture(branch)
            plan = fixture.plan()
            self.assertEqual(plan['branch'], branch)
            self.assertEqual(plan['revision'], REVISION)
            self.assertEqual(plan['trusted_workflow_sha'], TRUSTED)
            self.assertEqual((plan['source_run_id'], plan['source_run_number'], plan['source_run_attempt']), (1000, 10, 3))
            self.assertEqual((plan['publish_run_id'], plan['publish_run_attempt']), (2000, 2))
            publisher.verify_plan(plan, fixture.event, fixture.environ, fixture.read)

    def test_no_push_dispatch_dev_checkout_or_fork_can_authorize_writer(self):
        for key, value in (('GITHUB_EVENT_NAME', 'push'), ('GITHUB_REF', 'refs/heads/dev'),
                           ('GITHUB_WORKFLOW_REF', publisher.WORKFLOW_REFERENCE.replace('main', 'dev')),
                           ('GITHUB_SHA', REVISION), ('GITHUB_RUN_ID', '2000; curl bad')):
            fixture = Fixture(); fixture.environ[key] = value
            with self.subTest(key=key), self.assertRaises(publisher.PublicationRejected): fixture.plan()
        for key, value in (('event', 'pull_request'), ('head_branch', 'other'), ('conclusion', 'failure'),
                           ('status', 'in_progress'), ('head_sha', 'bad'), ('run_attempt', True), ('workflow_id', 3)):
            fixture = Fixture(); fixture.event['workflow_run'][key] = value
            with self.subTest(key=key), self.assertRaises(publisher.PublicationRejected): fixture.plan()
        fixture = Fixture(); fixture.source['head_repository']['full_name'] = 'fork/repo'
        with self.assertRaises(publisher.PublicationRejected): fixture.plan()

    def test_pending_newer_attempt_or_branch_advance_rejects_old_success(self):
        for change in ('pending', 'attempt', 'head'):
            fixture = Fixture()
            if change == 'pending':
                newer = copy.deepcopy(fixture.source); newer.update(id=1100, run_number=11, status='queued', conclusion=None)
                fixture.runs.append(newer)
            elif change == 'attempt': fixture.source['run_attempt'] = 4
            else: fixture.head = 'e' * 40
            with self.subTest(change=change), self.assertRaises(publisher.PublicationRejected): fixture.plan()

    def test_source_plan_cannot_invent_identity_component_or_existing_digest(self):
        fixture = Fixture()
        for key, value in (('revision', 'e'*40), ('branch', 'main'), ('source_run_id', 900),
                           ('source_run_attempt', True), ('publish_run_id', 1999), ('trusted_workflow_sha', REVISION)):
            plan = fixture.plan(); plan[key] = value
            with self.subTest(key=key), self.assertRaises(publisher.PublicationRejected):
                publisher.verify_plan(plan, fixture.event, fixture.environ, fixture.read)
        plan = fixture.plan(); plan['components']['web']['image'] = 'ghcr.io/evil/old@sha256:' + 'c'*64
        with self.assertRaises(publisher.PublicationRejected): publisher.verify_plan(plan, fixture.event, fixture.environ, fixture.read)

    def test_only_canonical_absence_authorizes_compilation(self):
        fixture = Fixture()
        self.assertTrue(all(value['missing'] for value in fixture.plan(True)['components'].values()))
        for error in (OSError('network'), ValueError('private'), publisher.registry_images.ImageUnavailable('generic404')):
            with self.subTest(error=type(error).__name__), self.assertRaises(type(error)):
                publisher.source_proof(fixture.event, fixture.environ, fixture.read, Mock(side_effect=error))

    def test_artifact_bound_to_current_run_attempt_component_and_trusted_main(self):
        fixture = Fixture()
        self.assertEqual(publisher.artifact_record(fixture.environ, 'web', fixture.read)['id'], 55)
        for key, value in (('name', 'native-oci-2000-1-web'), ('expired', True), ('size_in_bytes', publisher.MAX_ARCHIVE * 2),
                           ('digest', 'sha256:bad')):
            fixture = Fixture(); fixture.record[key] = value
            with self.subTest(key=key), self.assertRaises(publisher.PublicationRejected):
                publisher.artifact_record(fixture.environ, 'web', fixture.read)
        for key, value in (('id', 1999), ('head_sha', REVISION), ('head_branch', 'dev')):
            fixture = Fixture(); fixture.record['workflow_run'][key] = value
            with self.subTest(key=key), self.assertRaises(publisher.PublicationRejected):
                publisher.artifact_record(fixture.environ, 'web', fixture.read)
        fixture = Fixture(); fixture.artifacts.append(copy.deepcopy(fixture.record))
        with self.assertRaises(publisher.PublicationRejected): publisher.artifact_record(fixture.environ, 'web', fixture.read)

    def test_valid_oci_is_bounded_data_and_preserves_exact_manifest_digest(self):
        for component in publisher.COMPONENTS:
            entries, digest = oci_payload(component)
            with tempfile.TemporaryDirectory() as directory:
                verified = publisher.verify_oci(save_oci(directory, entries), REVISION, component)
                self.assertEqual(verified['digest'], digest)
                self.assertEqual('sha256:' + hashlib.sha256(verified['manifest']).hexdigest(), digest)
                self.assertEqual(len(verified['blobs']), 2)

    def test_oci_wrong_labels_platform_or_revision_never_reaches_writer(self):
        for mutation in (lambda conf: conf.update(os='windows'), lambda conf: conf.update(architecture='arm64'),
                         lambda conf: conf['config']['Labels'].update({'frontiercloud.revision': 'e'*40}),
                         lambda conf: conf['config']['Labels'].update({'frontiercloud.component': 'updater'}),
                         lambda conf: conf['config']['Labels'].update({'frontiercloud.schema-generation': '2'}),
                         lambda conf: conf['config']['Labels'].update({'frontiercloud.release-manifest-version': '0'})):
            entries, _digest = oci_payload(mutate=mutation)
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(publisher.PublicationRejected):
                publisher.verify_oci(save_oci(directory, entries), REVISION, 'web')

    def test_tar_path_link_duplicate_extra_blob_and_hash_corruption_fail_closed(self):
        def duplicate(archive):
            member = tarfile.TarInfo('index.json'); member.size = 2
            archive.addfile(member, io.BytesIO(b'{}'))
        def link(archive):
            member = tarfile.TarInfo('blobs/sha256/' + 'd'*64); member.type = tarfile.SYMTYPE; member.linkname = '/etc/passwd'
            archive.addfile(member)
        for change in ('path', 'link', 'duplicate', 'extra', 'hash'):
            entries, _digest = oci_payload()
            extra = None
            if change == 'path': entries['../../helper.py'] = b'executable? never'
            elif change == 'link': extra = link
            elif change == 'duplicate': extra = duplicate
            elif change == 'extra': entries['blobs/sha256/' + hashlib.sha256(b'extra').hexdigest()] = b'extra'
            else:
                name = next(name for name in entries if name.startswith('blobs/'))
                entries[name] = b'x' * len(entries[name])
            with tempfile.TemporaryDirectory() as directory, self.subTest(change=change), self.assertRaises(publisher.PublicationRejected):
                publisher.verify_oci(save_oci(directory, entries, extra), REVISION, 'web')

    def test_same_sha_reuses_and_drift_disappearance_never_upload(self):
        fixture = Fixture(); plan = fixture.plan(); writer = Mock()
        for _attempt in range(2):
            result = publisher.publish(plan, fixture.event, fixture.environ, 'web', fixture.read,
                                       probe=Mock(return_value=fixture.proof()), writer=writer)
            self.assertEqual(result['action'], 'reused')
        for probe in (Mock(side_effect=publisher.registry_images.ManifestUnknown()),
                      Mock(return_value={**fixture.proof(), 'tag_digest': 'sha256:' + 'e'*64})):
            with self.assertRaises(publisher.PublicationRejected):
                publisher.publish(plan, fixture.event, fixture.environ, 'web', fixture.read, probe=probe, writer=writer)
        writer.transfer.assert_not_called()

    def test_missing_sha_transfer_occurs_once_and_only_at_exact_source_tag(self):
        fixture = Fixture(); plan = fixture.plan(True)
        entries, digest = oci_payload()
        proof = {**fixture.proof(), 'tag_digest': digest}
        writer = Mock()
        with tempfile.TemporaryDirectory() as directory:
            archive = save_oci(directory, entries)
            result = publisher.publish(plan, fixture.event, fixture.environ, 'web', fixture.read, archive,
                                       Mock(side_effect=[publisher.registry_images.ManifestUnknown(),
                                                         publisher.registry_images.ManifestUnknown(), proof]), writer)
            self.assertEqual(result['action'], 'published')
            self.assertEqual(writer.transfer.call_count, 1)
            self.assertEqual(writer.transfer.call_args.args[2], REVISION)

    def test_filled_missing_tag_reuses_without_transfer_and_errors_never_grant_upload(self):
        fixture = Fixture(); plan = fixture.plan(True); writer = Mock()
        result = publisher.publish(plan, fixture.event, fixture.environ, 'web', fixture.read,
                                   probe=Mock(return_value=fixture.proof()), writer=writer)
        self.assertEqual(result['action'], 'reused')
        for error in (OSError(), ValueError(), publisher.registry_images.ImageUnavailable()):
            with self.assertRaises(type(error)):
                publisher.publish(plan, fixture.event, fixture.environ, 'web', fixture.read,
                                  probe=Mock(side_effect=error), writer=writer)
        writer.transfer.assert_not_called()

    def test_registry_token_is_scoped_and_authenticated_upload_cannot_redirect_or_choose_old_tag(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_args): pass
            def read(self, _size): return b'{"token":"fixture-scoped-token"}'
        opener = Mock(); opener.open.return_value = Response()
        writer = publisher.RegistryWriter('web', 'wongyiuming', 'fixture-only-automatic-token', opener)
        request = opener.open.call_args.args[0]
        self.assertIn('repository%3Awongyiuming%2Ffrontiercloud-gin-web%3Apull%2Cpush', request.full_url)
        with self.assertRaises(publisher.PublicationRejected): writer.request('/v2/evil/manifests/old', 'PUT', b'data')
        with self.assertRaises(publisher.PublicationRejected): writer.transfer('unused', {}, 'old-tag')
        self.assertIsNone(publisher.registry_images.NoRedirect().redirect_request(None, None, None, None, None, None))

    def test_scoped_registry_transfer_reads_opaque_blob_and_rejects_external_upload_location(self):
        entries, _digest = oci_payload()
        repo = '/v2/wongyiuming/frontiercloud-gin-web/blobs/'
        for location in ('https://evil.example/uploads/id', '/v2/evil/blobs/uploads/id',
                         '//ghcr.io' + repo + 'upload/id', 'http://ghcr.io' + repo + 'upload/id',
                         'https://user@ghcr.io' + repo + 'upload/id',
                         'https://ghcr.io:444' + repo + 'upload/id',
                         repo + 'upload/', repo + 'upload/..', repo + 'upload/id/extra',
                         repo + 'upload/%2e%2e', repo + 'upload/id\\extra',
                         repo + 'upload/id#fragment', repo + 'upload/id\nheader',
                         repo + 'upload/id?digest=sha256:other'):
            writer = object.__new__(publisher.RegistryWriter); writer.repository = 'wongyiuming/frontiercloud-gin-web'
            writer.request = Mock(side_effect=[urllib.error.HTTPError('https://ghcr.io', 404, '', {}, None), {'Location': location}])
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(publisher.PublicationRejected):
                archive = save_oci(directory, entries)
                writer.transfer(archive, publisher.verify_oci(archive, REVISION, 'web'), REVISION)

    def test_rest_blob_upload_streams_exact_bytes_and_only_fixed_revision_manifest(self):
        entries, digest = oci_payload()
        writer = object.__new__(publisher.RegistryWriter)
        writer.repository = 'wongyiuming/frontiercloud-gin-web'
        calls = []
        def request(path, method, data=None, headers=None, statuses=(200,)):
            calls.append((path, method))
            if method == 'HEAD': raise urllib.error.HTTPError('https://ghcr.io', 404, '', {}, None)
            if method == 'POST': return {'Location': '/v2/' + writer.repository + '/blobs/uploads/fixed?state=opaque'}
            if '/blobs/uploads/' in path:
                body = b''.join(data)
                self.assertEqual(len(body), int(headers['Content-Length']))
                self.assertIn('digest=sha256%3A' + hashlib.sha256(body).hexdigest(), path)
                return {}
            self.assertEqual(path, '/v2/' + writer.repository + '/manifests/' + REVISION)
            self.assertEqual('sha256:' + hashlib.sha256(data).hexdigest(), digest)
            return {'Docker-Content-Digest': digest}
        writer.request = request
        with tempfile.TemporaryDirectory() as directory:
            archive = save_oci(directory, entries)
            writer.transfer(archive, publisher.verify_oci(archive, REVISION, 'web'), REVISION)
        self.assertEqual(sum('/manifests/' in path for path, _method in calls), 1)

    def test_ghcr_singular_upload_location_retains_scope_opaque_state_and_exact_bytes(self):
        entries, digest = oci_payload()
        for origin in ('', 'https://ghcr.io', 'https://ghcr.io:443'):
            with self.subTest(origin=origin):
                writer = object.__new__(publisher.RegistryWriter)
                writer.repository = 'wongyiuming/frontiercloud-gin-web'
                uploads = []
                def request(path, method, data=None, headers=None, statuses=(200,)):
                    if method == 'HEAD': raise urllib.error.HTTPError('https://ghcr.io', 404, '', {}, None)
                    if method == 'POST':
                        return {'location': origin + '/v2/' + writer.repository + '/blobs/upload/opaque-id?state=opaque%2Bvalue'}
                    if '/blobs/upload/' in path:
                        self.assertEqual(method, 'PUT')
                        self.assertTrue(path.startswith('/v2/' + writer.repository + '/blobs/upload/opaque-id?'))
                        query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
                        self.assertEqual(query['state'], ['opaque+value'])
                        body = b''.join(data)
                        self.assertEqual(len(body), int(headers['Content-Length']))
                        self.assertEqual(query['digest'], ['sha256:' + hashlib.sha256(body).hexdigest()])
                        uploads.append(body)
                        return {}
                    self.assertEqual(path, '/v2/' + writer.repository + '/manifests/' + REVISION)
                    self.assertEqual('sha256:' + hashlib.sha256(data).hexdigest(), digest)
                    return {'Docker-Content-Digest': digest}
                writer.request = request
                with tempfile.TemporaryDirectory() as directory:
                    archive = save_oci(directory, entries)
                    verified = publisher.verify_oci(archive, REVISION, 'web')
                    writer.transfer(archive, verified, REVISION)
                    self.assertEqual(len(uploads), len(verified['blobs']))

    def test_artifact_zip_digest_bound_and_signed_url_receives_no_github_authorization(self):
        entries, _digest = oci_payload()
        with tempfile.TemporaryDirectory() as directory:
            archive = save_oci(directory, entries)
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED) as zipped:
                zipped.writestr('web.oci.tar', archive.read_bytes())
            raw = buffer.getvalue()
        record = Fixture().record
        record.update(size_in_bytes=len(raw), digest='sha256:' + hashlib.sha256(raw).hexdigest())
        class Response(io.BytesIO):
            status = 200
        class Opener:
            def __init__(self, location='https://fixture.blob.core.windows.net/zip?signed=opaque'): self.location = location
            def open(self, request, timeout):
                if request.full_url.startswith(publisher.API_ROOT):
                    self.asserted_auth = request.get_header('Authorization')
                    raise urllib.error.HTTPError(request.full_url, 302, '', {'Location': self.location}, None)
                if request.get_header('Authorization') is not None: raise AssertionError('Authorization forwarded')
                return Response(raw)
        opener = Opener()
        with tempfile.TemporaryDirectory() as directory:
            output = publisher.download_artifact(record, 'fixture-read-only-token', directory, 'web', opener)
            publisher.verify_oci(output, REVISION, 'web')
        self.assertEqual(opener.asserted_auth, 'Bearer fixture-read-only-token')
        for bad in ('https://evil.example/zip', 'http://fixture.blob.core.windows.net/zip',
                    'https://user:secret@fixture.blob.core.windows.net/zip'):
            with tempfile.TemporaryDirectory() as directory, self.subTest(host=bad), self.assertRaises(publisher.PublicationRejected):
                publisher.download_artifact(record, 'fixture-read-only-token', directory, 'web', Opener(bad))
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(publisher.PublicationRejected):
            publisher.download_artifact({**record, 'digest': 'sha256:' + 'f'*64}, 'fixture-token', directory, 'web', Opener())

    def test_compile_and_write_credential_jobs_are_separated_in_trusted_workflow(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/publish-images.yml').read_text()
        compile_part = workflow.split('  compile:\n')[1].split('  publish:\n')[0]
        publish_part = workflow.split('  publish:\n')[1].split('  notify-staging:\n')[0]
        self.assertIn('workflow_run:', workflow)
        self.assertIn('workflows: ["Build and Test Docker Compose"]', workflow)
        self.assertNotIn('195000', workflow)
        self.assertEqual(workflow.count('packages: write'), 1)
        self.assertNotIn('GHCR_PUBLISH_TOKEN', workflow)
        self.assertNotIn('secrets.', compile_part)
        self.assertNotIn('docker login', compile_part)
        self.assertNotIn('--push', compile_part)
        self.assertIn('--provenance=false --sbom=false', compile_part)
        self.assertNotIn('packages: write', compile_part)
        self.assertNotIn('environment: native-image-publish-main', publish_part)
        self.assertIn('packages: write', publish_part)
        self.assertIn('GITHUB_TOKEN: ${{ github.token }}', publish_part)
        self.assertIn('ref: ${{ github.workflow_sha }}', publish_part)
        self.assertNotIn('ref: ${{ needs.plan.outputs.revision }}', publish_part)
        self.assertNotIn('docker ', publish_part)
        self.assertNotIn('go build', publish_part)

    def test_cli_publishes_with_automatic_token_and_ignores_old_personal_pat(self):
        fixture = Fixture()
        automatic = 'fixture-only-automatic-token'
        fixture.environ.update(GITHUB_TOKEN=automatic, GHCR_PUBLISH_TOKEN='fixture-only-unused-personal-token',
                               PLAN_JSON=json.dumps(fixture.plan(True)))
        entries, _digest = oci_payload()
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / 'event.json'
            event_path.write_text(json.dumps(fixture.event), encoding='utf-8')
            fixture.environ['GITHUB_EVENT_PATH'] = str(event_path)
            archive = save_oci(directory, entries)
            with patch.dict(publisher.os.environ, fixture.environ, clear=True), \
                 patch('sys.argv', ['publisher', 'publish', '--component', 'web']), \
                 patch.object(publisher.subprocess, 'check_output', return_value=TRUSTED + '\n'), \
                 patch.object(publisher, 'github_reader', return_value=fixture.read), \
                 patch.object(publisher, 'download_artifact', return_value=archive) as download, \
                 patch.object(publisher, 'RegistryWriter') as writer, \
                 patch.object(publisher, 'publish', return_value={'action': 'fixture-only'}) as publish, \
                 patch('builtins.print'):
                publisher.main()
            writer.assert_called_once_with('web', 'wongyiuming', automatic)
            self.assertEqual(download.call_args.args[1], automatic)
            self.assertIs(publish.call_args.kwargs['writer'], writer.return_value)

    def test_missing_automatic_token_cannot_fall_back_to_personal_pat(self):
        fixture = Fixture()
        fixture.environ['GHCR_PUBLISH_TOKEN'] = 'fixture-only-unused-personal-token'
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / 'event.json'
            event_path.write_text(json.dumps(fixture.event), encoding='utf-8')
            fixture.environ['GITHUB_EVENT_PATH'] = str(event_path)
            with patch.dict(publisher.os.environ, fixture.environ, clear=True), \
                 patch('sys.argv', ['publisher', 'publish', '--component', 'web']), \
                 patch.object(publisher.subprocess, 'check_output', return_value=TRUSTED + '\n'), \
                 patch.object(publisher.urllib.request, 'build_opener') as opener, \
                 self.assertRaises(publisher.PublicationRejected):
                publisher.main()
            opener.assert_not_called()

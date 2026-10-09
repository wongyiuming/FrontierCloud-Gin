"""Privileged notifier proof tests; no GitHub, registry, HMAC secret or deployment I/O."""
import copy
import hashlib
import hmac
import json
import unittest

from scripts import trusted_staging_notify as notify


REVISION = 'a' * 40
TRUSTED = 'b' * 40


def run(identity, filename, number, attempt=1):
    return {'workflow_id': identity, 'path': '.github/workflows/' + filename,
            'head_sha': REVISION, 'head_branch': 'dev', 'event': 'push',
            'head_repository': {'full_name': notify.REPOSITORY}, 'id': number * 100,
            'run_number': number, 'run_attempt': attempt,
            'status': 'completed', 'conclusion': 'success'}


class Fixture:
    def __init__(self):
        self.environ = {'GITHUB_EVENT_NAME': 'workflow_run', 'GITHUB_REPOSITORY': notify.REPOSITORY,
                        'GITHUB_REF': 'refs/heads/main', 'GITHUB_WORKFLOW_REF': notify.WORKFLOW_REFERENCE,
                        'GITHUB_SHA': TRUSTED, 'GITHUB_WORKFLOW_SHA': TRUSTED}
        self.publication = run(1, 'publish-images.yml', 12, 2)
        self.publication['name'] = notify.PUBLISH_NAME
        self.source = run(2, 'docker.yml', 10, 3)
        self.event = {'action': 'completed', 'repository': {'full_name': notify.REPOSITORY, 'default_branch': 'main'},
                      'workflow_run': copy.deepcopy(self.publication)}
        self.pub_runs = [self.publication]
        self.source_runs = [self.source]
        self.jobs = [{'name': 'publish (' + component + ')', 'status': 'completed', 'conclusion': 'success'}
                     for component in notify.COMPONENTS]
        self.head = REVISION
        self.images = []
        self.api_calls = []

    def read(self, path):
        self.api_calls.append(path)
        if path == '/actions/workflows/publish-images.yml':
            return {'id': 1, 'path': '.github/workflows/publish-images.yml', 'name': notify.PUBLISH_NAME}
        if path == '/actions/workflows/docker.yml':
            return {'id': 2, 'path': '.github/workflows/docker.yml', 'name': notify.SOURCE_NAME}
        if path == '/actions/runs/1200':
            return copy.deepcopy(self.publication)
        if path.startswith('/actions/workflows/1/runs?'):
            return {'workflow_runs': copy.deepcopy(self.pub_runs), 'total_count': len(self.pub_runs)}
        if path.startswith('/actions/workflows/2/runs?'):
            return {'workflow_runs': copy.deepcopy(self.source_runs), 'total_count': len(self.source_runs)}
        if path == '/actions/runs/1200/attempts/2/jobs?per_page=100':
            return {'jobs': copy.deepcopy(self.jobs), 'total_count': len(self.jobs)}
        if path == '/git/ref/heads/dev':
            return {'object': {'type': 'commit', 'sha': self.head}}
        raise AssertionError('Unexpected proof path ' + path)

    def resolve(self, revision, component, architecture):
        self.images.append((revision, component, architecture))
        return 'ghcr.io/wongyiuming/frontiercloud-gin-' + component + '@sha256:' + 'c'*64

    def verify(self):
        return notify.verify_image_ready(self.event, self.environ, self.read, self.resolve)


class TrustedStagingNotifyTests(unittest.TestCase):
    def test_default_main_verifies_all_images_and_retains_original_source_ci_identity(self):
        fixture = Fixture()
        payload = fixture.verify()
        self.assertEqual(payload['sha'], REVISION)
        self.assertEqual((payload['run_id'], payload['run_number'], payload['run_attempt']), (1000, 10, 3))
        self.assertEqual(set(fixture.images), {(REVISION, component, 'amd64') for component in notify.COMPONENTS})
        self.assertGreaterEqual(fixture.api_calls.count('/git/ref/heads/dev'), 2)

    def test_untrusted_workflow_refs_branches_events_and_repositories_are_rejected(self):
        for key, value in (('GITHUB_EVENT_NAME', 'push'), ('GITHUB_REF', 'refs/heads/dev'),
                           ('GITHUB_WORKFLOW_REF', notify.WORKFLOW_REFERENCE.replace('main', 'dev')),
                           ('GITHUB_SHA', REVISION), ('GITHUB_REPOSITORY', 'fork/repo')):
            fixture = Fixture(); fixture.environ[key] = value
            with self.subTest(key=key), self.assertRaises(notify.NotificationRejected): fixture.verify()
            self.assertEqual(fixture.images, [])
        for key, value in (('event', 'pull_request'), ('head_branch', 'main'), ('status', 'in_progress'),
                           ('conclusion', 'failure'), ('head_sha', 'a; curl bad'), ('run_attempt', True),
                           ('name', notify.SOURCE_NAME), ('workflow_id', 2)):
            fixture = Fixture(); fixture.event['workflow_run'][key] = value
            with self.subTest(key=key), self.assertRaises(notify.NotificationRejected): fixture.verify()
            self.assertEqual(fixture.images, [])
        fixture = Fixture(); fixture.event['workflow_run']['head_repository']['full_name'] = 'fork/repo'
        with self.assertRaises(notify.NotificationRejected): fixture.verify()

    def test_newest_source_ci_pending_failed_or_foreign_cannot_be_replaced_with_old_success(self):
        for field, value in (('status', 'in_progress'), ('conclusion', 'failure'), ('conclusion', 'cancelled')):
            fixture = Fixture()
            newer = run(2, 'docker.yml', 11); newer[field] = value
            fixture.source_runs.append(newer)
            with self.subTest(value=value), self.assertRaises(notify.NotificationRejected): fixture.verify()
            self.assertEqual(fixture.images, [])
        fixture = Fixture(); fixture.source_runs[0]['head_repository']['full_name'] = 'fork/repo'
        with self.assertRaises(notify.NotificationRejected): fixture.verify()

    def test_old_publication_attempt_and_newer_publication_are_rejected(self):
        fixture = Fixture(); fixture.publication['run_attempt'] = 3
        with self.assertRaises(notify.NotificationRejected): fixture.verify()
        fixture = Fixture(); fixture.pub_runs.append(run(1, 'publish-images.yml', 13))
        with self.assertRaises(notify.NotificationRejected): fixture.verify()

    def test_truncated_or_paginated_run_and_job_proofs_fail_closed(self):
        for endpoint in ('/actions/workflows/1/runs?', '/actions/workflows/2/runs?',
                         '/actions/runs/1200/attempts/2/jobs?'):
            for total in (-1, 0, 100, True):
                fixture = Fixture()
                def read(path):
                    document = fixture.read(path)
                    if path.startswith(endpoint): document['total_count'] = total
                    return document
                with self.subTest(endpoint=endpoint, total=total), self.assertRaises(notify.NotificationRejected):
                    notify.verify_image_ready(fixture.event, fixture.environ, read, fixture.resolve)
                self.assertEqual(fixture.images, [])

    def test_each_exact_publish_job_is_required_not_merely_workflow_name_success(self):
        for change in ('missing', 'skipped', 'failed', 'duplicate'):
            fixture = Fixture()
            if change == 'missing': fixture.jobs.pop()
            elif change == 'duplicate': fixture.jobs[2] = copy.deepcopy(fixture.jobs[0])
            else: fixture.jobs[0]['conclusion'] = change
            with self.subTest(change=change), self.assertRaises(notify.NotificationRejected): fixture.verify()
            self.assertEqual(fixture.images, [])

    def test_public_proof_missing_private_or_invalid_never_uses_compile_fallback(self):
        for failure in (notify.registry_images.ImageUnavailable('absent'), ValueError('private'), ValueError('digest')):
            fixture = Fixture()
            def broken(*_args, **_kwargs): raise failure
            with self.subTest(failure=type(failure).__name__), self.assertRaises(type(failure)):
                notify.verify_image_ready(fixture.event, fixture.environ, fixture.read, broken)
        fixture = Fixture()
        with self.assertRaises(notify.NotificationRejected):
            notify.verify_image_ready(fixture.event, fixture.environ, fixture.read, lambda *_a, **_k: 'http://evil/image')

    def test_superseded_dev_or_ci_during_image_proof_does_not_notify(self):
        fixture = Fixture(); fixture.head = 'd'*40
        with self.assertRaises(notify.NotificationRejected): fixture.verify()
        for change in ('head', 'source', 'publication'):
            fixture = Fixture()
            def resolve(*args, **kwargs):
                if change == 'head': fixture.head = 'd'*40
                elif change == 'source': fixture.source_runs = [run(2, 'docker.yml', 11)]
                else: fixture.pub_runs = [run(1, 'publish-images.yml', 13)]
                return fixture.resolve(*args, **kwargs)
            with self.subTest(change=change), self.assertRaises(notify.NotificationRejected):
                notify.verify_image_ready(fixture.event, fixture.environ, fixture.read, resolve)

    def test_redirect_and_tls_policy_remain_strict_and_signature_is_exact(self):
        self.assertIsNone(notify.registry_images.NoRedirect().redirect_request(None, None, None, None, None, None))
        captured = {}
        class Response:
            status = 202
            def __enter__(self): return self
            def __exit__(self, *_args): pass
        class Opener:
            def open(self, request, timeout):
                captured['request'], captured['timeout'] = request, timeout
                return Response()
        payload = Fixture().verify()
        secret = 'fixture-only-not-production-secret'*2
        notify.send_notification(payload, secret, Opener())
        request = captured['request']
        self.assertEqual(request.full_url, notify.NOTIFICATION_URL)
        self.assertEqual(captured['timeout'], 20)
        self.assertEqual(json.loads(request.data), payload)
        self.assertEqual(request.get_header('X-frontiercloud-signature'),
                         'sha256=' + hmac.new(secret.encode(), request.data, hashlib.sha256).hexdigest())
        with self.assertRaises(notify.NotificationRejected): notify.send_notification(payload, 'short', Opener())

    def test_receiver_requires_202_and_never_accepts_http_redirect_or_success_200(self):
        class Response:
            def __init__(self, status): self.status = status
            def __enter__(self): return self
            def __exit__(self, *_args): pass
        for status in (200, 301, 302, 307, 400, 403, 500):
            class Opener:
                def open(self, _request, timeout): return Response(status)
            with self.subTest(status=status), self.assertRaises(notify.NotificationRejected):
                notify.send_notification(Fixture().verify(), 'fixture-only-test-secret'*2, Opener())

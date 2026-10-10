"""Credential-isolated staging proof tests; no network or deployment I/O."""
import copy
import hashlib
import hmac
import json
import unittest

from scripts import trusted_staging_notify as notify

REVISION, TRUSTED = 'a' * 40, 'b' * 40
REJECTIONS = (notify.NotificationRejected, notify.publication.PublicationRejected, ValueError)


def source_run(number=10, attempt=3):
    return {'workflow_id': 2, 'path': '.github/workflows/docker.yml', 'head_sha': REVISION,
            'head_branch': 'dev', 'event': 'push', 'head_repository': {'full_name': notify.REPOSITORY},
            'id': number * 100, 'run_number': number, 'run_attempt': attempt,
            'name': notify.SOURCE_NAME, 'status': 'completed', 'conclusion': 'success'}


class Fixture:
    def __init__(self):
        self.environ = {'GITHUB_EVENT_NAME': 'workflow_run', 'GITHUB_REPOSITORY': notify.REPOSITORY,
                        'GITHUB_REF': 'refs/heads/main', 'GITHUB_WORKFLOW_REF': notify.WORKFLOW_REFERENCE,
                        'GITHUB_SHA': TRUSTED, 'GITHUB_WORKFLOW_SHA': TRUSTED,
                        'GITHUB_RUN_ID': '1200', 'GITHUB_RUN_ATTEMPT': '2'}
        self.source = source_run()
        self.event = {'action': 'completed', 'repository': {'full_name': notify.REPOSITORY, 'default_branch': 'main'},
                      'workflow_run': copy.deepcopy(self.source)}
        self.publication = {'id': 1200, 'run_attempt': 2, 'workflow_id': 1,
                            'path': '.github/workflows/publish-images.yml', 'event': 'workflow_run',
                            'status': 'in_progress', 'conclusion': None,
                            'head_repository': {'full_name': notify.REPOSITORY}}
        self.source_runs = [self.source]
        self.jobs = [{'name': 'publish (' + component + ')', 'run_id': 1200,
                      'status': 'completed', 'conclusion': 'success'} for component in notify.COMPONENTS]
        self.plan = {'version': 1, 'revision': REVISION, 'branch': 'dev',
                     'source_run_id': 1000, 'source_run_number': 10, 'source_run_attempt': 3,
                     'publish_run_id': 1200, 'publish_run_attempt': 2, 'trusted_workflow_sha': TRUSTED,
                     'components': {component: {'missing': True} for component in notify.COMPONENTS}}
        self.refresh_plan()
        self.head, self.images, self.api_calls = REVISION, [], []

    def refresh_plan(self):
        self.environ['PLAN_JSON'] = json.dumps(self.plan)

    def read(self, path):
        self.api_calls.append(path)
        if path == '/actions/workflows/publish-images.yml':
            return {'id': 1, 'path': '.github/workflows/publish-images.yml', 'name': notify.PUBLISH_NAME}
        if path == '/actions/workflows/docker.yml':
            return {'id': 2, 'path': '.github/workflows/docker.yml', 'name': notify.SOURCE_NAME}
        if path == '/actions/runs/1200': return copy.deepcopy(self.publication)
        if path == '/actions/runs/1000': return copy.deepcopy(self.source)
        if path.startswith('/actions/workflows/2/runs?'):
            return {'workflow_runs': copy.deepcopy(self.source_runs), 'total_count': len(self.source_runs)}
        if path == '/actions/runs/1200/attempts/2/jobs?per_page=100':
            return {'jobs': copy.deepcopy(self.jobs), 'total_count': len(self.jobs)}
        if path == '/git/ref/heads/dev': return {'object': {'type': 'commit', 'sha': self.head}}
        raise AssertionError('Unexpected proof path ' + path)

    def probe(self, revision, component):
        self.images.append((revision, component))
        return {'image': 'ghcr.io/wongyiuming/frontiercloud-gin-' + component + '@sha256:' + 'c' * 64,
                'tag_digest': 'sha256:' + 'd' * 64, 'config_digest': 'sha256:' + 'e' * 64}

    def verify(self):
        return notify.verify_image_ready(self.event, self.environ, self.read, self.probe)


class TrustedStagingNotifyTests(unittest.TestCase):
    def test_same_trusted_run_verifies_images_and_retains_original_source_ci_identity(self):
        fixture = Fixture()
        payload = fixture.verify()
        self.assertEqual(payload['sha'], REVISION)
        self.assertEqual((payload['run_id'], payload['run_number'], payload['run_attempt']), (1000, 10, 3))
        self.assertEqual(set(fixture.images), {(REVISION, component) for component in notify.COMPONENTS})
        self.assertGreaterEqual(fixture.api_calls.count('/git/ref/heads/dev'), 2)
        self.assertEqual(fixture.api_calls.count('/actions/runs/1200/attempts/2/jobs?per_page=100'), 2)
        self.assertFalse(any('artifacts' in path for path in fixture.api_calls))

    def test_untrusted_workflow_refs_branches_events_and_repositories_are_rejected(self):
        for key, value in (('GITHUB_EVENT_NAME', 'push'), ('GITHUB_REF', 'refs/heads/dev'),
                           ('GITHUB_WORKFLOW_REF', notify.WORKFLOW_REFERENCE.replace('main', 'dev')),
                           ('GITHUB_SHA', REVISION), ('GITHUB_REPOSITORY', 'fork/repo')):
            fixture = Fixture(); fixture.environ[key] = value
            with self.subTest(key=key), self.assertRaises(REJECTIONS): fixture.verify()
            self.assertEqual(fixture.images, [])
        for key, value in (('event', 'pull_request'), ('head_branch', 'main'), ('status', 'in_progress'),
                           ('conclusion', 'failure'), ('head_sha', 'a; curl bad'), ('run_attempt', True),
                           ('name', notify.PUBLISH_NAME), ('workflow_id', 1)):
            fixture = Fixture(); fixture.event['workflow_run'][key] = value
            with self.subTest(key=key), self.assertRaises(REJECTIONS): fixture.verify()
            self.assertEqual(fixture.images, [])
        fixture = Fixture(); fixture.event['workflow_run']['head_repository']['full_name'] = 'fork/repo'
        with self.assertRaises(REJECTIONS): fixture.verify()

    def test_newest_source_ci_pending_failed_or_foreign_cannot_use_old_success(self):
        for field, value in (('status', 'in_progress'), ('conclusion', 'failure'), ('conclusion', 'cancelled')):
            fixture = Fixture(); newer = source_run(11); newer[field] = value; fixture.source_runs.append(newer)
            with self.subTest(value=value), self.assertRaises(REJECTIONS): fixture.verify()
            self.assertEqual(fixture.images, [])
        fixture = Fixture(); fixture.source_runs[0]['head_repository']['full_name'] = 'fork/repo'
        with self.assertRaises(REJECTIONS): fixture.verify()

    def test_plan_cannot_spoof_source_or_publication_identity_or_trusted_revision(self):
        for key, value in (('source_run_id', 1100), ('source_run_attempt', 4), ('revision', 'f' * 40),
                           ('publish_run_id', 1300), ('publish_run_attempt', 3), ('trusted_workflow_sha', REVISION)):
            fixture = Fixture(); fixture.plan[key] = value; fixture.refresh_plan()
            with self.subTest(key=key), self.assertRaises(REJECTIONS): fixture.verify()
            self.assertEqual(fixture.images, [])
        fixture = Fixture(); fixture.environ['PLAN_JSON'] = 'x' * 65537
        with self.assertRaises(REJECTIONS): fixture.verify()
        fixture = Fixture(); fixture.environ['GITHUB_RUN_ATTEMPT'] = '3'
        with self.assertRaises(REJECTIONS): fixture.verify()

    def test_wrong_current_publisher_state_attempt_or_origin_is_rejected(self):
        for key, value in (('event', 'push'), ('run_attempt', 3), ('workflow_id', 2),
                           ('status', 'completed'), ('conclusion', 'failure')):
            fixture = Fixture(); fixture.publication[key] = value
            with self.subTest(key=key), self.assertRaises(REJECTIONS): fixture.verify()
            self.assertEqual(fixture.images, [])

    def test_truncated_or_paginated_source_and_job_proofs_fail_closed(self):
        for endpoint in ('/actions/workflows/2/runs?', '/actions/runs/1200/attempts/2/jobs?'):
            for total in (-1, 0, 100, True):
                fixture = Fixture()
                def read(path):
                    document = fixture.read(path)
                    if path.startswith(endpoint): document['total_count'] = total
                    return document
                with self.subTest(endpoint=endpoint, total=total), self.assertRaises(REJECTIONS):
                    notify.verify_image_ready(fixture.event, fixture.environ, read, fixture.probe)
                self.assertEqual(fixture.images, [])

    def test_each_exact_publish_job_required_not_just_workflow_name(self):
        for change in ('missing', 'skipped', 'failed', 'duplicate', 'wrong-run'):
            fixture = Fixture()
            if change == 'missing': fixture.jobs.pop()
            elif change == 'duplicate': fixture.jobs[2] = copy.deepcopy(fixture.jobs[0])
            elif change == 'wrong-run': fixture.jobs[0]['run_id'] = 1100
            else: fixture.jobs[0]['conclusion'] = change
            with self.subTest(change=change), self.assertRaises(REJECTIONS): fixture.verify()
            self.assertEqual(fixture.images, [])

    def test_public_proof_errors_private_missing_and_digest_drift_never_compile(self):
        for failure in (notify.registry_images.ImageUnavailable('absent'), ValueError('private'), ValueError('digest')):
            fixture = Fixture()
            def broken(*_args): raise failure
            with self.subTest(failure=type(failure).__name__), self.assertRaises(type(failure)):
                notify.verify_image_ready(fixture.event, fixture.environ, fixture.read, broken)
        fixture = Fixture()
        for component in notify.COMPONENTS:
            fixture.plan['components'][component] = {'missing': False, **fixture.probe(REVISION, component),
                                                      'tag_digest': 'sha256:' + 'f' * 64}
        fixture.refresh_plan()
        with self.assertRaises(REJECTIONS): fixture.verify()

    def test_changed_head_source_or_publication_after_image_proof_does_not_notify(self):
        for change in ('head', 'source', 'publication', 'jobs'):
            fixture = Fixture()
            def probe(*args):
                if change == 'head': fixture.head = 'f' * 40
                elif change == 'source': fixture.source_runs = [source_run(11)]
                elif change == 'publication': fixture.publication['run_attempt'] = 3
                else: fixture.jobs[0]['conclusion'] = 'failure'
                return fixture.probe(*args)
            with self.subTest(change=change), self.assertRaises(REJECTIONS):
                notify.verify_image_ready(fixture.event, fixture.environ, fixture.read, probe)

    def test_redirect_tls_signature_and_original_payload_remain_exact(self):
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
        payload, secret = Fixture().verify(), 'fixture-only-not-production-secret' * 2
        notify.send_notification(payload, secret, Opener())
        request = captured['request']
        self.assertEqual(request.full_url, notify.NOTIFICATION_URL)
        self.assertEqual(captured['timeout'], 20)
        self.assertEqual(json.loads(request.data), payload)
        self.assertEqual(request.get_header('X-frontiercloud-signature'),
                         'sha256=' + hmac.new(secret.encode(), request.data, hashlib.sha256).hexdigest())
        with self.assertRaises(REJECTIONS): notify.send_notification(payload, 'short', Opener())

    def test_receiver_requires_202_never_redirect_or_success_200(self):
        class Response:
            def __init__(self, status): self.status = status
            def __enter__(self): return self
            def __exit__(self, *_args): pass
        for status in (200, 301, 302, 307, 400, 403, 500):
            class Opener:
                def open(self, _request, timeout): return Response(status)
            with self.subTest(status=status), self.assertRaises(REJECTIONS):
                notify.send_notification(Fixture().verify(), 'fixture-only-test-secret' * 2, Opener())

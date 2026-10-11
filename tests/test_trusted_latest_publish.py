"""Latest is a main-only pointer to fully proven bytes, never a dev build."""
import copy
import hashlib
import json
import unittest
from unittest.mock import Mock

from scripts import trusted_latest_publish as latest
from tests.test_trusted_staging_notify import Fixture, REJECTIONS, REVISION


class LatestFixture(Fixture):
    def __init__(self):
        super().__init__()
        self.source['head_branch'] = 'main'
        self.event['workflow_run']['head_branch'] = 'main'
        self.plan['branch'] = 'main'
        self.body = json.dumps({'schemaVersion': 2, 'mediaType': latest.publication.OCI_MANIFEST}).encode()
        self.digest = 'sha256:' + hashlib.sha256(self.body).hexdigest()
        self.writes = []

    def read(self, path):
        if path == '/git/ref/heads/main':
            return {'object': {'type': 'commit', 'sha': self.head}}
        return super().read(path)

    def probe(self, revision, component):
        return {'image': 'ghcr.io/wongyiuming/frontiercloud-gin-' + component + '@' + self.digest,
                'tag_digest': self.digest, 'config_digest': 'sha256:' + 'e' * 64}

    def load(self, revision, component, proof):
        return self.body, latest.publication.OCI_MANIFEST

    def writer(self, component, _username, _token):
        writer = Mock(repository='wongyiuming/frontiercloud-gin-' + component)
        def request(path, method, body, headers, statuses):
            self.writes.append((component, path, method, body))
            return {'Docker-Content-Digest': self.digest}
        writer.request.side_effect = request
        return writer

    def promote(self):
        return latest.promote(self.plan, self.event, self.environ, self.read, self.probe, self.load, self.writer)


class TrustedLatestTests(unittest.TestCase):
    def test_current_main_all_three_verified_components_and_retry(self):
        fixture = LatestFixture()
        for _ in range(2):
            self.assertEqual(fixture.promote()['revision'], REVISION)
        self.assertEqual(len(fixture.writes), 6)
        for component, path, method, body in fixture.writes:
            self.assertEqual(path, '/v2/wongyiuming/frontiercloud-gin-' + component + '/manifests/latest')
            self.assertEqual((method, body), ('PUT', fixture.body))

    def test_dev_stale_main_bad_attempt_and_incomplete_jobs_never_write(self):
        for mutation in ('dev', 'head', 'attempt', 'jobs', 'failure'):
            with self.subTest(mutation=mutation):
                fixture = LatestFixture()
                if mutation == 'dev':
                    fixture.source['head_branch'] = fixture.event['workflow_run']['head_branch'] = fixture.plan['branch'] = 'dev'
                if mutation == 'head': fixture.head = 'f' * 40
                if mutation == 'attempt': fixture.publication['run_attempt'] += 1
                if mutation == 'jobs': fixture.jobs.pop()
                if mutation == 'failure': fixture.jobs[-1]['conclusion'] = 'failure'
                with self.assertRaises(REJECTIONS): fixture.promote()
                self.assertEqual(fixture.writes, [])

    def test_all_proofs_complete_before_any_write(self):
        fixture = LatestFixture()
        def load(revision, component, proof):
            if component == 'nginx': raise ValueError('unavailable bytes')
            return fixture.load(revision, component, proof)
        with self.assertRaises(ValueError):
            latest.promote(fixture.plan, fixture.event, fixture.environ, fixture.read, fixture.probe, load, fixture.writer)
        self.assertEqual(fixture.writes, [])

    def test_accepted_exact_digest_drift_and_head_change_during_credentials_stop(self):
        fixture = LatestFixture()
        fixture.plan['components']['web'] = {'missing': False, **fixture.probe(REVISION, 'web')}
        fixture.plan['components']['web']['tag_digest'] = 'sha256:' + 'f' * 64
        with self.assertRaises(REJECTIONS): fixture.promote()
        self.assertEqual(fixture.writes, [])
        fixture = LatestFixture()
        def writer(*args):
            result = fixture.writer(*args)
            fixture.head = 'f' * 40
            return result
        with self.assertRaises(REJECTIONS):
            latest.promote(fixture.plan, fixture.event, fixture.environ, fixture.read, fixture.probe, fixture.load, writer)
        self.assertEqual(fixture.writes, [])

    def test_manifest_bytes_digest_auth_and_media_type_are_checked(self):
        fixture = LatestFixture()
        request = Mock(return_value=(200, {'Docker-Content-Digest': fixture.digest}, fixture.body))
        proof = fixture.probe(REVISION, 'web')
        self.assertEqual(latest.manifest_bytes(REVISION, 'web', proof, request)[0], fixture.body)
        self.assertIn(proof['tag_digest'], request.call_args.args[0])
        for status, headers, body in ((404, {}, b'{}'), (200, {}, fixture.body),
                                      (200, {'Docker-Content-Digest': fixture.digest}, fixture.body + b' ')):
            with self.assertRaises(REJECTIONS):
                latest.manifest_bytes(REVISION, 'web', proof, Mock(return_value=(status, headers, body)))


if __name__ == '__main__':
    unittest.main()

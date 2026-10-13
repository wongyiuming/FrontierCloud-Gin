"""Credential-isolated staging proof tests; no network or deployment I/O."""
import copy
import hashlib
import hmac
import json
import unittest

from scripts import publication_proof as notify

REVISION, TRUSTED = 'a' * 40, 'b' * 40
REJECTIONS = (notify.publication.PublicationRejected, ValueError)


def source_run(number=10, attempt=3):
    return {'workflow_id': 2, 'path': '.github/workflows/docker.yml', 'head_sha': REVISION,
            'head_branch': 'dev', 'event': 'push', 'head_repository': {'full_name': notify.REPOSITORY},
            'id': number * 100, 'run_number': number, 'run_attempt': attempt,
            'name': notify.publication.SOURCE_NAME, 'status': 'completed', 'conclusion': 'success'}


class Fixture:
    def __init__(self):
        self.environ = {'GITHUB_EVENT_NAME': 'workflow_run', 'GITHUB_REPOSITORY': notify.REPOSITORY,
                        'GITHUB_REF': 'refs/heads/main', 'GITHUB_WORKFLOW_REF': notify.publication.WORKFLOW_REFERENCE,
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
            return {'id': 2, 'path': '.github/workflows/docker.yml', 'name': notify.publication.SOURCE_NAME}
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


"""Explicit first-publication authorization; no external actions or registry I/O."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, mock_open, patch

from scripts import bootstrap_native_publish as bootstrap
from tests.test_trusted_native_publish import Fixture as SourceFixture, REVISION, TRUSTED, oci_payload, save_oci


class Fixture(SourceFixture):
    def __init__(self):
        super().__init__()
        self.environ.update(GITHUB_EVENT_NAME='pull_request', GITHUB_ACTOR=bootstrap.OWNER,
                            GITHUB_TRIGGERING_ACTOR=bootstrap.OWNER, GITHUB_REF='refs/pull/5/merge',
                            GITHUB_WORKFLOW_REF=bootstrap.native.REPOSITORY + '/' + bootstrap.WORKFLOW_FILE + '@refs/pull/5/merge')
        self.pr = {'number': 5, 'state': 'open', 'merged': False, 'merge_commit_sha': TRUSTED,
                   'head': {'ref': 'dev', 'sha': REVISION, 'repo': {'full_name': bootstrap.native.REPOSITORY}},
                   'base': {'ref': 'main', 'sha': 'c'*40, 'repo': {'full_name': bootstrap.native.REPOSITORY}},
                   'labels': [{'name': bootstrap.LABEL_PREFIX + REVISION}]}
        self.event = {'action': 'labeled', 'number': 5,
                      'repository': {'full_name': bootstrap.native.REPOSITORY, 'default_branch': 'main'},
                      'pull_request': copy.deepcopy(self.pr), 'label': {'name': bootstrap.LABEL_PREFIX + REVISION},
                      'sender': {'login': bootstrap.OWNER}}
        self.current = {'id': 2000, 'workflow_id': 20, 'run_number': 30, 'run_attempt': 2,
                        'name': bootstrap.WORKFLOW_NAME, 'path': bootstrap.WORKFLOW_FILE,
                        'event': 'pull_request', 'head_branch': 'dev', 'head_sha': REVISION,
                        'head_repository': {'full_name': bootstrap.native.REPOSITORY}, 'status': 'in_progress',
                        'display_title': 'Bootstrap images PR5 ' + bootstrap.LABEL_PREFIX + REVISION,
                        'actor': {'login': bootstrap.OWNER}, 'triggering_actor': {'login': bootstrap.OWNER}}
        self.history = [self.current]
        self.merge_head = TRUSTED
        self.record['workflow_run'].update(head_branch='dev', head_sha=REVISION)

    def read(self, path):
        if path == '/pulls/5': return copy.deepcopy(self.pr)
        if path == '/git/ref/pull/5/merge': return {'object': {'type': 'commit', 'sha': self.merge_head}}
        if path == '/actions/workflows/bootstrap-images.yml':
            return {'id': 20, 'path': bootstrap.WORKFLOW_FILE, 'name': bootstrap.WORKFLOW_NAME}
        if path == '/actions/runs/2000': return copy.deepcopy(self.current)
        if path.startswith('/actions/workflows/20/runs?'):
            return {'total_count': len(self.history), 'workflow_runs': copy.deepcopy(self.history)}
        return super().read(path)

    def plan(self, missing=False):
        def probe(_revision, component):
            if missing: raise bootstrap.native.registry_images.ManifestUnknown()
            return self.proof(component)
        return bootstrap.make_plan(self.event, self.environ, self.read, probe)


class BootstrapNativePublishTests(unittest.TestCase):
    def test_owner_label_binds_source_ci_and_actual_pr_workflow_snapshot_without_main_impersonation(self):
        fixture = Fixture(); before = copy.deepcopy(fixture.environ)
        with patch.object(bootstrap.native, 'identity', side_effect=AssertionError('Normal identity must not be called')):
            plan = fixture.plan()
            bootstrap.verify_plan(plan, fixture.event, fixture.environ, fixture.read)
        self.assertEqual(fixture.environ, before)
        self.assertEqual(plan['mode'], 'owner-pr-bootstrap')
        self.assertEqual(plan['workflow_merge_sha'], TRUSTED)
        self.assertEqual(plan['revision'], REVISION)
        self.assertEqual(plan['pr_number'], 5)
        self.assertEqual((plan['source_run_id'], plan['source_run_attempt']), (1000, 3))
        self.assertEqual((plan['bootstrap_run_id'], plan['bootstrap_run_attempt']), (2000, 2))

    def test_owner_actor_sender_and_triggering_actor_are_required(self):
        for key in ('GITHUB_ACTOR', 'GITHUB_TRIGGERING_ACTOR'):
            fixture = Fixture(); fixture.environ[key] = 'integration[bot]'
            with self.subTest(key=key), self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()
        fixture = Fixture(); fixture.event['sender']['login'] = 'integration[bot]'
        with self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()

    def test_workflow_snapshot_is_not_source_head_main_ref_or_mismatched_event_merge(self):
        for change in ('workflow_sha', 'both_shas', 'workflow_ref', 'event_merge'):
            fixture = Fixture()
            if change == 'workflow_sha': fixture.environ['GITHUB_WORKFLOW_SHA'] = REVISION
            elif change == 'both_shas': fixture.environ.update(GITHUB_WORKFLOW_SHA=REVISION, GITHUB_SHA=REVISION)
            elif change == 'workflow_ref': fixture.environ['GITHUB_WORKFLOW_REF'] = fixture.environ['GITHUB_WORKFLOW_REF'].replace('refs/pull/5/merge', 'refs/heads/main')
            else: fixture.event['pull_request']['merge_commit_sha'] = REVISION
            with self.subTest(change=change), self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()

    def test_cli_without_automatic_token_rejects_before_any_network_request(self):
        fixture = Fixture(); environ = {**fixture.environ, 'GITHUB_EVENT_PATH': 'fixture-event.json'}
        with patch.dict(os.environ, environ, clear=True), patch('sys.argv', ['bootstrap_native_publish.py', 'plan']), \
             patch('builtins.open', mock_open(read_data=json.dumps(fixture.event).encode())), \
             patch.object(bootstrap.subprocess, 'check_output', return_value=TRUSTED + '\n'), \
             patch.object(bootstrap.native.urllib.request, 'build_opener', side_effect=AssertionError('Network forbidden')) as network:
            with self.assertRaisesRegex(SystemExit, 'Bootstrap gate rejected: Missing GitHub proof token'):
                bootstrap.cli()
            network.assert_not_called()

    def test_cli_wrong_checkout_rejects_before_api_or_token_use(self):
        fixture = Fixture(); environ = {**fixture.environ, 'GITHUB_EVENT_PATH': 'fixture-event.json', 'GITHUB_TOKEN': 'fixture-only-token'}
        with patch.dict(os.environ, environ, clear=True), patch('sys.argv', ['bootstrap_native_publish.py', 'plan']), \
             patch('builtins.open', mock_open(read_data=json.dumps(fixture.event).encode())), \
             patch.object(bootstrap.subprocess, 'check_output', return_value=REVISION + '\n'), \
             patch.object(bootstrap.native.urllib.request, 'build_opener', side_effect=AssertionError('Network forbidden')) as network:
            with self.assertRaisesRegex(SystemExit, 'Bootstrap gate rejected: Not executing the approved PR workflow snapshot'):
                bootstrap.cli()
            network.assert_not_called()

    def test_unexpected_cli_error_never_prints_hidden_candidate_or_credentials(self):
        with patch.object(bootstrap, 'main', side_effect=ValueError('private credential and event text')):
            with self.assertRaises(SystemExit) as failure: bootstrap.cli()
        self.assertIn('unexpected-error', str(failure.exception))
        self.assertNotIn('private credential', str(failure.exception))

    def test_wrong_label_prefix_short_sha_wrong_sha_and_nonlabel_events_rejected(self):
        for label in ('bootstrap', 'bootstrap:' + REVISION[:12], 'bootstrap:' + 'd'*40, 'bootstrap-images:' + REVISION):
            fixture = Fixture(); fixture.event['label']['name'] = label
            with self.subTest(label=label), self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()
        for action in ('opened', 'synchronize', 'unlabeled', 'closed'):
            fixture = Fixture(); fixture.event['action'] = action
            with self.subTest(action=action), self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()
        fixture = Fixture(); fixture.environ['GITHUB_EVENT_NAME'] = 'pull_request_target'
        with self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()

    def test_fixed_pr5_and_same_repository_dev_to_main_only(self):
        for field, value in (('number', 6), ('state', 'closed'), ('merged', True)):
            fixture = Fixture(); fixture.event['pull_request'][field] = value
            with self.subTest(field=field), self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()
        for side, field, value in (('head', 'ref', 'main'), ('base', 'ref', 'dev'), ('head', 'repo', {'full_name': 'fork/repo'})):
            fixture = Fixture(); fixture.event['pull_request'][side][field] = value
            with self.subTest(field=field), self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()

    def test_current_pr_base_head_merge_and_label_must_remain_fixed(self):
        for change in ('head', 'base', 'merge', 'label', 'closed', 'merge_ref'):
            fixture = Fixture()
            if change == 'head': fixture.pr['head']['sha'] = 'd'*40
            elif change == 'base': fixture.pr['base']['sha'] = 'd'*40
            elif change == 'merge': fixture.pr['merge_commit_sha'] = 'd'*40
            elif change == 'label': fixture.pr['labels'] = []
            elif change == 'closed': fixture.pr['state'] = 'closed'
            else: fixture.merge_head = 'd'*40
            with self.subTest(change=change), self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()
        fixture = Fixture(); fixture.head = 'd'*40
        with self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()

    def test_latest_exact_source_ci_pending_failure_or_new_attempt_rejects_old_plan(self):
        for status, conclusion in (('queued', None), ('in_progress', None), ('completed', 'failure')):
            fixture = Fixture()
            newer = copy.deepcopy(fixture.source); newer.update(id=1100, run_number=11, status=status, conclusion=conclusion)
            fixture.runs.append(newer)
            with self.subTest(status=status, conclusion=conclusion), self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()
        fixture = Fixture(); plan = fixture.plan(); fixture.source['run_attempt'] = 4
        with self.assertRaises(bootstrap.native.PublicationRejected):
            bootstrap.verify_plan(plan, fixture.event, fixture.environ, fixture.read)

    def test_first_matching_authorization_run_wins_and_relabelled_new_run_is_rejected(self):
        fixture = Fixture()
        previous = copy.deepcopy(fixture.current); previous.update(id=1999, run_number=29, status='completed')
        fixture.history.insert(0, previous)
        with self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()
        # Wrong-label/skipped runs do not consume this exact label authorization.
        fixture = Fixture()
        previous = copy.deepcopy(fixture.current); previous.update(id=1999, run_number=29, display_title='Bootstrap images PR5 other')
        fixture.history.insert(0, previous)
        fixture.plan()

    def test_same_claimed_run_latest_owner_attempt_can_recover_old_attempt_is_rejected(self):
        fixture = Fixture(); fixture.plan()
        fixture.current['run_attempt'] = 3
        with self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()
        fixture.environ['GITHUB_RUN_ATTEMPT'] = '3'
        plan = fixture.plan()
        self.assertEqual(plan['bootstrap_run_attempt'], 3)
        fixture.current['triggering_actor']['login'] = 'other'
        with self.assertRaises(bootstrap.native.PublicationRejected): fixture.plan()

    def test_artifact_head_is_pr_source_not_workflow_merge_and_attempt_name_is_exact(self):
        fixture = Fixture()
        self.assertEqual(bootstrap.artifact_record(fixture.environ, 'web', REVISION, fixture.read)['id'], 55)
        for change in ('attempt', 'merge_sha', 'foreign_run', 'branch', 'expired'):
            fixture = Fixture()
            if change == 'attempt': fixture.record['name'] = 'native-oci-2000-1-web'
            elif change == 'merge_sha': fixture.record['workflow_run']['head_sha'] = TRUSTED
            elif change == 'foreign_run': fixture.record['workflow_run']['id'] = 1999
            elif change == 'branch': fixture.record['workflow_run']['head_branch'] = 'main'
            else: fixture.record['expired'] = True
            with self.subTest(change=change), self.assertRaises(bootstrap.native.PublicationRejected):
                bootstrap.artifact_record(fixture.environ, 'web', REVISION, fixture.read)

    def test_repeat_tag_reuses_accepted_bytes_and_drift_disappearance_never_rewrites(self):
        fixture = Fixture(); plan = fixture.plan(); writer = Mock()
        for _repeat in range(2):
            result = bootstrap.publish(plan, fixture.event, fixture.environ, fixture.read, 'web', writer=writer,
                                       probe=Mock(return_value=fixture.proof()))
            self.assertEqual(result['action'], 'reused')
        for probe in (Mock(side_effect=bootstrap.native.registry_images.ManifestUnknown()),
                      Mock(return_value={**fixture.proof(), 'tag_digest': 'sha256:' + 'd'*64})):
            with self.assertRaises(bootstrap.native.PublicationRejected):
                bootstrap.publish(plan, fixture.event, fixture.environ, fixture.read, 'web', writer=writer, probe=probe)
        writer.transfer.assert_not_called()

    def test_missing_oci_is_verified_then_only_exact_authorized_tag_is_transferred(self):
        fixture = Fixture(); plan = fixture.plan(True); writer = Mock()
        entries, digest = oci_payload()
        with tempfile.TemporaryDirectory() as directory:
            archive = save_oci(directory, entries)
            result = bootstrap.publish(plan, fixture.event, fixture.environ, fixture.read, 'web', archive, writer,
                                       Mock(side_effect=[bootstrap.native.registry_images.ManifestUnknown(),
                                                         bootstrap.native.registry_images.ManifestUnknown(),
                                                         {**fixture.proof(), 'tag_digest': digest}]))
        self.assertEqual(result['action'], 'published')
        self.assertEqual(writer.transfer.call_args.args[2], REVISION)
        self.assertEqual(writer.transfer.call_count, 1)

    def test_stale_source_plan_changed_during_compilation_blocks_any_transfer(self):
        fixture = Fixture(); plan = fixture.plan(True); writer = Mock()
        fixture.head = 'd'*40
        with self.assertRaises(bootstrap.native.PublicationRejected):
            bootstrap.publish(plan, fixture.event, fixture.environ, fixture.read, 'web', writer=writer)
        writer.transfer.assert_not_called()

    def test_workflow_has_no_staging_key_environment_pat_or_candidate_execution_with_writer(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/bootstrap-images.yml').read_text()
        compile_part = workflow.split('  compile:\n')[1].split('  publish:\n')[0]
        publish_part = workflow.split('  publish:\n')[1]
        self.assertIn('types: [labeled]', workflow)
        self.assertIn('github.event.pull_request.number == 5', workflow)
        self.assertIn("github.actor == 'wongyiuming'", workflow)
        self.assertIn("format('bootstrap:{0}'", workflow)
        self.assertEqual(workflow.count('packages: write'), 1)
        self.assertNotIn('packages:', compile_part)
        self.assertNotIn('secrets.', workflow)
        self.assertNotIn('environment:', workflow)
        self.assertNotIn('STAGING_', workflow)
        self.assertNotIn('GHCR_PUBLISH_TOKEN', workflow)
        self.assertIn('timeout-minutes: 10', compile_part)
        self.assertIn('timeout-minutes: 3', publish_part)
        self.assertIn('ref: ${{ github.workflow_sha }}', publish_part)
        self.assertNotIn('docker ', publish_part)
        self.assertNotIn('go build', publish_part)


if __name__ == '__main__': unittest.main()

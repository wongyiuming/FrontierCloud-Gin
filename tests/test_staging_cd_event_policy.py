"""Lightweight source contracts; receiver execution is tested in Go on Dev."""
from pathlib import Path
import unittest
import json
import tempfile

from scripts.ops.staging_updater_state import read_state

ROOT = Path(__file__).resolve().parents[1]


class StagingEventPolicyTests(unittest.TestCase):
    def test_rn_cutover_keeps_shared_production_storage_outside_cd_and_cert_hook(self):
        controller = (ROOT / 'scripts/ops/staging-cd.sh').read_text()
        hook = (ROOT / 'scripts/ops/staging-certificate-deploy.sh').read_text()
        self.assertIn('SERVER_NAME=www4399.sbs', controller)
        self.assertIn('lineage=/etc/letsencrypt/live/www4399.sbs', hook)
        self.assertIn('racknerd-2ee08ce', hook)
        self.assertNotIn('/opt/frontiercloud-storage', hook)
        self.assertNotIn('frontiercloud-storage-web-1', hook)
        self.assertNotIn('ml.520mall.cc', controller + hook)

    def test_only_completed_successful_same_repo_dev_push_can_notify(self):
        publisher = (ROOT / '.github/workflows/publish-images.yml').read_text()
        self.assertFalse((ROOT / '.github/workflows/staging-cd.yml').exists())
        for value in ('workflow_run:', 'workflows: ["Build and Test Docker Compose"]',
                      "github.ref == 'refs/heads/main'", "github.event.repository.default_branch == 'main'",
                      "github.event.workflow_run.conclusion == 'success'",
                      "github.event.workflow_run.event == 'push'", 'head_repository.full_name'):
            self.assertIn(value, publisher)
        workflow = publisher.split('  notify-staging:\n', 1)[1]
        for value in ("needs: [plan, publish]", "if: needs.plan.outputs.branch == 'dev'",
                      'ref: ${{ github.workflow_sha }}', 'persist-credentials: false',
                      'environment: staging-cd-main',
                      'timeout-minutes: 3', 'secrets.STAGING_CD_SECRET',
                      'PLAN_JSON: ${{ needs.plan.outputs.plan }}',
                      'scripts/trusted_staging_notify.py', 'scripts/trusted_native_publish.py',
                      'scripts/registry_images.py'):
            self.assertIn(value, workflow)
        for forbidden in ('ref: ${{ github.event.workflow_run.head_sha }}', 'schedule:',
                          'download-artifact', 'setup-go', 'ssh ', 'docker ', 'sudo '):
            self.assertNotIn(forbidden, workflow)
        self.assertIn('permissions: {}', publisher)
        self.assertIn('contents: read', workflow)
        self.assertIn('actions: read', workflow)

    def test_no_timer_and_receiver_has_no_runtime_mutation_permissions(self):
        self.assertFalse((ROOT / 'scripts/ops/frontiercloud-staging-cd.timer').exists())
        service = (ROOT / 'scripts/ops/frontiercloud-staging-trigger.service').read_text()
        for value in ('User=frontiercloud-staging-trigger', 'NoNewPrivileges=true',
                      'ProtectSystem=strict', 'MemoryMax=64M', 'CPUQuota=10%'):
            self.assertIn(value, service)
        path = (ROOT / 'scripts/ops/frontiercloud-staging-cd.path').read_text()
        self.assertIn('PathExists=/var/lib/frontiercloud-staging-trigger/pending.json', path)
        self.assertIn('Unit=frontiercloud-staging-cd.service', path)

    def test_wait_covers_native_build_and_recovery_without_live_web_dependency(self):
        source = (ROOT / 'scripts/ops/staging-cd.sh').read_text()
        self.assertIn('deadline=$((SECONDS + 3300))', source)
        self.assertIn('queued|running|distributing|restarting)', source)
        self.assertIn('com.docker.compose.volume', source)
        self.assertLess(source.index('staging_updater_state.py'), source.index('ps -q web'))
        service = (ROOT / 'scripts/ops/frontiercloud-staging-cd.service').read_text()
        self.assertIn('TimeoutStartSec=3660', service)

    def test_native_journal_states_and_fail_closed_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'status.json'
            for state in ('idle', 'queued', 'running', 'distributing', 'restarting', 'success', 'failed'):
                path.write_text(json.dumps({'release_branch': 'main', 'state': state,
                                            'current_sha': 'a'*40, 'updater_runtime_sha': 'b'*40}))
                self.assertEqual(read_state(path), state)
            for raw in ('{}', '[]', 'x'*8193,
                        '{"state":"idle","state":"success"}',
                        '{"release_branch":"dev","current_sha":"a"}'):
                path.write_text(raw)
                with self.assertRaises(ValueError):
                    read_state(path)


if __name__ == '__main__':
    unittest.main()

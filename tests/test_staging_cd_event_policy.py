"""Lightweight source contracts; receiver execution is tested in Go on Dev."""
from pathlib import Path
import unittest
import json
import tempfile

from scripts.ops.staging_updater_state import read_state

ROOT = Path(__file__).resolve().parents[1]


class StagingEventPolicyTests(unittest.TestCase):
    def test_only_completed_successful_same_repo_dev_push_can_notify(self):
        text = (ROOT / '.github/workflows/staging-cd.yml').read_text()
        for value in ('workflow_run:', 'types: [completed]', 'branches: [dev]',
                      "conclusion == 'success'", "event == 'push'",
                      "head_branch == 'dev'", 'head_repository.full_name == github.repository',
                      'permissions: {}', 'timeout-minutes: 1', 'secrets.STAGING_CD_SECRET'):
            self.assertIn(value, text)
        for forbidden in ('uses: actions/checkout', 'schedule:', 'ssh ', 'docker ', 'sudo '):
            self.assertNotIn(forbidden, text)

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

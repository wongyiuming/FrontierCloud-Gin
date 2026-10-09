"""Lightweight source contracts; receiver execution is tested in Go on Dev."""
from pathlib import Path
import unittest

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


if __name__ == '__main__':
    unittest.main()

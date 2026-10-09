"""Real-driver fixtures stay bounded without relying on host swap availability."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DevelopmentMySQLBudgetTests(unittest.TestCase):
    def test_real_driver_fixtures_have_explicit_server_and_cgroup_budgets(self):
        for name in ('test-go-business.sh', 'test-native-api.sh'):
            with self.subTest(script=name):
                source = (ROOT / 'scripts' / name).read_text()
                for contract in ('--memory=768m --memory-swap=768m --cpus=1',
                                 '--innodb-buffer-pool-size=64M', '--performance-schema=OFF',
                                 '--max-connections=64', 'mysql:8.4.11',
                                 'oom={{.State.OOMKilled}}', 'if [ "$test_status" -ne 0 ]'):
                    self.assertIn(contract, source)
                self.assertNotIn('--memory=512m', source)
                self.assertNotIn('--skip-grant-tables', source)

    def test_go_compilation_keeps_two_workers_and_explicit_heap_cgroup_limits(self):
        source = (ROOT / 'scripts/test-go-business.sh').read_text()
        for contract in ('--cpus=2 --memory=3g --memory-swap=3g',
                         '-e GOMAXPROCS=2 -e GOMEMLIMIT=512MiB -e GOGC=25',
                         'Test compiler OOM:'):
            self.assertIn(contract, source)
        commands = re.findall(r'go test ([^\n]+)', source)
        self.assertEqual(len(commands), 7)
        for command in commands:
            self.assertIn('-p=2', command)
            self.assertIn('-count=1', command)
        self.assertEqual(source.count('docker run --rm "${go_test_budget[@]}"'), 7)

    def test_sdk_build_stages_cannot_borrow_additional_host_swap(self):
        for name in ('test-go-business.sh', 'test-native-api.sh'):
            commands = re.findall(r'DOCKER_BUILDKIT=0 docker build ([^\n]+)',
                                  (ROOT / 'scripts' / name).read_text())
            self.assertTrue(commands)
            for command in commands:
                self.assertIn('--memory=3g --memory-swap=3g', command)
                self.assertIn('--cpu-quota=200000', command)


if __name__ == '__main__':
    unittest.main()

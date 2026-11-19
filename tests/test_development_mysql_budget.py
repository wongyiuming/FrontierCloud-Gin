"""Real-driver fixtures stay bounded without relying on host swap availability."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DevelopmentBuildBudgetTests(unittest.TestCase):
    def test_development_fixtures_use_embedded_sqlite(self):
        for name in ('test-go-business.sh', 'test-native-api.sh'):
            with self.subTest(script=name):
                source = (ROOT / 'scripts' / name).read_text()
                self.assertNotIn('mysql:', source)
                self.assertNotIn('MYSQL_', source)

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

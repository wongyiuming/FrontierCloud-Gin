"""Real-driver fixtures stay bounded without relying on host swap availability."""
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()

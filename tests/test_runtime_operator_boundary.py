"""The application owns its status contract; host tools depend on that contract."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RuntimeOperatorBoundaryTests(unittest.TestCase):
    def test_shipped_runtime_packages_do_not_import_host_operator(self):
        files = list((ROOT / 'internal').rglob('*.go'))
        for command in ('frontiercloud', 'frontiercloud-tls-edge'):
            files.extend((ROOT / 'cmd' / command).rglob('*.go'))
        rejected = []
        for source in files:
            relative = source.relative_to(ROOT)
            if source.name.endswith('_test.go') or relative.parts[:2] == ('internal', 'operator'):
                continue
            if re.search(r'"github\.com/wongyiuming/FrontierCloud-Gin/internal/operator(?:/[^"\n]+)?"',
                         source.read_text(encoding='utf-8')):
                rejected.append(relative.as_posix())
        self.assertEqual(rejected, [], 'runtime must expose neutral facts without linking the host management tool')


if __name__ == '__main__':
    unittest.main()

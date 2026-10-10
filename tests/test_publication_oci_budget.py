"""The real-format fixture is bounded and never writes product registry state."""
from pathlib import Path
import unittest


class PublicationOCIFormatBudgetTests(unittest.TestCase):
    def test_fixture_builder_name_limits_and_cleanup_are_scope_bound(self):
        source = (Path(__file__).resolve().parents[1] / 'scripts/test-publication-oci.sh').read_text()
        self.assertLess(source.index('builder=${builder,,}'), source.index('docker buildx create'))
        self.assertIn('memory=512m,memory-swap=512m', source)
        self.assertIn('cpu-period=100000,cpu-quota=100000', source)
        self.assertIn('docker buildx rm "$builder"', source)
        self.assertIn('if test "$created" = true;', source)
        self.assertIn('moby/buildkit@sha256:', source)
        for forbidden in ('docker login', '--push', '--load', 'docker run', 'docker system prune'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()

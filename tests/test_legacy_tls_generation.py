"""Legacy identity staging shares current publication admission, without I/O."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.ops import stage_legacy_tls
from scripts.registry_images import SCHEMA_GENERATION

ROOT = Path(__file__).resolve().parents[1]
REVISION = 'a' * 40


class LegacyTLSGenerationTests(unittest.TestCase):
    def labels(self, generation):
        return {'frontiercloud.revision': REVISION, 'frontiercloud.runtime': 'go',
                'frontiercloud.component': 'web', 'frontiercloud.schema-generation': generation,
                'frontiercloud.automatic-tls': '1'}

    def test_current_image_passes_proof_and_wrong_generations_stop_before_mutation(self):
        self.assertEqual(stage_legacy_tls.SCHEMA_GENERATION, SCHEMA_GENERATION)
        for generation in (SCHEMA_GENERATION, str(int(SCHEMA_GENERATION) - 1), str(int(SCHEMA_GENERATION) + 1)):
            image = json.dumps([{'Config': {'Labels': self.labels(generation)}}]).encode()
            with tempfile.TemporaryDirectory() as directory:
                backup = Path(directory) / 'must-not-be-created'
                with patch.object(stage_legacy_tls, 'call', side_effect=[image, b'']) as read, \
                     patch.object(stage_legacy_tls.subprocess, 'run') as mutate:
                    message = 'requires a running legacy' if generation == SCHEMA_GENERATION else 'published automatic TLS image proof missing'
                    with self.assertRaisesRegex(RuntimeError, message):
                        stage_legacy_tls.stage('fixture', REVISION, backup)
                    self.assertEqual(read.call_count, 2 if generation == SCHEMA_GENERATION else 1)
                    mutate.assert_not_called()
                self.assertFalse(backup.exists())

    def test_direct_cli_resolves_shared_metadata_outside_repository_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/ops/stage_legacy_tls.py'), '--help'],
                                    cwd=directory, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--revision', result.stdout)


if __name__ == '__main__':
    unittest.main()

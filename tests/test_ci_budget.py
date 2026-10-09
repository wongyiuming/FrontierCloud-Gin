"""Keep hosted CI lightweight, even when acceptance scripts evolve."""
from pathlib import Path
import unittest

from scripts.check_ci_budget import check_workflows, inspect_workflow


class CIBudgetTests(unittest.TestCase):
    def test_artifact_exception_does_not_relax_test_ci_or_allow_acceptance(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/publish-images.yml').read_text(encoding='utf-8')
        self.assertEqual(inspect_workflow(workflow, 'publish-images.yml'), [])
        self.assertTrue(inspect_workflow(workflow, 'docker.yml'))
        for work in ('go test ./...', 'bash scripts/test-go-business.sh', 'docker compose up'):
            self.assertTrue(inspect_workflow(workflow + '\n    run: ' + work, 'publish-images.yml'))
        self.assertTrue(inspect_workflow(workflow.replace("newest.conclusion !== 'success'", 'false'), 'publish-images.yml'))
    def test_all_actual_workflows_fit_budget(self):
        self.assertEqual(check_workflows(Path(__file__).resolve().parents[1] / ".github/workflows"), [])

    def test_missing_extended_or_dynamic_timeout_fails(self):
        for value in ("", "    timeout-minutes: 65\n", "    timeout-minutes: ${{ inputs.limit }}\n"):
            self.assertTrue(inspect_workflow("name: test\njobs:\n  check:\n" + value, "fixture"))

    def test_heavywork_and_chains_cannot_hide_behind_short_timeout(self):
        for step in ("bash scripts/test-mixed-runtime.sh", "docker build .", "nohup test &", "federation_stack.py", "bash scripts/test-go-updater.sh",
                     "bash scripts/test-native-api.sh", "bash scripts/test-native-matrix.sh",
                     "bash scripts/test-native-release.sh"):
            self.assertTrue(inspect_workflow("name: test\njobs:\n  check:\n    timeout-minutes: 3\n    run: " + step, "fixture"))
        self.assertTrue(inspect_workflow("name: test\njobs:\n  check:\n    timeout-minutes: 3\n    needs: previous\n", "fixture"))

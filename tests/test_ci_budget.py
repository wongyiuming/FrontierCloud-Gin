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
        self.assertTrue(inspect_workflow(workflow.replace('workflow_run:', 'push:'), 'publish-images.yml'))
        publisher = workflow.split('  publish:\n', 1)[1].split('  notify-staging:\n', 1)[0]
        self.assertTrue(inspect_workflow(workflow.replace(publisher, publisher.replace('timeout-minutes: 3', 'timeout-minutes: 4')),
                                        'publish-images.yml'))
    def test_all_actual_workflows_fit_budget(self):
        self.assertEqual(check_workflows(Path(__file__).resolve().parents[1] / ".github/workflows"), [])

    def test_bootstrap_is_owner_authorized_pr5_only_and_cannot_deploy(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/bootstrap-images.yml').read_text()
        self.assertEqual(inspect_workflow(workflow, 'bootstrap-images.yml'), [])
        for before, after in (
            ('types: [labeled]', 'types: [opened, synchronize]'),
            ('branches: [main]', 'branches: [dev]'),
            ('github.event.pull_request.number == 5', 'github.event.pull_request.number > 0'),
            ("github.actor == 'wongyiuming'", "github.actor != ''"),
            ("github.event.sender.login == 'wongyiuming'", 'true'),
            ('github.event.pull_request.head.repo.full_name == github.repository', 'true'),
            ("github.event.label.name == format('bootstrap:{0}', github.event.pull_request.head.sha)", 'true'),
            ('pull_request:', 'pull_request_target:'),
            ('github.workflow_sha', 'github.event.pull_request.head.sha'),
            ('needs: [plan, compile]', 'needs: [plan]'),
            ('needs: [plan]', ''),
            ('      packages: write\n', ''),
        ):
            with self.subTest(before=before):
                self.assertTrue(inspect_workflow(workflow.replace(before, after), 'bootstrap-images.yml'))
        for unsafe in ('    environment: staging-cd-main',
                       '    env: {KEY: "${{ secrets.STAGING_CD_SECRET }}"}',
                       '    env: {KEY: "${{ secrets.OTHER_SECRET }}"}',
                       '    run: docker load candidate.tar',
                       '    permissions:\n      contents: write',
                       '    run: go test ./...',
                       '    run: bash scripts/test-native-api.sh'):
            self.assertTrue(inspect_workflow(workflow.replace('  publish:\n', '  publish:\n' + unsafe + '\n'),
                                            'bootstrap-images.yml'))
        for job in ('plan', 'compile'):
            self.assertTrue(inspect_workflow(workflow.replace('  ' + job + ':\n',
                '  ' + job + ':\n    permissions:\n      packages: write\n'), 'bootstrap-images.yml'))
        self.assertTrue(inspect_workflow(workflow + '\n  deploy:\n    timeout-minutes: 3\n', 'bootstrap-images.yml'))
        self.assertTrue(inspect_workflow(workflow.replace('  pull_request:\n', '  push:\n  pull_request:\n'),
                                        'bootstrap-images.yml'))

    def test_compile_exception_does_not_grant_other_writers_or_long_publish_jobs(self):
        for name in ('publish-images.yml', 'bootstrap-images.yml'):
            workflow = (Path(__file__).resolve().parents[1] / '.github/workflows' / name).read_text()
            self.assertTrue(inspect_workflow(workflow.replace('      packages: write',
                '      packages: write\n      contents: write'), name))
            publish = workflow.split('  publish:\n', 1)[1].split('  notify-staging:\n', 1)[0]
            self.assertTrue(inspect_workflow(workflow.replace(publish,
                publish.replace('timeout-minutes: 3', 'timeout-minutes: 4')), name))

    def test_missing_extended_or_dynamic_timeout_fails(self):
        for value in ("", "    timeout-minutes: 65\n", "    timeout-minutes: ${{ inputs.limit }}\n"):
            self.assertTrue(inspect_workflow("name: test\njobs:\n  check:\n" + value, "fixture"))

    def test_cd_secret_cannot_be_added_to_push_source_or_compilation_workflow(self):
        source = "name: test\non:\n  push:\njobs:\n  check:\n    timeout-minutes: 3\n    env:\n      KEY: ${{ secrets.STAGING_CD_SECRET }}\n"
        self.assertTrue(inspect_workflow(source, 'docker.yml'))
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/publish-images.yml').read_text()
        self.assertEqual(inspect_workflow(workflow, 'publish-images.yml'), [])
        self.assertTrue(inspect_workflow(workflow.replace('github.workflow_sha', 'github.event.workflow_run.head_sha'), 'publish-images.yml'))
        self.assertTrue(inspect_workflow(workflow.replace('environment: staging-cd-main', 'environment: staging'), 'publish-images.yml'))
        self.assertTrue(inspect_workflow(workflow, 'staging-cd.yml'))

    def test_package_writer_isolated_from_candidate_execution_and_token_requests(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/publish-images.yml').read_text()
        self.assertTrue(inspect_workflow(workflow + '\n    packages: write\n', 'publish-images.yml'))
        self.assertTrue(inspect_workflow(workflow.replace('      packages: write\n', ''), 'publish-images.yml'))
        self.assertTrue(inspect_workflow(workflow.replace('permissions: {}', 'permissions:\n  packages: write'), 'publish-images.yml'))
        for job in ('plan', 'compile', 'notify-staging'):
            unsafe = workflow.replace('  ' + job + ':\n', '  ' + job + ':\n    permissions:\n      packages: write\n')
            self.assertTrue(inspect_workflow(unsafe, 'publish-images.yml'))
        unsafe = workflow.replace('  publish:\n', '  publish:\n    run: docker load candidate.tar\n')
        self.assertTrue(inspect_workflow(unsafe, 'publish-images.yml'))
        unsafe = workflow.replace('  compile:\n', '  compile:\n    env:\n      TOKEN: ${{ secrets.GHCR_PUBLISH_TOKEN }}\n')
        self.assertTrue(inspect_workflow(unsafe, 'publish-images.yml'))
        unsafe = workflow.replace('  notify-staging:\n', '  notify-staging:\n    uses: actions/download-artifact@v4\n')
        self.assertTrue(inspect_workflow(unsafe, 'publish-images.yml'))

    def test_personal_pat_is_not_a_publication_prerequisite(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/publish-images.yml').read_text()
        self.assertEqual(inspect_workflow(workflow, 'publish-images.yml'), [])
        self.assertNotIn('native-image-publish-main', workflow)
        self.assertNotIn('GHCR_PUBLISH_TOKEN', workflow)
        unsafe = workflow.replace('  publish:\n', '  publish:\n    env:\n      TOKEN: ${{ secrets.GHCR_PUBLISH_TOKEN }}\n')
        self.assertTrue(inspect_workflow(unsafe, 'publish-images.yml'))
        self.assertTrue(inspect_workflow(workflow.replace('permissions: {}', 'permissions: write-all'), 'publish-images.yml'))
        self.assertTrue(inspect_workflow(workflow.replace('  compile:\n', '  compile:\n    permissions: write-all\n'), 'publish-images.yml'))

    def test_heavywork_and_chains_cannot_hide_behind_short_timeout(self):
        for step in ("bash scripts/test-mixed-runtime.sh", "docker build .", "nohup test &", "federation_stack.py", "bash scripts/test-go-updater.sh",
                     "bash scripts/test-native-api.sh", "bash scripts/test-native-matrix.sh",
                     "bash scripts/test-native-release.sh", "bash scripts/test-publication-oci.sh"):
            self.assertTrue(inspect_workflow("name: test\njobs:\n  check:\n    timeout-minutes: 3\n    run: " + step, "fixture"))
        self.assertTrue(inspect_workflow("name: test\njobs:\n  check:\n    timeout-minutes: 3\n    needs: previous\n", "fixture"))

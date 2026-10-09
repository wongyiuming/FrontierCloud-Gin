"""Keep test CI at three minutes; compilation has its own isolated budget."""
from pathlib import Path
import re


HEAVY = re.compile(
    r"test-(?:mixed-runtime|mixed-release|native-matrix|native-release|native-api|go-business|go-updater|native-default|store-interop|go-deployment|publication-oci)\.sh"
    r"|docker\s+(?:build|buildx|compose\s+up)|federation_stack\.py|browser_ui_regression\.py"
    r"|runs-on:\s*.*self-hosted|\bnohup\b"
)


def inspect_workflow(text: str, name: str) -> list[str]:
    findings = []
    jobs = text.split("\njobs:\n", 1)
    if len(jobs) != 2:
        return findings + [f"{name}: jobs block missing"]
    artifact = name == 'publish-images.yml'
    if re.search(r'permissions:\s*write-all', text):
        findings.append(f"{name}: broad write-all permissions are forbidden")
    if re.search(r'packages:\s*write', jobs[0]) or (not artifact and re.search(r'packages:\s*write', jobs[1])):
        findings.append(f"{name}: package write belongs only to the isolated publication job")
    if 'GHCR_PUBLISH_TOKEN' in text:
        findings.append(f"{name}: retired personal package PAT must not be requested")
    if 'secrets.STAGING_CD_SECRET' in text and not artifact:
        findings.append(f"{name}: privileged secrets belong only to default-main publication jobs")
    if name == 'staging-cd.yml':
        findings.append(f"{name}: retired source-only/third-level notifier must not be reintroduced")
    if HEAVY.search(jobs[1]) and not artifact:
        findings.append(f"{name}: heavyweight/background acceptance is prohibited in hosted CI")
    if artifact:
        forbidden = re.compile(r'test-[\w-]+\.sh|\bgo\s+test\b|federation_stack|browser_ui_regression|docker\s+compose\s+up|self-hosted|\bnohup\b')
        if forbidden.search(jobs[1]):
            findings.append(f"{name}: compilation workflow must not run acceptance/background work")
        for contract in ('workflow_run:', 'workflows: ["Build and Test Docker Compose"]',
                         "github.ref == 'refs/heads/main'", 'github.workflow_sha',
                         'persist-credentials: false', 'scripts/trusted_native_publish.py'):
            if contract not in text:
                findings.append(f"{name}: immutable default-main source-success publication gate missing")
        if re.search(r'(?m)^  (?:push|pull_request|pull_request_target|workflow_dispatch|schedule):', text):
            findings.append(f"{name}: credentialed publication must use only completed source workflow_run")
        if '195000' in text or 'Await newest successful test CI' in text:
            findings.append(f"{name}: source-CI queue polling must not replace the completed event")
    blocks = re.split(r"(?m)^  ([a-zA-Z0-9_-]+):\s*$", jobs[1])
    for index in range(1, len(blocks), 2):
        job, block = blocks[index:index + 2]
        limits = re.findall(r"(?m)^    timeout-minutes:\s*(\d+)\s*$", block)
        maximum = 10 if artifact and job == 'compile' else 3
        if len(limits) != 1 or not 1 <= int(limits[0]) <= maximum:
            findings.append(f"{name}/{job}: explicit timeout-minutes from 1 through {maximum} required")
        dependencies = re.findall(r"(?m)^    needs:\s*(.+)$", block)
        allowed = {'compile': '[plan]', 'publish': '[plan, compile]', 'notify-staging': '[plan, publish]'}
        if dependencies and not (artifact and dependencies == [allowed.get(job)]):
            findings.append(f"{name}/{job}: serial CI job chains can exceed the workflow budget")
        if artifact:
            package_permissions = re.findall(r'(?m)^      packages:\s*(\w+)\s*$', block)
            if (job == 'publish' and package_permissions != ['write']) or (job != 'publish' and re.search(r'packages:\s*write', block)):
                findings.append(f"{name}/{job}: automatic package write belongs only to trusted publisher")
            if 'secrets.STAGING_CD_SECRET' in block and job != 'notify-staging':
                findings.append(f"{name}/{job}: signing secret exposed outside trusted notifier")
            if job == 'publish':
                for contract in ('github.workflow_sha', 'GITHUB_TOKEN: ${{ github.token }}',
                                 'persist-credentials: false', 'scripts/trusted_native_publish.py'):
                    if contract not in block:
                        findings.append(f"{name}/{job}: isolated trusted publisher contract missing")
                if re.search(r'docker\s+(?:build|buildx|load|run|login)|\bgo\s+build|ref:.*needs\.plan', block):
                    findings.append(f"{name}/{job}: candidate execution is forbidden with package credentials")
            if job == 'notify-staging':
                for contract in ('environment: staging-cd-main', 'github.workflow_sha',
                                 'persist-credentials: false', 'scripts/trusted_staging_notify.py'):
                    if contract not in block:
                        findings.append(f"{name}/{job}: isolated trusted notifier contract missing")
                if re.search(r'download-artifact|docker\s+(?:build|buildx|load|run)|ref:.*needs\.plan', block):
                    findings.append(f"{name}/{job}: candidate artifacts/execution forbidden in signed notification")
    return findings


def check_workflows(directory: Path) -> list[str]:
    return [finding for path in sorted(directory.glob("*.y*ml"))
            for finding in inspect_workflow(path.read_text(encoding="utf-8"), path.name)]


if __name__ == "__main__":
    issues = check_workflows(Path(__file__).resolve().parents[1] / ".github/workflows")
    if issues:
        raise SystemExit("\n".join(issues))
    print("CI budget passed: test jobs <=3 minutes; isolated gated compilation <=10; no hosted acceptance")

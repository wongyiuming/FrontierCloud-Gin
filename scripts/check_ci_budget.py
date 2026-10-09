"""Keep test CI at three minutes; compilation has its own isolated budget."""
from pathlib import Path
import re


HEAVY = re.compile(
    r"test-(?:mixed-runtime|mixed-release|native-matrix|native-release|native-api|go-business|go-updater|native-default|store-interop|go-deployment)\.sh"
    r"|docker\s+(?:build|buildx|compose\s+up)|federation_stack\.py|browser_ui_regression\.py"
    r"|runs-on:\s*.*self-hosted|\bnohup\b"
)


def inspect_workflow(text: str, name: str) -> list[str]:
    findings = []
    jobs = text.split("\njobs:\n", 1)
    if len(jobs) != 2:
        return findings + [f"{name}: jobs block missing"]
    artifact = name == 'publish-images.yml'
    if 'secrets.STAGING_CD_SECRET' in text and name != 'staging-cd.yml':
        findings.append(f"{name}: CD signing secret is forbidden outside the trusted main notifier")
    if name == 'staging-cd.yml':
        for contract in ('workflow_run:', 'workflows: ["Publish native images"]',
                         "github.ref == 'refs/heads/main'", "github.workflow_sha",
                         'persist-credentials: false', 'scripts/trusted_staging_notify.py',
                         'environment: staging-cd-main'):
            if contract not in text:
                findings.append(f"{name}: default-main notification trust gate missing")
        if re.search(r'(?m)^  (?:push|pull_request|pull_request_target|workflow_dispatch|schedule):', text):
            findings.append(f"{name}: privileged notifier must use only workflow_run")
        if 'ref: ${{ github.event.workflow_run.head_sha }}' in text:
            findings.append(f"{name}: candidate source checkout is forbidden in the secret-bearing notifier")
    if HEAVY.search(jobs[1]) and not artifact:
        findings.append(f"{name}: heavyweight/background acceptance is prohibited in hosted CI")
    if artifact:
        forbidden = re.compile(r'test-[\w-]+\.sh|\bgo\s+test\b|federation_stack|browser_ui_regression|docker\s+compose\s+up|self-hosted|\bnohup\b')
        if forbidden.search(jobs[1]):
            findings.append(f"{name}: compilation workflow must not run acceptance/background work")
        for contract in ("workflow_id: 'docker.yml'", "newest.conclusion !== 'success'", "head_sha: context.sha"):
            if contract not in text:
                findings.append(f"{name}: exact successful source-CI gate missing")
    blocks = re.split(r"(?m)^  ([a-zA-Z0-9_-]+):\s*$", jobs[1])
    for index in range(1, len(blocks), 2):
        job, block = blocks[index:index + 2]
        limits = re.findall(r"(?m)^    timeout-minutes:\s*(\d+)\s*$", block)
        maximum = 10 if artifact and job == 'publish' else 3
        if len(limits) != 1 or not 1 <= int(limits[0]) <= maximum:
            findings.append(f"{name}/{job}: explicit timeout-minutes from 1 through {maximum} required")
        if re.search(r"(?m)^    needs:", block):
            findings.append(f"{name}/{job}: serial CI job chains can exceed the workflow budget")
    return findings


def check_workflows(directory: Path) -> list[str]:
    return [finding for path in sorted(directory.glob("*.y*ml"))
            for finding in inspect_workflow(path.read_text(encoding="utf-8"), path.name)]


if __name__ == "__main__":
    issues = check_workflows(Path(__file__).resolve().parents[1] / ".github/workflows")
    if issues:
        raise SystemExit("\n".join(issues))
    print("CI budget passed: test jobs <=3 minutes; isolated gated compilation <=10; no hosted acceptance")

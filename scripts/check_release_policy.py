#!/usr/bin/env python3
"""Protect native deployment, reviewed release provenance and hosted CI limits."""
from pathlib import Path
import ast
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)

release = read("internal/release/verification.go")
workflow = read(".github/workflows/docker.yml")
compose = read("docker-compose.yaml")
web = read("Dockerfile")
require('Policy{"main", "dev"}' in release and 'Policy{"gin_main", "gin_dev"}' in release,
        "Release policy must retain both authorized provenance pairs")
for token in ('p.MergeSHA == sha', 'p.Base.Ref == v.policy.Branch',
              'p.Head.Ref == v.policy.Source', 'p.Head.Repo.FullName == "wongyiuming/FrontierCloud-Gin"',
              'reviewed.Commit.Tree.SHA != tree', 'head_sha="+source',
              'r.Branch != v.policy.Source', 'r.Event != "push"', 'r.SHA != source'):
    require(token in release, f"Exact reviewed source provenance missing: {token}")
for path in ("internal/updater", "cmd/frontiercloud-updater", "updater", "ci/Dockerfile.updater",
             "scripts/test-go-updater.sh", "cmd/frontiercloud/staging.go"):
    require(not (ROOT / path).exists(), f"Retired update controller source exists: {path}")
for path in ("scripts/registry_images.py", "scripts/trusted_native_publish.py"):
    require("'web', 'nginx'" in read(path) and "'web', 'updater', 'nginx'" not in read(path),
            f"Publication must require only Web and Nginx: {path}")
for path in ("internal/operator/deployment.go", "internal/operator/upgrade.go"):
    require('[]string{"web", "nginx"}' in read(path), f"Operator component proof drift: {path}")
for token in ('promote-main:', 'reviewed.data.commit.tree.sha !== commit.data.commit.tree.sha',
              'head_sha: source', 'head_sha: context.sha', "pr?.base?.ref === 'main'",
              "pr?.head?.ref === 'dev'", 'listPullRequestsAssociatedWithCommit'):
    require(token in workflow, f"Reviewed CI promotion guard missing: {token}")
require('github.paginate' not in workflow, "Promotion lookup must remain bounded")

require(web == read("Dockerfile.gin") and compose == read("docker-compose.gin.yaml"),
        "Native aliases must match defaults")
for path in ("Dockerfile.python", "docker-compose.python.yaml",
             "scripts/test-mixed-runtime.sh", "scripts/test-mixed-release.sh",
             "scripts/test-store-interop.sh", "tests/store.Dockerfile"):
    require(not (ROOT / path).exists(), f"Retired runtime/interop entrypoint exists: {path}")
for path in ("app", "main.py", "updater/server.py", "updater/release_evidence.py",
             "migrations/__init__.py"):
    require(not (ROOT / path).exists(), f"Retired Python application source exists: {path}")
for path in ROOT.rglob("*.py"):
    relative = path.relative_to(ROOT)
    if any(part.startswith(".") for part in relative.parts):
        continue
    require(relative.parts[0] in {"scripts", "tests"},
            f"Python is restricted to script/test drivers: {relative}")
require('FROM golang:1.26.8-bookworm' in web,
        "Native builder base must remain patch-pinned")
for token, path in (('FROM nginx:1.30.4-alpine', "nginx/Dockerfile"),
                    ('image: redis:7.4.11-alpine', "docker-compose.yaml"),
                    ('image: mysql:8.4.11', "docker-compose.gin-mysql.yaml"),
                    ('image: coturn/coturn:4.17.2-r0-alpine', "docker-compose.yaml")):
    require(token in read(path), f"Patch-pinned runtime base missing: {path}")
require('ARG FRONTIERCLOUD_RUNTIME=go' in read("nginx/Dockerfile"), "Edge defaults must be native")
require('  mysql:' not in compose and 'DB_TYPE: ${DB_TYPE:-sqlite}' in compose,
        "Default native SQLite must not require MySQL")
require('command: [init-secrets]' in compose and 'command: [init-media]' in compose
        and '  build:' not in compose, "Initializers must be native")
for token in ('RELEASE_BRANCH:', 'RELEASE_SOURCE_BRANCH:', 'GITHUB_API_TOKEN:', 'STAGING_CD:'):
    require(token not in compose, f"Business Compose retains retired release configuration: {token}")
for token in ("app/", "main.py", "tests/", "scripts/"):
    require(token in read(".dockerignore").splitlines(), f"Build context exclusion missing: {token}")

for forbidden in ('  updater:', '/var/run/docker.sock', 'updater_control', 'maintenance_state'):
    require(forbidden not in compose, f"Retired online updater deployment exists: {forbidden}")
require('RegisterReleaseAdmin' not in read('cmd/frontiercloud/http.go'),
        'Retired release HTTP control is reachable')
for path in ("Dockerfile", "nginx/Dockerfile"):
    require("COPY --chmod=" not in read(path) and "RUN --mount=" not in read(path),
            f"Bounded legacy Docker build required: {path}")
for path in (ROOT / "tests").glob("*.py"):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        names = ([v.name for v in node.names] if isinstance(node, ast.Import)
                 else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
        require(not any(v.split(".")[0] in {"app", "main", "fastapi", "sqlalchemy", "updater"}
                        for v in names), f"Test imports retired Python application: {path.name}")
    require(not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"spec_from_file_location", "exec_module"}
                    for node in ast.walk(tree)),
            f"Test dynamically loads Python application code: {path.name}")
fleet = read("internal/nativeacceptance/native_matrix_real_test.go")
require('const fleetNodeCount = 5' in fleet and 'go-sqlite' in fleet and 'go-mysql' in fleet,
        "Acceptance requires five native nodes and both database combinations")
require('python-' not in fleet.lower() and 'referenceWeb' not in fleet,
        "Native fleet must not select a Python runtime")
from scripts.check_ci_budget import check_workflows
require(not check_workflows(ROOT / ".github/workflows"), "Test CI or isolated compilation exceeds its boundary")
from tests.test_repository_policy import RepositoryPolicyRegressionTests
result = unittest.TextTestRunner(verbosity=1).run(
    unittest.defaultTestLoader.loadTestsFromTestCase(RepositoryPolicyRegressionTests))
require(result.wasSuccessful(), "Repository policy regression failed")
print("Native policy passed: reviewed provenance, three-minute test CI and separate bounded compilation")

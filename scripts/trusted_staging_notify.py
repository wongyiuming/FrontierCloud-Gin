"""Sign staging wakeups only inside the immutable-main publication workflow.

The source-success event and plan originate in the credential-free trusted plan
job. Candidate code/artifacts never execute in this secret-bearing job. External
main-only Environment and package ACL configuration remain operator prerequisites.
"""
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import subprocess
import time
import urllib.request

if __package__:
    from . import registry_images, trusted_native_publish as publication
else:
    import registry_images
    import trusted_native_publish as publication

REPOSITORY = 'wongyiuming/FrontierCloud-Gin'
WORKFLOW_REFERENCE = REPOSITORY + '/.github/workflows/publish-images.yml@refs/heads/main'
NOTIFICATION_URL = 'https://www4399.sbs:9443/staging-ci-success'
COMPONENTS = ('web', 'updater', 'nginx')
PUBLISH_NAME = 'Publish native images'
SOURCE_NAME = 'Build and Test Docker Compose'
SHA = re.compile(r'[0-9a-f]{40}\Z')


class NotificationRejected(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise NotificationRejected(reason)


def positive(value):
    return type(value) is int and 0 < value < 2**63


def event_revision(event, environ):
    require(environ.get('GITHUB_EVENT_NAME') == 'workflow_run', 'Wrong notification event')
    require(environ.get('GITHUB_REPOSITORY') == REPOSITORY, 'Wrong notification repository')
    require(environ.get('GITHUB_REF') == 'refs/heads/main', 'Notification must execute default main')
    require(environ.get('GITHUB_WORKFLOW_REF') == WORKFLOW_REFERENCE, 'Untrusted workflow reference')
    trusted_sha = environ.get('GITHUB_WORKFLOW_SHA', '')
    require(SHA.fullmatch(trusted_sha) is not None and environ.get('GITHUB_SHA') == trusted_sha,
            'Untrusted notification code revision')
    require(event.get('action') == 'completed', 'Incomplete source event')
    repository = event.get('repository', {})
    require(repository.get('full_name') == REPOSITORY and repository.get('default_branch') == 'main',
            'Wrong default repository branch')
    run = event.get('workflow_run', {})
    revision = run.get('head_sha', '')
    require(isinstance(revision, str) and SHA.fullmatch(revision) is not None, 'Invalid candidate revision')
    require(run.get('head_repository', {}).get('full_name') == REPOSITORY and
            run.get('head_branch') == 'dev' and run.get('event') == 'push' and
            run.get('status') == 'completed' and run.get('conclusion') == 'success' and
            run.get('name') == SOURCE_NAME, 'Ineligible source-success notification event')
    require(all(positive(run.get(field)) for field in ('id', 'workflow_id', 'run_number', 'run_attempt')),
            'Invalid source CI identity')
    return revision


def publication_jobs(read, plan):
    run = read(f'/actions/runs/{plan["publish_run_id"]}')
    workflow = read('/actions/workflows/publish-images.yml')
    require(positive(workflow.get('id')) and workflow.get('path') == '.github/workflows/publish-images.yml' and
            workflow.get('name') == PUBLISH_NAME, 'Unexpected publication workflow')
    require(run.get('id') == plan['publish_run_id'] and run.get('run_attempt') == plan['publish_run_attempt'] and
            run.get('workflow_id') == workflow['id'] and run.get('path') == workflow['path'] and
            run.get('event') == 'workflow_run' and run.get('status') == 'in_progress' and
            run.get('conclusion') is None and run.get('head_repository', {}).get('full_name') == REPOSITORY,
            'Notification must belong to this active trusted publication attempt')
    document = read(f'/actions/runs/{plan["publish_run_id"]}/attempts/{plan["publish_run_attempt"]}/jobs?per_page=100')
    jobs = document.get('jobs')
    require(isinstance(jobs, list) and type(document.get('total_count')) is int and
            document['total_count'] == len(jobs) and len(jobs) < 100, 'Incomplete publication job proof')
    expected = {'publish (' + component + ')' for component in COMPONENTS}
    actual = [job for job in jobs if job.get('name') in expected]
    require(len(actual) == 3 and {job['name'] for job in actual} == expected and
            all(job.get('run_id') == plan['publish_run_id'] and
                job.get('status') == 'completed' and job.get('conclusion') == 'success' for job in actual),
            'All three exact publication jobs must succeed before notification')


def verify_image_ready(event, environ, read, probe=registry_images.publication_probe):
    revision = event_revision(event, environ)
    raw = environ.get('PLAN_JSON', '')
    require(isinstance(raw, str) and len(raw.encode()) <= 65536, 'Missing or oversized trusted plan')
    plan = registry_images.strict_json(raw)
    publication.verify_plan(plan, event, environ, read)
    require(plan['branch'] == 'dev' and plan['revision'] == revision, 'Wrong notification source plan')
    publication_jobs(read, plan)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = {component: pool.submit(probe, revision, component) for component in COMPONENTS}
        images = {component: future.result() for component, future in futures.items()}
    for component, state in images.items():
        require(isinstance(state, dict) and re.fullmatch(
            'ghcr.io/wongyiuming/frontiercloud-gin-' + component + '@sha256:[0-9a-f]{64}', state.get('image', '')),
            'Invalid anonymous exact image proof')
        prior = plan['components'][component]
        if prior.get('missing') is False:
            require(state == {key: prior[key] for key in ('image', 'tag_digest', 'config_digest')},
                    'Previously accepted publication drifted before notification')
    publication.verify_plan(plan, event, environ, read)
    publication_jobs(read, plan)
    return {'repository': REPOSITORY, 'branch': 'dev', 'event': 'push', 'conclusion': 'success',
            'sha': revision, 'run_id': plan['source_run_id'], 'run_number': plan['source_run_number'],
            'run_attempt': plan['source_run_attempt'], 'timestamp': int(time.time())}


def send_notification(payload, secret, opener=None):
    require(isinstance(secret, str) and 32 <= len(secret.encode()) <= 4096, 'CD signing secret not configured')
    body = json.dumps(payload, separators=(',', ':')).encode()
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(NOTIFICATION_URL, body, headers={
        'Content-Type': 'application/json', 'X-FrontierCloud-Signature': 'sha256=' + signature,
    }, method='POST')
    opener = opener or urllib.request.build_opener(registry_images.NoRedirect)
    with opener.open(request, timeout=20) as response:
        require(response.status == 202, 'Staging rejected image-ready event')


def main():
    environ = os.environ
    with open(environ['GITHUB_EVENT_PATH'], 'rb') as source:
        data = source.read((1 << 20) + 1)
    require(len(data) <= 1 << 20, 'Workflow event too large')
    event = registry_images.strict_json(data)
    require(isinstance(event, dict), 'Invalid source-success event')
    event_revision(event, environ)
    checked_out = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, timeout=5).strip()
    require(checked_out == environ['GITHUB_WORKFLOW_SHA'], 'Notifier checkout is not trusted workflow SHA')
    payload = verify_image_ready(event, environ, publication.github_reader(environ.get('GITHUB_TOKEN', '')))
    send_notification(payload, environ.get('STAGING_CD_SECRET', ''))
    print('Trusted main verified source CI and three published images; signed wakeup accepted.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Trusted staging notification rejected; no deployment eligibility bypass.')

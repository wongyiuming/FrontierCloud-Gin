"""Default-main-only image-ready staging notifier; candidate revisions are DATA.

The workflow requires the main-only protected Environment staging-cd-main.
STAGING_CD_SECRET must exist only in that Environment, never as a repository or
organization secret available to dev. YAML alone cannot configure the external
branch policy or relocate an existing secret; no ACL is changed by this script.
"""
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request

if __package__:
    from . import registry_images
else:
    import registry_images

REPOSITORY = 'wongyiuming/FrontierCloud-Gin'
WORKFLOW_REFERENCE = REPOSITORY + '/.github/workflows/staging-cd.yml@refs/heads/main'
API_ROOT = 'https://api.github.com/repos/' + REPOSITORY
NOTIFICATION_URL = 'https://ml.520mall.cc:9443/staging-ci-success'
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
    require(event.get('action') == 'completed', 'Incomplete workflow event')
    repository = event.get('repository', {})
    require(repository.get('full_name') == REPOSITORY and repository.get('default_branch') == 'main',
            'Wrong default repository branch')
    run = event.get('workflow_run', {})
    revision = run.get('head_sha', '')
    require(isinstance(revision, str) and SHA.fullmatch(revision) is not None, 'Invalid candidate revision')
    require(run.get('head_repository', {}).get('full_name') == REPOSITORY and
            run.get('head_branch') == 'dev' and run.get('event') == 'push' and
            run.get('status') == 'completed' and run.get('conclusion') == 'success' and
            run.get('name') == PUBLISH_NAME, 'Ineligible image publication event')
    require(all(positive(run.get(field)) for field in ('id', 'workflow_id', 'run_number', 'run_attempt')),
            'Invalid publication identity')
    return revision


def github_reader(token):
    require(isinstance(token, str) and token and len(token) <= 8192 and
            not any(c in token for c in '\r\n'), 'Missing trusted read-only GitHub token')
    opener = urllib.request.build_opener(registry_images.NoRedirect)

    def read(path):
        require(path.startswith('/') and not path.startswith('//'), 'Invalid GitHub API path')
        request = urllib.request.Request(API_ROOT + path, headers={
            'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'FrontierCloud-trusted-CD',
        })
        with opener.open(request, timeout=10) as response:
            require(response.status == 200, 'GitHub proof request failed')
            data = response.read((4 << 20) + 1)
            require(len(data) <= 4 << 20, 'GitHub proof response too large')
            result = registry_images.strict_json(data)
            require(isinstance(result, dict), 'Invalid GitHub proof document')
            return result
    return read


def workflow_id(read, filename, name):
    workflow = read('/actions/workflows/' + filename)
    require(positive(workflow.get('id')) and workflow.get('path') == '.github/workflows/' + filename and
            workflow.get('name') == name, 'Unexpected workflow identity')
    return workflow['id']


def eligible(run, revision, identity, filename):
    return (isinstance(run, dict) and run.get('workflow_id') == identity and
            run.get('path') == '.github/workflows/' + filename and run.get('head_sha') == revision and
            run.get('head_branch') == 'dev' and run.get('event') == 'push' and
            run.get('head_repository', {}).get('full_name') == REPOSITORY and
            all(positive(run.get(field)) for field in ('id', 'run_number', 'run_attempt')))


def newest_success(read, revision, identity, filename):
    query = urllib.parse.urlencode({'event': 'push', 'branch': 'dev', 'head_sha': revision, 'per_page': 100})
    document = read(f'/actions/workflows/{identity}/runs?{query}')
    runs = document.get('workflow_runs')
    require(isinstance(runs, list) and len(runs) < 100 and
            type(document.get('total_count')) is int and document['total_count'] == len(runs),
            'Ambiguous or paginated workflow proof')
    matching = [run for run in runs if eligible(run, revision, identity, filename)]
    matching.sort(key=lambda run: (run['run_number'], run['run_attempt']), reverse=True)
    require(matching, 'Exact successful push proof missing')
    latest = matching[0]
    require(latest.get('status') == 'completed' and latest.get('conclusion') == 'success',
            'Newest exact push has not succeeded')
    return latest


def same_run(left, right):
    return all(left.get(field) == right.get(field) for field in ('id', 'run_number', 'run_attempt', 'workflow_id', 'head_sha'))


def current_dev(read, revision):
    reference = read('/git/ref/heads/dev').get('object', {})
    require(reference.get('type') == 'commit' and reference.get('sha') == revision, 'Candidate is no longer current dev')


def publication_jobs(read, run):
    document = read(f'/actions/runs/{run["id"]}/attempts/{run["run_attempt"]}/jobs?per_page=100')
    jobs = document.get('jobs')
    require(isinstance(jobs, list) and type(document.get('total_count')) is int and
            document['total_count'] == len(jobs) and len(jobs) < 100, 'Incomplete publication job proof')
    expected = {'publish (' + component + ')' for component in COMPONENTS}
    actual = [job for job in jobs if job.get('name') in expected]
    require(len(actual) == 3 and {job['name'] for job in actual} == expected and
            all(job.get('status') == 'completed' and job.get('conclusion') == 'success' for job in actual),
            'All three exact publication jobs must succeed')


def verify_image_ready(event, environ, read, resolve=registry_images.resolve):
    revision = event_revision(event, environ)
    publish_identity = workflow_id(read, 'publish-images.yml', PUBLISH_NAME)
    source_identity = workflow_id(read, 'docker.yml', SOURCE_NAME)
    trigger = event['workflow_run']
    require(trigger['workflow_id'] == publish_identity, 'Foreign publication workflow')
    run = read(f'/actions/runs/{trigger["id"]}')
    require(eligible(run, revision, publish_identity, 'publish-images.yml') and same_run(trigger, run) and
            run.get('status') == 'completed' and run.get('conclusion') == 'success', 'Publication identity superseded')
    publication = newest_success(read, revision, publish_identity, 'publish-images.yml')
    require(same_run(publication, trigger), 'Newer publication supersedes this event')
    publication_jobs(read, run)
    source = newest_success(read, revision, source_identity, 'docker.yml')
    current_dev(read, revision)
    # No login token/credential, image pull, docker run, downloaded script,
    # candidate checkout, cache restore, or candidate artifact execution here.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = {component: pool.submit(resolve, revision, component, architecture='amd64')
                   for component in COMPONENTS}
        images = {component: future.result() for component, future in futures.items()}
    for component, reference in images.items():
        require(isinstance(reference, str) and re.fullmatch(
            'ghcr.io/wongyiuming/frontiercloud-gin-' + component + '@sha256:[0-9a-f]{64}', reference),
            'Invalid anonymous exact image proof')
    # Recheck after the network proof. The receiver independently rechecks too.
    current_dev(read, revision)
    require(same_run(publication, newest_success(read, revision, publish_identity, 'publish-images.yml')),
            'Publication changed during proof')
    require(same_run(source, newest_success(read, revision, source_identity, 'docker.yml')),
            'Source CI changed during proof')
    return {'repository': REPOSITORY, 'branch': 'dev', 'event': 'push', 'conclusion': 'success',
            'sha': revision, 'run_id': source['id'], 'run_number': source['run_number'],
            'run_attempt': source['run_attempt'], 'timestamp': int(time.time())}


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
    require(isinstance(event, dict), 'Invalid workflow event')
    event_revision(event, environ)
    checked_out = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, timeout=5).strip()
    require(checked_out == environ['GITHUB_WORKFLOW_SHA'], 'Notifier checkout is not trusted workflow SHA')
    payload = verify_image_ready(event, environ, github_reader(environ.get('GITHUB_TOKEN', '')))
    send_notification(payload, environ.get('STAGING_CD_SECRET', ''))
    print('Trusted main verified newest exact source CI and all public images; signed wakeup accepted.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never print HTTP bodies, credentials, signatures or event-controlled
        # errors. Details can be diagnosed using the independent proof runs.
        raise SystemExit('Trusted staging notification rejected; no deployment eligibility bypass.')

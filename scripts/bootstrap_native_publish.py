"""Explicit owner-authorized PR #5 bootstrap, not default-main impersonation.

Only an owner-applied bootstrap:<full head SHA> label authorizes this one PR.
Its first matching workflow run may recover via its newest attempt; additional
label-triggered runs cannot claim the same authorization. No staging key/PAT is
used. The PR workflow snapshot is explicitly authorized candidate code, not an
assertion that it came from main. OCI verification/REST transfer are shared with
normal publication without calling or weakening its main-only identity gate.
"""
import argparse
import json
import os
import re
import subprocess
import tempfile
import urllib.parse

if __package__:
    from . import trusted_native_publish as native
else:
    import trusted_native_publish as native

require, positive = native.require, native.positive
AUTHORIZED_PR = 5
OWNER = 'wongyiuming'
LABEL_PREFIX = 'bootstrap:'
WORKFLOW_FILE = '.github/workflows/bootstrap-images.yml'
WORKFLOW_NAME = 'Bootstrap native images once'


def identity(event, environ):
    pr = event.get('pull_request', {})
    revision = pr.get('head', {}).get('sha', '')
    require(environ.get('GITHUB_EVENT_NAME') == 'pull_request' and event.get('action') == 'labeled' and
            environ.get('GITHUB_REPOSITORY') == native.REPOSITORY and
            event.get('repository', {}).get('full_name') == native.REPOSITORY and
            event.get('repository', {}).get('default_branch') == 'main' and
            environ.get('GITHUB_ACTOR') == OWNER and environ.get('GITHUB_TRIGGERING_ACTOR') == OWNER and
            event.get('sender', {}).get('login') == OWNER, 'Bootstrap requires explicit owner label event')
    require(type(pr.get('number')) is int and pr['number'] == AUTHORIZED_PR and
            event.get('number') == AUTHORIZED_PR and pr.get('state') == 'open' and not pr.get('merged') and
            pr.get('head', {}).get('ref') == 'dev' and pr.get('base', {}).get('ref') == 'main' and
            pr.get('head', {}).get('repo', {}).get('full_name') == native.REPOSITORY and
            pr.get('base', {}).get('repo', {}).get('full_name') == native.REPOSITORY and
            isinstance(revision, str) and native.SHA.fullmatch(revision), 'Only fixed same-repository PR5 dev to main')
    ref = f'refs/pull/{AUTHORIZED_PR}/merge'
    code_sha = environ.get('GITHUB_WORKFLOW_SHA', '')
    require(environ.get('GITHUB_REF') == ref and
            environ.get('GITHUB_WORKFLOW_REF') == native.REPOSITORY + '/' + WORKFLOW_FILE + '@' + ref and
            native.SHA.fullmatch(code_sha) and environ.get('GITHUB_SHA') == code_sha and
            pr.get('merge_commit_sha') == code_sha, 'Unbound bootstrap workflow snapshot')
    require(event.get('label', {}).get('name') == LABEL_PREFIX + revision, 'Label must authorize exact full head SHA')
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        require(re.fullmatch(r'[1-9][0-9]{0,18}', environ.get(key, '')) and positive(int(environ[key])), 'Invalid bootstrap run')
    return revision


def facts(event, environ, read):
    revision = identity(event, environ)
    snapshot = event['pull_request']
    pr = read(f'/pulls/{AUTHORIZED_PR}')
    require(pr.get('number') == AUTHORIZED_PR and pr.get('state') == 'open' and not pr.get('merged') and
            pr.get('head', {}).get('sha') == revision and pr.get('head', {}).get('ref') == 'dev' and
            pr.get('base', {}).get('ref') == 'main' and
            pr.get('base', {}).get('sha') == snapshot['base'].get('sha') and
            pr.get('head', {}).get('repo', {}).get('full_name') == native.REPOSITORY and
            pr.get('base', {}).get('repo', {}).get('full_name') == native.REPOSITORY and
            pr.get('merge_commit_sha') == environ['GITHUB_WORKFLOW_SHA'] and
            any(label.get('name') == LABEL_PREFIX + revision for label in pr.get('labels', [])),
            'PR, base, authorization label or workflow snapshot changed')
    head = read('/git/ref/heads/dev').get('object', {})
    require(head.get('type') == 'commit' and head.get('sha') == revision, 'Development head advanced')
    merge = read(f'/git/ref/pull/{AUTHORIZED_PR}/merge').get('object', {})
    require(merge.get('type') == 'commit' and merge.get('sha') == environ['GITHUB_WORKFLOW_SHA'], 'PR merge snapshot advanced')
    source_workflow = read('/actions/workflows/docker.yml')
    require(positive(source_workflow.get('id')) and source_workflow.get('path') == '.github/workflows/docker.yml' and
            source_workflow.get('name') == native.SOURCE_NAME, 'Wrong source CI workflow')
    query = urllib.parse.urlencode({'event': 'push', 'branch': 'dev', 'head_sha': revision, 'per_page': 100})
    source = read(f'/actions/workflows/{source_workflow["id"]}/runs?{query}')
    runs = source.get('workflow_runs')
    require(isinstance(runs, list) and len(runs) < 100 and type(source.get('total_count')) is int and
            source['total_count'] == len(runs), 'Incomplete source CI proof')
    eligible = [run for run in runs if isinstance(run, dict) and run.get('workflow_id') == source_workflow['id'] and
                run.get('path') == source_workflow['path'] and run.get('head_sha') == revision and
                run.get('head_branch') == 'dev' and run.get('event') == 'push' and
                run.get('head_repository', {}).get('full_name') == native.REPOSITORY and
                all(positive(run.get(key)) for key in ('id', 'run_number', 'run_attempt'))]
    eligible.sort(key=lambda run: (run['run_number'], run['run_attempt']), reverse=True)
    require(eligible and eligible[0].get('status') == 'completed' and eligible[0].get('conclusion') == 'success',
            'Newest exact source CI must succeed before any compilation')
    source_run = eligible[0]
    actual = read(f'/actions/runs/{source_run["id"]}')
    require(all(actual.get(key) == source_run.get(key) for key in
                ('id', 'workflow_id', 'path', 'head_sha', 'head_branch', 'event', 'run_number', 'run_attempt', 'status', 'conclusion'))
            and actual.get('head_repository', {}).get('full_name') == native.REPOSITORY, 'Source attempt changed')
    workflow = read('/actions/workflows/bootstrap-images.yml')
    require(positive(workflow.get('id')) and workflow.get('path') == WORKFLOW_FILE and
            workflow.get('name') == WORKFLOW_NAME, 'Wrong bootstrap workflow')
    current = read(f'/actions/runs/{int(environ["GITHUB_RUN_ID"])}')
    title = f'Bootstrap images PR{AUTHORIZED_PR} {LABEL_PREFIX}{revision}'
    def authorized_run(run):
        return (isinstance(run, dict) and run.get('workflow_id') == workflow['id'] and run.get('path') == WORKFLOW_FILE and
                run.get('event') == 'pull_request' and run.get('head_branch') == 'dev' and run.get('head_sha') == revision and
                run.get('display_title') == title and run.get('actor', {}).get('login') == OWNER and
                run.get('head_repository', {}).get('full_name') == native.REPOSITORY and
                all(positive(run.get(key)) for key in ('id', 'run_number', 'run_attempt')))
    require(authorized_run(current) and current.get('run_attempt') == int(environ['GITHUB_RUN_ATTEMPT']) and
            current.get('triggering_actor', {}).get('login') == OWNER and current.get('status') == 'in_progress',
            'Bootstrap attempt is old, foreign or no longer running')
    candidates = read(f'/actions/workflows/{workflow["id"]}/runs?' +
                      urllib.parse.urlencode({'event': 'pull_request', 'head_sha': revision, 'per_page': 100}))
    history = candidates.get('workflow_runs')
    require(isinstance(history, list) and len(history) < 100 and type(candidates.get('total_count')) is int and
            candidates['total_count'] == len(history), 'Incomplete authorization run history')
    matching = sorted((run for run in history if authorized_run(run)), key=lambda run: (run['run_number'], run['id']))
    require(matching and matching[0]['id'] == current['id'], 'Authorization already claimed by its first run')
    return {'version': 1, 'mode': 'owner-pr-bootstrap', 'pr_number': AUTHORIZED_PR, 'revision': revision,
            'authorization_label': LABEL_PREFIX + revision, 'workflow_merge_sha': environ['GITHUB_WORKFLOW_SHA'],
            'source_run_id': source_run['id'], 'source_run_number': source_run['run_number'],
            'source_run_attempt': source_run['run_attempt'], 'bootstrap_run_id': current['id'],
            'bootstrap_run_attempt': current['run_attempt']}


def verify_plan(plan, event, environ, read):
    expected = facts(event, environ, read)
    require(isinstance(plan, dict) and set(plan) == set(expected) | {'components'} and
            all(type(plan.get(key)) is type(value) and plan.get(key) == value for key, value in expected.items()), 'Bootstrap plan changed')
    require(isinstance(plan.get('components'), dict) and set(plan['components']) == set(native.COMPONENTS), 'Incomplete image plan')
    for component, state in plan['components'].items():
        require(isinstance(state, dict) and type(state.get('missing')) is bool, 'Invalid image plan')
        if state['missing']:
            require(set(state) == {'missing'}, 'Ambiguous missing image plan')
        else:
            prefix = 'ghcr.io/wongyiuming/frontiercloud-gin-' + component + '@'
            require(set(state) == {'missing', 'image', 'tag_digest', 'config_digest'} and
                    isinstance(state.get('image'), str) and state['image'].startswith(prefix) and
                    native.registry_images.DIGEST.fullmatch(state['image'][len(prefix):]) and
                    all(isinstance(state.get(key), str) and native.registry_images.DIGEST.fullmatch(state[key])
                        for key in ('tag_digest', 'config_digest')), 'Invalid existing image proof')


def make_plan(event, environ, read, probe=native.registry_images.publication_probe):
    plan = facts(event, environ, read)
    plan['components'] = {}
    for component in native.COMPONENTS:
        try: plan['components'][component] = {'missing': False, **probe(plan['revision'], component)}
        except native.registry_images.ManifestUnknown: plan['components'][component] = {'missing': True}
    verify_plan(plan, event, environ, read)
    return plan


def artifact_record(environ, component, revision, read):
    document = read(f'/actions/runs/{int(environ["GITHUB_RUN_ID"])}/artifacts?per_page=100')
    artifacts = document.get('artifacts')
    require(isinstance(artifacts, list) and len(artifacts) < 100 and type(document.get('total_count')) is int and
            document['total_count'] == len(artifacts), 'Incomplete artifact proof')
    matching = [item for item in artifacts if item.get('name') == native.artifact_name(environ, component)]
    require(len(matching) == 1, 'Missing/ambiguous current-run OCI')
    item = matching[0]
    run = item.get('workflow_run', {})
    require(positive(item.get('id')) and item.get('expired') is False and type(item.get('size_in_bytes')) is int and
            0 < item['size_in_bytes'] <= native.MAX_ARCHIVE + (4 << 20) and
            run.get('id') == int(environ['GITHUB_RUN_ID']) and run.get('head_sha') == revision and
            run.get('head_branch') == 'dev' and isinstance(item.get('digest'), str) and
            native.registry_images.DIGEST.fullmatch(item['digest']), 'Foreign/bootstrap-old OCI artifact')
    return item


def publish(plan, event, environ, read, component, archive=None, writer=None, probe=native.registry_images.publication_probe):
    verify_plan(plan, event, environ, read)
    require(component in native.COMPONENTS, 'Wrong component')
    state = plan['components'][component]
    try: current = probe(plan['revision'], component)
    except native.registry_images.ManifestUnknown:
        require(state['missing'], 'Previously accepted image disappeared; never replace')
        require(archive is not None and writer is not None, 'Missing OCI or automatic writer')
        verified = native.verify_oci(archive, plan['revision'], component)
        verify_plan(plan, event, environ, read)
        try: current = probe(plan['revision'], component)
        except native.registry_images.ManifestUnknown:
            writer.transfer(archive, verified, plan['revision'])
            current = probe(plan['revision'], component)
            require(current['tag_digest'] == verified['digest'], 'Published bootstrap digest drifted')
            return {'action': 'published', **current}
    if not state['missing']:
        require(current == {key: state[key] for key in ('image', 'tag_digest', 'config_digest')}, 'Accepted bytes drifted; never overwrite')
    return {'action': 'reused', **current}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('plan', 'publish'))
    parser.add_argument('--component', choices=native.COMPONENTS)
    args = parser.parse_args()
    environ = os.environ
    with open(environ['GITHUB_EVENT_PATH'], 'rb') as source: data = source.read(native.MAX_JSON + 1)
    require(len(data) <= native.MAX_JSON, 'Bootstrap event too large')
    event = native.registry_images.strict_json(data)
    require(isinstance(event, dict), 'Invalid event')
    identity(event, environ)
    checkout = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, timeout=5).strip()
    require(checkout == environ['GITHUB_WORKFLOW_SHA'], 'Not executing the approved PR workflow snapshot')
    read = native.github_reader(environ.get('GITHUB_TOKEN', ''))
    if args.operation == 'plan':
        plan = make_plan(event, environ, read)
        with open(environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            output.write('plan=' + json.dumps(plan, separators=(',', ':')) + '\nrevision=' + plan['revision'] + '\n')
            for component in native.COMPONENTS:
                output.write('missing_' + component + '=' + str(plan['components'][component]['missing']).lower() + '\n')
        return
    raw = environ.get('PLAN_JSON', '')
    require(len(raw) <= native.MAX_JSON and args.component in native.COMPONENTS, 'Missing bounded plan or component')
    plan = native.registry_images.strict_json(raw.encode())
    verify_plan(plan, event, environ, read)
    component = args.component
    if not plan['components'][component]['missing']:
        result = publish(plan, event, environ, read, component)
    else:
        record = artifact_record(environ, component, plan['revision'], read)
        with tempfile.TemporaryDirectory(prefix='fc-bootstrap-oci-') as directory:
            archive = native.download_artifact(record, environ['GITHUB_TOKEN'], directory, component)
            native.verify_oci(archive, plan['revision'], component)
            writer = native.RegistryWriter(component, OWNER, environ.get('GITHUB_TOKEN', ''))
            result = publish(plan, event, environ, read, component, archive, writer)
    print(json.dumps(result, sort_keys=True))


def cli():
    try: main()
    except native.PublicationRejected as error:
        # These gate reasons are fixed strings in trusted require() calls, never
        # interpolated event/HTTP bodies, labels, credentials or parser details.
        raise SystemExit('Bootstrap gate rejected: ' + str(error))
    except Exception:
        raise SystemExit('Bootstrap gate rejected: unexpected-error; no secret or candidate data logged.')


if __name__ == '__main__': cli()

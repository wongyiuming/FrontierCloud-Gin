"""Default-main-only publication; OCI candidate data is verified, never executed.

The isolated publisher uses its automatic GITHUB_TOKEN with packages:write.
Compilation has no package credential and no personal PAT is required. Package
Actions access must allow this repository; repository workflow writers are
trusted administrators of this publication path, not anonymous public readers.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

if __package__:
    from . import registry_images
else:
    import registry_images

REPOSITORY = 'wongyiuming/FrontierCloud-Gin'
WORKFLOW_REFERENCE = REPOSITORY + '/.github/workflows/publish-images.yml@refs/heads/main'
API_ROOT = 'https://api.github.com/repos/' + REPOSITORY
SOURCE_NAME = 'Build and Test Docker Compose'
COMPONENTS = ('web', 'updater', 'nginx')
SHA = re.compile(r'[0-9a-f]{40}\Z')
OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
MAX_ARCHIVE, MAX_BLOB, MAX_JSON = 1 << 30, 512 << 20, 2 << 20


class PublicationRejected(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise PublicationRejected(reason)


def positive(value):
    return type(value) is int and 0 < value < 2**63


def github_reader(token):
    require(isinstance(token, str) and token and len(token) <= 8192 and
            not any(c in token for c in '\r\n'), 'Missing GitHub proof token')
    opener = urllib.request.build_opener(registry_images.NoRedirect)
    def read(path):
        require(path.startswith('/') and not path.startswith('//'), 'Invalid GitHub proof path')
        request = urllib.request.Request(API_ROOT + path, headers={
            'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'FrontierCloud-trusted-publisher'})
        with opener.open(request, timeout=10) as response:
            require(response.status == 200, 'GitHub proof request failed')
            data = response.read((4 << 20) + 1)
        require(len(data) <= 4 << 20, 'GitHub proof too large')
        value = registry_images.strict_json(data)
        require(isinstance(value, dict), 'Invalid GitHub proof')
        return value
    return read


def identity(event, environ):
    require(environ.get('GITHUB_EVENT_NAME') == 'workflow_run' and
            environ.get('GITHUB_REPOSITORY') == REPOSITORY and environ.get('GITHUB_REF') == 'refs/heads/main' and
            environ.get('GITHUB_WORKFLOW_REF') == WORKFLOW_REFERENCE, 'Untrusted publisher workflow')
    trusted = environ.get('GITHUB_WORKFLOW_SHA', '')
    require(SHA.fullmatch(trusted) is not None and environ.get('GITHUB_SHA') == trusted, 'Untrusted code SHA')
    require(event.get('action') == 'completed' and event.get('repository', {}).get('full_name') == REPOSITORY and
            event.get('repository', {}).get('default_branch') == 'main', 'Foreign source event')
    run = event.get('workflow_run', {})
    revision = run.get('head_sha', '')
    require(isinstance(revision, str) and SHA.fullmatch(revision) is not None and
            run.get('head_branch') in ('dev', 'main') and run.get('event') == 'push' and
            run.get('name') == SOURCE_NAME and run.get('status') == 'completed' and run.get('conclusion') == 'success' and
            run.get('head_repository', {}).get('full_name') == REPOSITORY and
            all(positive(run.get(key)) for key in ('id', 'workflow_id', 'run_number', 'run_attempt')), 'Ineligible source CI')
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        require(re.fullmatch(r'[1-9][0-9]{0,18}', environ.get(key, '')) is not None and
                positive(int(environ[key])), 'Invalid publisher identity')
    return run


def source_facts(event, environ, read):
    trigger = identity(event, environ)
    workflow = read('/actions/workflows/docker.yml')
    require(positive(workflow.get('id')) and workflow['id'] == trigger['workflow_id'] and
            workflow.get('name') == SOURCE_NAME and workflow.get('path') == '.github/workflows/docker.yml', 'Foreign CI')
    query = urllib.parse.urlencode({'event': 'push', 'branch': trigger['head_branch'],
                                   'head_sha': trigger['head_sha'], 'per_page': 100})
    document = read(f'/actions/workflows/{workflow["id"]}/runs?{query}')
    runs = document.get('workflow_runs')
    require(isinstance(runs, list) and len(runs) < 100 and type(document.get('total_count')) is int and
            document['total_count'] == len(runs), 'Incomplete source run proof')
    matching = [run for run in runs if isinstance(run, dict) and
                run.get('workflow_id') == workflow['id'] and run.get('path') == workflow['path'] and
                run.get('head_sha') == trigger['head_sha'] and run.get('head_branch') == trigger['head_branch'] and
                run.get('event') == 'push' and run.get('head_repository', {}).get('full_name') == REPOSITORY and
                all(positive(run.get(key)) for key in ('id', 'run_number', 'run_attempt'))]
    matching.sort(key=lambda run: (run['run_number'], run['run_attempt']), reverse=True)
    require(matching and matching[0].get('status') == 'completed' and matching[0].get('conclusion') == 'success' and
            all(matching[0].get(key) == trigger[key] for key in ('id', 'run_number', 'run_attempt')), 'Superseded source CI')
    actual = read(f'/actions/runs/{trigger["id"]}')
    require(all(actual.get(key) == matching[0].get(key) for key in
                ('id', 'workflow_id', 'path', 'head_sha', 'head_branch', 'event', 'run_number', 'run_attempt', 'status', 'conclusion'))
            and actual.get('head_repository', {}).get('full_name') == REPOSITORY, 'Changed source attempt')
    head = read('/git/ref/heads/' + trigger['head_branch']).get('object', {})
    require(head.get('type') == 'commit' and head.get('sha') == trigger['head_sha'], 'Candidate superseded')
    return {'version': 1, 'revision': trigger['head_sha'], 'branch': trigger['head_branch'],
            'source_run_id': trigger['id'], 'source_run_number': trigger['run_number'], 'source_run_attempt': trigger['run_attempt'],
            'publish_run_id': int(environ['GITHUB_RUN_ID']), 'publish_run_attempt': int(environ['GITHUB_RUN_ATTEMPT']),
            'trusted_workflow_sha': environ['GITHUB_WORKFLOW_SHA']}


def source_proof(event, environ, read, probe=registry_images.publication_probe):
    plan = source_facts(event, environ, read)
    plan['components'] = {}
    for component in COMPONENTS:
        try: plan['components'][component] = {'missing': False, **probe(plan['revision'], component)}
        except registry_images.ManifestUnknown: plan['components'][component] = {'missing': True}
    verify_plan(plan, event, environ, read)
    return plan


def verify_plan(plan, event, environ, read):
    facts = source_facts(event, environ, read)
    require(isinstance(plan, dict) and set(plan) == set(facts) | {'components'} and
            all(type(plan.get(key)) is type(value) and plan.get(key) == value for key, value in facts.items()), 'Plan identity mismatch')
    require(isinstance(plan.get('components'), dict) and set(plan['components']) == set(COMPONENTS), 'Incomplete plan')
    for component, state in plan['components'].items():
        require(isinstance(state, dict) and type(state.get('missing')) is bool, 'Invalid component plan')
        if state['missing']:
            require(set(state) == {'missing'}, 'Ambiguous missing plan')
        else:
            prefix = 'ghcr.io/wongyiuming/frontiercloud-gin-' + component + '@'
            require(set(state) == {'missing', 'image', 'tag_digest', 'config_digest'} and
                    isinstance(state.get('image'), str) and state['image'].startswith(prefix) and
                    all(isinstance(state.get(key), str) and registry_images.DIGEST.fullmatch(state[key])
                        for key in ('tag_digest', 'config_digest')) and
                    registry_images.DIGEST.fullmatch(state['image'][len(prefix):]), 'Invalid existing digests')


def artifact_name(environ, component):
    require(component in COMPONENTS, 'Invalid component')
    return f'native-oci-{environ["GITHUB_RUN_ID"]}-{environ["GITHUB_RUN_ATTEMPT"]}-{component}'


def artifact_record(environ, component, read):
    document = read(f'/actions/runs/{int(environ["GITHUB_RUN_ID"])}/artifacts?per_page=100')
    artifacts = document.get('artifacts')
    require(isinstance(artifacts, list) and len(artifacts) < 100 and type(document.get('total_count')) is int and
            document['total_count'] == len(artifacts), 'Incomplete artifact proof')
    matching = [item for item in artifacts if item.get('name') == artifact_name(environ, component)]
    require(len(matching) == 1, 'Missing/ambiguous current-run artifact')
    item = matching[0]
    run = item.get('workflow_run', {})
    require(positive(item.get('id')) and item.get('expired') is False and
            type(item.get('size_in_bytes')) is int and 0 < item['size_in_bytes'] <= MAX_ARCHIVE + (4 << 20) and
            run.get('id') == int(environ['GITHUB_RUN_ID']) and run.get('head_sha') == environ['GITHUB_WORKFLOW_SHA'] and
            run.get('head_branch') == 'main' and isinstance(item.get('digest'), str) and
            registry_images.DIGEST.fullmatch(item['digest']), 'Foreign/unbounded artifact')
    return item


def download_artifact(record, token, destination, component, opener=None):
    opener = opener or urllib.request.build_opener(registry_images.NoRedirect)
    request = urllib.request.Request(API_ROOT + f'/actions/artifacts/{record["id"]}/zip',
                                     headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json'})
    try:
        response = opener.open(request, timeout=10)
        response.close()
        raise PublicationRejected('Expected immutable artifact redirect')
    except urllib.error.HTTPError as error:
        require(error.code == 302, 'Artifact unavailable')
        location = error.headers.get('Location', '')
        error.close()
    target = urllib.parse.urlsplit(location)
    require(target.scheme == 'https' and target.hostname is not None and target.hostname.endswith('.blob.core.windows.net') and
            not target.username and not target.password and target.port in (None, 443), 'Untrusted artifact host')
    archive = Path(destination) / 'artifact.zip'
    digest, size = hashlib.sha256(), 0
    # Fresh request: never forward GitHub authorization to the Azure signed URL.
    with opener.open(urllib.request.Request(location), timeout=30) as response, archive.open('xb') as output:
        require(response.status == 200, 'Artifact download failed')
        while block := response.read(1 << 20):
            size += len(block)
            require(size <= record['size_in_bytes'] and size <= MAX_ARCHIVE + (4 << 20), 'Artifact too large')
            digest.update(block)
            output.write(block)
    require(size == record['size_in_bytes'] and 'sha256:' + digest.hexdigest() == record['digest'], 'Artifact digest mismatch')
    output = Path(destination) / (component + '.oci.tar')
    with zipfile.ZipFile(archive) as zipped:
        entries = zipped.infolist()
        require(len(entries) == 1 and entries[0].filename == component + '.oci.tar' and not entries[0].is_dir() and
                not entries[0].flag_bits & 1 and 0 < entries[0].file_size <= MAX_ARCHIVE, 'Unsafe artifact ZIP')
        with zipped.open(entries[0]) as source, output.open('xb') as target_file:
            size = 0
            while block := source.read(1 << 20):
                size += len(block)
                require(size <= MAX_ARCHIVE, 'OCI too large')
                target_file.write(block)
        require(size == entries[0].file_size, 'Incomplete OCI archive')
    return output


def verify_oci(path, revision, component):
    require(SHA.fullmatch(revision) and component in COMPONENTS and Path(path).stat().st_size <= MAX_ARCHIVE, 'Invalid OCI identity')
    entries = {}
    with tarfile.open(path, mode='r:') as archive:
        for member in archive:
            if member.isdir() and member.name.rstrip('/') in ('blobs', 'blobs/sha256'): continue
            require(member.isfile() and member.name not in entries and len(entries) < 4096 and
                    (member.name in ('index.json', 'oci-layout') or re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', member.name)) and
                    0 <= member.size <= MAX_BLOB, 'Unsafe OCI tar member')
            entries[member.name] = member
        require('index.json' in entries and 'oci-layout' in entries, 'Incomplete OCI layout')
        def document(name):
            require(entries[name].size <= MAX_JSON, 'OCI JSON too large')
            value = registry_images.strict_json(archive.extractfile(entries[name]).read())
            require(isinstance(value, dict), 'Invalid OCI JSON')
            return value
        def descriptor(value):
            require(isinstance(value, dict) and not value.get('urls') and isinstance(value.get('digest'), str) and
                    registry_images.DIGEST.fullmatch(value['digest']) and type(value.get('size')) is int and
                    0 < value['size'] <= MAX_BLOB, 'Invalid OCI descriptor')
            name = 'blobs/sha256/' + value['digest'][7:]
            require(name in entries and entries[name].size == value['size'], 'Missing/incorrect OCI blob')
            digest = hashlib.sha256()
            with archive.extractfile(entries[name]) as source:
                while block := source.read(1 << 20): digest.update(block)
            require('sha256:' + digest.hexdigest() == value['digest'], 'OCI blob hash mismatch')
            return name
        require(document('oci-layout') == {'imageLayoutVersion': '1.0.0'}, 'Unsupported OCI layout')
        index = document('index.json')
        manifests = index.get('manifests')
        require(index.get('schemaVersion') == 2 and isinstance(manifests, list) and len(manifests) == 1, 'Ambiguous OCI platform')
        selected = manifests[0]
        require(selected.get('mediaType') == OCI_MANIFEST, 'Unsupported OCI manifest')
        platform = selected.get('platform')
        require(platform is None or (platform.get('os') == 'linux' and platform.get('architecture') == 'amd64'), 'Wrong OCI platform')
        manifest_name = descriptor(selected)
        manifest = document(manifest_name)
        require(manifest.get('schemaVersion') == 2 and manifest.get('mediaType') == OCI_MANIFEST, 'Invalid manifest body')
        config = manifest.get('config')
        require(isinstance(config, dict) and config.get('mediaType') == 'application/vnd.oci.image.config.v1+json', 'Invalid config')
        config_name = descriptor(config)
        configuration = document(config_name)
        expected = {'org.opencontainers.image.source': registry_images.SOURCE, 'org.opencontainers.image.revision': revision,
                    'frontiercloud.revision': revision, 'frontiercloud.component': component,
                    'frontiercloud.runtime': 'go', 'frontiercloud.schema-generation': registry_images.SCHEMA_GENERATION}
        labels = configuration.get('config', {}).get('Labels', {})
        require(configuration.get('os') == 'linux' and configuration.get('architecture') == 'amd64' and
                all(labels.get(key) == value for key, value in expected.items()) and
                (component == 'nginx' or labels.get('frontiercloud.release-manifest-version') == '1'), 'OCI provenance mismatch')
        layers = manifest.get('layers')
        require(isinstance(layers, list) and 0 < len(layers) <= 128, 'Invalid layer count')
        names = [manifest_name, config_name]
        for layer in layers:
            require(isinstance(layer, dict) and layer.get('mediaType') in
                    ('application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip'), 'Foreign layer')
            names.append(descriptor(layer))
        require(set(entries) == {'index.json', 'oci-layout'} | set(names), 'Unreferenced OCI payload')
        return {'digest': selected['digest'], 'manifest': archive.extractfile(entries[manifest_name]).read(),
                'blobs': [(value['digest'], entries[name].offset_data, entries[name].size)
                          for value, name in zip([config] + layers, names[1:])]}


class RegistryWriter:
    """Scoped REST transfer, with no Docker load/run/build and no candidate code."""
    def __init__(self, component, username, password, opener=None):
        require(component in COMPONENTS and username == 'wongyiuming' and isinstance(password, str) and
                20 <= len(password) <= 4096 and not any(c in password for c in '\r\n'), 'Missing automatic package token')
        self.repository = 'wongyiuming/frontiercloud-gin-' + component
        self.opener = opener or urllib.request.build_opener(registry_images.NoRedirect)
        query = urllib.parse.urlencode({'service': 'ghcr.io', 'scope': 'repository:' + self.repository + ':pull,push'})
        basic = base64.b64encode((username + ':' + password).encode()).decode()
        request = urllib.request.Request('https://ghcr.io/token?' + query, headers={'Authorization': 'Basic ' + basic})
        with self.opener.open(request, timeout=15) as response:
            require(response.status == 200, 'Token exchange failed')
            body = response.read(MAX_JSON + 1)
        require(len(body) <= MAX_JSON, 'Token response too large')
        token = registry_images.strict_json(body).get('token', '')
        require(isinstance(token, str) and 0 < len(token) <= 16384 and not any(c in token for c in '\r\n'), 'Invalid scoped token')
        self.token = token

    def request(self, path, method, data=None, headers=None, statuses=(200,)):
        require(path.startswith('/v2/' + self.repository + '/') and not path.startswith('//'), 'Foreign write path')
        request = urllib.request.Request('https://ghcr.io' + path, data=data,
                                         headers={'Authorization': 'Bearer ' + self.token, **(headers or {})}, method=method)
        with self.opener.open(request, timeout=30) as response:
            require(response.status in statuses, 'Registry rejected operation')
            return dict(response.headers)

    def transfer(self, path, verified, revision):
        require(SHA.fullmatch(revision), 'Invalid immutable tag')
        for digest, offset, size in verified['blobs']:
            try:
                self.request('/v2/' + self.repository + '/blobs/' + digest, 'HEAD')
                continue
            except urllib.error.HTTPError as error:
                require(error.code == 404, 'Blob lookup failed')
                error.close()
            headers = self.request('/v2/' + self.repository + '/blobs/uploads/', 'POST', b'', statuses=(202,))
            location = headers.get('Location', headers.get('location', ''))
            require(isinstance(location, str) and 0 < len(location) <= 8192 and
                    not any(ord(char) <= 32 or ord(char) == 127 for char in location), 'Invalid upload location')
            parsed = urllib.parse.urlsplit(location)
            require(((parsed.scheme == '' and parsed.netloc == '' and location.startswith('/')) or
                     (parsed.scheme == 'https' and parsed.netloc in ('ghcr.io', 'ghcr.io:443'))) and
                    not parsed.fragment, 'Foreign upload origin')
            # GHCR returns singular /upload/; distribution commonly uses /uploads/.
            # Keep the returned opaque upload ID, but never cross repository scope.
            prefixes = tuple('/v2/' + self.repository + '/blobs/' + segment + '/'
                             for segment in ('upload', 'uploads'))
            prefix = next((value for value in prefixes if parsed.path.startswith(value)), None)
            upload_id = parsed.path[len(prefix):] if prefix else ''
            require(upload_id not in ('', '.', '..') and
                    not any(char in parsed.path for char in ('%', '\\')) and '/' not in upload_id,
                    'Foreign upload path')
            query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            require(not any(key == 'digest' for key, _value in query), 'Ambiguous digest')
            target = parsed.path + '?' + urllib.parse.urlencode(query + [('digest', digest)])
            with Path(path).open('rb') as source:
                source.seek(offset)
                def chunks():
                    remaining = size
                    while remaining:
                        block = source.read(min(1 << 20, remaining))
                        require(block, 'Blob truncated during transfer')
                        remaining -= len(block)
                        yield block
                self.request(target, 'PUT', chunks(), {'Content-Type': 'application/octet-stream', 'Content-Length': str(size)}, (201,))
        headers = self.request('/v2/' + self.repository + '/manifests/' + revision, 'PUT', verified['manifest'],
                               {'Content-Type': OCI_MANIFEST}, (201,))
        require(headers.get('Docker-Content-Digest', headers.get('docker-content-digest')) == verified['digest'], 'Manifest digest mismatch')


def publish(plan, event, environ, component, read, archive=None, probe=registry_images.publication_probe, writer=None):
    verify_plan(plan, event, environ, read)
    require(component in COMPONENTS, 'Invalid component')
    state = plan['components'][component]
    try: current = probe(plan['revision'], component)
    except registry_images.ManifestUnknown:
        require(state['missing'] is True, 'Verified image disappeared; never rebuild')
        require(archive is not None and writer is not None, 'Missing artifact or trusted writer')
        verified = verify_oci(archive, plan['revision'], component)
        verify_plan(plan, event, environ, read)
        try: current = probe(plan['revision'], component)
        except registry_images.ManifestUnknown:
            writer.transfer(archive, verified, plan['revision'])
            current = probe(plan['revision'], component)
            require(current['tag_digest'] == verified['digest'], 'Published digest drifted')
            return {'action': 'published', **current}
    if not state['missing']:
        require(current == {key: state[key] for key in ('image', 'tag_digest', 'config_digest')}, 'Verified digest drifted; never replace')
    return {'action': 'reused', **current}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('plan', 'publish'))
    parser.add_argument('--component', choices=COMPONENTS)
    args = parser.parse_args()
    environ = os.environ
    with open(environ['GITHUB_EVENT_PATH'], 'rb') as source: data = source.read(MAX_JSON + 1)
    require(len(data) <= MAX_JSON, 'Event too large')
    event = registry_images.strict_json(data)
    require(isinstance(event, dict), 'Invalid source event')
    identity(event, environ)
    checked_out = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, timeout=5).strip()
    require(checked_out == environ['GITHUB_WORKFLOW_SHA'], 'Not at trusted workflow SHA')
    read = github_reader(environ.get('GITHUB_TOKEN', ''))
    if args.operation == 'plan':
        plan = source_proof(event, environ, read)
        with open(environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            output.write('plan=' + json.dumps(plan, separators=(',', ':')) + '\n')
            for key in ('revision', 'branch', 'source_run_id', 'source_run_number', 'source_run_attempt'):
                output.write(key + '=' + str(plan[key]) + '\n')
            for component in COMPONENTS:
                output.write('missing_' + component + '=' + str(plan['components'][component]['missing']).lower() + '\n')
        return
    require(args.component in COMPONENTS, 'Missing component')
    raw = environ.get('PLAN_JSON', '')
    require(len(raw) <= MAX_JSON, 'Plan too large')
    plan = registry_images.strict_json(raw.encode())
    verify_plan(plan, event, environ, read)
    component = args.component
    if not plan['components'][component]['missing']:
        result = publish(plan, event, environ, component, read)
    else:
        record = artifact_record(environ, component, read)
        with tempfile.TemporaryDirectory(prefix='fc-trusted-oci-') as directory:
            archive = download_artifact(record, environ['GITHUB_TOKEN'], directory, component)
            verify_oci(archive, plan['revision'], component)
            writer = RegistryWriter(component, 'wongyiuming', environ.get('GITHUB_TOKEN', ''))
            result = publish(plan, event, environ, component, read, archive, writer=writer)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('Trusted publication rejected; no credential or candidate data logged.')

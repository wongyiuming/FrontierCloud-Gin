"""Resolve public exact-SHA GHCR images; only proven absence permits fallback."""
import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = 'https://ghcr.io'
SOURCE = 'https://github.com/wongyiuming/FrontierCloud-Gin'
SCHEMA_GENERATION = '3'
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
ACCEPT = ', '.join(('application/vnd.oci.image.index.v1+json',
                    'application/vnd.docker.distribution.manifest.list.v2+json',
                    'application/vnd.oci.image.manifest.v1+json',
                    'application/vnd.docker.distribution.manifest.v2+json'))
MANIFESTS = ('application/vnd.oci.image.manifest.v1+json',
             'application/vnd.docker.distribution.manifest.v2+json')
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']


class ImageUnavailable(Exception):
    pass


class ManifestUnknown(ImageUnavailable):
    """Only this proven absence permits the publisher to create a SHA tag."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def strict_json(body):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate registry JSON key')
            result[key] = value
        return result
    return json.loads(body, object_pairs_hook=pairs)


def fetch(path, token=''):
    request = urllib.request.Request(ROOT + path, headers={'Accept': ACCEPT})
    if token:
        request.add_header('Authorization', 'Bearer ' + token)
    try:
        response = urllib.request.build_opener(NoRedirect).open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read((4 << 20) + 1)
        if len(body) > 4 << 20:
            raise ValueError('Registry response is too large')
        # GHCR serves config blobs through this fixed public GitHub artifact
        # host. Never follow arbitrary redirects or forward its Bearer token.
        # Callers additionally verify the descriptor size and SHA256 bytes.
        if response.status == 307 and re.fullmatch(r'/v2/wongyiuming/frontiercloud-gin-(web|updater|nginx)/blobs/sha256:[0-9a-f]{64}', path):
            location = response.headers.get('Location', '')
            target = urllib.parse.urlsplit(location)
            if (target.scheme != 'https' or target.hostname != 'pkg-containers.githubusercontent.com'
                    or target.port not in (None, 443) or target.username or target.password or target.fragment):
                raise ValueError('Untrusted registry blob redirect')
            # A fresh request has NO registry Authorization header.
            redirected = urllib.request.Request(location, headers={'Accept': 'application/octet-stream'})
            with urllib.request.build_opener(NoRedirect).open(redirected, timeout=15) as blob:
                raw = blob.read((4 << 20) + 1)
                if len(raw) > 4 << 20:
                    raise ValueError('Registry config blob is too large')
                return blob.status, blob.headers, raw
        return response.status, response.headers, body


def resolve(revision, component, architecture=None, request=fetch):
    if not re.fullmatch(r'[0-9a-f]{40}', revision) or component not in ('web', 'updater', 'nginx'):
        raise ValueError('An exact committed SHA and native component are required')
    name = 'wongyiuming/frontiercloud-gin-' + component
    path = '/v2/' + name + '/manifests/' + revision
    status, headers, body = request(path)
    if status == 401:
        query = urllib.parse.urlencode({'service': 'ghcr.io', 'scope': 'repository:' + name + ':pull'})
        code, _, raw = request('/token?' + query)
        if code != 200:
            raise ValueError('Public anonymous registry access rejected')
        token = strict_json(raw).get('token')
        if not isinstance(token, str) or not 1 <= len(token) <= 8192 or '\r' in token or '\n' in token:
            raise ValueError('Invalid public registry read token')
        status, headers, body = request(path, token)
    if status == 404:
        errors = strict_json(body).get('errors', [])
        if len(errors) == 1 and errors[0].get('code') == 'MANIFEST_UNKNOWN':
            raise ManifestUnknown('Exact version is unavailable')
        raise ValueError('Unconfirmed registry absence')
    if status != 200:
        raise ValueError('Public registry access failed')
    digest = headers.get('Docker-Content-Digest', '')
    if not DIGEST.fullmatch(digest) or digest != 'sha256:' + hashlib.sha256(body).hexdigest():
        raise ValueError('Manifest digest mismatch')
    manifest = strict_json(body)
    if manifest.get('schemaVersion') != 2:
        raise ValueError('Invalid manifest schema')
    kind = manifest.get('mediaType')
    if kind in ('application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'):
        architecture = architecture or {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine(), platform.machine())
        selected = [entry for entry in manifest.get('manifests', [])
                    if entry.get('platform', {}).get('os') == 'linux'
                    and entry.get('platform', {}).get('architecture') == architecture]
        if not selected:
            raise ImageUnavailable('Current platform is unavailable')
        if len(selected) != 1 or selected[0].get('mediaType') not in MANIFESTS or not DIGEST.fullmatch(selected[0].get('digest', '')):
            raise ValueError('Ambiguous or invalid image platform')
        digest = selected[0]['digest']
    elif kind not in MANIFESTS:
        raise ValueError('Unsupported manifest type')
    return 'ghcr.io/' + name + '@' + digest


def publication_probe(revision, component, request=fetch):
    """Verify existing bytes anonymously; no Docker pull/build/write is needed.

    Runtime fallback may support another host platform; publication is stricter:
    an existing SHA without our linux/amd64 runtime is invalid, never "missing".
    """
    if not re.fullmatch(r'[0-9a-f]{40}', revision) or component not in ('web', 'updater', 'nginx'):
        raise ValueError('Exact native publication identity required')
    name = 'wongyiuming/frontiercloud-gin-' + component
    prefix = '/v2/' + name
    token = ''

    def read(path, absence=False):
        nonlocal token
        status, headers, body = request(path, token) if token else request(path)
        if status == 401 and not token:
            query = urllib.parse.urlencode({'service': 'ghcr.io', 'scope': 'repository:' + name + ':pull'})
            code, _, raw = request('/token?' + query)
            if code != 200:
                raise ValueError('Anonymous publication evidence access rejected')
            token = strict_json(raw).get('token')
            if not isinstance(token, str) or not 1 <= len(token) <= 8192 or '\r' in token or '\n' in token:
                raise ValueError('Invalid anonymous publication token')
            status, headers, body = request(path, token)
        if status == 404 and absence:
            errors = strict_json(body).get('errors')
            if isinstance(errors, list) and len(errors) == 1 and isinstance(errors[0], dict) and errors[0].get('code') == 'MANIFEST_UNKNOWN':
                raise ManifestUnknown('Exact publication tag is absent')
        if status != 200:
            raise ValueError('Publication evidence access failed, not proven absence')
        return headers, body

    def manifest(path, expected=None):
        headers, raw = read(path, absence=expected is None)
        digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        if headers.get('Docker-Content-Digest') != digest or (expected is not None and digest != expected):
            raise ValueError('Publication manifest digest mismatch')
        value = strict_json(raw)
        if value.get('schemaVersion') != 2:
            raise ValueError('Publication manifest schema mismatch')
        return digest, value

    tag_digest, image = manifest(prefix + '/manifests/' + revision)
    kind = image.get('mediaType')
    runtime_digest = tag_digest
    if kind in ('application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'):
        entries = [item for item in image.get('manifests', [])
                   if item.get('platform', {}).get('os') == 'linux'
                   and item.get('platform', {}).get('architecture') == 'amd64']
        if len(entries) != 1 or entries[0].get('mediaType') not in MANIFESTS or not DIGEST.fullmatch(entries[0].get('digest', '')):
            raise ValueError('Existing publication does not contain one valid linux/amd64 image')
        runtime_digest, image = manifest(prefix + '/manifests/' + entries[0]['digest'], entries[0]['digest'])
    if image.get('mediaType') not in MANIFESTS:
        raise ValueError('Unsupported publication runtime manifest')
    descriptor = image.get('config', {})
    config_digest = descriptor.get('digest', '')
    if (descriptor.get('mediaType') not in ('application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json')
            or not DIGEST.fullmatch(config_digest) or type(descriptor.get('size')) is not int or descriptor['size'] <= 0):
        raise ValueError('Invalid publication config descriptor')
    _, raw = read(prefix + '/blobs/' + config_digest)
    if len(raw) != descriptor['size'] or 'sha256:' + hashlib.sha256(raw).hexdigest() != config_digest:
        raise ValueError('Publication config content digest mismatch')
    configuration = strict_json(raw)
    expected = {'frontiercloud.revision': revision, 'frontiercloud.component': component,
                'frontiercloud.runtime': 'go', 'frontiercloud.schema-generation': SCHEMA_GENERATION,
                'org.opencontainers.image.source': SOURCE, 'org.opencontainers.image.revision': revision}
    labels = configuration.get('config', {}).get('Labels', {})
    if (configuration.get('os') != 'linux' or configuration.get('architecture') != 'amd64'
            or any(labels.get(key) != value for key, value in expected.items())
            or (component != 'nginx' and labels.get('frontiercloud.release-manifest-version') != '1')):
        raise ValueError('Existing publication provenance/platform/schema mismatch')
    return {'image': 'ghcr.io/' + name + '@' + runtime_digest,
            'tag_digest': tag_digest, 'config_digest': config_digest}


def publication_plan(revision, request=fetch):
    """All components are checked before any build; partial valid releases resume."""
    components = {}
    for component in ('web', 'updater', 'nginx'):
        try:
            components[component] = {'missing': False, **publication_probe(revision, component, request)}
        except ManifestUnknown:
            components[component] = {'missing': True}
    return {'revision': revision, 'components': components}


def ensure(revision, component):
    ref = resolve(revision, component)
    # A failed pull after a positive registry proof is NOT absence/fallback.
    result = subprocess.run(DOCKER + ['pull', ref], capture_output=True, text=True)
    if result.returncode:
        raise ValueError('Public image pull failed; local compilation forbidden')
    result = subprocess.run(DOCKER + ['image', 'inspect', ref], capture_output=True, text=True)
    if result.returncode:
        raise ValueError('Pulled image inspection failed')
    image = json.loads(result.stdout)[0]
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine(), platform.machine())
    labels = image.get('Config', {}).get('Labels', {})
    expected = {'frontiercloud.revision': revision, 'frontiercloud.component': component,
                'frontiercloud.runtime': 'go', 'frontiercloud.schema-generation': SCHEMA_GENERATION,
                'org.opencontainers.image.source': SOURCE, 'org.opencontainers.image.revision': revision}
    if any(labels.get(key) != value for key, value in expected.items()) or image.get('Os') != 'linux' or image.get('Architecture') != architecture:
        raise ValueError('Public image provenance/schema mismatch')
    if component != 'nginx' and labels.get('frontiercloud.release-manifest-version') != '1':
        raise ValueError('Public release image contract mismatch')
    alias = 'frontiercloud-go-' + component + ':' + revision
    subprocess.run(DOCKER + ['tag', ref, alias], check=True, capture_output=True)
    print('Pulled verified public image:', component, revision)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('--resolve', '--ensure', '--publication-plan'))
    parser.add_argument('revision')
    parser.add_argument('component', choices=('web', 'updater', 'nginx'))
    # Treat the explicit operation switch as a positional mode.
    args = parser.parse_args(['--', *sys.argv[1:]])
    try:
        if args.operation == '--resolve':
            print(resolve(args.revision, args.component))
        elif args.operation == '--publication-plan':
            print(json.dumps(publication_plan(args.revision), sort_keys=True))
        else:
            ensure(args.revision, args.component)
    except ImageUnavailable:
        print('Exact public image/platform is confirmed unavailable.', file=sys.stderr)
        return 3
    except (ValueError, IndexError, KeyError, TypeError, AttributeError, urllib.error.URLError, OSError, subprocess.SubprocessError):
        # Do not expose tokens, raw registry responses or image configuration.
        print('Public image validation failed; local compilation forbidden.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

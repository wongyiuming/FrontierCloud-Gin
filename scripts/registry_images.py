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
            raise ImageUnavailable('Exact version is unavailable')
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
                'frontiercloud.runtime': 'go', 'frontiercloud.schema-generation': '2',
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
    parser.add_argument('operation', choices=('--resolve', '--ensure'))
    parser.add_argument('revision')
    parser.add_argument('component', choices=('web', 'updater', 'nginx'))
    # Treat the explicit operation switch as a positional mode.
    args = parser.parse_args(['--', *sys.argv[1:]])
    try:
        if args.operation == '--resolve':
            print(resolve(args.revision, args.component))
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

"""Promote verified main images to the public fresh-install alias; no build/run."""
import hashlib
import json
import os
import subprocess
import urllib.parse

if __package__:
    from . import registry_images as registry, trusted_native_publish as publication
    from .trusted_staging_notify import publication_jobs
else:
    import registry_images as registry
    import trusted_native_publish as publication
    from trusted_staging_notify import publication_jobs

require = publication.require


def manifest_bytes(revision, component, proof, request=registry.fetch):
    """Read the already proven tag digest; never follow a moving alias."""
    repository = 'wongyiuming/frontiercloud-gin-' + component
    path = '/v2/' + repository + '/manifests/' + proof['tag_digest']
    status, headers, body = request(path)
    if status == 401:
        query = urllib.parse.urlencode({'service': 'ghcr.io', 'scope': 'repository:' + repository + ':pull'})
        code, _, raw = request('/token?' + query)
        require(code == 200, 'Anonymous read rejected')
        token = registry.strict_json(raw).get('token')
        require(isinstance(token, str) and 1 <= len(token) <= 8192 and not any(c in token for c in '\r\n'),
                'Invalid read token')
        status, headers, body = request(path, token)
    require(status == 200 and len(body) <= 4 << 20, 'Manifest unavailable')
    digest = 'sha256:' + hashlib.sha256(body).hexdigest()
    require(digest == proof['tag_digest'] and headers.get('Docker-Content-Digest') == digest,
            'Manifest content drifted')
    kind = registry.strict_json(body).get('mediaType')
    require(kind in registry.ACCEPT.split(', '), 'Unsupported manifest')
    return body, kind


def promote(plan, event, environ, read, probe=registry.publication_probe,
            load=manifest_bytes, writer_factory=publication.RegistryWriter):
    publication.verify_plan(plan, event, environ, read)
    require(plan['branch'] == 'main', 'Only published main may become latest')
    publication_jobs(read, plan)
    # Complete all three anonymous provenance and byte checks before any write.
    ready = {}
    for component in publication.COMPONENTS:
        proof = probe(plan['revision'], component)
        prior = plan['components'][component]
        if not prior['missing']:
            require(proof == {key: prior[key] for key in ('image', 'tag_digest', 'config_digest')},
                    'Accepted exact publication drifted')
        ready[component] = (proof, *load(plan['revision'], component, proof))
    for component, (proof, body, kind) in ready.items():
        publication.verify_plan(plan, event, environ, read)
        publication_jobs(read, plan)
        writer = writer_factory(component, 'wongyiuming', environ.get('GITHUB_TOKEN', ''))
        # Recheck after credential exchange, immediately before the tag write.
        publication.verify_plan(plan, event, environ, read)
        require(probe(plan['revision'], component) == proof, 'Exact image changed before alias write')
        headers = writer.request('/v2/' + writer.repository + '/manifests/latest', 'PUT', body,
                                 {'Content-Type': kind}, (201,))
        require(headers.get('Docker-Content-Digest', headers.get('docker-content-digest')) == proof['tag_digest'],
                'Latest alias digest mismatch')
    return {'revision': plan['revision'], 'alias': 'latest', 'components': list(ready)}


def main():
    environ = os.environ
    with open(environ['GITHUB_EVENT_PATH'], 'rb') as source:
        raw = source.read(publication.MAX_JSON + 1)
    require(len(raw) <= publication.MAX_JSON, 'Event too large')
    event = registry.strict_json(raw)
    publication.identity(event, environ)
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, timeout=5).strip()
            == environ['GITHUB_WORKFLOW_SHA'], 'Not at trusted main workflow code')
    raw = environ.get('PLAN_JSON', '')
    require(len(raw.encode()) <= publication.MAX_JSON, 'Plan too large')
    plan = registry.strict_json(raw)
    print(json.dumps(promote(plan, event, environ, publication.github_reader(environ.get('GITHUB_TOKEN', '')))))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Latest promotion rejected; no credential or registry data logged.')

"""Publish once per SHA; reuse already verified bytes on reruns/promotions.

This is workflow-level write-once discipline, NOT a registry atomic-CAS promise.
Every trusted writer must use the same SHA+component concurrency group. External
package administrators can still mutate tags; digest checks fail closed on drift.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

try:
    from scripts.registry_images import DIGEST, ManifestUnknown, SOURCE, publication_probe, strict_json
except ModuleNotFoundError:
    from registry_images import DIGEST, ManifestUnknown, SOURCE, publication_probe, strict_json


def publish(revision, component, plan, probe=publication_probe, build=None):
    if plan.get('revision') != revision or component not in ('web', 'updater', 'nginx'):
        raise ValueError('Publication plan identity mismatch')
    state = plan.get('components', {}).get(component, {})
    if type(state.get('missing')) is not bool:
        raise ValueError('Publication plan does not prove existence or absence')
    try:
        current = probe(revision, component)
    except ManifestUnknown:
        if state['missing'] is not True:
            raise ValueError('Previously verified publication disappeared; never rebuild it')
        if build is None:
            raise ValueError('Missing publication has no bounded builder')
        produced = build(revision, component)
        if not isinstance(produced, str) or not DIGEST.fullmatch(produced):
            raise ValueError('Builder did not produce an exact publication digest')
        current = probe(revision, component)
        if current['tag_digest'] != produced:
            raise ValueError('Published digest changed or raced; release must not be accepted')
        return {'action': 'published', **current}
    if state['missing'] is False:
        expected = {key: state[key] for key in ('image', 'tag_digest', 'config_digest')}
        if current != expected:
            raise ValueError('Previously verified publication drifted; never overwrite it')
    # Another serialized trusted run may have filled a previously missing tag.
    # Its independently verified bytes win; there is no second build/push.
    return {'action': 'reused', **current}


def build_image(revision, component):
    head = subprocess.run(['git', 'rev-parse', 'HEAD'], check=True, capture_output=True, text=True).stdout.strip()
    if head != revision:
        raise ValueError('Build source does not match exact publication SHA')
    dockerfile = 'nginx/Dockerfile' if component == 'nginx' else 'ci/Dockerfile.' + component
    with tempfile.TemporaryDirectory(prefix='fc-publication-metadata-') as directory:
        metadata = Path(directory) / 'result.json'
        subprocess.run([
            'docker', 'buildx', 'build', '--platform', 'linux/amd64', '--file', dockerfile,
            '--build-arg', 'REVISION=' + revision, '--build-arg', 'FRONTIERCLOUD_RUNTIME=go',
            '--label', 'org.opencontainers.image.source=' + SOURCE,
            '--label', 'org.opencontainers.image.revision=' + revision,
            '--tag', 'ghcr.io/wongyiuming/frontiercloud-gin-' + component + ':' + revision,
            '--provenance=mode=max', '--metadata-file', str(metadata),
            '--cache-from', 'type=gha,scope=native-' + component,
            '--cache-to', 'type=gha,mode=max,scope=native-' + component, '--push', '.',
        ], check=True)
        return strict_json(metadata.read_bytes()).get('containerimage.digest')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('revision')
    parser.add_argument('component', choices=('web', 'updater', 'nginx'))
    parser.add_argument('--plan', type=Path, default=Path('.ci-publication-plan.json'))
    args = parser.parse_args()
    try:
        result = publish(args.revision, args.component, strict_json(args.plan.read_bytes()), build=build_image)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        # Never expose registry tokens, raw image configs or login credentials.
        print('Publication validation failed; no release acceptance permitted.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

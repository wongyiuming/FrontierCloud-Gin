"""Read the isolated native updater journal during container self-handoff."""
import json
import os
import re
import sys
from pathlib import Path


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('Duplicate updater journal field')
        result[name] = value
    return result


def read_state(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as source:
        raw = source.read(8193)
    if len(raw) > 8192:
        raise ValueError('Oversized updater journal')
    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, dict) or value.get('release_branch') != 'main':
        raise ValueError('Unexpected updater release profile')
    for field in ('current_sha', 'updater_runtime_sha'):
        if not re.fullmatch(r'[0-9a-f]{40}', str(value.get(field, ''))):
            raise ValueError('Invalid updater revision')
    state = value.get('state')
    if state not in {'idle', 'queued', 'running', 'distributing', 'restarting', 'success', 'failed'}:
        raise ValueError('Unknown updater state')
    return state


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('One verified staging journal path is required')
    try:
        print(read_state(Path(sys.argv[1])))
    except (OSError, ValueError, TypeError):
        raise SystemExit('Staging updater journal unavailable or invalid')

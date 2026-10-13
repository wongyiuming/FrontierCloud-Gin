"""Source-only build-context check; the Docker subprocess is an inert tar sink."""
import fnmatch
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('bash') and shutil.which('git'), 'requires source checkout and Bash')
class ArchivedBuildInputs(unittest.TestCase):
    def test_committed_archive_contains_every_local_web_copy_source(self):
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        with tempfile.TemporaryDirectory(prefix='fc-context-check-') as directory:
            root = Path(directory)
            binary = root / 'bin'
            binary.mkdir()
            capture = root / 'context.tar'
            docker = binary / 'docker'
            docker.write_text('#!/usr/bin/env python3\nimport os,shutil,sys\n'
                              'with open(os.environ["FC_ARCHIVE_CAPTURE"],"wb") as output:\n'
                              ' shutil.copyfileobj(sys.stdin.buffer,output)\n', encoding='utf8')
            docker.chmod(0o700)
            env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ['PATH'],
                       FRONTIERCLOUD_IMAGE_SOURCE='local', FC_ARCHIVE_CAPTURE=str(capture))
            subprocess.run(['bash', 'scripts/build-native-images.sh', revision, 'web-only'],
                           cwd=ROOT, env=env, check=True, capture_output=True, timeout=30)
            with tarfile.open(capture) as archive:
                names = set(archive.getnames())
                for filename in ['Dockerfile', 'Dockerfile.gin']:
                    content = archive.extractfile(filename).read().decode()
                    for line in content.splitlines():
                        if not line.strip().startswith('COPY '):
                            continue
                        parts = shlex.split(line.strip())
                        if any(part.startswith('--from=') for part in parts):
                            continue  # Builder-stage output does not come from the source archive.
                        sources = [part for part in parts[1:-1] if not part.startswith('--')]
                        for source in sources:
                            source = source.removeprefix('./').rstrip('/')
                            self.assertTrue(any(fnmatch.fnmatch(name, source) or
                                                name.startswith(source + '/') for name in names),
                                            (filename, source))
            self.assertNotIn('.env', names)
            self.assertFalse(any(name.startswith(('.git/', 'data/')) for name in names))


if __name__ == '__main__':
    unittest.main()

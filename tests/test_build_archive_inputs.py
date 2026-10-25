"""Source-only build-context check; the Docker subprocess is an inert tar sink."""
import fnmatch
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('bash') and shutil.which('git'), 'requires source checkout and Bash')
class ArchivedBuildInputs(unittest.TestCase):
    builders = {'scripts/build-native-images.sh',
                'scripts/test-storage-certificate-containers.sh'}

    def test_every_archive_builder_has_a_copy_input_check(self):
        discovered = {path.relative_to(ROOT).as_posix()
                      for path in (ROOT / 'scripts').rglob('*.sh')
                      if re.search(r'\bgit\s+archive\b', path.read_text())}
        self.assertEqual(discovered, self.builders,
                         'Add every new archive builder to the actual COPY-input checks')

    def capture(self, checkout, script, revision, output):
        source = (checkout / script).read_text()
        binary = output / 'bin'
        binary.mkdir()
        capture, arguments = output / 'context.tar', output / 'arguments.json'
        docker = binary / 'docker'
        docker.write_text('#!/usr/bin/env python3\nimport json,os,shutil,sys\n'
                          'assert "build" in sys.argv[1:]\n'
                          'json.dump(sys.argv[1:],open(os.environ["FC_ARGUMENT_CAPTURE"],"w"))\n'
                          'with open(os.environ["FC_ARCHIVE_CAPTURE"],"wb") as output:\n'
                          ' shutil.copyfileobj(sys.stdin.buffer,output)\n', encoding='utf8')
        docker.chmod(0o700)
        env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ['PATH'],
                   FRONTIERCLOUD_IMAGE_SOURCE='local', FC_ARCHIVE_CAPTURE=str(capture),
                   FC_ARGUMENT_CAPTURE=str(arguments))
        if script == 'scripts/build-native-images.sh':
            command = ['bash', script, revision, 'web-only']
        else:
            # Execute the actual selector and archive/build command only. The
            # surrounding script is heavyweight container acceptance and must
            # never run as part of this source-only check.
            selector = re.search(r'(?ms)^paths=\([^\n]*\)\n(?:if git cat-file.*?^fi\n)?', source)
            pipeline = re.search(r'(?m)^git archive[^\n]+\|[^\n]+docker build[^\n]+$', source)
            self.assertIsNotNone(selector, script)
            self.assertIsNotNone(pipeline, script)
            command = ['bash', '-c', 'set -euo pipefail\nrevision="$1"\ndriver=archive-input-check\n' +
                       selector.group() + pipeline.group() + '\n', 'archive-input-check', revision]
        subprocess.run(command, cwd=checkout, env=env, check=True, capture_output=True, timeout=30)
        args = json.loads(arguments.read_text())
        self.assertEqual(args[-1], '-', 'The inspected context must be the actual build stdin')
        self.assertEqual(args[args.index('-f') + 1], 'Dockerfile.gin')
        target = args[args.index('--target') + 1] if '--target' in args else None
        return capture, target

    def assert_copy_inputs(self, capture, target):
        with tarfile.open(capture) as archive:
            names = set(archive.getnames())
            for filename in ('Dockerfile', 'Dockerfile.gin'):
                content = archive.extractfile(filename).read().decode()
                stage, found_target = None, target is None
                for line in content.replace('\\\n', ' ').splitlines():
                    if not re.match(r'(?i)^(?:FROM|COPY)\s', line.strip()):
                        continue
                    parts = shlex.split(line.strip())
                    if not parts:
                        continue
                    if parts[0].upper() == 'FROM':
                        if target and stage == target:
                            break
                        stage = parts[-1] if len(parts) >= 4 and parts[-2].upper() == 'AS' else None
                        found_target = found_target or stage == target
                    if parts[0].upper() != 'COPY' or any(part.startswith('--from=') for part in parts):
                        continue
                    for source in (part for part in parts[1:-1] if not part.startswith('--')):
                        source = source.removeprefix('./').rstrip('/')
                        self.assertTrue(any(fnmatch.fnmatch(name, source) or name.startswith(source + '/')
                                            for name in names), (filename, target, source))
                self.assertTrue(found_target, (filename, target))
            self.assertNotIn('.env', names)
            self.assertFalse(any(name.startswith(('.git/', 'data/')) for name in names))

    def test_all_committed_web_build_targets_have_copy_inputs(self):
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        for script in sorted(self.builders):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix='fc-context-check-') as directory:
                capture, target = self.capture(ROOT, script, revision, Path(directory))
                self.assert_copy_inputs(capture, target)

    def test_archive_builders_select_the_historical_installer_layout(self):
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        with tempfile.TemporaryDirectory(prefix='fc-context-check-') as directory:
            root = Path(directory)
            context = root / 'current'
            context.mkdir()
            capture, _ = self.capture(ROOT, 'scripts/build-native-images.sh', revision, context)
            historical = root / 'historical'
            historical.mkdir()
            with tarfile.open(capture) as archive:
                archive.extractall(historical, filter='data')
            (historical / 'deploy/compose.foc.yaml').rename(historical / 'compose.foc.yaml')
            for filename in ('Dockerfile', 'Dockerfile.gin'):
                path = historical / filename
                path.write_text(path.read_text().replace('deploy/compose.foc.yaml', 'compose.foc.yaml'))
            for script in self.builders:
                path = historical / script
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text((ROOT / script).read_text())
            subprocess.run(['git', 'init', '-q', '-b', 'dev'], cwd=historical, check=True, capture_output=True)
            subprocess.run(['git', 'add', '.'], cwd=historical, check=True, capture_output=True)
            subprocess.run(['git', '-c', 'user.name=Archive fixture', '-c', 'user.email=archive@invalid',
                            '-c', 'commit.gpgsign=false', 'commit', '-qm', 'historical layout fixture'],
                           cwd=historical, check=True, capture_output=True)
            old_revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=historical, text=True).strip()
            for index, script in enumerate(sorted(self.builders)):
                with self.subTest(script=script):
                    output = root / ('legacy-' + str(index))
                    output.mkdir()
                    capture, target = self.capture(historical, script, old_revision, output)
                    self.assert_copy_inputs(capture, target)
                    with tarfile.open(capture) as archive:
                        self.assertIn('compose.foc.yaml', archive.getnames())
                        self.assertNotIn('deploy/compose.foc.yaml', archive.getnames())

    def test_build_target_check_rejects_an_omitted_installer_copy_input(self):
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        with tempfile.TemporaryDirectory(prefix='fc-context-check-') as directory:
            root = Path(directory)
            capture, target = self.capture(ROOT, 'scripts/test-storage-certificate-containers.sh', revision, root)
            self.assertEqual(target, 'build')
            incomplete = root / 'incomplete.tar'
            with tarfile.open(capture) as source, tarfile.open(incomplete, 'w') as output:
                self.assertIn('deploy/compose.foc.yaml', source.getnames())
                for member in source:
                    if member.name != 'deploy/compose.foc.yaml':
                        output.addfile(member, source.extractfile(member) if member.isfile() else None)
            with self.assertRaisesRegex(AssertionError, r'deploy/compose\.foc\.yaml'):
                self.assert_copy_inputs(incomplete, target)


if __name__ == '__main__':
    unittest.main()

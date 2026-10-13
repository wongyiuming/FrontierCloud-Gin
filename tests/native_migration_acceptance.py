"""Serial native migration acceptance with an optional real Chromium handoff.

This development-only driver requires already compiled private fixture images
and Go test binaries. It never installs, builds, publishes or operates a deployed
project. Every invocation owns a fresh five-node fleet and retains its data.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid


def command(arguments):
    result = subprocess.run(arguments, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError('private Docker fixture operation failed')
    return result.stdout


def container(ident):
    result = subprocess.run(['docker', 'inspect', ident], capture_output=True, timeout=60)
    if result.returncode:
        if b'no such' in result.stderr.lower():
            return None
        raise RuntimeError('private fixture container inspection failed')
    return json.loads(result.stdout)[0]


def remove_container(ident):
    for arguments in (['docker', 'stop', '--time', '15', ident], ['docker', 'rm', '-f', ident]):
        result = subprocess.run(arguments, capture_output=True, timeout=60)
        if result.returncode and container(ident) is not None:
            raise RuntimeError('private fixture container cleanup failed')


def cleanup(project, prefix):
    # Match the exact project born in this invocation, including stopped nodes.
    for ident in command(['docker', 'ps', '-aq', '--filter',
                          'label=com.docker.compose.project=' + project]).decode().split():
        value = container(ident)
        if value is None:
            continue
        if (value.get('Config', {}).get('Labels', {}).get('com.docker.compose.project') != project
                or not value.get('Name', '').lstrip('/').startswith(project + '-')):
            raise RuntimeError('private fixture ownership changed')
        remove_container(ident)
    for ident in command(['docker', 'network', 'ls', '-q', '--filter',
                          'label=frontiercloud.acceptance=' + project]).decode().split():
        value = json.loads(command(['docker', 'network', 'inspect', ident]))[0]
        if value.get('Labels', {}).get('frontiercloud.acceptance') == project and not value.get('Containers'):
            command(['docker', 'network', 'rm', ident])
    values = command(['docker', 'ps', '-aq', '--filter', 'name=^/' + prefix + '-driver$']).decode().split()
    for ident in values:
        value = container(ident)
        if value is not None and value.get('Config', {}).get('Labels', {}).get('frontiercloud.acceptance') == prefix:
            remove_container(ident)


def run(options):
    if os.geteuid() != 0:
        raise RuntimeError('isolated root Linux development host required')
    if options.no_direct and (options.browser or options.traffic or options.wait_cleanup or options.during):
        raise RuntimeError('unreachable-peer refusal is a separate native scenario')
    if options.during and not options.browser:
        raise RuntimeError('during-copy verification requires the real browser')
    for name in ('test_binary', 'certificate_test_binary', 'output'):
        setattr(options, name, getattr(options, name).resolve())
    # Keep the venv's executable path: resolving its symlink would select the
    # system interpreter and discard the isolated Playwright installation.
    options.browser_python = options.browser_python.absolute()
    for path in (options.test_binary, options.certificate_test_binary, options.browser_python):
        if not path.is_file():
            raise RuntimeError('prebuilt fixture binary missing')
    options.output.mkdir(parents=True, exist_ok=True)
    # Honor TMPDIR so retained native data need not consume a host tmpfs.
    work = Path(tempfile.mkdtemp(prefix='fc-native-matrix-'))
    if options.audio:
        # Offline test fixture generation only; no encoder runs in a product
        # process or image. The long tone crosses the one-MiB crypto boundary.
        audio = work / 'audio-fixtures'
        audio.mkdir(mode=0o700)
        for name, frequency, duration in (('short.mp3', 440, 3), ('long.mp3', 660, 75)):
            generated = subprocess.run(['ffmpeg', '-hide_banner', '-loglevel', 'error',
                '-threads', '1', '-f', 'lavfi', '-i',
                f'sine=frequency={frequency}:sample_rate=44100:duration={duration}',
                '-c:a', 'libmp3lame', '-b:a', '128k', '-threads', '1', str(audio / name)],
                capture_output=True, timeout=60)
            if generated.returncode or not 1024 <= (audio / name).stat().st_size <= 2 * 1024 * 1024:
                raise RuntimeError('bounded private audio fixture generation failed')
    prefix = 'fc-matrix-' + str(uuid.uuid4())
    project = prefix + '-' + options.case + '-' + options.database
    shutil.copyfile(options.certificate_test_binary, work / 'certificate.test')
    os.chmod(work / 'certificate.test', 0o755)
    images = {name: json.loads(command(['docker', 'image', 'inspect', image]))[0]['Id']
              for name, image in (('native', options.native_image), ('agent', options.agent_image),
                                  ('edge', options.edge_image))}
    timeout = '100m' if options.wait_cleanup else '45m'
    arguments = ['docker', 'run', '--rm', '--cpus=2', '--memory=2g', '--memory-swap=2g',
                 '--name', prefix + '-driver', '--label', 'frontiercloud.acceptance=' + prefix,
                 '-e', 'GOMAXPROCS=2', '-v', '/var/run/docker.sock:/var/run/docker.sock',
                 '-v', str(work) + ':' + str(work), '-v', str(options.test_binary) + ':/updater.test:ro']
    environment = {'FRONTIERCLOUD_TEST_DOCKER_SOCKET': '/var/run/docker.sock',
        'FRONTIERCLOUD_TEST_NATIVE_MATRIX_WORKSPACE': str(work),
        'FRONTIERCLOUD_TEST_NATIVE_MATRIX_PREFIX': prefix,
        'FRONTIERCLOUD_TEST_NATIVE_MATRIX_MASTER': options.database,
        'FRONTIERCLOUD_TEST_NATIVE_MIGRATION_CASE': options.case,
        'FRONTIERCLOUD_TEST_NATIVE_MIGRATION_BROWSER': '1' if options.browser else '',
        'FRONTIERCLOUD_TEST_NATIVE_MIGRATION_WAIT_CLEANUP': '1' if options.wait_cleanup else '',
        'FRONTIERCLOUD_TEST_NATIVE_MIGRATION_TRAFFIC': '1' if options.traffic else '',
        'FRONTIERCLOUD_TEST_NATIVE_MIGRATION_AUDIO': '1' if options.audio else '',
        'FRONTIERCLOUD_TEST_NATIVE_MIGRATION_DURING': '1' if options.during else '',
        'FRONTIERCLOUD_TEST_NATIVE_MIGRATION_MANY_SMALL': '1' if options.many_small_files else '',
        'FRONTIERCLOUD_TEST_MIGRATION_NO_DIRECT': '1' if options.no_direct else '',
        'FRONTIERCLOUD_TEST_NATIVE_MATRIX_NATIVE_IMAGE': images['native'],
        'FRONTIERCLOUD_TEST_NATIVE_MATRIX_AGENT_IMAGE': images['agent'],
        'FRONTIERCLOUD_TEST_NATIVE_MATRIX_EDGE_IMAGE': images['edge']}
    for key, value in environment.items():
        arguments += ['-e', key + '=' + value]
    arguments += ['golang:1.26.8-bookworm', '/updater.test', '-test.timeout=' + timeout,
                  '-test.v', '-test.run=^TestRealNativeMatrixFleetMigrations$']
    with options.test_binary.open('rb') as binary:
        binary_sha = hashlib.file_digest(binary, 'sha256').hexdigest()
    result = {'status': 'running', 'database': options.database, 'combination': options.case,
              'workspace': str(work), 'project': project, 'image_ids': images,
              'test_binary_sha256': binary_sha,
              'private_test_images': True, 'public_release_proof': False, 'real_cleanup_wait_selected': options.wait_cleanup,
              'real_business_traffic_selected': options.traffic, 'unreachable_peer_selected': options.no_direct,
              'generated_mp3_selected': options.audio, 'during_copy_browser_selected': options.during,
              'additional_actual_small_files': 1024 if options.many_small_files else 0}
    browser_result = None
    browser_phases = {}
    browser_seen = set()
    started = time.monotonic()
    process = None
    try:
        with (options.output / 'native.txt').open('wb') as log:
            process = subprocess.Popen(arguments, stdout=log, stderr=subprocess.STDOUT)
            while process.poll() is None:
                if options.browser:
                    candidates = [file for file in work.glob('*/*/browser*-fixture.json') if file not in browser_seen]
                    if len(candidates) > 1:
                        raise RuntimeError('multiple browser handoffs in one serial case')
                    if candidates:
                        fixture = candidates[0]
                        browser_seen.add(fixture)
                        phase = 'during' if fixture.name == 'browser-during-fixture.json' else 'after'
                        script = Path(__file__).with_name('node_migration_native_browser.py')
                        private_log = fixture.with_name('browser-' + phase + '-private-process.txt')
                        with os.fdopen(os.open(private_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as browser_log:
                            completed = subprocess.run([str(options.browser_python), str(script), '--fixture', str(fixture)],
                                stdout=browser_log, stderr=subprocess.STDOUT, timeout=180,
                                # Chromium's sandboxed compositor cannot use
                                # the root-only retained-data parent for shared
                                # memory. Keep its disposable IPC separate and
                                # bind fixture reads to this exact owned root.
                                env=dict(os.environ, DEBUG='pw:browser', TMPDIR='/tmp',
                                    FRONTIERCLOUD_TEST_NATIVE_MATRIX_WORKSPACE=str(work)))
                        result_file = fixture.with_name('browser-during-result.json' if phase == 'during' else 'browser-result.json')
                        value = json.loads(result_file.read_text()) if result_file.is_file() else {'passed': False, 'stage': 'browser_driver_unavailable'}
                        (options.output / ('browser-during.txt' if phase == 'during' else 'browser.txt')).write_text(
                            ('PASS' if completed.returncode == 0 and value.get('passed') else 'FAIL')
                            + ': native Chromium phase ' + phase + '; stage ' + str(value.get('stage', 'unknown')) + '\n')
                        browser_result = value
                        browser_phases[phase] = value
                        if completed.returncode == 0 and value.get('passed'):
                            print('Actual Chromium verification passed; native fixture continues.', flush=True)
                if time.monotonic() - started > (6120 if options.wait_cleanup else 2820):
                    raise RuntimeError('native fixture exceeded bounded lifetime')
                time.sleep(1)
        if process.returncode or options.browser and (not browser_result or not browser_result.get('passed')):
            raise RuntimeError('native acceptance failed; exact fixture evidence retained')
        if options.during and (set(browser_phases) != {'during', 'after'} or not all(v.get('passed') for v in browser_phases.values())):
            raise RuntimeError('native during/after browser evidence incomplete')
        result.update(status='passed', elapsed_seconds=round(time.monotonic() - started, 3),
                      actual_chromium=browser_result, chromium_phases=browser_phases)
    except BaseException as error:
        result.update(status='failed', error_type=type(error).__name__, actual_chromium=browser_result, chromium_phases=browser_phases)
        raise
    finally:
        try:
            if process is not None and process.poll() is None:
                cleanup(project, prefix)
                process.wait(timeout=60)
            cleanup(project, prefix)
            result['owned_cleanup_complete'] = True
        except BaseException as error:
            result.update(status='failed', owned_cleanup_complete=False, cleanup_error_type=type(error).__name__)
            raise
        finally:
            (options.output / 'evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: native serial migration case ' + options.database + '/' + options.case, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-binary', type=Path, required=True)
    parser.add_argument('--certificate-test-binary', type=Path, required=True)
    parser.add_argument('--native-image', required=True)
    parser.add_argument('--agent-image', required=True)
    parser.add_argument('--edge-image', required=True)
    parser.add_argument('--browser-python', type=Path, required=True)
    parser.add_argument('--database', choices=('go-sqlite', 'go-mysql'), required=True)
    parser.add_argument('--case', choices=('dd', 'dr', 'rd', 'rr'), required=True)
    parser.add_argument('--browser', action='store_true')
    parser.add_argument('--wait-cleanup', action='store_true')
    parser.add_argument('--traffic', action='store_true', help='exercise actual public traffic, quiet resume and durable manual pause')
    parser.add_argument('--audio', action='store_true', help='generate test-only MP3 tones and verify real player decoding/continuation and lyrics')
    parser.add_argument('--during', action='store_true', help='run the real browser both during copying and after cutover')
    parser.add_argument('--many-small-files', action='store_true', help='copy 1024 additional real files in one ownership unit across sixteen pages')
    parser.add_argument('--no-direct', action='store_true', help='isolate peers and prove refusal without a Master data fallback')
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args())

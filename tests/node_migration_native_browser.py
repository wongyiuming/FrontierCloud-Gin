"""Chromium acceptance against a live, owned five-node native migration fixture.

No routes, API responses, scripts or cryptography are replaced. Optional private
generated MP3 tones exercise actual decoding and the shipped continuous player.
Only bounded boolean/hash evidence is saved; credentials and URLs are not logged.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import traceback
from urllib.parse import urlsplit
import uuid

from playwright.sync_api import sync_playwright, expect


def regular_owned(path, root, maximum):
    if not path.is_absolute() or not path.is_relative_to(root):
        raise ValueError('owned absolute fixture path required')
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError('fixture symlink refused')
        if part == root:
            break
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
        raise ValueError('bounded regular fixture file required')
    return path.read_bytes()


def fixture_root(path):
    if not path.is_absolute() or path.name not in ('browser-fixture.json', 'browser-during-fixture.json'):
        raise ValueError('absolute browser fixture contract required')
    roots = [parent for parent in path.parents if parent.name.startswith('fc-native-matrix-')]
    expected = os.environ.get('FRONTIERCLOUD_TEST_NATIVE_MATRIX_WORKSPACE')
    if len(roots) != 1 or (expected is not None and roots[0] != Path(expected)) or (expected is None and roots[0].parent != Path(tempfile.gettempdir()).resolve()):
        raise ValueError('owned temporary native matrix root required')
    root = roots[0]
    if root.is_symlink() or not root.is_dir():
        raise ValueError('unsafe fixture root')
    return root


def read_fixture(path, root):
    value = json.loads(regular_owned(path, root, 32768))
    if value.get('phase', 'after') not in ('after', 'during'):
        raise ValueError('native browser phase invalid')
    hosts = value.get('hosts')
    if not isinstance(hosts, dict) or set(hosts) != {f'site{i}.fleet.invalid' for i in range(5)}:
        raise ValueError('exactly five native fixture hosts required')
    for address in hosts.values():
        ip = ipaddress.ip_address(address)
        if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            raise ValueError('private Docker IPv4 fixture endpoints required')
    if value.get('origin') != 'https://site0.fleet.invalid':
        raise ValueError('native master HTTPS origin required')
    for name in ('task_id', 'source_id', 'target_id'):
        if not re.fullmatch(r'[a-f0-9]{32}', value.get(name, '')):
            raise ValueError('native fixture identifier required')
    if value['source_id'] == value['target_id']:
        raise ValueError('different native migration members required')
    encrypted = value.get('encrypted', {})
    if (not re.fullmatch(r'[a-f0-9]{32}', encrypted.get('file_id', ''))
            or not re.fullmatch(r'[a-f0-9]{64}', encrypted.get('plaintext_sha256', ''))
            or not isinstance(encrypted.get('plaintext_bytes'), int)
            or not 1048620 <= encrypted['plaintext_bytes'] <= 16 * 1024 * 1024):
        raise ValueError('bounded cross-chunk encrypted fixture required')
    media = encrypted.get('path', '')
    if (not isinstance(media, str) or len(media) > 1024 or not media.startswith('music/')
            or any(part in ('', '.', '..') for part in media.split('/')) or any(c in media for c in '\\?#\x00\r\n')):
        raise ValueError('managed native fixture media path required')
    keyfile = Path(value.get('admin_key_file', ''))
    if 'audio' in value and value['audio'] != {
            'plain_directory': 'music/migrate/parent1',
            'plain_first_path': 'music/migrate/parent1/track-016.mp3',
            'plain_second_path': 'music/migrate/parent1/track-017.mp3',
            'lyric_path': 'lyrics/migration/tone.lrc'}:
        raise ValueError('bounded native MP3/lyric fixture required')
    if keyfile.name != 'admin_key' or keyfile.parent.name != 'secrets':
        raise ValueError('private fixture admin key file required')
    key = regular_owned(keyfile, root, 4096).decode('utf-8').strip()
    if not 16 <= len(key) <= 512 or keyfile.stat().st_mode & 0o077:
        raise ValueError('private bounded fixture credential required')
    return value, key


def write_result(path, value):
    temporary = path.with_name('.browser-result-' + uuid.uuid4().hex + '.tmp')
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='utf-8') as file:
        json.dump(value, file, indent=2)
        file.write('\n')
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run(fixture, key, result):
    executable = os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE')
    if not executable:
        found = sorted(Path('/root/.cache/ms-playwright').glob('**/chrome-headless-shell'))
        if not found:
            raise RuntimeError('installed Chromium unavailable')
        executable = str(found[-1])
    rules = ','.join('MAP ' + host + ' ' + address for host, address in sorted(fixture['hosts'].items()))
    # The browser process gets a private resolver map, never a host DNS change.
    rules += ',MAP * ~NOTFOUND'
    counters = {'crypto_session': 0, 'crypto_key': 0, 'cipher_response': 0, 'service_worker_response': 0}

    def observed(response):
        parsed = urlsplit(response.url)
        if parsed.hostname not in fixture['hosts']:
            return
        if response.status in (200, 206):
            if parsed.path.endswith('/crypto/session'):
                counters['crypto_session'] += 1
            elif parsed.path.endswith('/crypto/key'):
                counters['crypto_key'] += 1
            elif parsed.path == '/api/v1/media/stream' or parsed.path.startswith('/internal/v1/media/'):
                counters['cipher_response'] += 1
            if parsed.path.startswith('/__fc_media/') and response.from_service_worker:
                counters['service_worker_response'] += 1

    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(executable_path=executable, headless=True,
            args=['--no-sandbox', '--no-proxy-server', '--disable-background-networking',
                  '--autoplay-policy=no-user-gesture-required',
                  '--ignore-certificate-errors', '--host-resolver-rules=' + rules])
        try:
            context = browser.new_context(ignore_https_errors=True, viewport={'width': 1360, 'height': 1000})
            context.on('response', observed)
            page = context.new_page()
            page.set_default_timeout(30000)
            result['stage'] = 'native_authentication'
            page.goto(fixture['origin'] + '/api/v1/media/', wait_until='domcontentloaded')
            authenticated = page.evaluate('''async key => {
                const r = await fetch('/api/v1/media/admin/elevate', {method:'POST', credentials:'same-origin',
                    headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:new URLSearchParams({token:key})});
                return r.status;
            }''', key)
            key = None
            if authenticated != 200:
                raise RuntimeError('native admin authentication failed')
            result['stage'] = 'native_nodes_module'
            page.goto(fixture['origin'] + '/api/v1/media/admin/', wait_until='domcontentloaded')
            panel = page.locator('#nodesPanel')
            expect(panel).to_be_attached()
            if 'expanded' not in (panel.get_attribute('class') or '').split():
                panel.locator('.module-heading').click()
            result['stage'] = 'native_nodes_refresh'
            panel.locator('#nodesRefresh').click()
            migration_panel = page.locator('#migrationsPanel')
            migration_panel.locator('.module-heading').click()
            migration_panel.locator('#migrationsRefresh').click()
            card = migration_panel.locator('article.node-config-box').filter(has_text=fixture['task_id'])
            result['stage'] = 'native_task_card'
            expect(card).to_have_count(1)
            result['stage'] = 'native_task_state'
            expected_state = 'copying' if fixture.get('phase') == 'during' else 'cleanup_pending'
            expect(card).to_contain_text(re.compile('复制中|等待业务低峰') if expected_state == 'copying' else '清理待办')
            result['stage'] = 'native_task_members'
            expect(card).to_contain_text(fixture['source_id'])
            expect(card).to_contain_text(fixture['target_id'])
            result['stage'] = 'native_task_api'
            task = page.evaluate('''async id => {
                const r=await fetch('/api/v1/media/admin/nodes/migrations/'+id,{credentials:'same-origin'});
                if(!r.ok) return null;
                const v=await r.json(); return {id:v.task?.task_id,state:v.task?.state,source:v.task?.source_id,target:v.task?.target_id};
            }''', fixture['task_id'])
            if task != {'id': fixture['task_id'], 'state': expected_state, 'source': fixture['source_id'], 'target': fixture['target_id']}:
                raise RuntimeError('native task checkpoint differs')
            result['stage'] = 'native_retirement_ui'
            panel.locator('.module-heading').click()
            panel.locator('#nodesRefresh').click()
            source = panel.locator('article.node-card').filter(has=page.get_by_text(fixture['source_id'], exact=True))
            expect(source).to_have_count(1)
            source.locator('.node-details-toggle[aria-expanded="false"]').click()
            with page.expect_response(lambda response: urlsplit(response.url).path.endswith('/retire/check')) as observation:
                source.get_by_role('button', name='执行只读退役检查', exact=True).click()
            response = observation.value
            report = response.json()
            if isinstance(report.get('report'), dict):
                report = report['report']
            blocked = (bool(report.get('master', {}).get('blockers')) or bool(report.get('peer', {}).get('blockers'))
                       or bool(report.get('concerns')) or int(report.get('expected_items') or 0) > 0)
            if not blocked:
                raise RuntimeError('retained migration source unexpectedly retirement-clear')
            expect(source).to_contain_text(re.compile('盘点已完成|检查未完成'))
            expect(source.get_by_role('button', name='确认安全退役', exact=True)).to_have_count(0)
            result.update(real_task_cleanup_pending=expected_state == 'cleanup_pending', real_task_copying=expected_state == 'copying', source_target_visible=True, source_retirement_blocked=True)

            result['stage'] = 'native_service_worker_decryption'
            # Use the public shipped module's key/read protocol rather than the
            # Admin download variant; synthetic audio bytes need no decoder.
            page = context.new_page()
            page.goto(fixture['origin'] + '/api/v1/media/', wait_until='domcontentloaded')
            page.wait_for_function('() => typeof window.FrontierMediaCrypto?.ensureWorker === "function"')
            proof = page.evaluate('''async expected => {
                await FrontierMediaCrypto.ensureWorker();
                if (!navigator.serviceWorker.controller) throw Error('worker controller absent');
                const url=FrontierMediaCrypto.virtualUrl(expected.path,false,expected.file_id);
                const full=await fetch(url,{credentials:'same-origin',cache:'no-store'});
                if(full.status!==200) throw Error('full plaintext response failed');
                const bytes=new Uint8Array(await full.arrayBuffer());
                if(bytes.length!==expected.plaintext_bytes) throw Error('plaintext length differs');
                const sha=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
                if(sha!==expected.plaintext_sha256) throw Error('plaintext hash differs');
                const start=1048541,end=1048619;
                const ranged=await fetch(url,{credentials:'same-origin',cache:'no-store',headers:{Range:`bytes=${start}-${end}`}});
                const part=new Uint8Array(await ranged.arrayBuffer());
                if(ranged.status!==206||ranged.headers.get('Content-Range')!==`bytes ${start}-${end}/${bytes.length}`
                   ||part.length!==end-start+1||part.some((byte,i)=>byte!==bytes[start+i])) throw Error('cross-chunk Range differs');
                return {decrypted:true,plaintext_bytes:bytes.length,plaintext_sha256:sha,cross_chunk_range:true,
                    range_status:ranged.status,service_worker_controlled:true,secure_context:isSecureContext};
            }''', fixture['encrypted'])
            if not all(counters.values()):
                raise RuntimeError('real ciphertext/session/key/worker responses not observed')
            result.update(proof)
            if 'audio' in fixture:
                result['stage'] = 'native_continuous_audio'
                player = context.new_page()
                player.goto(fixture['origin'] + '/api/v1/media/music/category?path=music%2Fmigrate%2Fparent1', wait_until='domcontentloaded')
                player.wait_for_function('() => typeof art!=="undefined" && art?.video?.currentTime > 0.1 && window.frontierCloudContinuousAudio?.status().active_segment', timeout=45000)
                first = player.evaluate('''() => {
                    window.nativeMigrationVideo = art.video;
                    window.nativeMigrationSource = art.url;
                    return {path:currentMediaList[currentIndex].media_path, error:!!art.video.error};
                }''')
                if first != {'path': fixture['audio']['plain_first_path'], 'error': False}:
                    raise RuntimeError('native first migrated MP3 did not decode')
                player.wait_for_function('expected => currentMediaList[currentIndex]?.media_path===expected && art.video.currentTime > 0.1', arg=fixture['audio']['plain_second_path'], timeout=45000)
                continuation = player.evaluate('''() => ({
                    same_video: art.video === window.nativeMigrationVideo,
                    same_source: art.url === window.nativeMigrationSource,
                    decoder_error: !!art.video.error,
                    pipeline_error: window.frontierCloudContinuousAudio.status().pipeline_error,
                    warnings: currentMediaList.some(v => !!v.continuous_stream_skip_reason)
                })''')
                if (not continuation['same_video'] or not continuation['same_source']
                        or continuation['decoder_error'] or continuation['pipeline_error']
                        or continuation['warnings']):
                    raise RuntimeError('native continuous MP3 transition changed session or failed')
                player.close()
                result['stage'] = 'native_encrypted_audio'
                encrypted_player = context.new_page()
                encrypted_player.goto(fixture['origin'] + '/api/v1/media/music/category?path=music%2Fmigrate%2Fencrypted', wait_until='domcontentloaded')
                encrypted_player.wait_for_function('() => typeof art!=="undefined" && art?.video?.currentTime > 0.2', timeout=45000)
                decoded = encrypted_player.evaluate('''() => ({
                    path: currentMediaList[currentIndex].media_path,
                    virtual: currentMediaList[currentIndex].url.includes('/__fc_media/'),
                    error: !!art.video.error,
                    pipeline_error: window.frontierCloudContinuousAudio?.status().pipeline_error
                })''')
                if (decoded['path'] != fixture['encrypted']['path'] or not decoded['virtual']
                        or decoded['error'] or decoded['pipeline_error']):
                    raise RuntimeError('native encrypted migrated MP3 did not decode')
                encrypted_player.close()
                result['stage'] = 'native_lyric_relation'
                lyric = context.new_page()
                lyric.goto(fixture['origin'] + '/api/v1/media/lyrics?track=music%2Fmigrate%2Fencrypted%2Fopaque.mp3', wait_until='domcontentloaded')
                lyric.wait_for_function("() => document.getElementById('lyricsBoard')?.textContent.includes('Original business relation retained')", timeout=30000)
                lyric.close()
                relation = page.evaluate('''async expected => {
                    const match=[];
                    for(const directory of [expected.plain_directory,'music/migrate/encrypted']) {
                        const r=await fetch('/api/v1/media/admin/lyrics/catalog?track_path='+encodeURIComponent(directory)+'&lyric_path=lyrics%2Fmigration',{credentials:'same-origin'});
                        if(!r.ok) return false;
                        const v=await r.json();
                        match.push(...(v.tracks||[]).filter(t=>t.path===expected.plain_first_path || t.path==='music/migrate/encrypted/opaque.mp3'));
                    }
                    return match.length===2 && match.every(t=>t.lyric_path===expected.lyric_path);
                }''', fixture['audio'])
                if not relation:
                    raise RuntimeError('native business lyric relation changed after migration')
                result.update(decoded_playback_verified=True, encrypted_playback_verified=True,
                              continuous_playback_verified=True, same_media_element=True,
                              lyric_relation_verified=True, generated_test_tones=True)
            result.update(network_response_counts=counters, native_authentication=True, real_server=True,
                          shipped_browser_modules=True, no_backend_mocks=True, audible_playback_verified=False,
                          browser_private_ca_exception=True, passed=True, stage='complete')
        finally:
            browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    options = parser.parse_args()
    output = None
    result = {'passed': False, 'real_server': False, 'decrypted': False, 'stage': 'fixture_validation'}
    try:
        root = fixture_root(options.fixture)
        regular_owned(options.fixture, root, 32768)
        output = options.fixture.with_name('browser-during-result.json' if options.fixture.name == 'browser-during-fixture.json' else 'browser-result.json')
        if output.exists() or output.is_symlink():
            raise ValueError('browser result already exists')
        fixture, key = read_fixture(options.fixture, root)
        run(fixture, key, result)
    except BaseException as error:
        # Playwright errors may include signed URLs, request headers or arguments.
        # Report only an allowlisted stage and exception type, never raw detail.
        result['error_type'] = type(error).__name__
        if output is not None:
            # Raw Playwright details stay beside private credentials, never in
            # the public acceptance report or driver output.
            diagnostic = output.with_name(output.stem + '-private-diagnostic.txt')
            with os.fdopen(os.open(diagnostic, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='utf-8') as file:
                file.write(traceback.format_exc()[-32768:])
        if output is not None and not output.exists():
            write_result(output, result)
        print('FAIL: native browser acceptance at ' + result['stage'], file=sys.stderr)
        return 1
    write_result(output, result)
    print('PASS: native Chromium task UI, blocked retirement and service-worker plaintext/Range integrity')
    return 0


if __name__ == '__main__':
    sys.exit(main())

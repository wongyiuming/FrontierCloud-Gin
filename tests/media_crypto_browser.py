"""Real Chromium encryption acceptance against a fresh loopback TLS fixture."""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import urllib.parse
import zipfile

from playwright.sync_api import sync_playwright


def digest(data):
    return hashlib.sha256(data).hexdigest()


def visible_captcha_answer(svg):
    # Read the public bitmap as a human would. Normal CAPTCHA consumption and
    # registration admission remain enabled; no fixture SQL/security bypass.
    font = (pathlib.Path(__file__).resolve().parents[1] / 'internal/karaoke/captcha.go').read_text()
    glyphs = {tuple(re.findall(r'"([01]{5})"', rows)): character
              for character, rows in re.findall(r"'(.)':\s*\{([^}]+)\}", font)}
    cells = [[[0] * 5 for _ in range(7)] for _ in range(5)]
    for x, y in re.findall(r'M(\d+) (\d+)h3v4h-3z', svg):
        x, y = int(x) - 13, int(y) - 12
        index, column, row = x // 28, (x % 28) // 3, y // 4
        assert 0 <= index < 5 and 0 <= column < 5 and 0 <= row < 7
        cells[index][row][column] = 1
    return ''.join(glyphs[tuple(''.join(map(str, row)) for row in glyph)] for glyph in cells)


def recording_footer(data):
    marker = b'FRONTIERCLOUD-KARAOKE-V1'
    assert data.endswith(marker)
    end = len(data) - len(marker) - 8
    size = int.from_bytes(data[end:end + 8], 'big')
    assert 0 < size <= 2 * 1024 * 1024 and size <= end
    return json.loads(data[end - size:end])


def open_upload_choice(page, button):
    # The media module and hover/focus upload menu follow the normal Admin UI.
    page.locator('#uploadBtn').click()
    page.locator(button).click()
    dialog = page.locator('dialog.upload-storage-mode-dialog')
    dialog.wait_for(state='visible')
    return dialog


def choose_files(page, button, mode, files, expected_success):
    dialog = open_upload_choice(page, button)
    assert dialog.locator('div button').all_text_contents() == ['加密落盘', '明文落盘']
    # A new picker must never inherit the previous selection's mode.
    assert page.evaluate("() => [...document.querySelectorAll('input[type=file]')].every(input => !input.dataset.storageMode)")
    with page.expect_file_chooser() as chooser:
        dialog.get_by_role('button', name=mode, exact=True).click()
    chooser.value.set_files(files)
    page.wait_for_function(
        "count => document.getElementById('uploadSummary').textContent === `完成：成功 ${count}，失败 0`",
        arg=expected_success, timeout=90000)
    assert page.evaluate("() => [...document.querySelectorAll('input[type=file]')].every(input => !input.dataset.storageMode)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--fixtures', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    parsed = urllib.parse.urlsplit(args.base_url)
    if parsed.scheme != 'https' or parsed.hostname != '127.0.0.1' or not parsed.port:
        raise SystemExit('Only a fresh loopback HTTPS fixture is allowed')
    base = args.base_url.rstrip('/')
    fixtures = pathlib.Path(args.fixtures).resolve()
    output = pathlib.Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    folder = fixtures / 'encrypted-fixture'
    expected = {name: (folder / name).read_bytes() for name in ('01-first.mp3', '02-second.mp3')}
    assert len(expected['01-first.mp3']) > 1048576, 'first MP3 must cross an authenticated chunk boundary'
    lyric = fixtures / 'crypto-lyrics.lrc'
    lyric_text = lyric.read_text(encoding='utf-8')
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(
            executable_path=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE'), headless=True,
            args=['--no-sandbox', '--ignore-certificate-errors', '--autoplay-policy=no-user-gesture-required',
                  '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'])
        context = browser.new_context(ignore_https_errors=True, accept_downloads=True)
        context.add_init_script("""(() => {
            const now=Date.now.bind(Date);
            window.cryptoTestClockOffset=7*60*60*1000;
            Date.now=()=>now()+window.cryptoTestClockOffset;
        })();""")
        context.add_init_script("window.cspViolations=[];document.addEventListener('securitypolicyviolation',e=>window.cspViolations.push(e.effectiveDirective));")
        requests = []
        grants = []
        recording_tickets = []
        context.on('request', lambda request: requests.append({'url': request.url, 'method': request.method}))
        context.on('request', lambda request: recording_tickets.append(json.loads(request.post_data))
                   if request.url.endswith('/recordings/ticket') else None)

        def record_grant(response):
            if response.url.split('?')[0].endswith('/crypto/key') and response.status == 200:
                grants.append(response.json())

        context.on('response', record_grant)
        login = context.request.post(base + '/api/v1/media/admin/elevate', form={'token': os.environ['ADMIN_KEY']})
        assert login.status == 200
        admin = context.new_page()
        admin.goto(base + '/api/v1/media/admin/', wait_until='networkidle')
        admin.locator('.admin-module[data-admin-module="media"] .module-heading').click()
        admin.locator('#uploadSiteType').wait_for(state='visible')
        admin.wait_for_function("() => [...document.getElementById('uploadSiteType').options].some(option => option.value === 'primary' && !option.disabled)")
        admin.locator('#uploadSiteType').select_option('primary')
        admin.locator('.tree-row[data-path="music"]').dblclick()
        admin.wait_for_function("() => currentPath === 'music'")
        choose_files(admin, '#uploadFolder', '加密落盘', str(folder), 2)
        admin.locator('.tree-row[data-path="music/encrypted-fixture"]').dblclick()
        admin.locator('.tree-row[data-path="music/encrypted-fixture/01-first.mp3"]').wait_for()
        admin.wait_for_function("() => [...document.querySelectorAll('.media-encryption-badge')].map(item=>item.textContent).join(',') === '加密落盘,加密落盘'")
        assert admin.locator('.media-encryption-badge').all_text_contents() == ['加密落盘', '加密落盘']
        assert sum(item['url'].endswith('/admin/crypto/session') for item in requests) == 1
        # Another file must reuse the same deadline even after a wall-clock jump.
        admin.evaluate('window.cryptoTestClockOffset=-7*60*60*1000')
        assert admin.evaluate("""async () => {
            const root=await navigator.storage.getDirectory();
            const directory=await root.getDirectoryHandle('frontiercloud-cipher-upload-v1');
            let count=0;for await(const entry of directory.entries())count++;return count;
        }""") == 0

        # Every subsequent file/lyric choice independently asks for its mode.
        open_upload_choice(admin, '#uploadFiles').get_by_role('button', name='取消', exact=True).click()
        choose_files(admin, '#uploadFiles', '明文落盘', str(fixtures / 'plain.wav'), 1)
        choose_files(admin, '#uploadLyrics', '加密落盘', str(lyric), 1)
        admin.evaluate("async()=>{currentPath='vido';clearMediaSelection();await renderTree()}")
        choose_files(admin, '#uploadFolder', '加密落盘', str(fixtures / 'encrypted-video'), 1)
        admin.evaluate("""async () => await api('/api/v1/media/admin/lyrics/relations', {
            method:'POST', headers:requestHeaders(), body:JSON.stringify({origin_kind:'track',
            origin_path:'music/encrypted-fixture/01-first.mp3',linked_paths:['lyrics/crypto-lyrics.lrc']})
        })""")
        assert sum(item['url'].endswith('/admin/crypto/session') for item in requests) == 1

        # Artificially fail the encryption component; the upload path must stop
        # before a multipart request and must not switch to plaintext.
        before_uploads = sum(item['url'].endswith('/upload/item') for item in requests)
        admin.evaluate("() => {window.testOriginalEncrypt=FrontierMediaCrypto.encryptFile;FrontierMediaCrypto.encryptFile=async()=>{throw new Error('acceptance encryption failure')};}")
        dialog = open_upload_choice(admin, '#uploadFiles')
        with admin.expect_file_chooser() as chooser:
            dialog.get_by_role('button', name='加密落盘', exact=True).click()
        chooser.value.set_files({'name': 'must-not-publish.wav', 'mimeType': 'audio/wav', 'buffer': b'must not leave browser as plaintext'})
        admin.wait_for_function("() => document.getElementById('uploadSummary').textContent === '完成：成功 0，失败 1'")
        assert sum(item['url'].endswith('/upload/item') for item in requests) == before_uploads
        admin.evaluate('FrontierMediaCrypto.encryptFile=window.testOriginalEncrypt;delete window.testOriginalEncrypt')

        # Download the actual stored ciphertext via the same authorized source
        # used by playback; compare its size/hash with the uploaded plaintext.
        plan = admin.evaluate("async()=>await api('/api/v1/media/admin/download/plan?paths='+encodeURIComponent(JSON.stringify(['music/encrypted-fixture','lyrics/crypto-lyrics.lrc','vido/encrypted-video'])))")
        encrypted_items = [item for item in plan['items'] if item.get('encryption')]
        assert len(encrypted_items) == 4
        with admin.expect_download(timeout=90000) as event:
            admin.evaluate('items=>FrontierMediaCrypto.downloadPlan(items)', plan['items'])
        archive_path = output / 'encrypted-and-plain.zip'
        event.value.save_as(archive_path)
        assert event.value.failure() is None
        with zipfile.ZipFile(archive_path) as archive:
            assert archive.testzip() is None
            for name, original in expected.items():
                assert digest(archive.read('music/encrypted-fixture/' + name)) == digest(original)
            assert archive.read('lyrics/crypto-lyrics.lrc').decode('utf-8') == lyric_text
            assert digest(archive.read('music/encrypted-fixture/plain.wav')) == digest((fixtures / 'plain.wav').read_bytes())
            assert digest(archive.read('vido/encrypted-video/clip.mp4')) == digest((fixtures / 'encrypted-video/clip.mp4').read_bytes())
        with admin.expect_download(timeout=90000) as event:
            single_item = next(item for item in encrypted_items if item['path'].endswith('.mp3'))
            admin.evaluate('item=>FrontierMediaCrypto.downloadPlan([item])', single_item)
        single_path = output / 'single-download.mp3'
        event.value.save_as(single_path)
        assert event.value.failure() is None
        assert digest(single_path.read_bytes()) == digest(expected[pathlib.PurePosixPath(single_item['path']).name])
        assert admin.evaluate('window.cspViolations') == []

        # Native video retains normal Range/seek behavior through the same
        # browser adapter. Rename/delete use only supported business APIs.
        video = context.new_page()
        video.goto(base + '/api/v1/media/video/category?path=vido%2Fencrypted-video', wait_until='networkidle')
        video.wait_for_function('() => art && art.video.currentTime > 0.05', timeout=30000)
        assert video.evaluate("art.video.src.includes('/__fc_media/') && !art.video.error")
        video.evaluate('art.currentTime=4')
        video.wait_for_function('() => art.currentTime >= 4 && art.currentTime < 6', timeout=15000)
        assert video.evaluate('window.cspViolations') == []
        video_id = video.evaluate('currentMediaList[0].encryption.file_id')
        video.close()
        renamed = admin.evaluate("""async()=>await api('/api/v1/media/admin/directory/rename', {
            method:'POST',headers:requestHeaders(),body:JSON.stringify({path:'vido/encrypted-video',new_name:'renamed-video'})
        })""")
        assert renamed['new_path'] == 'vido/renamed-video'
        renamed_video = context.new_page()
        renamed_video.goto(base + '/api/v1/media/video/category?path=vido%2Frenamed-video', wait_until='networkidle')
        renamed_video.wait_for_function('() => art && art.video.currentTime > 0.05', timeout=30000)
        assert renamed_video.evaluate('currentMediaList[0].encryption.file_id') == video_id
        assert renamed_video.evaluate("currentMediaList[0].media_path === 'vido/renamed-video/clip.mp4'")
        renamed_video.close()
        deleted = admin.evaluate("""async()=>await api('/api/v1/media/admin/delete', {
            method:'POST',headers:requestHeaders(),body:JSON.stringify({paths:['vido/renamed-video/clip.mp4']})
        })""")
        assert deleted.get('deleted', 0) == 1
        admin.evaluate("FrontierMediaCrypto.resetFault('vido/renamed-video/clip.mp4')")
        denied = admin.evaluate("""async id=>{
            await FrontierMediaCrypto.ensureWorker();
            const response=await fetch(FrontierMediaCrypto.virtualUrl('vido/renamed-video/clip.mp4',false,id));
            return response.status;
        }""", video_id)
        assert denied == 404, f'deleted encrypted object still authorized: HTTP {denied}'

        audio_url = base + '/api/v1/media/music/category?path=music%2Fencrypted-fixture'
        audio_session_baseline = sum(item['url'].endswith('/media/crypto/session') for item in requests)
        player = context.new_page()
        player.goto(audio_url, wait_until='networkidle')
        player.wait_for_function('() => art && art.currentTime > 0.05 && window.frontierCloudContinuousAudio.status().active_segment', timeout=45000)
        state = player.evaluate("() => ({index:currentIndex,url:currentMediaList[currentIndex].url,entries:currentMediaList})")
        first_entry = next(item for item in state['entries'] if item['media_path'].endswith('01-first.mp3'))
        assert first_entry.get('encryption')
        assert '/__fc_media/' in first_entry['url']
        crossing = player.evaluate("""async url=>{
            const response=await fetch(url,{credentials:'same-origin',headers:{Range:'bytes=1048541-1048619'}});
            const bytes=new Uint8Array(await response.arrayBuffer());
            return {status:response.status,range:response.headers.get('Content-Range'),
                bytes:btoa(String.fromCharCode(...bytes))};
        }""", first_entry['url'])
        assert crossing['status'] == 206
        assert crossing['range'] == f"bytes 1048541-1048619/{len(expected['01-first.mp3'])}"
        assert base64.b64decode(crossing['bytes']) == expected['01-first.mp3'][1048541:1048620]
        suffix = player.evaluate("""async url=>{
            const response=await fetch(url,{headers:{Range:'bytes=-23'}});return btoa(String.fromCharCode(...new Uint8Array(await response.arrayBuffer())));
        }""", first_entry['url'])
        assert base64.b64decode(suffix) == expected['01-first.mp3'][-23:]
        for grant in grants:
            if grant['encryption']['file_id'] != first_entry['encryption']['file_id']:
                continue
            source_url = urllib.parse.urljoin(base, grant['source_url'])
            raw = context.request.get(source_url)
            assert raw.status == 200
            assert raw.headers.get('content-type', '').split(';', 1)[0].strip() == 'application/octet-stream', raw.headers
            assert 'no-store' in raw.headers.get('cache-control', '').lower(), raw.headers
            assert len(raw.body()) == grant['encryption']['ciphertext_size']
            assert digest(raw.body()) != digest(expected['01-first.mp3'])
            break
        else:
            raise AssertionError('actual encrypted source grant not observed')
        player.wait_for_function("() => activeLyricEntries.some(entry=>entry.text === '浏览器解密歌词')", timeout=15000)
        assert sum(item['url'].endswith('/media/crypto/session') for item in requests) == audio_session_baseline + 1
        video_identity = player.evaluate('window.cryptoAcceptanceVideo=art.video;window.cryptoAcceptanceSource=art.url;true')
        assert video_identity
        player.evaluate('art.currentTime=75')
        player.wait_for_function('() => art.currentTime >= 74.5 && art.currentTime < 80', timeout=45000)
        assert player.evaluate('art.video === window.cryptoAcceptanceVideo')
        player.wait_for_function('() => window.frontierCloudContinuousAudio.status().active_segment?.end !== null', timeout=30000)
        player.evaluate('window.cryptoAcceptanceSource=art.url')
        player.evaluate('art.currentTime=art.duration-0.8')
        player.wait_for_function("() => currentMediaList[currentIndex].media_path.endsWith('02-second.mp3') && art.currentTime > 0.05", timeout=45000)
        assert player.evaluate('art.video === window.cryptoAcceptanceVideo && art.url === window.cryptoAcceptanceSource'), 'continuous transition recreated the media session'
        assert sum(item['url'].endswith('/media/crypto/session') for item in requests) == audio_session_baseline + 1, 'multiple playback files must share one crypto session'
        assert player.evaluate('window.frontierCloudContinuousAudio.status().pipeline_error') is None
        assert player.evaluate('window.cspViolations') == []

        # Read the encrypted lyric through both standalone and karaoke paths.
        lyrics_page = context.new_page()
        lyrics_page.goto(base + '/api/v1/media/lyrics?track=music%2Fencrypted-fixture%2F01-first.mp3', wait_until='networkidle')
        lyrics_page.wait_for_function("() => document.getElementById('lyricsBoard').textContent.includes('浏览器解密歌词')", timeout=15000)
        assert lyrics_page.evaluate('window.cspViolations') == []
        karaoke_id = first_entry['karaoke_id']
        karaoke = context.new_page()
        karaoke.goto(base + '/karaoke/?media=' + urllib.parse.quote(karaoke_id), wait_until='networkidle')
        karaoke.wait_for_function("() => state.lyrics.some(entry=>entry.text==='浏览器解密歌词')", timeout=15000)
        assert karaoke.evaluate("state.context.stream_url.includes('/__fc_media/')")
        assert karaoke.evaluate('window.cspViolations') == []

        # Save only the browser-encrypted snapshot, including the audio footer.
        # The supported TLS promotion/account APIs prepare a real local pool.
        promoted = admin.evaluate("""async () => {
            const nodes=await api('/api/v1/media/admin/nodes');
            if(nodes.role==='Standalone')return api('/api/v1/media/admin/nodes/promote', {
                method:'POST',headers:requestHeaders(),body:JSON.stringify({role:'Master',endpoint:'https://nginx',local_capacity_gib:2})
            });
            return nodes;
        }""")
        assert promoted['role'] == 'Master'
        context.grant_permissions(['microphone'], origin=base)
        karaoke_session_baseline = sum(item['url'].endswith('/media/crypto/session') for item in requests)
        karaoke.locator('#record').click()
        karaoke.wait_for_function("() => state.phase === 'recording'", timeout=30000)
        karaoke.wait_for_timeout(1300)
        karaoke.locator('#stop').click()
        karaoke.wait_for_function("() => state.phase === 'preview' && state.recordedBlob?.size > 0", timeout=30000)
        assert karaoke.evaluate("() => state.sourceLyricsEncrypted && !state.account")
        assert '登录上传' in karaoke.locator('#previewHint').inner_text()
        guest = karaoke.evaluate("async () => btoa(String.fromCharCode(...new Uint8Array(await state.recordedBlob.arrayBuffer())))")
        assert '浏览器解密歌词'.encode() not in base64.b64decode(guest)
        assert not base64.b64decode(guest).endswith(b'FRONTIERCLOUD-KARAOKE-V1')
        captcha = context.request.get(base + '/api/v1/karaoke/account/captcha')
        assert captcha.status == 200
        challenge = captcha.json()
        image = context.request.get(urllib.parse.urljoin(base, challenge['image_url']))
        assert image.status == 200
        registered = context.request.post(base + '/api/v1/karaoke/account/register', data={
            'username': 'browser_snapshot_owner', 'password': 'BrowserTest@1234',
            'challenge': challenge['challenge'], 'captcha': visible_captcha_answer(image.text()), 'webrtc_addresses': []})
        assert registered.status == 200, (registered.status, registered.json().get('detail'))
        karaoke.evaluate('async()=>await refreshAccount()')
        karaoke.evaluate("state.recordingSnapshot.title=' \\u0085 '+state.recordingSnapshot.title+' \\u0085 '")
        karaoke.locator('#upload').click()
        karaoke.wait_for_function("() => document.getElementById('status').textContent === '录音已上传到个人空间。'", timeout=60000)
        assert len(recording_tickets) == 1
        submitted = recording_tickets[0]
        assert submitted['lyrics'] == [] and submitted['preparation_token']
        assert submitted['title'] == karaoke.evaluate('recordingTitle(state.recordingSnapshot.title)')
        assert '浏览器解密歌词' not in json.dumps(submitted, ensure_ascii=False)
        assert set(submitted['encrypted_lyrics']) == {'encryption', 'ciphertext'}
        saved = karaoke.evaluate("async()=>await accountApi('/recordings')")['items']
        assert len(saved) == 1 and saved[0]['lyrics'] == []
        assert saved[0]['encrypted_lyrics'] == submitted['encrypted_lyrics']
        recording_id = saved[0]['recording_id']
        stored = context.request.get(base + '/api/v1/karaoke/account/recordings/' + recording_id + '/download')
        assert stored.status == 200
        opaque_footer = recording_footer(stored.body())
        assert opaque_footer['lyrics'] == [] and opaque_footer['encrypted_lyrics'] == submitted['encrypted_lyrics']
        assert opaque_footer['title'] == submitted['title']
        assert 'preparation_token' not in opaque_footer
        assert '浏览器解密歌词'.encode() not in stored.body()
        assert len(stored.body()) == submitted['size_bytes']
        deleted_lyric = admin.evaluate("""async()=>await api('/api/v1/media/admin/delete', {
            method:'POST',headers:requestHeaders(),body:JSON.stringify({paths:['lyrics/crypto-lyrics.lrc']})
        })""")
        assert deleted_lyric.get('deleted', 0) == 1
        karaoke.evaluate('state.lyrics=[];state.activeLyric=-2')
        karaoke.locator('#account').click()
        karaoke.locator('.recording-item').get_by_role('button', name='试听', exact=True).click()
        karaoke.wait_for_function("() => state.lyrics.some(entry=>entry.text==='浏览器解密歌词') && document.getElementById('preview').currentTime > 0", timeout=30000)
        assert sum(item['url'].endswith('/media/crypto/session') for item in requests) == karaoke_session_baseline
        assert karaoke.evaluate('window.cspViolations') == []
        karaoke.locator('#account').click()
        with karaoke.expect_download(timeout=30000) as event:
            karaoke.locator('.recording-item').get_by_role('button', name='下载', exact=True).click()
        recording_path = output / 'encrypted-lyric-recording.webm'
        event.value.save_as(recording_path)
        assert event.value.failure() is None
        assert recording_footer(recording_path.read_bytes()) == opaque_footer
        karaoke.close()
        lyrics_page.close()
        player.close()

        # Tamper a test-only response, never managed disk bytes. Authentication
        # failure must hold the MSE track, with no plaintext fallthrough/retry loop.
        tampered_requests = []

        def tamper(route):
            original = route.fetch()
            payload = bytearray(original.body())
            if payload:
                payload[0] ^= 1
            tampered_requests.append(route.request.url)
            route.fulfill(response=original, body=bytes(payload))

        context.route(base + '/api/v1/media/stream**', tamper)
        broken = context.new_page()
        broken.goto(audio_url, wait_until='networkidle')
        broken.wait_for_function("""() => currentMediaList.length &&
            FrontierMediaCrypto.failureFor(currentMediaList[currentIndex]?.url) &&
            window.frontierCloudContinuousAudio.status().pipeline_error""", timeout=30000)
        count = len(tampered_requests)
        assert count > 0
        broken.wait_for_timeout(1500)
        assert len(tampered_requests) <= count + 1, 'authenticated decryption failure entered a network retry loop'
        assert broken.evaluate('window.cspViolations') == []
        browser.close()
        print('PASS: real Chromium explicit storage choices; bounded encrypted upload; OPFS cleanup; plaintext failure refused; authenticated Range/seek/continuous MP3; native MP4 seek; rename/delete authorization; session reuse; encrypted lyric/karaoke; opaque recorded lyric ticket/footer/history/download after source deletion; ZIP64/single downloads; tamper held')


if __name__ == '__main__':
    main()

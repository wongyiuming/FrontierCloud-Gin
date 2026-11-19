import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import vm from 'node:vm';

const nodes = new Map();
function node() {
    return {textContent: '', style: {}, value: '', checked: false, disabled: false, hidden: false,
        dataset: {}, classList: {toggle() {}}, addEventListener() {}, pause() {}, removeAttribute() {},
        add() {}, append() {}, replaceChildren() {}, click() {}, play: async () => {}};
}
const calls = [];
const lyrics = [{time: 0.1, text: 'private encrypted lyric snapshot'}];
const encrypted = {encryption: {file_id: 'new-recording-identity'}, ciphertext: 'opaqueCiphertext=='};
let encryptionFailure = false;
let sealed = false, loseTicket = false, loseUpload = false, invalidOwner = false, overQuota = false;
let preparedAudio, sealedCleanup = 0, audioEncryptions = 0;
const recordingID = 'a'.repeat(32), recordingOwner = 'b'.repeat(32), browserSession = 'c'.repeat(32);
const ownerOrigin = 'https://recording-owner.example';
const ownerUpload = `${ownerOrigin}/api/v1/node/recording-selected-upload`;
const capability = 'signed.fixture';
const signed = {receipt: {recording_id: recordingID}, signature: 'fixture-signed-receipt'};
const cipherBytes = new Uint8Array(113).fill(0x9a);
const context = {
    console, Blob, TextEncoder, TextDecoder, Uint8Array, DataView, URLSearchParams, setTimeout,
    URL: class extends URL {
        static createObjectURL() { return 'blob:test-preview'; }
        static revokeObjectURL() {}
    },
    location: {search: '?media=opaque-media-id', protocol: 'https:', origin: 'https://karaoke.example'},
    document: {cookie: '__Host-karaoke_csrf=test-csrf',
        getElementById(id) { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); },
        createElement: () => node()},
    navigator: {mediaDevices: {addEventListener() {}}},
    requestAnimationFrame() {}, addEventListener() {}, Option: class {},
    FrontierMediaCrypto: {async encryptRecordingLyrics(entries, prepare) {
        assert.deepEqual(JSON.parse(JSON.stringify(entries)), lyrics);
        if (encryptionFailure) throw new Error('authenticated encryption failed');
        const preparation = await prepare({session_id: 'existing-session', plaintext_size: 61});
        assert.equal(preparation.preparation_token, 'signed-preparation');
        return {encrypted_lyrics: encrypted, preparation_token: 'signed-preparation'};
    }, async withRecordingSession(id, send) {
        assert.equal(id, recordingID);
        return send(browserSession);
    }, async encryptRecordingAudio(blob, prepare) {
        audioEncryptions++;
        preparedAudio = new Uint8Array(await blob.arrayBuffer());
        const response = await prepare({session_id: browserSession, plaintext_size: blob.size});
        return {recording_id: response.recording_id, preparation_token: response.preparation_token,
            encryption: {file_id: 'd'.repeat(32)}, file: new Blob([cipherBytes]), async cleanup() { sealedCleanup++; }};
    }},
    async fetch(path, options = {}) {
        calls.push({path, options});
        if (path.endsWith('/status')) return Response.json({user: null});
        if (path.endsWith('/crypto/prepare')) return Response.json({preparation_token: 'signed-preparation'});
        if (path.endsWith('/crypto/audio-prepare')) return Response.json({recording_id: recordingID, preparation_token: 'audio-preparation'});
        if (sealed && (path.endsWith('/ticket') || path.endsWith('/audio-recover'))) {
            const recovering = path.endsWith('/audio-recover');
            if (!recovering && overQuota) return Response.json({detail: '录音超出个人配额'}, {status: 413});
            if (!recovering && loseTicket) throw new Error('recording ticket response lost');
            return Response.json({recording_id: recordingID, storage_member_id: invalidOwner ? 'e'.repeat(32) : recordingOwner,
                state: 'pending', transport: 'Direct', capability, url: ownerUpload + (recovering ? '/recover' : ''),
                ...(recovering ? {retry_upload_url: ownerUpload} : {})});
        }
        if (path === ownerUpload || path === `${ownerUpload}/recover`) {
            if (loseUpload && path === ownerUpload) throw new Error('recording upload response lost');
            if (loseUpload) return new Response('', {status: 404});
            return Response.json(signed);
        }
        if (sealed && path.endsWith('/audio-complete')) return Response.json({recording_id: recordingID, status: 'ready'});
        if (path.endsWith('/ticket')) return Response.json({recording_id: 'saved-id', filename: 'recording.webm', upload_url: '/upload-recording'});
        return Response.json({});
    }, Response,
};
context.window = context;
vm.createContext(context);
vm.runInContext(fs.readFileSync('static/js/upload-sha256.js', 'utf8'), context);
vm.runInContext(fs.readFileSync('static/js/karaoke.js', 'utf8'), context);
await new Promise(resolve => setTimeout(resolve, 0));
vm.runInContext(`state.context={title:'Recording'};state.sourceLyricsEncrypted=true;
    state.sourceLyrics=${JSON.stringify(lyrics)};state.lyrics=state.sourceLyrics;
    state.recordingSnapshot={encrypted:true,media:'opaque-media-id',title:' \\u0085 Recording \\u0085 ',lyrics:state.lyrics};
    state.chunks=[new Blob(['audio-only'],{type:'audio/webm'})];refreshAccount=async()=>{};`, context);
await vm.runInContext('finishRecording()', context);
const audio = vm.runInContext('state.recordedBlob', context);
assert.equal(await audio.text(), 'audio-only', 'guest recording has no plaintext lyric footer');
assert.match(nodes.get('previewHint').textContent, /本页面内存.*登录上传/);
vm.runInContext('state.account={id:"current-owner"}', context);
await context.uploadBlob(audio, 'Recording', 'opaque-media-id');
const prepare = calls.find(call => call.path.endsWith('/crypto/prepare'));
const ticket = calls.find(call => call.path.endsWith('/ticket'));
const upload = calls.find(call => call.path === '/upload-recording');
assert.deepEqual(JSON.parse(prepare.options.body), {media: 'opaque-media-id', session_id: 'existing-session', plaintext_size: 61});
const requested = JSON.parse(ticket.options.body);
assert.deepEqual(requested.lyrics, []);
assert.deepEqual(requested.encrypted_lyrics, encrypted);
assert.equal(requested.preparation_token, 'signed-preparation');
assert.equal(requested.title, 'Recording', 'ticket title uses the same Unicode whitespace normalization as its footer');
assert(!ticket.options.body.includes(lyrics[0].text));
const bytes = new Uint8Array(await upload.options.body.arrayBuffer());
const marker = new TextEncoder().encode('FRONTIERCLOUD-KARAOKE-V1');
const lengthOffset = bytes.length - marker.length - 8;
assert.equal(new TextDecoder().decode(bytes.subarray(lengthOffset + 8)), 'FRONTIERCLOUD-KARAOKE-V1');
const length = Number(new DataView(bytes.buffer, lengthOffset, 8).getBigUint64(0));
const footer = JSON.parse(new TextDecoder().decode(bytes.subarray(lengthOffset - length, lengthOffset)));
assert.deepEqual(footer.lyrics, []);
assert.equal(footer.title, requested.title);
assert.deepEqual(footer.encrypted_lyrics, requested.encrypted_lyrics, 'ticket and audio footer share exactly one opaque snapshot');
assert(!Object.hasOwn(footer, 'preparation_token'));
assert(!new TextDecoder().decode(bytes).includes(lyrics[0].text), 'no original lyric crosses the upload transport');
assert.equal(requested.size_bytes, upload.options.body.size);
encryptionFailure = true;
const beforeFailure = calls.length;
await assert.rejects(context.uploadBlob(audio, 'Recording', 'opaque-media-id'), /authenticated encryption failed/);
assert.equal(calls.length, beforeFailure, 'encryption failure makes no ticket or upload request');
vm.runInContext('state.sourceLyricsEncrypted=false;state.recordingSnapshot={encrypted:false,title:"Plain",lyrics:state.lyrics}', context);
const plain = await context.addRecordingMetadata(audio);
assert((await plain.text()).includes(lyrics[0].text), 'plain-source recordings retain their original footer behavior');

sealed = true;
vm.runInContext(`state.account={user_id:'fixture-karaoke-owner',username:'owner',used_bytes:0,quota_bytes:4096};
    state.accountStatus={recording_upload_protocol:'sealed-v1',storage_available:false,recording_destinations:[]};
    state.sourceLyricsEncrypted=true; state.recordingSnapshot={encrypted:true,media:'opaque-media-id',title:'Recorded track',lyrics:state.lyrics};
    renderAccount();`, context);
const closedStart = calls.length;
assert.equal(nodes.get('upload').disabled, true);
await assert.rejects(context.uploadBlob(audio, 'Recording', 'opaque-media-id'), /可用的录音存储节点/);
assert.equal(calls.length, closedStart, 'closed sealed gate never falls through to plaintext upload');
vm.runInContext(`state.accountStatus.storage_available=true; state.accountStatus.recording_destinations=[
    {member_id:'${recordingOwner}',address:'${ownerOrigin}',transport:'Direct'},
    {member_id:'${'e'.repeat(32)}',address:'https://other.example',transport:'Local'}];`, context);
await assert.rejects(context.uploadBlob(audio, 'Recording', 'opaque-media-id'), /可用的录音存储节点/);
nodes.get('bindStorage').value = 'e'.repeat(32);
await assert.rejects(context.uploadBlob(audio, 'Recording', 'opaque-media-id'), /可用的录音存储节点/);
assert.equal(audioEncryptions, 0);
nodes.get('bindStorage').value = recordingOwner;
loseTicket = true;
await assert.rejects(context.uploadBlob(audio, 'Recording', 'opaque-media-id'), /ticket response lost/);
assert.equal(audioEncryptions, 1);
assert.equal(sealedCleanup, 0, 'lost ticket response retains the ciphertext in the current page');
assert.equal(nodes.get('retryRecordingUpload').hidden, false);
const preparedFooterEnd = preparedAudio.length - marker.length - 8;
const preparedFooterSize = Number(new DataView(preparedAudio.buffer, preparedFooterEnd, 8).getBigUint64(0));
assert.deepEqual(JSON.parse(new TextDecoder().decode(preparedAudio.subarray(preparedFooterEnd - preparedFooterSize, preparedFooterEnd))),
    {version: 1, title: 'Recorded track', lyrics}, 'the browser encrypts the audio together with its ordered lyrics');
const attempted = calls.filter(call => call.path.endsWith('/ticket')).at(-1);
assert(!attempted.options.body.includes(lyrics[0].text));
assert.equal(JSON.parse(attempted.options.body).storage_member_id, recordingOwner);
assert.equal(JSON.parse(attempted.options.body).cipher_sha256, createHash('sha256').update(cipherBytes).digest('hex'));

loseTicket = false;
invalidOwner = true;
const mismatchStart = calls.length;
await nodes.get('retryRecordingUpload').onclick();
assert.equal(calls.length, mismatchStart + 1, 'mismatched member receives no bytes');
assert(calls.at(-1).path.endsWith(`/recordings/${recordingID}/audio-recover`));
assert.equal(calls.at(-1).options.body, undefined);
invalidOwner = false;
loseUpload = true;
await nodes.get('retryRecordingUpload').onclick();
const encryptedTransfer = calls.at(-1);
assert.equal(encryptedTransfer.path, ownerUpload);
assert.equal(encryptedTransfer.options.method, 'PUT');
assert.equal(encryptedTransfer.options.headers['Content-Type'], 'application/octet-stream');
assert.equal(encryptedTransfer.options.headers['X-Fc-Selected-Upload'], capability);
assert.equal(encryptedTransfer.options.headers['X-Fc-Recording-Session'], undefined);
assert.equal(encryptedTransfer.options.headers['X-Karaoke-CSRF'], undefined);
assert.equal(encryptedTransfer.options.credentials, 'omit');
assert.equal(encryptedTransfer.options.redirect, 'error');
assert.deepEqual(new Uint8Array(await encryptedTransfer.options.body.arrayBuffer()), cipherBytes);
assert.equal(sealedCleanup, 0);
loseUpload = false;
await nodes.get('retryRecordingUpload').onclick();
const [recoverControl, recoverOwner, complete] = calls.slice(-3);
assert(recoverControl.path.endsWith(`/recordings/${recordingID}/audio-recover`));
assert.equal(recoverControl.options.headers['X-Fc-Recording-Session'], browserSession);
assert.equal(recoverControl.options.headers['X-Karaoke-CSRF'], 'test-csrf');
assert.equal(recoverOwner.path, `${ownerUpload}/recover`);
assert.equal(recoverOwner.options.method, 'POST');
assert.equal(recoverOwner.options.headers['X-Fc-Selected-Upload'], capability);
assert.equal(recoverOwner.options.credentials, 'omit');
assert.equal(recoverOwner.options.body, undefined, 'recovery confirms the original upload without resending bytes');
assert(complete.path.endsWith(`/recordings/${recordingID}/audio-complete`));
assert.deepEqual(JSON.parse(complete.options.body), signed);
assert.equal(sealedCleanup, 1);
assert.equal(audioEncryptions, 1);
assert.equal(vm.runInContext('state.recordingUpload', context), null);
overQuota = true;
await assert.rejects(context.uploadBlob(audio, 'Recording', 'opaque-media-id'), /超出个人配额/);
assert.equal(vm.runInContext('state.recordingUpload', context), null, 'definite quota refusal must not lock the next attempt');
assert.equal(nodes.get('retryRecordingUpload').hidden, true);
assert.equal(nodes.get('upload').disabled, false);
assert.equal(sealedCleanup, 2);
overQuota = false;
vm.runInContext(`state.recordingSnapshot={encrypted:false,media:'opaque-media-id',title:'No lyrics',lyrics:[]};
    state.sourceLyricsEncrypted=true;`, context);
const audioWithoutLyrics = await context.addRecordingMetadata(audio);
await context.uploadBlob(audioWithoutLyrics, 'No lyrics', 'opaque-media-id');
assert.deepEqual(preparedAudio, new Uint8Array(await audioWithoutLyrics.arrayBuffer()),
    'late encrypted lyrics do not alter or block a sealed upload captured without lyrics');
// Execute the real startup with independently deferred media and account replies.
const karaokeSource = fs.readFileSync('static/js/karaoke.js', 'utf8');
const karaokeTemplate = fs.readFileSync('static/media/karaoke.html', 'utf8');
assert.match(karaokeTemplate, /<button id="record"[^>]* disabled>/);
for (const first of ['media', 'account', 'media-failure', 'account-failure', 'account-late-failure']) {
    const controls = new Map();
    const control = id => {
        if (!controls.has(id)) controls.set(id, {...node(), disabled: id === 'record'});
        return controls.get(id);
    };
    let releaseMedia, releaseAccount, microphoneCalls = 0;
    const mediaReply = new Promise(resolve => { releaseMedia = resolve; });
    const accountReply = new Promise(resolve => { releaseAccount = resolve; });
    const fixture = {console, Blob, TextEncoder, TextDecoder, Uint8Array, DataView, URLSearchParams, setTimeout, Response,
        URL: {createObjectURL() {}, revokeObjectURL() {}}, location: {search: '?media=opaque-id', protocol: 'https:'},
        document: {cookie: '', getElementById: control, createElement: () => node()},
        navigator: {mediaDevices: {addEventListener() {}, getUserMedia() { microphoneCalls++; throw new Error('unexpected microphone'); }}},
        AudioContext: class {}, MediaRecorder: class {}, requestAnimationFrame() {}, addEventListener() {}, Option: class {},
        fetch: path => path.startsWith('/api/v1/karaoke/context?') ? mediaReply : accountReply,
    };
    fixture.window = fixture;
    vm.createContext(fixture);
    vm.runInContext(karaokeSource, fixture);
    const flush = async () => { for (let i = 0; i < 8; i++) await new Promise(setImmediate); };
    assert.equal(vm.runInContext('state.ready', fixture), false);
    await vm.runInContext('startRecording()', fixture);
    assert.equal(microphoneCalls, 0, 'pre-ready calls cannot open the microphone');
    const media = () => releaseMedia(Response.json({title: 'Ready track', type: 'audio', stream_url: '/stream', has_lyrics: false}));
    const account = () => releaseAccount(Response.json({user: null}));
    if (first === 'media' || first === 'account-late-failure') {
        media(); await flush();
        assert.equal(vm.runInContext('state.ready', fixture), true, 'media readiness does not wait for an optional account response');
        assert.equal(control('record').disabled, false);
        if (first === 'media') account();
        else releaseAccount(new Response('', {status: 502}));
    }
    if (first === 'account') { account(); await flush(); assert.equal(control('record').disabled, true); media(); }
    if (first === 'media-failure') {
        releaseMedia(new Response('', {status: 403})); await flush();
        assert.equal(vm.runInContext('state.ready', fixture), false);
        account();
    }
    if (first === 'account-failure') {
        releaseAccount(new Response('', {status: 502})); await flush();
        assert.equal(control('record').disabled, true, 'account failure cannot grant media readiness');
        media();
    }
    await flush();
    const succeeded = first !== 'media-failure';
    assert.equal(vm.runInContext('state.ready', fixture), succeeded);
    assert.equal(control('record').disabled, !succeeded, 'only mandatory media initialization grants recording readiness');
    if (first.includes('account') && first.includes('failure')) {
        assert.equal(vm.runInContext('state.account', fixture), null);
        assert.equal(vm.runInContext('state.accountStatus', fixture), null);
        assert.equal(control('accountName').textContent, '游客');
        assert.equal(control('upload').disabled, true, 'failed account lookup cannot grant an upload capability');
        assert.match(control('authMessage').textContent, /HTTP 502/);
        assert(!control('status').textContent.includes('初始化失败'), 'optional account error cannot replace media readiness');
    }
    if (!succeeded) {
        await vm.runInContext('startRecording()', fixture);
        assert.equal(microphoneCalls, 0, 'a failed startup remains fenced');
    }
}
for (const scenario of ['plain', 'encrypted', 'http-error', 'decrypt-error', 'late']) {
    const encryptedLyric = scenario !== 'plain';
    const controls = new Map(), calls = [];
    let lyricNotice, recordClick, rejectMicrophone, releaseLyrics;
    const lyricReply = new Promise(resolve => { releaseLyrics = resolve; });
    const control = id => {
        if (!controls.has(id)) controls.set(id, {...node(), disabled: id === 'record'});
        return controls.get(id);
    };
    control('lyrics').append = line => { lyricNotice = line.textContent; };
    control('record').addEventListener = (name, listener) => { if (name === 'click') recordClick = listener; };
    const fixture = {console, Blob, TextEncoder, TextDecoder, Uint8Array, DataView, URLSearchParams, setTimeout, Response,
        URL: {createObjectURL() {}, revokeObjectURL() {}}, location: {search: '?media=opaque-id', protocol: 'https:'},
        document: {cookie: '', getElementById: control, createElement: () => node()},
        navigator: {mediaDevices: {addEventListener() {}, getSupportedConstraints() { return {}; },
            getUserMedia() { return new Promise((_, reject) => { rejectMicrophone = reject; }); }}},
        AudioContext: class {}, MediaRecorder: class {}, requestAnimationFrame() {}, addEventListener() {}, Option: class {},
        fetch: async path => path.startsWith('/api/v1/karaoke/context?')
            ? Response.json({title: 'Native track', type: 'audio', file_path: 'music/test.mp3', native_source: true, has_lyrics: true, lyrics_url: '/api/v1/karaoke/lyrics?media=opaque-id'})
            : path.startsWith('/api/v1/karaoke/lyrics?')
                ? lyricReply
                : Response.json({user: null}),
        FrontierMediaCrypto: {
            async prepareCatalog(entries) { calls.push('catalog'); entries[0].url = '/__fc_media/native'; },
            async lyricTextFor(data) {
                calls.push(data.encrypted ? 'encrypted lyric' : 'plain lyric');
                if (scenario === 'decrypt-error') throw new Error('lyric authentication failed');
                return '[00:01.00] lyric';
            },
            parseLyrics() { return [{time: 1, text: 'lyric'}]; },
        },
    };
    fixture.window = fixture;
    vm.createContext(fixture);
    vm.runInContext(karaokeSource, fixture);
    const flush = async () => { for (let i = 0; i < 8; i++) await new Promise(setImmediate); };
    await flush();
    assert.deepEqual(calls, ['catalog']);
    assert.equal(control('media').src, '/__fc_media/native');
    assert.equal(vm.runInContext('state.ready', fixture), true);
    assert.equal(control('record').disabled, false, 'an unresolved lyric request cannot disable Start');
    assert.match(lyricNotice, /正在载入歌词/);

    let starting;
    if (scenario === 'late') {
        vm.runInContext('prepareAudioGraph = () => {}', fixture);
        starting = recordClick();
        assert.equal(typeof rejectMicrophone, 'function', 'Start reached the real microphone request');
        assert.match(lyricNotice, /本次录音暂无歌词/);
    }
    releaseLyrics(scenario === 'http-error' ? new Response('', {status: 503})
        : Response.json({file_path: 'lyrics/test.lrc', native_source: true, native_lyric: !encryptedLyric, encrypted: encryptedLyric}));
    await flush();
    assert.deepEqual(calls, scenario === 'http-error' ? ['catalog'] : ['catalog', encryptedLyric ? 'encrypted lyric' : 'plain lyric']);
    if (scenario.endsWith('error')) {
        assert.equal(control('record').disabled, false);
        assert.match(lyricNotice, /歌词暂不可用/);
        assert.doesNotMatch(control('status').textContent, /初始化失败/);
        assert.equal(vm.runInContext('state.sourceLyricsEncrypted', fixture), false);
    } else {
        assert.equal(vm.runInContext('state.sourceLyricsEncrypted', fixture), encryptedLyric);
        if (scenario === 'late') {
            assert.equal(vm.runInContext('state.sourceLyrics.length', fixture), 1);
            assert.equal(vm.runInContext('state.lyrics.length', fixture), 0);
            assert.equal(vm.runInContext('state.recordingSnapshot.lyrics.length', fixture), 0);
            assert.equal(vm.runInContext('state.recordingSnapshot.encrypted', fixture), false);
            rejectMicrophone(new Error('test microphone refusal'));
            await starting;
        }
        assert.equal(lyricNotice, 'lyric');
    }
}
console.log('karaoke-encrypted-snapshot-smoke-ok: optional account and lyrics, immutable encrypted recording snapshot');

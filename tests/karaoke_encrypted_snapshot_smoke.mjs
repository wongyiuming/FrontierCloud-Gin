import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const nodes = new Map();
function node() {
    return {textContent: '', style: {}, value: '', checked: false, disabled: false, hidden: false,
        dataset: {}, classList: {toggle() {}}, addEventListener() {}, pause() {}, removeAttribute() {},
        append() {}, replaceChildren() {}, click() {}, play: async () => {}};
}
const calls = [];
const lyrics = [{time: 0.1, text: 'private encrypted lyric snapshot'}];
const encrypted = {encryption: {file_id: 'new-recording-identity'}, ciphertext: 'opaqueCiphertext=='};
let encryptionFailure = false;
const context = {
    console, Blob, TextEncoder, TextDecoder, Uint8Array, DataView, URLSearchParams, setTimeout,
    URL: {createObjectURL: () => 'blob:test-preview', revokeObjectURL() {}},
    location: {search: '?media=opaque-media-id', protocol: 'https:'},
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
    }},
    async fetch(path, options = {}) {
        calls.push({path, options});
        if (path.endsWith('/status')) return Response.json({user: null});
        if (path.endsWith('/crypto/prepare')) return Response.json({preparation_token: 'signed-preparation'});
        if (path.endsWith('/ticket')) return Response.json({recording_id: 'saved-id', filename: 'recording.webm', upload_url: '/upload-recording'});
        return Response.json({});
    }, Response,
};
context.window = context;
vm.createContext(context);
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
console.log('karaoke-encrypted-snapshot-smoke-ok: opaque snapshot and independent optional account lifecycle');

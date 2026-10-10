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
console.log('karaoke-encrypted-snapshot-smoke-ok');

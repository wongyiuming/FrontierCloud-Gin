import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {createHash, webcrypto} from 'node:crypto';
import {MessageChannel} from 'node:worker_threads';

const directory = process.env.FRONTIER_CRYPTO_JS_DIR
    || (process.env.FC_CRYPTO_COMPILED === '1' ? 'static/js/compiled' : 'static/js');
const source = name => fs.readFileSync(`${directory}/${name}`, 'utf8');
let now = Date.now();
let serverNow = now - 7 * 60 * 60 * 1000;
let elapsed = 0;
const performance = {timeOrigin: now, now: () => elapsed};
function advance(milliseconds) {
    elapsed += milliseconds;
    serverNow += milliseconds;
    now += milliseconds;
}
class Clock extends Date { static now() { return now; } }
const calls = [];
const records = new Map();
const pathRecords = new Map();
const nativePlans = new Map();
const sessions = new Map();
const temporary = new Map();
const plainReads = [];
const cipherRequests = [];
const controllerMessages = [];
const downloadAnchors = [];
const workerListeners = new Map();
const controllerChanges = new Set();
let workerUpdate = async () => {};
let pageMessage;
let nextId = 1;
let nextSession = 1;
let keyDelay = 0;
let mismatchedEnvelope = false;
let sessionLifetime = 899;
let handshakeDelay = 0;
let sessionStatus = 0;
let keyStatus = 0;
let sourceUnavailable = false;
let cipherStatus = 0;
let worker;
let common;

const opfs = {
    async getDirectoryHandle() { return this; },
    async *entries() { for (const entry of temporary) yield entry; },
    async removeEntry(name) { temporary.delete(name); },
    async getFileHandle(name) {
        if (!temporary.has(name)) temporary.set(name, []);
        return {
            async createWritable() {
                return {
                    async write(value) { temporary.get(name).push(new Uint8Array(value).slice()); },
                    async close() {}, async abort() { temporary.delete(name); },
                };
            },
            async getFile() { return new Blob(temporary.get(name)); },
        };
    },
};
const client = {id: 'browser-tab', postMessage(data, ports = []) {
    pageMessage({data, source: controller, ports});
}};
const controller = {postMessage(data, ports = []) {
    controllerMessages.push(data.type);
    for (const listener of workerListeners.get('message') || []) listener({data, ports, source: client});
}};
async function workerFetch(input, init = {}, clientID = client.id) {
    const request = new Request(new URL(String(input), 'https://cloud.example'), init);
    let response;
    for (const listener of workerListeners.get('fetch') || []) {
        listener({request, clientId: clientID, respondWith(value) { response = Promise.resolve(value); }});
    }
    assert(response, 'virtual encrypted bytes must be handled by the service worker');
    return response;
}
async function envelope(active, record) {
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const wrapped = await webcrypto.subtle.encrypt({name: 'AES-GCM', iv,
        additionalData: new TextEncoder().encode(`frontiercloud:key-envelope:v1:${active.id}:${record.meta.file_id}`)},
    active.wrapKey, record.raw);
    return {iv: common.encode(iv), wrapped_key: common.encode(wrapped), expires_at: active.expires + (mismatchedEnvelope ? 1 : 0)};
}
async function backendFetch(input, init = {}) {
    const url = new URL(String(input), 'https://cloud.example');
    if (url.pathname.startsWith('/__fc_')) return workerFetch(url, init);
    if (!url.pathname.includes('/crypto/')) {
        const bytes = new TextEncoder().encode('plain legacy lyric');
        return new Response(bytes, {headers: {'Content-Length': String(bytes.length)}});
    }
    const body = init.body ? JSON.parse(init.body) : {};
    calls.push({url: url.pathname, body});
    if (url.pathname.endsWith('/session')) {
        if (sessionStatus) return Response.json({detail: 'temporary key session limit'}, {status: sessionStatus});
        const pair = await webcrypto.subtle.generateKey({name: 'ECDH', namedCurve: 'P-256'}, false, ['deriveBits']);
        const clientKey = await webcrypto.subtle.importKey('raw', common.decode(body.public_key),
            {name: 'ECDH', namedCurve: 'P-256'}, false, []);
        const shared = await webcrypto.subtle.deriveBits({name: 'ECDH', public: clientKey}, pair.privateKey, 256);
        const hkdf = await webcrypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
        const salt = new Uint8Array(32).fill(71);
        const id = (nextSession++).toString(16).padStart(32, '0');
        const wrapKey = await webcrypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256', salt,
            info: new TextEncoder().encode('frontiercloud:browser-wrap:v1:' + id)},
        hkdf, {name: 'AES-GCM', length: 256}, false, ['encrypt']);
        const expires = Math.floor(serverNow / 1000) + 900;
        sessions.set(id, {id, wrapKey, expires});
        advance(handshakeDelay);
        return Response.json({session_id: id, expires_at: expires, expires_in: sessionLifetime, salt: common.encode(salt),
            public_key: common.encode(await webcrypto.subtle.exportKey('raw', pair.publicKey))});
    }
    const active = sessions.get(body.session_id);
    if (!active || active.expires * 1000 <= serverNow) return Response.json({detail: 'expired session'}, {status: 403});
    if (url.pathname.endsWith('/native/source')) {
        const plan = nativePlans.get(body.file_path);
        if (!plan || body.resource_id !== plan.resource_id || body.object_id !== plan.object_id) return Response.json({detail: 'missing'}, {status: 404});
        return Response.json(plan);
    }
    if (url.pathname.endsWith('/prepare')) {
        const size = body.plaintext_size;
        const meta = {version: 1, algorithm: 'AES-256-GCM', file_id: (nextId++).toString(16).padStart(32, '0'),
            nonce_prefix: common.encode(webcrypto.getRandomValues(new Uint8Array(8))), plaintext_size: size,
            chunk_size: 1048576, ciphertext_size: size + 16 * Math.ceil(size / 1048576)};
        const record = {meta, raw: webcrypto.getRandomValues(new Uint8Array(32))};
        records.set(meta.file_id, record);
        return Response.json({encryption: meta, key_envelope: await envelope(active, record), preparation_token: 'signed-descriptor'});
    }
    if (url.pathname.endsWith('/key')) {
        if (keyStatus) return Response.json({detail: 'current object access denied'}, {status: keyStatus});
        advance(keyDelay);
        const record = pathRecords.get(body.file_path);
        if (!record) return Response.json({detail: 'missing'}, {status: 404});
        if (record.adminDownload && (body.resource_id !== record.adminDownload.resource_id || body.download_snapshot !== record.adminDownload.download_snapshot))
            return Response.json({detail: 'stale download'}, {status: 409});
        if (record.opaqueLyric && (body.resource_id !== record.opaqueLyric.resource_id || body.object_id !== record.opaqueLyric.object_id || body.track_resource_id !== record.opaqueLyric.track_resource_id)) return Response.json({detail: 'missing'}, {status: 404});
        if (sourceUnavailable) return Response.json({encryption: record.meta, key_envelope: await envelope(active, record),
            source_error: 'native_source_unavailable', content_type: 'audio/mpeg', filename: body.file_path.split('/').pop()});
        return Response.json({encryption: record.meta, key_envelope: await envelope(active, record),
            ...(record.opaqueLyric ? {transport: 'Native', source_identity_version: 1, resource_id: record.opaqueLyric.resource_id,
                object_id: record.opaqueLyric.object_id, source_object_id: record.opaqueLyric.alias, source_owner_id: record.opaqueLyric.owner ?? 'a'.repeat(32), source_revision: record.opaqueLyric.revision ?? 'b'.repeat(64)} : {}),
            ...(record.opaqueMedia ? {transport: 'Native', source_identity_version: 1, resource_id: record.opaqueMedia.resource_id, object_id: record.opaqueMedia.object_id,
                source_object_id: record.opaqueMedia.alias, source_owner_id: record.opaqueMedia.owner ?? 'a'.repeat(32), source_revision: record.opaqueMedia.revision ?? 'b'.repeat(64)} : {}),
            ...(record.adminDownload || {}),
            source_url: record.source, ...(record.sourceHeaders ? {source_headers: record.sourceHeaders} : {}),
            ...(record.sourceHeaders ? {source_expires_in: 120, source_expires_at: 9999999999} : {}),
            ...(record.sourceTransport ? {source_transport: record.sourceTransport, source_origin: record.sourceOrigin} : {}),
            content_type: 'audio/mpeg', filename: body.file_path.split('/').pop(), ...(record.keyResponseOverride || {})});
    }
    throw new Error('unexpected crypto API: ' + url);
}

const page = {
    crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, URL, URLSearchParams,
    Blob, Headers, Request, Response, ReadableStream, MessageChannel, Date: Clock, performance,
    atob, btoa, setTimeout, clearTimeout, console, isSecureContext: true,
    location: new URL('https://cloud.example/api/v1/media/admin'),
    document: {getElementById: id => id === 'uploadFiles' ? {} : null,
        createElement() { return {click() { downloadAnchors.push(this); }}; }},
    navigator: {storage: {getDirectory: async () => opfs}, serviceWorker: {controller,
        register: async () => ({update: () => workerUpdate()}), ready: Promise.resolve({}),
        addEventListener(type, listener) {
            if (type === 'message') pageMessage = listener;
            if (type === 'controllerchange') controllerChanges.add(listener);
        },
        removeEventListener(type, listener) {
            if (type === 'controllerchange') controllerChanges.delete(listener);
        },
    }},
    requestHeaders: () => ({'Content-Type': 'application/json', 'X-CSRF-Token': 'test'}),
    addEventListener() {}, dispatchEvent() {}, CustomEvent: class {}, fetch: backendFetch,
};
page.window = page;
vm.createContext(page);
vm.runInContext(source('media-crypto-common.js'), page);
common = page.FrontierCryptoCommon;
vm.runInContext(source('media-crypto.js'), page);
await new Promise(resolve => setTimeout(resolve, 0));

function inputFile(bytes, name) {
    return {name, size: bytes.length, slice(start, end) {
        return {async arrayBuffer() {
            plainReads.push(end - start);
            return bytes.slice(start, end).buffer;
        }};
    }, async arrayBuffer() { throw new Error('whole-file plaintext buffering is forbidden'); }};
}
async function prepare(bytes, path, sourceUrl) {
    const result = await page.FrontierMediaCrypto.encryptFile(inputFile(bytes, path.split('/').pop()));
    const record = records.get(result.encryption.file_id);
    record.ciphertext = new Uint8Array(await result.file.arrayBuffer());
    record.source = sourceUrl;
    pathRecords.set(path, record);
    assert.equal(result.file.size, result.encryption.ciphertext_size);
    await result.cleanup();
    return record;
}

const recordingAudio = new Uint8Array(common.CHUNK_SIZE + 7).fill(91);
const recordingID = '4'.repeat(32);
const recordingReads = plainReads.length;
const encryptedRecording = await page.FrontierMediaCrypto.encryptRecordingAudio(inputFile(recordingAudio, 'audio.webm'),
    async fields => {
        assert.equal(fields.plaintext_size, recordingAudio.byteLength);
        const response = await backendFetch('/fixture-recordings/crypto/prepare', {body: JSON.stringify(fields)});
        return {...await response.json(), recording_id: recordingID};
    });
assert.deepEqual(plainReads.slice(recordingReads), [common.CHUNK_SIZE, 7]);
assert.equal(encryptedRecording.recording_id, recordingID);
assert.equal(encryptedRecording.file.size, recordingAudio.byteLength + 2 * common.TAG_SIZE);
assert.equal(encryptedRecording.preparation_token, 'signed-descriptor');
const recordingKey = await webcrypto.subtle.importKey('raw', records.get(encryptedRecording.encryption.file_id).raw,
    'AES-GCM', false, ['decrypt']);
for (const index of [0, 1]) {
    const range = common.cipherRange(encryptedRecording.encryption, index);
    const cipherChunk = await encryptedRecording.file.slice(range.start, range.end + 1).arrayBuffer();
    const plaintext = await webcrypto.subtle.decrypt(common.parameters(encryptedRecording.encryption, index), recordingKey, cipherChunk);
    assert.deepEqual(new Uint8Array(plaintext), recordingAudio.subarray(index * common.CHUNK_SIZE, (index + 1) * common.CHUNK_SIZE));
}
await encryptedRecording.cleanup();
await assert.rejects(page.FrontierMediaCrypto.encryptRecordingAudio(inputFile(recordingAudio, 'audio.webm'),
    async () => ({recording_id: 'missing', preparation_token: 'signed-descriptor'})), /录音加密准备无效/);

const validationCalls = calls.length;
for (const name of ['bad.mp3', 'bad.flac', 'bad.wav', 'bad.m4a', 'bad.mp4', 'bad.webm', 'bad.mkv', 'bad.txt']) {
    await assert.rejects(page.FrontierMediaCrypto.encryptUploadFile(
        inputFile(new TextEncoder().encode('not media'), name)), /媒体格式/);
}
for (const invalid of [new TextEncoder().encode('not lyrics'), new Uint8Array([0xff, 0xfe]),
    new TextEncoder().encode('[00:01]bad\0lyric'), new Uint8Array(2 * 1024 * 1024 + 1)]) {
    await assert.rejects(page.FrontierMediaCrypto.encryptUploadFile(inputFile(invalid, 'bad.lrc')));
}
assert.equal(calls.length, validationCalls, 'invalid plaintext creates no handshake/preparation requests');
assert.equal(temporary.size, 0, 'invalid plaintext creates no ciphertext temporary object');
for (const [name, header] of [
    ['valid.mp3', new TextEncoder().encode('ID3')],
    ['valid.flac', new TextEncoder().encode('fLaC')],
    ['valid.wav', new TextEncoder().encode('RIFF0000WAVE')],
    ['valid.m4a', new TextEncoder().encode('0000ftyp0000')],
    ['valid.mp4', new TextEncoder().encode('0000ftyp0000')],
    ['valid.webm', new Uint8Array([0x1a, 0x45, 0xdf, 0xa3])],
    ['valid.mkv', new Uint8Array([0x1a, 0x45, 0xdf, 0xa3])],
    ['valid.lrc', new TextEncoder().encode('[00:01.00]valid lyric')],
]) {
    const validUpload = await page.FrontierMediaCrypto.encryptUploadFile(inputFile(header, name));
    assert.equal(validUpload.encryption.plaintext_size, header.length);
    await validUpload.cleanup();
}
const bytes = Uint8Array.from({length: 2 * 1048576 + 97}, (_, index) => index % 251);
const retained = await page.FrontierMediaCrypto.encryptFile(inputFile(new Uint8Array([1, 2, 3]), 'retained.mp3'));
retained.retain();
assert.equal((await page.FrontierMediaCrypto.readRetainedUpload(retained.retainedName)).size, retained.file.size);
assert.equal(retained.key, undefined, 'retained ciphertext descriptor contains no file key');
await assert.rejects(page.FrontierMediaCrypto.readRetainedUpload('../unrelated'), /恢复记录/);
await page.FrontierMediaCrypto.forgetRetainedUpload(retained.retainedName);
assert.equal(temporary.size, 0, 'explicit cleanup removes only the retained ciphertext file');
const first = await prepare(bytes, 'music/a.mp3', 'https://direct.example/cipher/a');
const secondBytes = new TextEncoder().encode('second encrypted resource');
const second = await prepare(secondBytes, 'music/b.mp3', 'https://cloud.example/relay/b');
assert.equal(calls.filter(call => call.url.endsWith('/session')).length, 1, 'multiple upload files reuse one P-256 handshake');
assert.equal(temporary.size, 0, 'ciphertext temporary files are removed after upload');
assert(plainReads.every(length => length <= 1048576), 'plaintext reads remain within one encryption chunk');
assert.notDeepEqual(first.ciphertext.subarray(0, 1024), bytes.subarray(0, 1024));
const fileKey = await webcrypto.subtle.importKey('raw', first.raw, 'AES-GCM', false, ['decrypt']);
const firstRange = common.cipherRange(first.meta, 0);
assert.deepEqual(new Uint8Array(await webcrypto.subtle.decrypt(common.parameters(first.meta, 0), fileKey,
    first.ciphertext.subarray(firstRange.start, firstRange.end + 1))), bytes.subarray(0, 1048576));
await assert.rejects(webcrypto.subtle.decrypt(common.parameters(first.meta, 1), fileKey,
    first.ciphertext.subarray(firstRange.start, firstRange.end + 1)), 'moving chunks must fail authentication');
await assert.rejects(webcrypto.subtle.decrypt(common.parameters({...first.meta, plaintext_size: first.meta.plaintext_size - 1}, 0),
    fileKey, first.ciphertext.subarray(firstRange.start, firstRange.end + 1)), 'length is authenticated');
assert.equal(fileKey.extractable, false);
assert.throws(() => common.validate({...first.meta, ciphertext_size: bytes.length}));
assert.throws(() => common.validate({...first.meta, plaintext_size: 0, ciphertext_size: 0}));
assert.equal(common.range('bytes=0-1,3-4', bytes.length), null);
assert.equal(common.range('bytes=99999999999-', bytes.length), null);
assert.deepEqual(JSON.parse(JSON.stringify(common.parseLyrics('[offset:100]\n[00:01.20][00:02.30]词\n[ar:Artist]'))),
    [{time: 1.3, text: '词'}, {time: 2.4, text: '词'}]);
// These expectations are shared with the server's ParseLRC contract. The
// compiled and source modules must preserve exactly the same valid grammar.
const lyricVectors = JSON.parse(fs.readFileSync('protocol/lrc_parsing_vectors.json', 'utf8'));
for (const vector of lyricVectors) {
    if (vector.error) assert.throws(() => common.parseLyrics(vector.input),
        error => error.message === vector.error, vector.name);
    else assert.deepEqual(JSON.parse(JSON.stringify(common.parseLyrics(vector.input))), vector.entries, vector.name);
}
assert.equal(common.parseLyrics('[00:01]' + '😀'.repeat(4000))[0].text, '😀'.repeat(4000),
    'the 4000-character boundary counts Unicode code points, as Go counts UTF-8 runes');
assert.throws(() => common.parseLyrics('[00:01]' + '乐'.repeat(4001)), /4000/);
assert.throws(() => common.parseLyrics('[00:01]' + '😀'.repeat(4001)), /4000/);
assert.throws(() => common.parseLyrics('[00:01]bad\ud800'), /UTF-8/);
const maximumLyrics = Array.from({length: 10000}, (_, index) => '[00:01]' + index).join('\n');
assert.equal(common.parseLyrics(maximumLyrics).length, 10000);
assert.throws(() => common.parseLyrics(maximumLyrics + '\n[00:01]extra'), /10000/);
assert.equal(common.parseLyrics(Array.from({length: 10001}, () => '[00:01]duplicate').join('\n')).length, 1,
    'duplicate entries are removed before the 10000-entry limit');

// A recorded encrypted-source lyric is an independent opaque object. Its
// plaintext never enters the preparation request or the stored footer shape.
const snapshotLyrics = Array.from({length: 1200}, (_, index) => ({time: index / 10,
    text: 'private recorded lyric marker ' + 'x'.repeat(900)}));
const snapshotRequests = [];
const prepareSnapshot = async fields => {
    snapshotRequests.push(fields);
    return (await backendFetch('/api/v1/karaoke/account/recordings/crypto/prepare', {
        method: 'POST', body: JSON.stringify(fields),
    })).json();
};
const snapshot = await page.FrontierMediaCrypto.encryptRecordingLyrics(snapshotLyrics, prepareSnapshot);
assert(snapshot.encrypted_lyrics.encryption.plaintext_size > 1048576, 'snapshot exercises both authenticated chunks');
assert.deepEqual(Object.keys(snapshotRequests[0]).sort(), ['plaintext_size', 'session_id']);
assert(!JSON.stringify(snapshot).includes('private recorded lyric marker'), 'ticket/footer contain no original lyric text');
assert.deepEqual(Object.keys(snapshot.encrypted_lyrics).sort(), ['ciphertext', 'encryption']);
assert.equal(snapshot.preparation_token, 'signed-descriptor');
const snapshotRecord = records.get(snapshot.encrypted_lyrics.encryption.file_id);
let returnedSnapshot = snapshot.encrypted_lyrics;
const authorizeSnapshot = async fields => {
    assert.deepEqual(Object.keys(fields), ['session_id']);
    return {encrypted_lyrics: returnedSnapshot, key_envelope: await envelope(sessions.get(fields.session_id), snapshotRecord)};
};
assert.deepEqual(JSON.parse(JSON.stringify(await page.FrontierMediaCrypto.decryptRecordingLyrics(authorizeSnapshot))), snapshotLyrics);
const anotherSnapshot = await page.FrontierMediaCrypto.encryptRecordingLyrics(snapshotLyrics, prepareSnapshot);
assert.notEqual(anotherSnapshot.encrypted_lyrics.encryption.file_id, snapshot.encrypted_lyrics.encryption.file_id,
    'each saved recording gets a new independent immutable key/nonce identity');
assert.equal(calls.filter(call => call.url.endsWith('/session')).length, 1,
    'recordings and media retain the existing multi-file P-256 session');
const snapshotCipher = common.decode(snapshot.encrypted_lyrics.ciphertext);
snapshotCipher[1048592] ^= 1;
returnedSnapshot = {...snapshot.encrypted_lyrics, ciphertext: common.encode(snapshotCipher)};
await assert.rejects(page.FrontierMediaCrypto.decryptRecordingLyrics(authorizeSnapshot), 'second-chunk tag failure returns no partial lyric snapshot');
returnedSnapshot = {...snapshot.encrypted_lyrics, ciphertext: snapshot.encrypted_lyrics.ciphertext + '\n'};
await assert.rejects(page.FrontierMediaCrypto.decryptRecordingLyrics(authorizeSnapshot), /描述无效/, 'snapshot requires canonical strict base64');
returnedSnapshot = snapshot.encrypted_lyrics;
await assert.rejects(page.FrontierMediaCrypto.decryptRecordingLyrics(async () => {
    const error = new Error('not current owner'); error.status = 403; throw error;
}), /not current owner/, 'owner authorization errors never fall through to plaintext lyrics');
const snapshotsBeforeOversize = snapshotRequests.length;
await assert.rejects(page.FrontierMediaCrypto.encryptRecordingLyrics(
    Array.from({length: 1500}, (_, index) => ({time: index, text: 'x'.repeat(1000)})), prepareSnapshot), /1400 KiB/);
assert.equal(snapshotRequests.length, snapshotsBeforeOversize, 'oversize plaintext never leaves the browser even in preparation');
await assert.rejects(page.FrontierMediaCrypto.encryptRecordingLyrics([{time: Infinity, text: 'bad'}], prepareSnapshot));
await assert.rejects(page.FrontierMediaCrypto.encryptRecordingLyrics([{time: 0, text: 'x'.repeat(4097)}], prepareSnapshot));

const cryptoKeyConstructor = fileKey.constructor;
function createWorker() {
    workerListeners.clear();
    worker = {
        crypto: webcrypto, CryptoKey: cryptoKeyConstructor, TextEncoder, TextDecoder, Uint8Array, Uint32Array,
        ArrayBuffer, DataView, URL, URLSearchParams, Headers, Request, Response, ReadableStream, AbortController,
        MessageChannel, Date: Clock,
        performance: {timeOrigin: performance.timeOrigin - 5000, now: () => elapsed + 5000},
        atob, btoa, setTimeout, clearTimeout,
        location: new URL('https://cloud.example/media-crypto-sw.js'),
        clients: {get: async id => id === client.id ? client : null, claim: async () => {}},
        skipWaiting: async () => {},
        addEventListener(type, listener) {
            if (!workerListeners.has(type)) workerListeners.set(type, []);
            workerListeners.get(type).push(listener);
        },
        importScripts() { vm.runInContext(source('media-crypto-common.js'), worker); },
        async fetch(input, init = {}) {
            const record = [...records.values()].reverse().find(value => value.source === String(input));
            if (!record) return backendFetch(input, init);
            const headers = new Headers(init.headers);
            const header = headers.get('Range');
            cipherRequests.push({url: String(input), range: header, capability: headers.get('X-Media-Capability'),
                relay: headers.get('X-Media-Relay'), credentials: init.credentials, redirect: init.redirect});
            if (record.recordingRevision) {
                assert.equal(init.redirect, 'error');
                if (record.recordingSource) {
                    assert.equal(init.credentials, 'omit');
                    assert.equal(init.mode, 'cors');
                    assert.equal(headers.get('X-Media-Capability'), record.recordingSource.capability);
                    assert.equal(headers.get('X-Fc-Recording-Session'), null);
                } else {
                    assert.equal(init.credentials, 'same-origin');
                    assert.equal(init.mode, 'same-origin');
                    assert(sessions.has(headers.get('X-Fc-Recording-Session')));
                }
            }
            if (record.adminDirect) {
                assert.equal(init.credentials, 'omit');
                assert.equal(init.mode, 'cors');
                assert.equal(init.redirect, 'error');
                assert.equal(headers.get('X-Media-Capability'), record.sourceHeaders['X-Media-Capability']);
                assert.equal(headers.get('X-Fc-Download-Session'), null);
            } else if (record.adminS3) {
                assert.equal(init.credentials, 'omit');
                assert.equal(init.mode, 'cors');
                assert.equal(init.redirect, 'error');
                assert.equal(headers.get('If-Match'), `"${record.etagOverride}"`);
                assert.equal(headers.get('X-Fc-Download-Session'), null);
            } else if (record.adminDownload) {
                assert.equal(init.credentials, 'same-origin');
                assert.equal(init.mode, 'same-origin');
                assert.equal(init.redirect, 'error');
                assert.equal(init.referrerPolicy, 'no-referrer');
                assert(sessions.has(headers.get('X-Fc-Download-Session')));
            }
            if (cipherStatus) return new Response('ciphertext request limit', {status: cipherStatus});
            if (record.emptyResponse) {
                const payload = init.method === 'HEAD' ? null : record.ciphertext;
                const suffix = !record.nginxMedia && header === 'bytes=-1';
                const headers = {'Content-Length': record.emptyLength ?? '0'};
                if (suffix) headers['Content-Range'] = 'bytes 0--1/0';
                return new Response(payload, {status: suffix ? 206 : 200, headers});
            }
            const range = /^bytes=(\d+)-(\d+)$/.exec(header);
            assert(range, 'ciphertext fetches must name one exact authenticated chunk');
            const start = Number(range[1]); const end = Number(range[2]);
            assert(end - start + 1 <= 1048576 + 16, 'network reads remain within one ciphertext chunk');
            const payload = record.ciphertext.slice(start, end + 1);
            if (record.onFetch) record.onFetch(start, end);
            return new Response(payload, {status: 206, headers: {
                'Content-Range': record.contentRangeOverride ?? `bytes ${start}-${end}/${record.ciphertext.length}`,
                'Content-Length': String(payload.length), 'Content-Type': 'application/octet-stream',
                ...(record.recordingRevision || record.adminDownload ? {ETag: `"${record.etagOverride || record.recordingRevision || record.adminDownload.download_snapshot}"`} : {}),
            }});
        },
    };
    worker.self = worker;
    vm.createContext(worker);
    vm.runInContext(source('media-crypto-sw.js'), worker);
}
createWorker();
const catalog = [{media_path: 'music/a.mp3', encryption: first.meta}, {media_path: 'music/b.mp3', encryption: second.meta}];
await page.FrontierMediaCrypto.prepareCatalog(catalog);
assert.match(catalog[0].url, /^\/__fc_media\/.*\?object=/);
vm.runInContext(`capabilities.clear();
    for (let index = 0; index < 256; index++)
        capabilities.set(index.toString(16).padStart(32, '0'), {clientId: 'crashed-' + index});
    grants.set('00000000000000000000000000000000:dead:', {});
    zipPlans.set('dead-plan', {token: '00000000000000000000000000000000'});`, worker);
await page.FrontierMediaCrypto.ensureWorker();
assert.equal(vm.runInContext('capabilities.size', worker), 1, 'crashed clients cannot permanently exhaust registration');
assert.equal(vm.runInContext("grants.has('00000000000000000000000000000000:dead:') || zipPlans.has('dead-plan')", worker), false,
    'dead-client reclamation removes its cached keys and ZIP plans');
vm.runInContext(`capabilities.clear();
    for (let index = 0; index < 256; index++)
        capabilities.set(index.toString(16).padStart(32, '0'), {clientId: 'browser-tab'});`, worker);
let fullRegistration;
const fullEvent = {data: {type: 'fc-crypto-register', token: 'f'.repeat(32)}, source: client,
    ports: [{postMessage(value) { fullRegistration = value; }}], waitUntil: value => value};
for (const listener of workerListeners.get('message')) listener(fullEvent);
await new Promise(resolve => setTimeout(resolve, 0));
assert(fullRegistration.error, '256 live capabilities retain the cap');
assert.equal(vm.runInContext('capabilities.size', worker), 256);
vm.runInContext('capabilities.clear()', worker);
await page.FrontierMediaCrypto.ensureWorker();

let response = await workerFetch(catalog[0].url, {headers: {Range: 'bytes=1048541-1048619'}});
assert.equal(response.status, 206);
assert.equal(response.headers.get('Content-Range'), `bytes 1048541-1048619/${bytes.length}`);
assert.equal(response.headers.get('Content-Length'), '79');
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes.subarray(1048541, 1048620));
assert.equal(cipherRequests.length, 2, 'a cross-chunk seek only fetches its two covering chunks');
response = await workerFetch(catalog[0].url, {headers: {Range: 'bytes=0-31'}});
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes.subarray(0, 32));
assert.equal(cipherRequests.length, 2, 'a repeated tag read reuses authenticated ciphertext without another network read');
assert.ok(vm.runInContext('cipherBytes <= CIPHER_CACHE_BYTES', worker));
response = await workerFetch(catalog[0].url, {headers: {Range: 'bytes=-17'}});
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes.slice(-17));
assert.equal(cipherRequests.length, 3, 'suffix Range fetches the final chunk only');
response = await workerFetch(catalog[0].url, {method: 'HEAD'});
assert.equal(response.headers.get('Content-Length'), String(bytes.length));
assert.equal((await response.arrayBuffer()).byteLength, 0);
response = await workerFetch(catalog[0].url, {headers: {Range: 'bytes=9000000-'}});
assert.equal(response.status, 416);
assert.equal(cipherRequests.length, 3, 'HEAD and invalid Range never consume ciphertext');
response = await workerFetch(catalog[1].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), secondBytes);
assert.equal(calls.filter(call => call.url.endsWith('/session')).length, 1, 'playback across files reuses the same session');
assert.equal(calls.filter(call => call.url.endsWith('/key')).length, 3,
    'cached ciphertext requires a fresh key authorization while uncached reads retain normal envelope reuse');

const originalDeadline = vm.runInContext('[...grants.values()][0].deadline', worker);
assert.equal(originalDeadline, performance.timeOrigin + 899000, 'grant lifetime starts before the handshake POST');
for (const skew of [-7, 7, -7]) {
    now = serverNow + skew * 60 * 60 * 1000;
    response = await workerFetch(catalog[1].url);
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), secondBytes);
    assert.equal(calls.filter(call => call.url.endsWith('/session')).length, 1,
        'wall-clock offsets and jumps cannot expire or renew live authorization');
}
keyDelay = 5000;
page.FrontierMediaCrypto.resetFault('music/b.mp3');
response = await workerFetch(catalog[1].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), secondBytes);
assert.equal(vm.runInContext('[...grants.values()].at(-1).deadline', worker), originalDeadline,
    'later file grants and response delays never extend the fixed session deadline');
keyDelay = 0;
mismatchedEnvelope = true;
page.FrontierMediaCrypto.resetFault('music/b.mp3');
assert.equal((await workerFetch(catalog[1].url)).status, 403, 'envelope lifetime must match its handshake exactly');
mismatchedEnvelope = false;
page.FrontierMediaCrypto.resetFault('music/b.mp3');
const originalPageMessage = pageMessage;
for (const invalidDeadline of [NaN, Infinity, common.monotonicNow() - 1, common.monotonicNow() + 900001]) {
    pageMessage = event => {
        const reply = event.ports[0];
        return originalPageMessage({...event, ports: [{postMessage(grant) {
            reply.postMessage({...grant, deadline: invalidDeadline});
        }}]});
    };
    page.FrontierMediaCrypto.resetFault('music/b.mp3');
    assert.equal((await workerFetch(catalog[1].url)).status, 403,
        'worker rejects missing/expired/unbounded deadlines without a wall-clock fallback');
}
pageMessage = originalPageMessage;
page.FrontierMediaCrypto.resetFault('music/b.mp3');

advance(901000);
response = await workerFetch(catalog[1].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), secondBytes);
assert.equal(calls.filter(call => call.url.endsWith('/session')).length, 2, 'expired authorization performs one fresh handshake');

// Recreated workers lose all in-memory keys/capabilities. A valid live tab can
// reauthorize its next seek, without keeping keys in persistent browser storage.
vm.runInContext('capabilities.clear(); grants.clear();', worker);
response = await workerFetch(catalog[1].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), secondBytes);

// A stopped worker starts with a fresh global scope. ZIP must register the
// already initialized page directly, before any virtual fetch can restore it.
createWorker();
assert.equal(vm.runInContext('capabilities.size + grants.size + zipPlans.size', worker), 0);
const restartMessages = controllerMessages.length;
const restartSessions = calls.filter(call => call.url.endsWith('/session')).length;
await page.FrontierMediaCrypto.downloadPlan([
    {path: 'music/b.mp3', filename: 'b.mp3', encryption: second.meta, size_bytes: secondBytes.length},
    {path: 'lyrics/plain.lrc', filename: 'plain.lrc', url: '/plain-lyric', size_bytes: 18},
    {path: 'music/other/b.mp3', filename: 'b.mp3', url: '/plain-lyric', size_bytes: 18},
]);
assert.deepEqual(controllerMessages.slice(restartMessages), ['fc-crypto-register', 'fc-crypto-zip']);
assert(!Object.hasOwn(downloadAnchors.at(-1), 'download'),
    'virtual ZIP uses attachment navigation so Chromium dispatches the worker fetch');
const zipId = vm.runInContext('[...zipPlans.keys()][0]', worker);
const zipItems = vm.runInContext('zipPlans.get(' + JSON.stringify(zipId) + ').items', worker);
response = await workerFetch('/__fc_zip/' + zipId);
const zip = new Uint8Array(await response.arrayBuffer());
assert.equal(response.headers.get('Content-Type'), 'application/zip');
let cursor = 0;
const archived = [];
const archivedNames = [];
for (let file = 0; file < 3; file += 1) {
    const view = new DataView(zip.buffer, cursor);
    assert.equal(view.getUint32(0, true), 0x04034b50);
    const nameLength = view.getUint16(26, true);
    const extraLength = view.getUint16(28, true);
    archivedNames.push(new TextDecoder().decode(zip.slice(cursor + 30, cursor + 30 + nameLength)));
    const size = Number(view.getBigUint64(30 + nameLength + 4, true));
    const start = cursor + 30 + nameLength + extraLength;
    archived.push(zip.slice(start, start + size));
    const descriptor = new DataView(zip.buffer, start + size);
    assert.equal(descriptor.getUint32(0, true), 0x08074b50);
    let crc = page.FrontierMediaCrypto.crcUpdate(0xffffffff, archived.at(-1));
    assert.equal(descriptor.getUint32(4, true), (crc ^ 0xffffffff) >>> 0);
    assert.equal(Number(descriptor.getBigUint64(8, true)), size);
    cursor = start + size + 24;
}
assert.deepEqual(archived[0], secondBytes);
assert.equal(new TextDecoder().decode(archived[1]), 'plain legacy lyric');
assert.equal(new TextDecoder().decode(archived[2]), 'plain legacy lyric');
assert.deepEqual(archivedNames, ['music/b.mp3', 'lyrics/plain.lrc', 'music/other/b.mp3'],
    'ZIP entries retain logical directories even when API filenames are identical basenames');
assert.equal(new DataView(zip.buffer, cursor).getUint32(0, true), 0x02014b50);
assert.equal(new DataView(zip.buffer, zip.length - 98).getUint32(0, true), 0x06064b50);
assert.equal(Number(new DataView(zip.buffer, zip.length - 98).getBigUint64(24, true)), 3);
assert.equal(calls.filter(call => call.url.endsWith('/session')).length, restartSessions,
    'worker restart restores its page capability and decrypts ZIP without another master handshake');
assert.equal((await workerFetch('/__fc_zip/' + zipId)).status, 403, 'download plan capability is consumed once');

// Exercise admission through the real worker message handler. Eight abandoned
// plans must expire without evicting any other valid plan or relaxing bounds.
const zipCapability = vm.runInContext('[...capabilities.keys()][0]', worker);
function queueZip(id, items = zipItems, sourceClient = client) {
    let reply;
    for (const listener of workerListeners.get('message') || []) {
        listener({data: {type: 'fc-crypto-zip', token: zipCapability, download_token: id, items},
            source: sourceClient, ports: [{postMessage(value) { reply = value; }}]});
    }
    return reply;
}
const planKeys = () => [...vm.runInContext('[...zipPlans.keys()]', worker)];
const boundarySessions = calls.filter(call => call.url.endsWith('/session')).length;
for (const invalidItems of [null, {}, Array(5001).fill(zipItems[0])]) {
    assert(queueZip('invalid-plan', invalidItems).error, 'worker rejects malformed or oversized ZIP plans');
    assert.equal(planKeys().length, 0);
}
const abandonedIds = Array.from({length: 8}, (_, index) => zipCapability + '-abandoned-' + index);
for (const [index, id] of abandonedIds.entries()) {
    assert.equal(queueZip(id, index === 0 ? Array(5000).fill(zipItems[0]) : zipItems).ok, true,
        'the existing 5000-entry limit remains inclusive');
}
assert.deepEqual(planKeys(), abandonedIds);
assert(queueZip('over-cap').error, 'eight live plans refuse a ninth plan');
assert(queueZip(abandonedIds[0]).error, 'a full queue cannot overwrite another live plan');
assert.equal(queueZip('another-client', zipItems, {id: 'other-browser-tab'}), undefined,
    'another client cannot admit plans using this page capability');
assert.deepEqual(planKeys(), abandonedIds);
advance(120000);
assert(queueZip('at-deadline').error, 'the exact expiry boundary retains the existing fetch validity');
assert.deepEqual(planKeys(), abandonedIds, 'the capacity check must retain every still-valid plan');
advance(1);
const firstRecoveredId = zipCapability + '-after-expiry';
assert.equal(queueZip(firstRecoveredId).ok, true, 'eight expired plans cannot permanently block new ZIP downloads');
assert.deepEqual(planKeys(), [firstRecoveredId]);
for (const id of abandonedIds) {
    assert.equal((await workerFetch('/__fc_zip/' + id)).status, 403, 'an expired plan cannot be consumed later');
}
for (let index = 0; index < 6; index += 1) assert.equal(queueZip('older-' + index).ok, true);
advance(60000);
const survivorId = zipCapability + '-survivor';
assert.equal(queueZip(survivorId).ok, true);
const survivorDeadline = vm.runInContext('zipPlans.get(' + JSON.stringify(survivorId) + ').expires', worker);
assert(queueZip('mixed-over-cap').error);
advance(60001);
const laterId = zipCapability + '-later';
assert.equal(queueZip(laterId).ok, true);
assert.deepEqual(planKeys(), [survivorId, laterId], 'a sweep removes only expired plans from a mixed queue');
assert.equal(vm.runInContext('zipPlans.get(' + JSON.stringify(survivorId) + ').expires', worker), survivorDeadline,
    'admitting another ZIP never extends an existing plan deadline');

// A consumed archive is held by its stream, not the pending-plan queue. Reading
// it may outlive the two-minute admission capability without a key renewal.
const activeArchive = await workerFetch('/__fc_zip/' + survivorId);
assert.equal(activeArchive.status, 200);
const activeReader = activeArchive.body.getReader();
const activeParts = [(await activeReader.read()).value];
advance(120001);
const currentId = zipCapability + '-current';
assert.equal(queueZip(currentId).ok, true);
assert.deepEqual(planKeys(), [currentId]);
while (true) {
    const part = await activeReader.read();
    if (part.done) break;
    activeParts.push(part.value);
}
const recoveredZip = new Uint8Array(await new Blob(activeParts).arrayBuffer());
let recoveredCursor = 0;
for (const [index, item] of zipItems.entries()) {
    const header = new DataView(recoveredZip.buffer, recoveredCursor);
    assert.equal(header.getUint32(0, true), 0x04034b50);
    const nameLength = header.getUint16(26, true);
    const extraLength = header.getUint16(28, true);
    assert.equal(new TextDecoder().decode(recoveredZip.slice(recoveredCursor + 30, recoveredCursor + 30 + nameLength)), item.path);
    const size = Number(header.getBigUint64(30 + nameLength + 4, true));
    const start = recoveredCursor + 30 + nameLength + extraLength;
    const body = recoveredZip.slice(start, start + size);
    assert.deepEqual(body, index === 0 ? secondBytes : new TextEncoder().encode('plain legacy lyric'));
    const descriptor = new DataView(recoveredZip.buffer, start + size);
    assert.equal(descriptor.getUint32(0, true), 0x08074b50);
    assert.equal(descriptor.getUint32(4, true), (page.FrontierMediaCrypto.crcUpdate(0xffffffff, body) ^ 0xffffffff) >>> 0);
    assert.equal(Number(descriptor.getBigUint64(8, true)), size);
    recoveredCursor = start + size + 24;
}
assert.equal(new DataView(recoveredZip.buffer, recoveredCursor).getUint32(0, true), 0x02014b50);
assert.equal(new DataView(recoveredZip.buffer, recoveredZip.length - 98).getUint32(0, true), 0x06064b50);
assert.equal(Number(new DataView(recoveredZip.buffer, recoveredZip.length - 98).getBigUint64(24, true)), zipItems.length);
assert.equal((await workerFetch('/__fc_zip/' + survivorId)).status, 403, 'a consumed active archive remains one-shot');
assert.equal((await workerFetch('/__fc_zip/' + laterId)).status, 403, 'swept plans cannot be revived');
const currentArchive = await workerFetch('/__fc_zip/' + currentId);
assert.deepEqual(new Uint8Array(await currentArchive.arrayBuffer()), recoveredZip,
    'new admission after a full expired queue produces the same complete ZIP bytes');
assert.equal((await workerFetch('/__fc_zip/' + currentId)).status, 403);
assert.equal(calls.filter(call => call.url.endsWith('/session')).length, boundarySessions,
    'ZIP queue expiry and a slow active stream cannot renew the fixed key session');

await page.FrontierMediaCrypto.downloadPlan([{path: 'music/b.mp3', encryption: second.meta}]);
assert(!Object.hasOwn(downloadAnchors.at(-1), 'download'),
    'single encrypted attachment also reaches the worker through navigation');
assert.match(downloadAnchors.at(-1).href, /[?&]download=1/);
await page.FrontierMediaCrypto.downloadPlan([{path: 'music/s3-plain.mp3', transport: 'S3', object_id: 'immutable-object'}]);
assert(!Object.hasOwn(downloadAnchors.at(-1), 'download'),
    'S3 plaintext attachments must navigate through the worker; Chromium download attribute bypasses its fetch handler');
assert.match(downloadAnchors.at(-1).href, /[?&]download=1/);
assert.match(downloadAnchors.at(-1).href, /[?&]object=immutable-object/);
await page.FrontierMediaCrypto.downloadPlan([{path: 'lyrics/plain.lrc', url: '/plain-lyric', filename: 'plain.lrc'}]);
assert.equal(downloadAnchors.at(-1).download, 'plain.lrc', 'normal backend downloads retain their filename attribute');

const exactDownload = {resource_id: 'e'.repeat(64), download_snapshot: 'f'.repeat(64)};
const exactDownloadSource = 'https://cloud.example/api/v1/media/admin/download/bytes?' +
    new URLSearchParams({resource_id: exactDownload.resource_id, snapshot: exactDownload.download_snapshot});
const exactDownloadPath = 'music/artist/private download.mp3';
const exactDownloadBytes = new TextEncoder().encode('sealed download bytes');
const exactDownloadRecord = await prepare(exactDownloadBytes, exactDownloadPath, exactDownloadSource);
exactDownloadRecord.adminDownload = exactDownload;
const exactDownloadItem = {path: exactDownloadPath, filename: 'private download.mp3', encryption: exactDownloadRecord.meta, ...exactDownload};
await page.FrontierMediaCrypto.downloadPlan([exactDownloadItem]);
const exactDownloadURL = downloadAnchors.at(-1).href;
assert(!Object.hasOwn(downloadAnchors.at(-1), 'download'));
assert(!decodeURIComponent(exactDownloadURL).includes(exactDownloadPath), 'worker navigation uses opaque download identity');
const exactResponse = await workerFetch(exactDownloadURL);
assert.match(exactResponse.headers.get('Content-Disposition'), /private%20download\.mp3/);
assert.deepEqual(new Uint8Array(await exactResponse.arrayBuffer()), exactDownloadBytes);
assert.deepEqual(calls.filter(call => call.url.endsWith('/key')).at(-1).body, {
    session_id: calls.filter(call => call.url.endsWith('/key')).at(-1).body.session_id, file_path: exactDownloadPath, ...exactDownload,
});
// The previous deployed worker acknowledged ZIP but lacked the Admin
// download header. The new page must wait for the matching controller.
const staleMessages = [];
const staleController = {postMessage(message, ports) {
    staleMessages.push(message.type);
    ports[0].postMessage({ok: true});
}};
const beforeWorkerUpgrade = downloadAnchors.length;
page.navigator.serviceWorker.controller = staleController;
workerUpdate = async () => { throw new Error('fixture update unavailable'); };
await assert.rejects(page.FrontierMediaCrypto.downloadPlan([exactDownloadItem], true), /刷新后重试下载/);
assert.deepEqual(staleMessages, ['fc-crypto-register']);
assert.equal(downloadAnchors.length, beforeWorkerUpgrade);
assert.equal(controllerChanges.size, 0);
workerUpdate = async () => {
    page.navigator.serviceWorker.controller = controller;
    for (const changed of [...controllerChanges]) changed();
};
await page.FrontierMediaCrypto.downloadPlan([exactDownloadItem], true);
assert.deepEqual(staleMessages, ['fc-crypto-register', 'fc-crypto-register']);
assert.equal(controllerChanges.size, 0);
workerUpdate = async () => {};
const exactZipURL = downloadAnchors.at(-1).href;
assert.match(exactZipURL, /^\/__fc_zip\//, 'one file selected through a directory still downloads a ZIP');
const exactZip = new Uint8Array(await (await workerFetch(exactZipURL)).arrayBuffer());
assert.equal(new DataView(exactZip.buffer).getUint32(0, true), 0x04034b50);
assert(Buffer.from(exactZip).includes(Buffer.from(exactDownloadBytes)));
exactDownloadRecord.etagOverride = '0'.repeat(64);
await assert.rejects((await workerFetch(exactDownloadURL)).arrayBuffer(), /密文身份不一致/);

const s3Download = {resource_id: '2'.repeat(64), download_snapshot: '3'.repeat(64)};
const s3DownloadObject = '4'.repeat(64);
const s3DownloadSource = 'https://objects.example/encrypted/opaque-key?sig=fixture';
const s3DownloadPath = 'music/artist/private S3 download.mp3';
const s3DownloadBytes = new TextEncoder().encode('sealed S3 download bytes');
const s3DownloadRecord = await prepare(s3DownloadBytes, s3DownloadPath, s3DownloadSource);
s3DownloadRecord.adminDownload = s3Download;
s3DownloadRecord.adminS3 = true;
s3DownloadRecord.etagOverride = 'immutable-s3-etag';
s3DownloadRecord.keyResponseOverride = {transport: 'S3', object_id: s3DownloadObject, expires_in: 120,
    size_bytes: s3DownloadRecord.meta.ciphertext_size, source_headers: {'If-Match': '"immutable-s3-etag"'}};
await page.FrontierMediaCrypto.downloadPlan([{path: s3DownloadPath, filename: 'private S3 download.mp3',
    encryption: s3DownloadRecord.meta, transport: 'S3', object_id: s3DownloadObject, ...s3Download}]);
const s3DownloadURL = downloadAnchors.at(-1).href;
assert(!decodeURIComponent(s3DownloadURL).includes(s3DownloadPath));
assert.deepEqual(new Uint8Array(await (await workerFetch(s3DownloadURL)).arrayBuffer()), s3DownloadBytes);
assert.equal(cipherRequests.at(-1).url, s3DownloadSource, 'S3 Admin bytes are fetched directly from the signed provider source');

const adminDirectDownload = {resource_id: '5'.repeat(64), download_snapshot: '6'.repeat(64)};
const directDownloadObject = '7'.repeat(64);
const directDownloadAlias = '8'.repeat(64);
const directDownloadOrigin = 'https://direct-owner.example';
const directDownloadSource = `${directDownloadOrigin}/internal/v1/opaque-media/${directDownloadAlias}`;
const directDownloadPath = 'music/artist/private direct download.mp3';
const directDownloadBytes = new TextEncoder().encode('sealed Direct download bytes');
const directDownloadRecord = await prepare(directDownloadBytes, directDownloadPath, directDownloadSource);
directDownloadRecord.adminDownload = adminDirectDownload;
directDownloadRecord.adminDirect = true;
directDownloadRecord.opaqueMedia = {resource_id: adminDirectDownload.resource_id, object_id: directDownloadObject, alias: directDownloadAlias};
directDownloadRecord.sourceTransport = 'Direct';
directDownloadRecord.sourceOrigin = directDownloadOrigin;
directDownloadRecord.sourceHeaders = {'X-Media-Capability': 'admin.read'};
directDownloadRecord.keyResponseOverride = {size_bytes: directDownloadRecord.meta.ciphertext_size};
await page.FrontierMediaCrypto.downloadPlan([{path: directDownloadPath, filename: 'private direct download.mp3',
    encryption: directDownloadRecord.meta, transport: 'Direct', object_id: directDownloadObject, ...adminDirectDownload}]);
assert.deepEqual(new Uint8Array(await (await workerFetch(downloadAnchors.at(-1).href)).arrayBuffer()), directDownloadBytes);
assert.equal(cipherRequests.at(-1).url, directDownloadSource, 'Direct Admin download goes to the paired resource origin');

const oldUrl = catalog[1].url;
const replacement = await prepare(new TextEncoder().encode('replaced'), 'music/b.mp3', second.source);
assert.equal(await page.FrontierMediaCrypto.textFor('music/b.mp3', replacement.meta.file_id), 'replaced',
    'a fresh lyric descriptor must replace a same-path cached key before its authorization expires');
advance(901000);
assert.equal((await workerFetch(oldUrl)).status, 409, 'same-path replacement cannot reuse another object key');
const fresh = [{media_path: 'music/b.mp3', encryption: replacement.meta}];
await page.FrontierMediaCrypto.prepareCatalog(fresh);
response = await workerFetch(fresh[0].url);
assert.equal(new TextDecoder().decode(await response.arrayBuffer()), 'replaced');

// Exercise text decoding through authenticated chunk playback, rather than
// passing already-decoded strings to the parser. A literal replacement code
// point is valid; invalid byte sequences cannot be silently replaced by it.
const encodedLyric = new TextEncoder().encode('\ufeff\ufeff[00:01]词\ufeff\n[00:02]�');
const lyricRecord = await prepare(encodedLyric, 'lyrics/utf8.lrc', 'https://cloud.example/relay/utf8-lyric');
const decodedLyric = await page.FrontierMediaCrypto.textFor('lyrics/utf8.lrc', lyricRecord.meta.file_id);
assert.equal(decodedLyric, '\ufeff\ufeff[00:01]词\ufeff\n[00:02]�', 'the decoder preserves the single-BOM parsing contract');
assert.deepEqual(JSON.parse(JSON.stringify(common.parseLyrics(decodedLyric))),
    [{time: 1, text: '\ufeff词\ufeff'}, {time: 2, text: '�'}]);
for (const [index, invalidBytes] of [
    [0xff], [0xe2, 0x82], [0xed, 0xa0, 0x80], [0xc0, 0xaf],
].entries()) {
    const invalidLyric = await prepare(Uint8Array.from(invalidBytes), 'lyrics/invalid-' + index + '.lrc',
        'https://cloud.example/relay/invalid-lyric-' + index);
    await assert.rejects(page.FrontierMediaCrypto.textFor('lyrics/invalid-' + index + '.lrc', invalidLyric.meta.file_id),
        error => error.name === 'TypeError', 'invalid UTF-8 must fail after successful authenticated decryption');
}

// A source or mid-transfer authorization limit must hold playback for an
// explicit user retry, rather than being classified as a resumable outage.
page.FrontierMediaCrypto.resetFault('music/a.mp3');
cipherStatus = 429;
response = await workerFetch(catalog[0].url);
await assert.rejects(response.arrayBuffer(), /存储节点/);
assert.match(page.FrontierMediaCrypto.failureFor(catalog[0].url), /限额/);
cipherStatus = 0;
page.FrontierMediaCrypto.resetFault('music/a.mp3');

replacement.ciphertext[0] ^= 1;
advance(300001);
response = await workerFetch(fresh[0].url);
await assert.rejects(response.arrayBuffer(), 'tampered ciphertext cannot return plaintext');
assert(page.FrontierMediaCrypto.failureFor(fresh[0].url), 'tag failures propagate to the playback retry guard');
assert.equal((await workerFetch(fresh[0].url)).status, 422, 'integrity failure must not be retried as a network failure');

advance(901000);
sessionStatus = 429;
const limitedSessionStart = calls.filter(call => call.url.endsWith('/session')).length;
const limitedCipherStart = cipherRequests.length;
const limitedKeysStart = calls.filter(call => call.url.endsWith('/key')).length;
const limitedRequests = await Promise.all([workerFetch(catalog[0].url), workerFetch(catalog[0].url)]);
for (const limited of limitedRequests) {
    assert.equal(limited.status, 429, 'an expired session preserves its failed handshake status');
    assert.equal(await limited.text(), 'temporary key session limit');
}
assert.equal(calls.filter(call => call.url.endsWith('/session')).length, limitedSessionStart + 1,
    'simultaneous requests coalesce one limited handshake without renewal loops');
assert.equal(calls.filter(call => call.url.endsWith('/key')).length, limitedKeysStart);
assert.equal(cipherRequests.length, limitedCipherStart, 'no ciphertext request can use an expired or denied session');
sessionStatus = 0;
for (const invalidLifetime of [0, 901, 1.5]) {
    sessionLifetime = invalidLifetime;
    await assert.rejects(page.FrontierMediaCrypto.encryptFile(inputFile(secondBytes, 'clock.mp3')),
        /会话期限无效/, 'invalid server lifetime cannot create a browser key authorization');
}
sessionLifetime = 899;
handshakeDelay = 900000;
await assert.rejects(page.FrontierMediaCrypto.encryptFile(inputFile(secondBytes, 'clock.mp3')),
    /授权已过期/, 'delayed handshake responses cannot restart the authorization lifetime');
handshakeDelay = 0;
const originalOrigin = performance.timeOrigin;
performance.timeOrigin = NaN;
assert.throws(() => common.monotonicNow(), /单调时钟不可用/, 'clock failure has no wall-clock fallback');
performance.timeOrigin = originalOrigin;
const guardedBytes = new TextEncoder().encode('cache authorization must stay current');
const guarded = await prepare(guardedBytes, 'music/cache-guard.mp3', 'https://cloud.example/relay/cache-guard');
const guardedCatalog = [{media_path: 'music/cache-guard.mp3', encryption: guarded.meta}];
await page.FrontierMediaCrypto.prepareCatalog(guardedCatalog);
response = await workerFetch(guardedCatalog[0].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), guardedBytes);
const beforeDeniedCache = cipherRequests.length;
keyStatus = 404;
response = await workerFetch(guardedCatalog[0].url);
await assert.rejects(response.arrayBuffer(), /current object access denied/,
    'a live cached envelope and warm ciphertext must not bypass hidden/deleted object authorization');
assert.equal(cipherRequests.length, beforeDeniedCache);
keyStatus = 0;
page.FrontierMediaCrypto.resetFault('music/cache-guard.mp3');
response = await workerFetch(guardedCatalog[0].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), guardedBytes);
await prepare(new TextEncoder().encode('different object'), 'music/cache-guard.mp3', guarded.source);
response = await workerFetch(guardedCatalog[0].url);
await assert.rejects(response.arrayBuffer(), /文件已替换/,
    'same-path replacement is rejected immediately even before the old envelope expires');

const unavailable = await prepare(guardedBytes, 'music/unavailable.mp3', 'https://cloud.example/relay/unavailable');
const unavailableCatalog = [{media_path: 'music/unavailable.mp3', encryption: unavailable.meta}];
await page.FrontierMediaCrypto.prepareCatalog(unavailableCatalog);
const beforeUnavailable = cipherRequests.length;
sourceUnavailable = true;
response = await workerFetch(unavailableCatalog[0].url);
assert.equal(response.status, 503, 'a valid key envelope does not imply an available data route');
assert.match(await response.text(), /资源数据路径不可用/);
assert.equal(cipherRequests.length, beforeUnavailable, 'unavailable source never tries a relay or another path');
sourceUnavailable = false;

const localURL = 'https://cloud.example/internal/v1/media/' + 'a'.repeat(64);
const localRecord = await prepare(guardedBytes, 'music/local-header.mp3', localURL);
localRecord.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
const localCatalog = [{media_path: 'music/local-header.mp3', encryption: localRecord.meta}];
await page.FrontierMediaCrypto.prepareCatalog(localCatalog);
const localStart = performance.timeOrigin + performance.now();
response = await workerFetch(localCatalog[0].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), guardedBytes);
assert.equal(cipherRequests.at(-1).url, localURL, 'capability is absent from the request URL');
assert.equal(cipherRequests.at(-1).capability, 'payload.signature', 'capability is sent only in its dedicated header');
const localDeadline = vm.runInContext("[...grants.entries()].find(([key]) => key.includes('music/local-header.mp3'))?.[1].deadline", worker);
assert(localDeadline <= localStart + 120000, 'browser never caches a source grant beyond its server-provided lifetime');

for (const [label, origin, mode, route] of [
    ['local', 'https://cloud.example', 'Local', '/internal/v1/opaque-media/'],
    ['direct', 'https://owner.example', 'Direct', '/internal/v1/opaque-media/'],
    ['master-direct', 'https://master.example', 'Direct', '/api/v1/media/master-direct/'],
    ['master-relay', 'https://cloud.example', 'Relay', '/api/v1/media/master-relay/'],
]) {
    const url = origin + route + 'a'.repeat(64);
    const record = await prepare(guardedBytes, `music/opaque-${label}.mp3`, url);
    record.sourceHeaders = {[mode === 'Relay' ? 'X-Media-Relay' : 'X-Media-Capability']: 'payload.signature'};
    record.sourceTransport = mode;
    if (mode === 'Direct') record.sourceOrigin = origin;
    record.opaqueMedia = {resource_id: '7'.repeat(64), object_id: '8'.repeat(64), alias: 'a'.repeat(64)};
    const catalog = [{media_path: `music/opaque-${label}.mp3`, native_source: true, source_identity_version: 1, resource_id: '7'.repeat(64),
        object_id: '8'.repeat(64), encryption: record.meta}];
    await page.FrontierMediaCrypto.prepareCatalog(catalog);
    const result = await workerFetch(catalog[0].url);
    assert.deepEqual(new Uint8Array(await result.arrayBuffer()), guardedBytes, `opaque ${label} decrypts through the worker`);
    assert.equal(cipherRequests.at(-1).url, url);
}

const wrongMasterURL = 'https://master.example/api/v1/media/master-direct/' + '8'.repeat(64);
const wrongMaster = await prepare(guardedBytes, 'music/master-wrong-alias.mp3', wrongMasterURL);
wrongMaster.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
wrongMaster.sourceTransport = 'Direct';
wrongMaster.sourceOrigin = 'https://master.example';
wrongMaster.opaqueMedia = {resource_id: '7'.repeat(64), object_id: '8'.repeat(64), alias: 'a'.repeat(64)};
const wrongMasterCatalog = [{media_path: 'music/master-wrong-alias.mp3', native_source: true, source_identity_version: 1,
    resource_id: '7'.repeat(64), object_id: '8'.repeat(64), encryption: wrongMaster.meta}];
await page.FrontierMediaCrypto.prepareCatalog(wrongMasterCatalog);
const beforeWrongMaster = cipherRequests.length;
assert.equal((await workerFetch(wrongMasterCatalog[0].url)).status, 403);
assert.equal(cipherRequests.length, beforeWrongMaster, 'Master Direct must use the authenticated source alias');

const directURL = 'https://master.example/api/v1/media/master-direct/' + 'c'.repeat(64);
const plainResource = '7'.repeat(64), plainObject = '8'.repeat(64);
const plainBytes = new TextEncoder().encode('plain media range example');
const plainURL = 'https://master.example/api/v1/media/master-direct/' + plainResource;
records.set('native-plain', {source: plainURL, ciphertext: plainBytes});
nativePlans.set('music/native-plain.mp3', {transport: 'Native', resource_id: plainResource, object_id: plainObject,
    size_bytes: plainBytes.length, source_revision: '9'.repeat(64), source_url: plainURL,
    source_headers: {'X-Media-Capability': 'payload.signature'}, source_transport: 'Direct', source_origin: 'https://master.example',
    source_expires_in: 120, source_expires_at: 9999999999, content_type: 'audio/mpeg', filename: 'native-plain.mp3'});
const plainCatalog = [{media_path: 'music/native-plain.mp3', native_source: true, resource_id: plainResource,
    object_id: plainObject, size_bytes: plainBytes.length}];
await page.FrontierMediaCrypto.prepareCatalog(plainCatalog);
response = await workerFetch(plainCatalog[0].url, {headers: {Range: 'bytes=2-8'}});
assert.equal(response.status, 206);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), plainBytes.slice(2, 9));
assert.equal(cipherRequests.at(-1).url, plainURL);
assert.equal(cipherRequests.at(-1).credentials, 'omit');
assert.equal(cipherRequests.at(-1).redirect, 'error');
response = await workerFetch(plainCatalog[0].url, {method: 'HEAD'});
assert.equal(response.status, 200);
assert.equal(response.headers.get('Content-Length'), String(plainBytes.length));
const plainRelayURL = 'https://cloud.example/api/v1/media/master-relay/' + plainResource;
records.set('native-plain-relay', {source: plainRelayURL, ciphertext: plainBytes});
nativePlans.set('music/native-relay.mp3', {...nativePlans.get('music/native-plain.mp3'), source_url: plainRelayURL,
    source_headers: {'X-Media-Relay': 'payload.signature'}, source_transport: 'Relay', source_origin: undefined});
const plainRelayCatalog = [{media_path: 'music/native-relay.mp3', native_source: true, resource_id: plainResource,
    object_id: plainObject, size_bytes: plainBytes.length}];
await page.FrontierMediaCrypto.prepareCatalog(plainRelayCatalog);
response = await workerFetch(plainRelayCatalog[0].url, {headers: {Range: 'bytes=1-4'}});
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), plainBytes.slice(1, 5));
assert.equal(cipherRequests.at(-1).url, plainRelayURL);
assert.equal(cipherRequests.at(-1).relay, 'payload.signature');
for (const [label, source, mode, origin, header] of [
    ['local', 'https://cloud.example/internal/v1/media/' + plainObject, 'Local', undefined, 'X-Media-Capability'],
    ['owner-direct', 'https://owner.example/internal/v1/media/' + plainObject, 'Direct', 'https://owner.example', 'X-Media-Capability'],
    ['opaque-local', 'https://cloud.example/internal/v1/opaque-media/' + '6'.repeat(64), 'Local', undefined, 'X-Media-Capability'],
    ['opaque-direct', 'https://owner.example/internal/v1/opaque-media/' + '6'.repeat(64), 'Direct', 'https://owner.example', 'X-Media-Capability'],
    ['opaque-relay', 'https://cloud.example/api/v1/media/opaque-follower-relay/' + '6'.repeat(64), 'Relay', undefined, 'X-Media-Relay'],
    ['owner-relay', 'https://cloud.example/api/v1/media/follower-relay/' + plainResource, 'Relay', undefined, 'X-Media-Relay'],
]) {
    const path = `music/native-${label}.mp3`;
    records.set(`native-${label}`, {source, ciphertext: plainBytes});
    nativePlans.set(path, {...nativePlans.get('music/native-plain.mp3'), source_url: source,
        source_headers: {[header]: 'payload.signature'}, source_transport: mode, source_origin: origin,
        ...(label.startsWith('opaque-') ? {source_identity_version: 1, source_object_id: '6'.repeat(64), source_owner_id: 'a'.repeat(32)} : {})});
    const catalog = [{media_path: path, native_source: true, resource_id: plainResource,
        object_id: plainObject, size_bytes: plainBytes.length}];
    await page.FrontierMediaCrypto.prepareCatalog(catalog);
    const result = await workerFetch(catalog[0].url, {headers: {Range: 'bytes=1-4'}});
    assert.equal(result.status, 206, `${label} plaintext range`);
    assert.equal(await result.text(), 'lain');
    assert.equal(cipherRequests.at(-1).url, source);
}
const badLocal = {...nativePlans.get('music/native-local.mp3'),
    source_url: 'https://cloud.example/internal/v1/media/' + 'f'.repeat(64)};
nativePlans.set('music/native-local-bad.mp3', badLocal);
const badLocalCatalog = [{media_path: 'music/native-local-bad.mp3', native_source: true, resource_id: plainResource,
    object_id: plainObject, size_bytes: plainBytes.length}];
await page.FrontierMediaCrypto.prepareCatalog(badLocalCatalog);
const beforeBadLocal = cipherRequests.length;
response = await workerFetch(badLocalCatalog[0].url);
assert.equal(response.status, 403);
assert.equal(cipherRequests.length, beforeBadLocal, 'wrong Local object must not be fetched');
nativePlans.set('music/native-opaque-bad.mp3', {...nativePlans.get('music/native-opaque-local.mp3'), source_object_id: plainObject});
const badOpaqueCatalog = [{media_path: 'music/native-opaque-bad.mp3', native_source: true, resource_id: plainResource,
    object_id: plainObject, size_bytes: plainBytes.length}];
await page.FrontierMediaCrypto.prepareCatalog(badOpaqueCatalog);
const beforeBadOpaque = cipherRequests.length;
response = await workerFetch(badOpaqueCatalog[0].url);
assert.equal(response.status, 403);
assert.equal(cipherRequests.length, beforeBadOpaque, 'historical object ID must not be reused as opaque locator');
const lyricID = '5'.repeat(64), lyricBytes = new TextEncoder().encode('[00:01.00] example\n');
const lyricURL = 'https://master.example/api/v1/media/master-direct-lyric/' + lyricID;
records.set('native-lyric', {source: lyricURL, ciphertext: lyricBytes});
nativePlans.set('lyrics/native.lrc', {...nativePlans.get('music/native-plain.mp3'), resource_id: lyricID, object_id: lyricID,
    size_bytes: lyricBytes.length, source_url: lyricURL, filename: 'native.lrc'});
assert.equal(await page.FrontierMediaCrypto.plainTextFor({file_path: 'lyrics/native.lrc', resource_id: lyricID,
    object_id: lyricID, size_bytes: lyricBytes.length}), '[00:01.00] example\n');
assert.equal(cipherRequests.at(-1).url, lyricURL);
const emptyLyricURL = 'https://master.example/api/v1/media/master-direct-lyric/' + lyricID;
records.set('native-empty-lyric', {source: emptyLyricURL, ciphertext: new Uint8Array(), emptyResponse: true});
nativePlans.set('lyrics/empty.lrc', {...nativePlans.get('lyrics/native.lrc'), size_bytes: 0, source_url: emptyLyricURL, filename: 'empty.lrc'});
const emptyLyricText = await page.FrontierMediaCrypto.plainTextFor({file_path: 'lyrics/empty.lrc', resource_id: lyricID, object_id: lyricID, size_bytes: 0});
assert.equal(emptyLyricText, '', 'empty historical lyric bytes are retained');
assert.throws(() => page.FrontierMediaCrypto.parseLyrics(emptyLyricText), 'empty lyric keeps the existing parse failure');
records.delete('native-empty-lyric');
const opaqueLyricID = '3'.repeat(64), opaqueLyricAlias = '6'.repeat(64), lyricTrackID = '2'.repeat(64);
const opaqueLyricURL = 'https://master.example/api/v1/media/master-direct-lyric/' + opaqueLyricAlias;
records.set('native-opaque-lyric', {source: opaqueLyricURL, ciphertext: lyricBytes});
nativePlans.set('lyrics/native-opaque.lrc', {...nativePlans.get('lyrics/native.lrc'), resource_id: opaqueLyricID,
    object_id: opaqueLyricID, source_identity_version: 1, source_object_id: opaqueLyricAlias, source_owner_id: 'a'.repeat(32), source_url: opaqueLyricURL});
assert.equal(await page.FrontierMediaCrypto.plainTextFor({file_path: 'lyrics/native-opaque.lrc', resource_id: opaqueLyricID,
    object_id: opaqueLyricID, track_resource_id: lyricTrackID, size_bytes: lyricBytes.length}), '[00:01.00] example\n');
assert.equal(calls.filter(call => call.url.endsWith('/native/source')).at(-1).body.track_resource_id, lyricTrackID);
assert.equal(cipherRequests.at(-1).url, opaqueLyricURL);
const lyricGrantRequests = calls.filter(call => call.url.endsWith('/native/source')).length;
await page.FrontierMediaCrypto.plainTextFor({file_path: 'lyrics/native-opaque.lrc', resource_id: opaqueLyricID,
    object_id: opaqueLyricID, track_resource_id: '1'.repeat(64), size_bytes: lyricBytes.length});
assert.equal(calls.filter(call => call.url.endsWith('/native/source')).length, lyricGrantRequests + 1, 'track changes require a new lyric grant');
const concurrentLyricRequests = calls.filter(call => call.url.endsWith('/native/source')).length;
const lyricDescriptor = {file_path: 'lyrics/native-opaque.lrc', resource_id: opaqueLyricID, object_id: opaqueLyricID, size_bytes: lyricBytes.length};
assert.deepEqual(await Promise.all(['7'.repeat(64), '8'.repeat(64)].map(track_resource_id =>
    page.FrontierMediaCrypto.plainTextFor({...lyricDescriptor, track_resource_id}))), ['[00:01.00] example\n', '[00:01.00] example\n']);
assert.deepEqual(calls.filter(call => call.url.endsWith('/native/source')).slice(concurrentLyricRequests).map(call => call.body.track_resource_id), ['7'.repeat(64), '8'.repeat(64)]);
await assert.rejects(page.FrontierMediaCrypto.plainTextFor({file_path: 'lyrics/native-opaque.lrc', resource_id: opaqueLyricID,
    object_id: opaqueLyricID, track_resource_id: 'invalid', size_bytes: lyricBytes.length}), /歌词身份无效/);
nativePlans.set('lyrics/native-opaque-mismatch.lrc', {...nativePlans.get('lyrics/native-opaque.lrc'), source_url: 'https://master.example/api/v1/media/master-direct-lyric/' + opaqueLyricID});
const beforeOpaqueLyricMismatch = cipherRequests.length;
await assert.rejects(page.FrontierMediaCrypto.plainTextFor({file_path: 'lyrics/native-opaque-mismatch.lrc', resource_id: opaqueLyricID,
    object_id: opaqueLyricID, track_resource_id: lyricTrackID, size_bytes: lyricBytes.length}));
assert.equal(cipherRequests.length, beforeOpaqueLyricMismatch, 'mismatched opaque lyric URL must not be fetched');
const opaqueRelayLyricID = '9'.repeat(64), opaqueRelayLyricAlias = 'a'.repeat(64);
const opaqueRelayLyricURL = 'https://cloud.example/api/v1/media/master-relay/' + opaqueRelayLyricAlias;
records.set('native-opaque-relay-lyric', {source: opaqueRelayLyricURL, ciphertext: lyricBytes});
nativePlans.set('lyrics/native-opaque-relay.lrc', {...nativePlans.get('lyrics/native.lrc'), resource_id: opaqueRelayLyricID,
    object_id: opaqueRelayLyricID, source_identity_version: 1, source_object_id: opaqueRelayLyricAlias, source_owner_id: 'a'.repeat(32), source_url: opaqueRelayLyricURL,
    source_headers: {'X-Media-Relay': 'payload.signature'}, source_transport: 'Relay', source_origin: undefined});
assert.equal(await page.FrontierMediaCrypto.plainTextFor({file_path: 'lyrics/native-opaque-relay.lrc', resource_id: opaqueRelayLyricID,
    object_id: opaqueRelayLyricID, track_resource_id: lyricTrackID, size_bytes: lyricBytes.length}), '[00:01.00] example\n');
assert.equal(cipherRequests.at(-1).url, opaqueRelayLyricURL);
assert.equal(cipherRequests.at(-1).relay, 'payload.signature');
const opaqueLocalLyricURL = 'https://cloud.example/api/v1/media/master-local-lyric/' + opaqueRelayLyricAlias;
records.set('native-opaque-local-lyric', {source: opaqueLocalLyricURL, ciphertext: lyricBytes});
nativePlans.set('lyrics/native-opaque-local.lrc', {...nativePlans.get('lyrics/native-opaque-relay.lrc'), source_url: opaqueLocalLyricURL,
    source_headers: {'X-Media-Capability': 'payload.signature'}, source_transport: 'Local'});
assert.equal(await page.FrontierMediaCrypto.plainTextFor({file_path: 'lyrics/native-opaque-local.lrc', resource_id: opaqueRelayLyricID,
    object_id: opaqueRelayLyricID, track_resource_id: lyricTrackID, size_bytes: lyricBytes.length}), '[00:01.00] example\n');
assert.equal(cipherRequests.at(-1).url, opaqueLocalLyricURL);
const opaqueLocalMediaAlias = 'f'.repeat(64), opaqueLocalMediaURL = 'https://cloud.example/api/v1/media/master-local/' + opaqueLocalMediaAlias;
records.set('native-opaque-local-media', {source: opaqueLocalMediaURL, ciphertext: plainBytes});
nativePlans.set('music/master-owned-local.mp3', {...nativePlans.get('music/native-plain.mp3'), source_identity_version: 1, source_object_id: opaqueLocalMediaAlias, source_owner_id: 'a'.repeat(32),
    source_url: opaqueLocalMediaURL, source_headers: {'X-Media-Capability': 'payload.signature'}, source_transport: 'Local', source_origin: undefined});
const localMediaCatalog = [{media_path: 'music/master-owned-local.mp3', native_source: true, resource_id: plainResource,
    object_id: plainObject, size_bytes: plainBytes.length}];
await page.FrontierMediaCrypto.prepareCatalog(localMediaCatalog);
response = await workerFetch(localMediaCatalog[0].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), plainBytes);
assert.equal(cipherRequests.at(-1).url, opaqueLocalMediaURL);
const opaqueLocalFollowerRelayURL = 'https://cloud.example/api/v1/media/opaque-local-follower-relay/' + opaqueLocalMediaAlias;
records.set('native-opaque-local-follower-relay', {source: opaqueLocalFollowerRelayURL, ciphertext: plainBytes});
nativePlans.set('music/master-ingress-follower-relay.mp3', {...nativePlans.get('music/master-owned-local.mp3'),
    source_url: opaqueLocalFollowerRelayURL, source_headers: {'X-Media-Relay': 'payload.signature'}, source_transport: 'Relay'});
const localFollowerRelayCatalog = [{media_path: 'music/master-ingress-follower-relay.mp3', native_source: true,
    resource_id: plainResource, object_id: plainObject, size_bytes: plainBytes.length}];
await page.FrontierMediaCrypto.prepareCatalog(localFollowerRelayCatalog);
response = await workerFetch(localFollowerRelayCatalog[0].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), plainBytes);
assert.equal(cipherRequests.at(-1).url, opaqueLocalFollowerRelayURL);
assert.equal(cipherRequests.at(-1).relay, 'payload.signature');
for (const [label, template] of [['Local', 'music/master-owned-local.mp3'],
    ['Direct', 'music/native-opaque-direct.mp3'], ['Relay', 'music/master-ingress-follower-relay.mp3']]) {
    const source = nativePlans.get(template).source_url;
    const path = `music/empty-${label}.mp3`;
    const emptyRecord = {source, ciphertext: new Uint8Array(), emptyResponse: true};
    records.set(`empty-${label}`, emptyRecord);
    nativePlans.set(path, {...nativePlans.get(template), size_bytes: 0, filename: `empty-${label}.mp3`});
    const entries = [{media_path: path, native_source: true, resource_id: plainResource, object_id: plainObject, size_bytes: 0}];
    await page.FrontierMediaCrypto.prepareCatalog(entries);
    for (const method of ['GET', 'HEAD']) {
        const count = cipherRequests.length;
        const empty = await workerFetch(entries[0].url, {method});
        assert.equal(empty.status, 200, `${label} empty ${method}`);
        assert.equal(empty.headers.get('Content-Length'), '0');
        assert.equal((await empty.arrayBuffer()).byteLength, 0);
        assert.equal(cipherRequests.length, count + 1, 'empty object requires a live owner request');
        const startRange = await workerFetch(entries[0].url, {method, headers: {Range: 'bytes=0-0'}});
        assert.equal(startRange.status, 200);
        assert.equal(startRange.headers.get('Content-Length'), '0');
        const suffixRange = await workerFetch(entries[0].url, {method, headers: {Range: 'bytes=-1'}});
        assert.equal(suffixRange.status, 206);
        assert.equal(suffixRange.headers.get('Content-Range'), 'bytes 0--1/0');
        emptyRecord.nginxMedia = true;
        const nginxSuffix = await workerFetch(entries[0].url, {method, headers: {Range: 'bytes=-1'}});
        assert.equal(nginxSuffix.status, 200);
        assert.equal(nginxSuffix.headers.get('Content-Range'), null);
        assert.equal(nginxSuffix.headers.get('Content-Length'), '0');
        emptyRecord.nginxMedia = false;
    }
    emptyRecord.ciphertext = new Uint8Array([42]);
    const invalid = await workerFetch(entries[0].url);
    assert.notEqual(invalid.status, 200, `${label} nonempty body cannot satisfy an empty grant`);
    records.delete(`empty-${label}`);
}
nativePlans.set('music/master-owned-local-bad.mp3', {...nativePlans.get('music/master-owned-local.mp3'),
    source_url: 'https://cloud.example/api/v1/media/master-local/' + plainObject});
const badLocalMediaCatalog = [{media_path: 'music/master-owned-local-bad.mp3', native_source: true, resource_id: plainResource,
    object_id: plainObject, size_bytes: plainBytes.length}];
await page.FrontierMediaCrypto.prepareCatalog(badLocalMediaCatalog);
const beforeBadLocalMedia = cipherRequests.length;
response = await workerFetch(badLocalMediaCatalog[0].url);
assert.equal(response.status, 403);
assert.equal(cipherRequests.length, beforeBadLocalMedia, 'Local media alias mismatch must not be fetched');
const localEncryptedMedia = await prepare(plainBytes, 'music/encrypted-opaque-local.mp3', opaqueLocalMediaURL);
localEncryptedMedia.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
localEncryptedMedia.sourceTransport = 'Local';
localEncryptedMedia.opaqueMedia = {resource_id: plainResource, object_id: plainObject, alias: opaqueLocalMediaAlias};
const encryptedLocalMediaCatalog = [{media_path: 'music/encrypted-opaque-local.mp3', native_source: true, source_identity_version: 1, resource_id: plainResource,
    object_id: plainObject, size_bytes: localEncryptedMedia.meta.ciphertext_size, encryption: localEncryptedMedia.meta}];
await page.FrontierMediaCrypto.prepareCatalog(encryptedLocalMediaCatalog);
response = await workerFetch(encryptedLocalMediaCatalog[0].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), plainBytes);
assert.equal(cipherRequests.at(-1).url, opaqueLocalMediaURL);

const changedDescriptorPath = 'music/opaque-catalog-change.mp3';
const changedDescriptorAlias = 'd'.repeat(64);
const changedDescriptorURL = `https://owner.example/internal/v1/opaque-media/${changedDescriptorAlias}`;
const changedDescriptorRecord = await prepare(new Uint8Array(32).fill(21), changedDescriptorPath, changedDescriptorURL);
changedDescriptorRecord.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
changedDescriptorRecord.sourceTransport = 'Direct'; changedDescriptorRecord.sourceOrigin = 'https://owner.example';
changedDescriptorRecord.opaqueMedia = {resource_id: plainResource, object_id: plainObject, alias: changedDescriptorAlias};
const descriptorEntry = {media_path: changedDescriptorPath, native_source: true, source_identity_version: 1,
    resource_id: plainResource, object_id: plainObject, size_bytes: changedDescriptorRecord.meta.ciphertext_size,
    encryption: changedDescriptorRecord.meta};
await page.FrontierMediaCrypto.prepareCatalog([descriptorEntry]);
let descriptorResponse = await workerFetch(descriptorEntry.url);
assert.equal((await descriptorResponse.arrayBuffer()).byteLength, 32);
const changedDescriptorEntry = {...descriptorEntry, encryption: {...changedDescriptorRecord.meta,
    nonce_prefix: common.encode(new Uint8Array(8).fill(42))}};
const keysBeforeDescriptorChange = calls.filter(call => call.url.endsWith('/key')).length;
const readsBeforeDescriptorChange = cipherRequests.length;
await page.FrontierMediaCrypto.prepareCatalog([changedDescriptorEntry]);
descriptorResponse = await workerFetch(changedDescriptorEntry.url);
assert.equal(descriptorResponse.status, 403, 'changed descriptor cannot reuse a cached grant for the same file ID');
assert.equal(calls.filter(call => call.url.endsWith('/key')).length, keysBeforeDescriptorChange + 1,
    'catalog descriptor change forces a fresh Master authorization');
assert.equal(cipherRequests.length, readsBeforeDescriptorChange, 'changed descriptor does not read stale bytes');
await assert.rejects(page.FrontierMediaCrypto.prepareCatalog([{media_path: changedDescriptorPath, url: '/legacy'}]),
    /媒体身份版本已变化/, 'a same-path catalog refresh cannot drop the opaque identity version');

// Deliver the two invalidation acknowledgements out of order. A slower old
// catalogue response must not install its descriptor after the newer one.
const raceOlder = {...descriptorEntry, encryption: {...changedDescriptorRecord.meta,
    nonce_prefix: common.encode(new Uint8Array(8).fill(43))}};
const raceNewer = {...descriptorEntry, encryption: {...changedDescriptorRecord.meta,
    nonce_prefix: common.encode(new Uint8Array(8).fill(44))}};
const originalPostMessage = controller.postMessage;
const heldAcknowledgements = [];
let announceBothAcknowledgements;
const bothAcknowledgements = new Promise(resolve => { announceBothAcknowledgements = resolve; });
try {
    controller.postMessage = function(data, ports = []) {
        if (data.type === 'fc-crypto-invalidate' && data.file_path === changedDescriptorPath) {
            const port = ports[0];
            return originalPostMessage.call(this, data, [{postMessage(value) {
                heldAcknowledgements.push(() => port.postMessage(value));
                if (heldAcknowledgements.length === 2) announceBothAcknowledgements();
            }}]);
        }
        return originalPostMessage.call(this, data, ports);
    };
    const olderResult = page.FrontierMediaCrypto.prepareCatalog([raceOlder]).then(() => null, error => error);
    const newerResult = page.FrontierMediaCrypto.prepareCatalog([raceNewer]);
    let barrierTimeout;
    try {
        await Promise.race([bothAcknowledgements, new Promise((_, reject) => {
            barrierTimeout = setTimeout(() => reject(new Error('catalog invalidation barrier timed out')), 10000);
        })]);
    } finally { clearTimeout(barrierTimeout); }
    assert.equal(heldAcknowledgements.length, 2);
    heldAcknowledgements[1]();
    await newerResult;
    heldAcknowledgements[0]();
    assert.match((await olderResult).message, /媒体目录已更新/);
} finally {
    controller.postMessage = originalPostMessage;
}
const invalidationsBeforeRaceCheck = controllerMessages.filter(type => type === 'fc-crypto-invalidate').length;
await page.FrontierMediaCrypto.prepareCatalog([{...raceNewer}]);
assert.equal(controllerMessages.filter(type => type === 'fc-crypto-invalidate').length, invalidationsBeforeRaceCheck,
    'the newest descriptor remains installed after out-of-order acknowledgements');

// A key response already in flight cannot repopulate the page envelope cache
// after the matching catalogue descriptor has changed.
await page.FrontierMediaCrypto.prepareCatalog([{...descriptorEntry}]);
const originalPageFetch = page.fetch;
let releaseKey, announceKey;
const keyStarted = new Promise(resolve => { announceKey = resolve; });
const keyReleased = new Promise(resolve => { releaseKey = resolve; });
try {
    page.fetch = async (input, init) => {
        const result = await originalPageFetch(input, init);
        if (String(input).endsWith('/key') && JSON.parse(init.body).file_path === changedDescriptorPath) {
            announceKey();
            await keyReleased;
        }
        return result;
    };
    const inFlight = workerFetch(descriptorEntry.url);
    await keyStarted;
    await page.FrontierMediaCrypto.prepareCatalog([{...changedDescriptorEntry}]);
    releaseKey();
    assert.equal((await inFlight).status, 409, 'stale page authorization is rejected after catalogue change');
} finally {
    releaseKey?.();
    page.fetch = originalPageFetch;
}
await page.FrontierMediaCrypto.prepareCatalog([{...descriptorEntry}]);
const keysAfterRace = calls.filter(call => call.url.endsWith('/key')).length;
assert.equal((await workerFetch(descriptorEntry.url)).status, 200);
assert.equal(calls.filter(call => call.url.endsWith('/key')).length, keysAfterRace + 1,
    'the rejected response did not repopulate the page envelope cache');

// Independently exercise the worker boundary even if a page were to provide
// a malformed non-Native Master Local grant. The opaque endpoint itself is a
// new-tree marker, so removing both transport and owner cannot downgrade it.
worker.savedRequestGrant = vm.runInContext('requestGrant', worker);
try {
    vm.runInContext('requestGrant = async () => globalThis.forgedGrant', worker);
    worker.forgedGrant = {encryption: localEncryptedMedia.meta, key: fileKey,
        source_url: opaqueLocalMediaURL, source_headers: {'X-Media-Capability': 'payload.signature'},
        source_transport: 'Local', kind: 'media', resource_id: plainResource, object_id: plainObject,
        source_object_id: opaqueLocalMediaAlias, source_revision: 'b'.repeat(64),
        deadline: common.monotonicNow() + 60000};
    await assert.rejects(vm.runInContext(`getGrant('${'a'.repeat(32)}', 'forged-local-owner')`, worker),
        'opaque Master Local grant cannot omit the Native marker and owner');
    worker.forgedGrant = {...worker.forgedGrant, source_object_id: undefined};
    await assert.rejects(vm.runInContext(`getGrant('${'a'.repeat(32)}', 'forged-local-alias')`, worker),
        'opaque endpoint cannot omit both the alias and owner identity');
} finally {
    vm.runInContext('requestGrant = globalThis.savedRequestGrant', worker);
    delete worker.savedRequestGrant;
    delete worker.forgedGrant;
}

// An encrypted stream must never join chunks or reuse cached ciphertext after
// the authenticated placement changes or a server omits its identity fields.
const encryptedIdentityMutations = [
    ['owner', {source_owner_id: 'c'.repeat(32)}],
    ['revision', {source_revision: 'c'.repeat(64)}],
    ['alias', {source_object_id: 'c'.repeat(64)}],
    ['resource', {resource_id: 'c'.repeat(64)}],
    ['object', {object_id: 'c'.repeat(64)}],
    ['owner-deleted', {source_owner_id: undefined}],
    ['alias-deleted', {source_object_id: undefined}],
    ['native-marker-deleted', {transport: undefined}],
    ['identity-version-deleted', {source_identity_version: undefined}],
    ['all-native-fields-deleted', {transport: undefined, source_headers: undefined, source_transport: undefined,
        source_owner_id: undefined, source_object_id: undefined, source_revision: undefined,
        source_url: '/api/v1/media/stream?file_path=legacy'}],
    ['descriptor', record => ({encryption: {...record.meta, nonce_prefix: common.encode(new Uint8Array(8).fill(44))}})],
];
for (const [index, [label, changed]] of encryptedIdentityMutations.entries()) {
    const alias = (index + 101).toString(16).padStart(64, '0');
    const path = `music/opaque-continuation-${label}.mp3`;
    const url = `https://owner.example/internal/v1/opaque-media/${alias}`;
    const record = await prepare(new Uint8Array(1048577).fill(47), path, url);
    record.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
    record.sourceTransport = 'Direct'; record.sourceOrigin = 'https://owner.example';
    record.opaqueMedia = {resource_id: plainResource, object_id: plainObject, alias};
    record.onFetch = start => {
        if (start === 0) { record.keyResponseOverride = typeof changed === 'function' ? changed(record) : changed; advance(111000); }
    };
    const entries = [{media_path: path, native_source: true, source_identity_version: 1, resource_id: plainResource,
        object_id: plainObject, size_bytes: record.meta.ciphertext_size, encryption: record.meta}];
    await page.FrontierMediaCrypto.prepareCatalog(entries);
    const before = cipherRequests.length;
    const partial = await workerFetch(entries[0].url);
    await assert.rejects(partial.arrayBuffer(), `${label} change rejects the continuation`);
    assert.equal(cipherRequests.slice(before).filter(request => request.url === url).length, 1,
        `${label} change never fetches a subsequent chunk`);
}
for (const [index, [label, changed]] of encryptedIdentityMutations.entries()) {
    const alias = (index + 201).toString(16).padStart(64, '0');
    const path = `music/opaque-cache-${label}.mp3`;
    const url = `https://owner.example/internal/v1/opaque-media/${alias}`;
    const record = await prepare(new Uint8Array(32).fill(29), path, url);
    record.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
    record.sourceTransport = 'Direct'; record.sourceOrigin = 'https://owner.example';
    record.opaqueMedia = {resource_id: plainResource, object_id: plainObject, alias};
    const entries = [{media_path: path, native_source: true, source_identity_version: 1, resource_id: plainResource,
        object_id: plainObject, size_bytes: record.meta.ciphertext_size, encryption: record.meta}];
    await page.FrontierMediaCrypto.prepareCatalog(entries);
    let result = await workerFetch(entries[0].url);
    assert.equal((await result.arrayBuffer()).byteLength, 32);
    record.keyResponseOverride = typeof changed === 'function' ? changed(record) : changed;
    const before = cipherRequests.length;
    result = await workerFetch(entries[0].url);
    await assert.rejects(result.arrayBuffer(), `${label} change rejects cached ciphertext`);
    assert.equal(cipherRequests.length, before, `${label} change does not fetch a substitute source`);
}
for (const [index, [label, changed]] of encryptedIdentityMutations.filter(([name]) => !['owner', 'revision'].includes(name)).entries()) {
    const alias = (index + 401).toString(16).padStart(64, '0');
    const path = `music/opaque-first-${label}.mp3`;
    const url = `https://owner.example/internal/v1/opaque-media/${alias}`;
    const record = await prepare(new Uint8Array(32).fill(31), path, url);
    record.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
    record.sourceTransport = 'Direct'; record.sourceOrigin = 'https://owner.example';
    record.opaqueMedia = {resource_id: plainResource, object_id: plainObject, alias};
    record.keyResponseOverride = typeof changed === 'function' ? changed(record) : changed;
    const entries = [{media_path: path, native_source: true, source_identity_version: 1, resource_id: plainResource,
        object_id: plainObject, size_bytes: record.meta.ciphertext_size, encryption: record.meta}];
    await page.FrontierMediaCrypto.prepareCatalog(entries);
    const before = cipherRequests.length;
    const result = await workerFetch(entries[0].url);
    assert(result.status >= 400, `${label} is rejected on the first grant`);
    assert.equal(cipherRequests.length, before, `${label} never reaches a substitute endpoint`);
}
nativePlans.set('lyrics/native-opaque-local-wrong.lrc', {...nativePlans.get('lyrics/native-opaque-local.lrc'), source_url: 'https://other.example/api/v1/media/master-local-lyric/' + opaqueRelayLyricAlias});
const beforeWrongLocal = cipherRequests.length;
await assert.rejects(page.FrontierMediaCrypto.plainTextFor({file_path: 'lyrics/native-opaque-local-wrong.lrc', resource_id: opaqueRelayLyricID,
    object_id: opaqueRelayLyricID, track_resource_id: lyricTrackID, size_bytes: lyricBytes.length}));
assert.equal(cipherRequests.length, beforeWrongLocal, 'Local lyric cannot target another origin');
for (const [mode, alias, source] of [
    ['Direct', 'b'.repeat(64), 'https://master.example/api/v1/media/master-direct-lyric/' + 'b'.repeat(64)],
    ['Relay', 'c'.repeat(64), 'https://cloud.example/api/v1/media/master-relay/' + 'c'.repeat(64)],
    ['Local', 'f'.repeat(64), 'https://cloud.example/api/v1/media/master-local-lyric/' + 'f'.repeat(64)],
]) {
    const filename = `lyrics/encrypted-opaque-${mode.toLowerCase()}.lrc`, id = mode === 'Direct' ? 'd'.repeat(64) : 'e'.repeat(64);
    const record = await prepare(lyricBytes, filename, source);
    record.sourceHeaders = {[mode === 'Relay' ? 'X-Media-Relay' : 'X-Media-Capability']: 'payload.signature'};
    record.sourceTransport = mode;
    if (mode === 'Direct') record.sourceOrigin = 'https://master.example';
    record.opaqueLyric = {resource_id: id, object_id: id, track_resource_id: lyricTrackID, alias};
    assert.equal(await page.FrontierMediaCrypto.lyricTextFor({file_path: filename, native_source: true, source_identity_version: 1, encrypted: true,
        resource_id: id, object_id: id, track_resource_id: lyricTrackID, size_bytes: record.meta.ciphertext_size, encryption: record.meta}), '[00:01.00] example\n');
    assert.equal(cipherRequests.at(-1).url, source);
    assert.equal(calls.filter(call => call.url.endsWith('/key')).at(-1).body.track_resource_id, lyricTrackID);
    const beforeWrongTrack = cipherRequests.length;
    await assert.rejects(page.FrontierMediaCrypto.lyricTextFor({file_path: filename, native_source: true, encrypted: true,
        resource_id: id, object_id: id, track_resource_id: '4'.repeat(64), size_bytes: record.meta.ciphertext_size, encryption: record.meta}));
    assert.equal(cipherRequests.length, beforeWrongTrack, 'unrelated track must not reuse an encrypted lyric grant');
}
const badEncryptedLyricPath = 'lyrics/encrypted-opaque-mismatch.lrc', badEncryptedLyricID = 'f'.repeat(64);
const badEncryptedLyric = await prepare(lyricBytes, badEncryptedLyricPath, 'https://master.example/api/v1/media/master-direct-lyric/' + '1'.repeat(64));
badEncryptedLyric.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
badEncryptedLyric.sourceTransport = 'Direct'; badEncryptedLyric.sourceOrigin = 'https://master.example';
badEncryptedLyric.opaqueLyric = {resource_id: badEncryptedLyricID, object_id: badEncryptedLyricID, track_resource_id: lyricTrackID, alias: '2'.repeat(64)};
const beforeBadEncryptedLyric = cipherRequests.length;
await assert.rejects(page.FrontierMediaCrypto.lyricTextFor({file_path: badEncryptedLyricPath, native_source: true, encrypted: true,
    resource_id: badEncryptedLyricID, object_id: badEncryptedLyricID, track_resource_id: lyricTrackID,
    size_bytes: badEncryptedLyric.meta.ciphertext_size, encryption: badEncryptedLyric.meta}));
assert.equal(cipherRequests.length, beforeBadEncryptedLyric, 'encrypted lyric alias mismatch must not be fetched');
const relayLyricID = '4'.repeat(64), relayLyricURL = 'https://cloud.example/api/v1/media/master-relay/' + relayLyricID;
records.set('native-relay-lyric', {source: relayLyricURL, ciphertext: lyricBytes});
nativePlans.set('lyrics/native-relay.lrc', {...nativePlans.get('lyrics/native.lrc'), resource_id: relayLyricID, object_id: relayLyricID,
    source_url: relayLyricURL, source_headers: {'X-Media-Relay': 'payload.signature'}, source_transport: 'Relay', source_origin: undefined});
assert.equal(await page.FrontierMediaCrypto.plainTextFor({file_path: 'lyrics/native-relay.lrc', resource_id: relayLyricID,
    object_id: relayLyricID, size_bytes: lyricBytes.length}), '[00:01.00] example\n');
assert.equal(cipherRequests.at(-1).relay, 'payload.signature');
await assert.rejects(page.FrontierMediaCrypto.plainTextFor({file_path: 'lyrics/native.lrc', resource_id: lyricID,
    object_id: plainObject, size_bytes: lyricBytes.length}), /歌词身份无效/);
const longPlain = new Uint8Array(1048580).fill(37);
const longPlainURL = 'https://master.example/api/v1/media/master-direct/' + '6'.repeat(64);
const longPlan = {...nativePlans.get('music/native-plain.mp3'), resource_id: '6'.repeat(64), size_bytes: longPlain.length, source_url: longPlainURL};
nativePlans.set('music/native-changing.mp3', longPlan);
records.set('native-changing', {source: longPlainURL, ciphertext: longPlain, onFetch(start) {
    if (start === 0) { nativePlans.set('music/native-changing.mp3', {...longPlan, source_revision: 'a'.repeat(64)}); advance(111000); }
}});
const changingCatalog = [{media_path: 'music/native-changing.mp3', native_source: true, resource_id: '6'.repeat(64),
    object_id: plainObject, size_bytes: longPlain.length}];
await page.FrontierMediaCrypto.prepareCatalog(changingCatalog);
response = await workerFetch(changingCatalog[0].url);
await assert.rejects(response.arrayBuffer(), /媒体对象已变化/, 'renewal never joins bytes from different revisions');

// Simulate a normally progressing playback across more than 30 minutes. This
// tests the existing chunk/reauthorization path, not a stalled-read retry: no
// source request is interrupted and no request silently switches transport.
const longRunningBytes = new Uint8Array(17 * 1048576).fill(73);
const longRunningURL = 'https://master.example/api/v1/media/master-direct/' + '5'.repeat(64);
const longRunningPath = 'music/native-long-running.mp3';
nativePlans.set(longRunningPath, {...longPlan, resource_id: '5'.repeat(64), size_bytes: longRunningBytes.length,
    source_url: longRunningURL});
records.set('native-long-running', {source: longRunningURL, ciphertext: longRunningBytes,
    onFetch() { advance(111000); }});
const longRunningCatalog = [{media_path: longRunningPath, native_source: true, resource_id: '5'.repeat(64),
    object_id: plainObject, size_bytes: longRunningBytes.length}];
const beforeLongSessions = nextSession, beforeLongRequests = cipherRequests.length, beforeLongTime = elapsed;
await page.FrontierMediaCrypto.prepareCatalog(longRunningCatalog);
response = await workerFetch(longRunningCatalog[0].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), longRunningBytes,
    'a normally progressing stream preserves every byte across grant and session renewals');
assert(elapsed - beforeLongTime > 30 * 60 * 1000, 'the simulated stream crosses the 30-minute boundary');
assert(nextSession - beforeLongSessions >= 2, 'a fresh browser crypto session was required');
const longRequests = cipherRequests.slice(beforeLongRequests);
assert.equal(longRequests.length, 17, 'the player uses bounded chunks instead of one long source request');
for (let index = 0; index < longRequests.length; index++) {
    assert.equal(longRequests[index].url, longRunningURL, 'reauthorization retains the chosen source');
    assert.equal(longRequests[index].range, `bytes=${index * 1048576}-${(index + 1) * 1048576 - 1}`);
}
// A later invalidation must fence even an authorization response that was
// already pending. A new request must not reuse that old pending promise.
const raceToken = new URL(longRunningCatalog[0].url, 'https://cloud.example').pathname.split('/')[2];
const racePath = 'music/pending-catalog-change.mp3';
let hijackResult;
await worker.registerCapability({source: {id: 'other-tab'}, ports: [{postMessage(value) { hijackResult = value; }}]}, {token: raceToken});
assert(hijackResult?.error, 'another page cannot replace a live capability owner');
assert.equal(vm.runInContext(`capabilities.get('${raceToken}')?.clientId`, worker), 'browser-tab');
let resolveOld, resolveNew, startedOld, startedNew;
const oldStarted = new Promise(resolve => { startedOld = resolve; });
const newStarted = new Promise(resolve => { startedNew = resolve; });
const oldGrant = new Promise(resolve => { resolveOld = resolve; });
const newGrant = new Promise(resolve => { resolveNew = resolve; });
let issued = 0;
worker.savedRequestGrant = vm.runInContext('requestGrant', worker);
worker.nextPendingGrant = () => { issued++; if (issued === 1) { startedOld(); return oldGrant; } startedNew(); return newGrant; };
try {
    vm.runInContext('requestGrant = async () => globalThis.nextPendingGrant()', worker);
    const input = `getGrant('${raceToken}', '${racePath}', '', 'browser-tab', true)`;
    const stale = vm.runInContext(input, worker).then(value => ({value}), error => ({error}));
    await oldStarted;
    let invalidated;
    const invalidation = {data: {type: 'fc-crypto-invalidate', token: raceToken, file_path: racePath},
        source: client, ports: [{postMessage(value) { invalidated = value; }}]};
    for (const listener of workerListeners.get('message')) listener(invalidation);
    assert.equal(invalidated?.ok, true);
    const current = vm.runInContext(input, worker);
    await newStarted;
    const makeGrant = owner => ({transport: 'Native', kind: 'media', resource_id: plainResource, object_id: plainObject,
        source_revision: '9'.repeat(64), source_url: plainURL, source_headers: {'X-Media-Capability': 'payload.signature'},
        source_transport: 'Direct', source_origin: 'https://master.example', size_bytes: plainBytes.length,
        filename: owner, deadline: common.monotonicNow() + 60000});
    resolveNew(makeGrant('new'));
    assert.equal((await current).filename, 'new');
    resolveOld(makeGrant('old'));
    assert.equal((await stale).error?.status, 409, 'late old authorization is rejected after invalidation');
    assert.equal(vm.runInContext(`grants.get('${raceToken}:${racePath}:')?.filename`, worker), 'new',
        'late authorization cannot overwrite the new cache');
} finally {
    vm.runInContext('requestGrant = globalThis.savedRequestGrant', worker);
    delete worker.savedRequestGrant;
    delete worker.nextPendingGrant;
}
for (const previouslyRegistered of [true, false]) {
    const revokedToken = (previouslyRegistered ? 'e' : 'f').repeat(32);
    if (previouslyRegistered) await worker.registerCapability({source: client, ports: []}, {token: revokedToken});
    let release, announce;
    const started = new Promise(resolve => { announce = resolve; });
    const delayed = new Promise(resolve => { release = resolve; });
    worker.savedRequestGrant = vm.runInContext('requestGrant', worker);
    worker.pendingRevokedGrant = () => { announce(); return delayed; };
    try {
        vm.runInContext('requestGrant = async () => globalThis.pendingRevokedGrant()', worker);
        const pending = vm.runInContext(`getGrant('${revokedToken}', '${racePath}', '', 'browser-tab', true)`, worker)
            .then(value => ({value}), error => ({error}));
        await started;
        for (const listener of workerListeners.get('message')) listener({data: {type: 'fc-crypto-revoke', token: revokedToken}, source: client, ports: []});
        release({transport: 'Native', kind: 'media', resource_id: plainResource, object_id: plainObject,
            source_revision: '9'.repeat(64), source_url: plainURL, source_headers: {'X-Media-Capability': 'payload.signature'},
            source_transport: 'Direct', source_origin: 'https://master.example', size_bytes: plainBytes.length,
            deadline: common.monotonicNow() + 60000});
        assert.equal((await pending).error?.status, 409, 'pagehide fences a late grant, including after worker restart');
        assert.equal(vm.runInContext(`capabilities.has('${revokedToken}')`, worker), false);
        assert.equal(vm.runInContext(`grants.has('${revokedToken}:${racePath}:')`, worker), false);
    } finally {
        vm.runInContext('requestGrant = globalThis.savedRequestGrant', worker);
        delete worker.savedRequestGrant;
        delete worker.pendingRevokedGrant;
    }
}
for (const [index, [label, changed]] of [
    ['owner', {source_owner_id: 'c'.repeat(32)}], ['revision', {source_revision: 'c'.repeat(64)}],
    ['alias', {source_object_id: 'c'.repeat(64)}], ['owner-deleted', {source_owner_id: undefined}],
    ['alias-deleted', {source_object_id: undefined}], ['native-marker-deleted', {transport: undefined}],
].entries()) {
    const alias = (index + 301).toString(16).padStart(64, '0');
    const path = `music/native-continuation-${label}.mp3`;
    const url = `https://owner.example/internal/v1/opaque-media/${alias}`;
    const plan = {...longPlan, resource_id: '5'.repeat(64), size_bytes: longPlain.length,
        source_url: url, source_origin: 'https://owner.example', source_identity_version: 1, source_object_id: alias, source_owner_id: 'a'.repeat(32)};
    nativePlans.set(path, plan);
    records.set(`native-continuation-${label}`, {source: url, ciphertext: longPlain,
        onFetch(start) { if (start === 0) { nativePlans.set(path, {...plan, ...changed}); advance(111000); } }});
    const entries = [{media_path: path, native_source: true, source_identity_version: 1, resource_id: '5'.repeat(64), object_id: plainObject,
        size_bytes: longPlain.length}];
    await page.FrontierMediaCrypto.prepareCatalog(entries);
    const before = cipherRequests.length;
    const partial = await workerFetch(entries[0].url);
    await assert.rejects(partial.arrayBuffer(), `${label} change rejects the plaintext continuation`);
    assert.equal(cipherRequests.slice(before).filter(request => request.url === url).length, 1,
        `${label} change never fetches a subsequent plaintext chunk`);
}
for (const [index, [label, changed]] of [
    ['version-deleted', {source_identity_version: undefined}],
    ['alias-deleted', {source_object_id: undefined}],
    ['full-legacy-downgrade', {source_identity_version: undefined, source_object_id: undefined,
        source_owner_id: undefined, source_url: plainURL, source_origin: 'https://master.example'}],
].entries()) {
    const alias = (index + 501).toString(16).padStart(64, '0');
    const path = `music/native-first-${label}.mp3`;
    const url = `https://owner.example/internal/v1/opaque-media/${alias}`;
    nativePlans.set(path, {...nativePlans.get('music/native-plain.mp3'), source_url: url,
        source_origin: 'https://owner.example', source_identity_version: 1, source_object_id: alias,
        source_owner_id: 'a'.repeat(32), ...changed});
    const entries = [{media_path: path, native_source: true, source_identity_version: 1, resource_id: plainResource,
        object_id: plainObject, size_bytes: plainBytes.length}];
    await page.FrontierMediaCrypto.prepareCatalog(entries);
    const before = cipherRequests.length;
    const result = await workerFetch(entries[0].url);
    assert(result.status >= 400, `${label} rejects the first opaque plaintext grant`);
    assert.equal(cipherRequests.length, before, `${label} never fetches an old or new source`);
}
const invalidNative = {...nativePlans.get('music/native-plain.mp3'), source_origin: 'https://other.example'};
nativePlans.set('music/native-invalid.mp3', invalidNative);
const invalidNativeCatalog = [{media_path: 'music/native-invalid.mp3', native_source: true, resource_id: plainResource,
    object_id: plainObject, size_bytes: plainBytes.length}];
await page.FrontierMediaCrypto.prepareCatalog(invalidNativeCatalog);
const beforeNativeFailure = cipherRequests.length;
response = await workerFetch(invalidNativeCatalog[0].url);
assert.equal(response.status, 403);
assert.equal(cipherRequests.length, beforeNativeFailure, 'invalid Direct origin never falls back to Relay');
const directRecord = await prepare(guardedBytes, 'music/master-direct.mp3', directURL);
directRecord.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
directRecord.sourceTransport = 'Direct'; directRecord.sourceOrigin = 'https://master.example';
const directCatalog = [{media_path: 'music/master-direct.mp3', encryption: directRecord.meta}];
await page.FrontierMediaCrypto.prepareCatalog(directCatalog);
response = await workerFetch(directCatalog[0].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), guardedBytes);
assert.equal(cipherRequests.at(-1).url, directURL);
assert.equal(cipherRequests.at(-1).credentials, 'omit', 'Direct never sends ingress cookies to Master');
assert.equal(cipherRequests.at(-1).redirect, 'error', 'Direct never follows a redirect with its capability');

for (const [name, source] of [
    ['follower-direct', 'https://owner.example/internal/v1/media/' + 'e'.repeat(64)],
    ['master-direct-lyric', 'https://master.example/api/v1/media/master-direct-lyric/' + 'f'.repeat(64)],
]) {
    const record = await prepare(guardedBytes, 'music/' + name + '.mp3', source);
    record.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
    record.sourceTransport = 'Direct'; record.sourceOrigin = new URL(source).origin;
    const catalog = [{media_path: 'music/' + name + '.mp3', encryption: record.meta}];
    await page.FrontierMediaCrypto.prepareCatalog(catalog);
    response = await workerFetch(catalog[0].url);
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), guardedBytes);
    assert.equal(cipherRequests.at(-1).url, source);
    assert.equal(cipherRequests.at(-1).capability, 'payload.signature');
    assert.equal(cipherRequests.at(-1).credentials, 'omit');
    assert.equal(cipherRequests.at(-1).redirect, 'error');
}

const wrongDirectOrigin = await prepare(guardedBytes, 'music/direct-origin-mismatch.mp3', 'https://owner.example/internal/v1/media/' + 'e'.repeat(64));
wrongDirectOrigin.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
wrongDirectOrigin.sourceTransport = 'Direct'; wrongDirectOrigin.sourceOrigin = 'https://other.example';
const wrongDirectCatalog = [{media_path: 'music/direct-origin-mismatch.mp3', encryption: wrongDirectOrigin.meta}];
await page.FrontierMediaCrypto.prepareCatalog(wrongDirectCatalog);
const beforeWrongDirect = cipherRequests.length;
response = await workerFetch(wrongDirectCatalog[0].url);
assert.equal(response.status, 403, 'Direct source must match the explicitly authorized origin');
assert.equal(cipherRequests.length, beforeWrongDirect);

const relayURL = 'https://cloud.example/api/v1/media/master-relay/' + 'd'.repeat(64);
const relayRecord = await prepare(guardedBytes, 'music/master-relay.mp3', relayURL);
relayRecord.sourceHeaders = {'X-Media-Relay': 'payload.signature'};
relayRecord.sourceTransport = 'Relay';
const relayCatalog = [{media_path: 'music/master-relay.mp3', encryption: relayRecord.meta}];
await page.FrontierMediaCrypto.prepareCatalog(relayCatalog);
response = await workerFetch(relayCatalog[0].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), guardedBytes);
assert.equal(cipherRequests.at(-1).url, relayURL, 'Relay stays on the selected ingress');
assert.equal(cipherRequests.at(-1).relay, 'payload.signature');
assert.equal(cipherRequests.at(-1).credentials, 'omit');
assert.equal(cipherRequests.at(-1).redirect, 'error');

const followerRelayURL = 'https://cloud.example/api/v1/media/follower-relay/' + 'e'.repeat(64);
const followerRelayRecord = await prepare(guardedBytes, 'music/follower-relay.mp3', followerRelayURL);
followerRelayRecord.sourceHeaders = {'X-Media-Relay': 'payload.signature'};
followerRelayRecord.sourceTransport = 'Relay';
const followerRelayCatalog = [{media_path: 'music/follower-relay.mp3', encryption: followerRelayRecord.meta}];
await page.FrontierMediaCrypto.prepareCatalog(followerRelayCatalog);
response = await workerFetch(followerRelayCatalog[0].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), guardedBytes);
assert.equal(cipherRequests.at(-1).url, followerRelayURL);
assert.equal(cipherRequests.at(-1).relay, 'payload.signature');
assert.equal(cipherRequests.at(-1).credentials, 'omit');
assert.equal(cipherRequests.at(-1).redirect, 'error');

const opaqueRelayURL = 'https://cloud.example/api/v1/media/opaque-follower-relay/' + 'f'.repeat(64);
const opaqueRelayRecord = await prepare(guardedBytes, 'music/opaque-relay.mp3', opaqueRelayURL);
opaqueRelayRecord.sourceHeaders = {'X-Media-Relay': 'payload.signature'};
opaqueRelayRecord.sourceTransport = 'Relay';
opaqueRelayRecord.opaqueMedia = {resource_id: '7'.repeat(64), object_id: '8'.repeat(64), alias: 'f'.repeat(64)};
const opaqueRelayCatalog = [{media_path: 'music/opaque-relay.mp3', native_source: true, source_identity_version: 1, resource_id: '7'.repeat(64),
    object_id: '8'.repeat(64), encryption: opaqueRelayRecord.meta}];
await page.FrontierMediaCrypto.prepareCatalog(opaqueRelayCatalog);
response = await workerFetch(opaqueRelayCatalog[0].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), guardedBytes);
assert.equal(cipherRequests.at(-1).url, opaqueRelayURL);
assert.equal(cipherRequests.at(-1).relay, 'payload.signature');

const invalidDirect = await prepare(guardedBytes, 'music/master-direct-invalid.mp3', directURL + '?token=secret');
invalidDirect.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
invalidDirect.sourceTransport = 'Direct'; invalidDirect.sourceOrigin = 'https://master.example';
const invalidDirectCatalog = [{media_path: 'music/master-direct-invalid.mp3', encryption: invalidDirect.meta}];
await page.FrontierMediaCrypto.prepareCatalog(invalidDirectCatalog);
const beforeInvalidDirect = cipherRequests.length;
response = await workerFetch(invalidDirectCatalog[0].url);
assert.equal(response.status, 403, 'Direct capability never appears in a resource URL');
assert.equal(cipherRequests.length, beforeInvalidDirect);

const forgedRecord = await prepare(guardedBytes, 'music/forged-header.mp3', 'https://other.example/internal/v1/media/' + 'b'.repeat(64));
forgedRecord.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
const forgedCatalog = [{media_path: 'music/forged-header.mp3', encryption: forgedRecord.meta}];
await page.FrontierMediaCrypto.prepareCatalog(forgedCatalog);
const beforeForged = cipherRequests.length;
response = await workerFetch(forgedCatalog[0].url);
assert.equal(response.status, 403, 'header capability cannot be sent to another origin');
assert.equal(cipherRequests.length, beforeForged);

const legacy = await prepare(guardedBytes, 'music/old-page.mp3', 'https://cloud.example/relay/old-page');
const legacyCatalog = [{media_path: 'music/old-page.mp3', encryption: legacy.meta}];
await page.FrontierMediaCrypto.prepareCatalog(legacyCatalog);
response = await workerFetch(legacyCatalog[0].url);
await response.arrayBuffer();
const currentPageMessage = pageMessage;
pageMessage = event => {
    const port = event.ports[0], send = port.postMessage.bind(port);
    port.postMessage = value => { const previous = {...value}; delete previous.revalidated; send(previous); };
    currentPageMessage(event);
};
const beforeLegacy = cipherRequests.length;
response = await workerFetch(legacyCatalog[0].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), guardedBytes);
assert.equal(cipherRequests.length, beforeLegacy + 1,
    'a page without fresh-authorization acknowledgement must use normal source reads');
pageMessage = currentPageMessage;
vm.runInContext(`cipherChunks.clear(); cipherBytes = 0;
    for (let i = 0; i < 5; i++) rememberCipherChunk('bounded-' + i, new Uint8Array(8 * 1024 * 1024));`, worker);
assert.equal(vm.runInContext('cipherBytes', worker), 32 * 1024 * 1024);
assert.equal(vm.runInContext("cipherChunks.has('bounded-0')", worker), false, 'oldest ciphertext is evicted at the byte budget');
vm.runInContext("cachedCipherChunk('bounded-1'); rememberCipherChunk('bounded-5', new Uint8Array(8 * 1024 * 1024))", worker);
assert.equal(vm.runInContext("cipherChunks.has('bounded-1') && !cipherChunks.has('bounded-2')", worker), true,
    'cache hits protect recently used ciphertext from eviction');
advance(300001);
assert.equal(vm.runInContext("cachedCipherChunk('bounded-1')", worker), null, 'expired ciphertext must be fetched again');
assert.equal(vm.runInContext('cipherBytes', worker), 0);

// A v5 owner can return a bounded encrypted range without hashing the entire
// object first. The browser must still authenticate before releasing a byte.
const corruptOpaqueAlias = 'e'.repeat(64);
const corruptOpaquePath = 'music/opaque-corrupt-gcm.mp3';
const corruptOpaqueURL = `https://owner.example/internal/v1/opaque-media/${corruptOpaqueAlias}`;
const corruptOpaque = await prepare(new Uint8Array(32).fill(37), corruptOpaquePath, corruptOpaqueURL);
corruptOpaque.sourceHeaders = {'X-Media-Capability': 'payload.signature'};
corruptOpaque.sourceTransport = 'Direct';
corruptOpaque.sourceOrigin = 'https://owner.example';
corruptOpaque.opaqueMedia = {resource_id: plainResource, object_id: plainObject, alias: corruptOpaqueAlias};
corruptOpaque.ciphertext[1] ^= 1;
const corruptCatalog = [{media_path: corruptOpaquePath, native_source: true, source_identity_version: 1,
    resource_id: plainResource, object_id: plainObject, size_bytes: corruptOpaque.meta.ciphertext_size,
    encryption: corruptOpaque.meta}];
await page.FrontierMediaCrypto.prepareCatalog(corruptCatalog);
const beforeCorruptRead = cipherRequests.length;
const corruptResponse = await workerFetch(corruptCatalog[0].url);
await assert.rejects(corruptResponse.arrayBuffer(), 'corrupted v5 ciphertext never yields plaintext');
assert.equal(cipherRequests.length, beforeCorruptRead + 1);
assert.equal(cipherRequests.at(-1).range, `bytes=0-${corruptOpaque.meta.ciphertext_size - 1}`);
assert.equal((await workerFetch(corruptCatalog[0].url)).status, 422, 'corrupt chunk is a fatal integrity failure');

const personalPage = {...page, document: {getElementById: () => null}, location: new URL('https://cloud.example/karaoke/')};
personalPage.window = personalPage;
vm.createContext(personalPage);
vm.runInContext(source('media-crypto.js'), personalPage);
const storedLyrics = [{time: 7, text: 'first stored line'}, {time: 3, text: 'second stored line'}];
const footerJSON = Buffer.from(JSON.stringify({version: 1, title: 'Private song', lyrics: storedLyrics}));
const footerMarker = Buffer.from('FRONTIERCLOUD-KARAOKE-V1');
const footerLength = Buffer.alloc(8);
footerLength.writeBigUInt64BE(BigInt(footerJSON.length));
const sourceAudio = new Uint8Array(3 * common.CHUNK_SIZE + 31).fill(0x4f);
const packedRecording = Buffer.concat([sourceAudio, footerJSON, footerLength, footerMarker]);
async function privateRecording(id, packed, directSource) {
    const path = directSource?.url ?? `https://cloud.example/api/v1/karaoke/account/recordings/${id}/audio-bytes`;
    const record = await prepare(Uint8Array.from(packed), `fixture/recording-${id}.webm`, path);
    record.recordingRevision = createHash('sha256').update(record.ciphertext).digest('hex');
    record.recordingSource = directSource;
    let keyRequests = 0;
    return {record, keyRequests: () => keyRequests, authorize: async ({session_id: idOfSession}) => {
        keyRequests++;
        return {recording_id: id, encryption: record.meta, content_type: 'audio/webm', filename: 'private.webm',
            source_revision: record.recordingRevision, key_envelope: await envelope(sessions.get(idOfSession), record),
            ...(record.recordingSource ? {source: record.recordingSource} : {})};
    }};
}
const privateObject = await privateRecording(recordingID, packedRecording);
const beforeFooter = cipherRequests.length;
const privatePlayback = await personalPage.FrontierMediaCrypto.recordingPlayback(recordingID, privateObject.authorize);
assert.deepEqual(JSON.parse(JSON.stringify(privatePlayback.lyrics)), storedLyrics, 'restore lyric ordering exactly');
assert.equal(privateObject.keyRequests(), 1, 'footer and playback reuse the page session envelope');
const footerRequests = cipherRequests.slice(beforeFooter);
assert.equal(footerRequests.length, 1, 'a small footer reuses the single authenticated final chunk');
assert(footerRequests.every(request => Number(/^bytes=(\d+)-/.exec(request.range)[1]) >= 3 * (common.CHUNK_SIZE + common.TAG_SIZE)),
    'reading the recording footer never downloads the leading audio');
const beforeForeign = cipherRequests.length;
assert.equal((await workerFetch(privatePlayback.url, {headers: {Range: 'bytes=0-7'}}, 'different-tab')).status, 403);
assert.equal(cipherRequests.length, beforeForeign);
const privateRange = await workerFetch(privatePlayback.url, {headers: {Range: 'bytes=0-7'}});
assert.equal(privateRange.status, 206);
assert.deepEqual(new Uint8Array(await privateRange.arrayBuffer()), sourceAudio.slice(0, 8));

const hugeFooter = Buffer.from(footerLength);
hugeFooter.writeBigUInt64BE(BigInt(2 * 1024 * 1024 + 1));
const badFooterID = '5'.repeat(32);
const badFooter = await privateRecording(badFooterID, Buffer.concat([sourceAudio.slice(0, 32), hugeFooter, footerMarker]));
const beforeBadFooter = cipherRequests.length;
await assert.rejects(personalPage.FrontierMediaCrypto.recordingPlayback(badFooterID, badFooter.authorize), /录音元数据长度无效/);
assert.equal(cipherRequests.length, beforeBadFooter + 1, 'oversize footer is rejected before fetching its body');

const wideLyrics = Array.from({length: 272}, (_, index) => ({time: index, text: 'x'.repeat(4000)}));
const wideFooter = Buffer.from(JSON.stringify({version: 1, lyrics: wideLyrics}));
const wideLength = Buffer.alloc(8);
wideLength.writeBigUInt64BE(BigInt(wideFooter.length));
const wideID = '7'.repeat(32);
const wideObject = await privateRecording(wideID, Buffer.concat([sourceAudio.slice(0, 32), wideFooter, wideLength, footerMarker]));
const beforeWide = cipherRequests.length;
const widePlayback = await personalPage.FrontierMediaCrypto.recordingPlayback(wideID, wideObject.authorize);
assert.deepEqual(JSON.parse(JSON.stringify(widePlayback.lyrics)), wideLyrics);
assert.equal(cipherRequests.length, beforeWide + 2, 'a two-chunk footer reads each required ciphertext chunk once');

const privateDownload = await personalPage.FrontierMediaCrypto.recordingPlayback(recordingID, privateObject.authorize, true);
assert.match(privateDownload.url, /download=1/);
privateObject.record.etagOverride = '6'.repeat(64);
const changedPrivateRange = await workerFetch(privateDownload.url, {headers: {Range: 'bytes=0-7'}});
await assert.rejects(changedPrivateRange.arrayBuffer(), /录音密文身份不一致/);
personalPage.FrontierMediaCrypto.forgetRecordingPlayback();
assert.equal((await workerFetch(privatePlayback.url, {headers: {Range: 'bytes=0-7'}})).status, 403);

const directRecordingID = '8'.repeat(32);
const directRecordingOrigin = 'https://recording-owner.example';
const directRecordingAlias = '9'.repeat(64);
const directRecordingURL = `${directRecordingOrigin}/internal/v1/opaque-media/${directRecordingAlias}`;
const directRecordingSource = {transport: 'Direct', origin: directRecordingOrigin, url: directRecordingURL,
    alias: directRecordingAlias, owner_id: 'a'.repeat(32), capability: 'recording.signature', expires_in: 120};
const directAudio = sourceAudio.subarray(0, common.CHUNK_SIZE + 8);
const directRecording = await privateRecording(directRecordingID,
    Buffer.concat([directAudio, footerJSON, footerLength, footerMarker]), directRecordingSource);
const openDirectRecording = (download = false) => personalPage.FrontierMediaCrypto.recordingPlayback(
    directRecordingID, directRecording.authorize, download);
const forgetDirectRecording = () => personalPage.FrontierMediaCrypto.forgetRecordingPlayback(directRecordingID);

directRecordingSource.url = directRecordingURL + '?ticket=unsafe';
const beforeUnsafeRecording = cipherRequests.length;
await assert.rejects(openDirectRecording(true), /录音读取授权已失效/);
assert.equal(cipherRequests.length, beforeUnsafeRecording, 'unsafe recording URLs never reach the owner');
directRecordingSource.url = directRecordingURL;

const directPlayback = await openDirectRecording();
assert.deepEqual(JSON.parse(JSON.stringify(directPlayback.lyrics)), storedLyrics);
const directRange = await workerFetch(directPlayback.url, {headers: {Range: 'bytes=0-7'}});
assert.equal(directRange.status, 206);
assert.deepEqual(new Uint8Array(await directRange.arrayBuffer()), directAudio.subarray(0, 8));
assert.deepEqual(cipherRequests.at(-1), {url: directRecordingURL,
    range: `bytes=0-${common.CHUNK_SIZE + common.TAG_SIZE - 1}`,
    capability: directRecordingSource.capability, relay: null, credentials: 'omit', redirect: 'error'});
forgetDirectRecording();

for (const [field, value, error] of [
    ['etagOverride', 'b'.repeat(64), /录音密文身份不一致/],
    ['contentRangeOverride', `bytes 1-${common.CHUNK_SIZE + common.TAG_SIZE}/${directRecording.record.ciphertext.length}`,
        /存储节点未返回所需的加密分块/],
]) {
    directRecording.record[field] = value;
    const download = await openDirectRecording(true);
    const response = await workerFetch(download.url, {headers: {Range: 'bytes=0-7'}});
    await assert.rejects(response.arrayBuffer(), error);
    forgetDirectRecording();
    delete directRecording.record[field];
}

const directDownload = await openDirectRecording(true);
const beforeOwnerChange = cipherRequests.length;
const beforeOwnerRenewal = directRecording.keyRequests();
directRecording.record.onFetch = start => {
    if (start !== 0) return;
    directRecordingSource.owner_id = 'c'.repeat(32);
    advance(111000);
};
const changedOwner = await workerFetch(directDownload.url, {headers: {Range: `bytes=0-${common.CHUNK_SIZE}`}});
await assert.rejects(changedOwner.arrayBuffer(), /播放文件已变化/);
assert.equal(directRecording.keyRequests(), beforeOwnerRenewal + 1, 'continuation revalidates the recording owner');
assert.equal(cipherRequests.length, beforeOwnerChange + 1, 'changed owner never receives the next ciphertext request');
forgetDirectRecording();

directRecordingSource.owner_id = 'a'.repeat(32);
delete directRecording.record.onFetch;
const pinnedDownload = await openDirectRecording(true);
const firstPinnedRange = await workerFetch(pinnedDownload.url, {headers: {Range: 'bytes=0-7'}});
assert.equal(firstPinnedRange.status, 206);
await firstPinnedRange.arrayBuffer();
directRecordingSource.owner_id = 'd'.repeat(32);
advance(111000);
const beforeSeparateRange = cipherRequests.length;
const nextPinnedRange = await workerFetch(pinnedDownload.url, {headers: {Range: `bytes=${common.CHUNK_SIZE}-${common.CHUNK_SIZE + 7}`}});
assert.equal(nextPinnedRange.status, 409);
assert.match(await nextPinnedRange.text(), /播放文件已变化/);
assert.equal(cipherRequests.length, beforeSeparateRange, 'a separate Range still pins the original recording owner');
forgetDirectRecording();

console.log('media-crypto-smoke-ok (' + directory + ')');

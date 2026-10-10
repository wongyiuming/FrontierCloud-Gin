import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
import {MessageChannel} from 'node:worker_threads';

const directory = process.env.FRONTIER_CRYPTO_JS_DIR
    || (process.env.FC_CRYPTO_COMPILED === '1' ? 'static/js/compiled' : 'static/js');
const source = name => fs.readFileSync(`${directory}/${name}`, 'utf8');
let now = Date.now();
class Clock extends Date { static now() { return now; } }
const calls = [];
const records = new Map();
const pathRecords = new Map();
const sessions = new Map();
const temporary = new Map();
const plainReads = [];
const cipherRequests = [];
const workerListeners = new Map();
let pageMessage;
let nextId = 1;
let nextSession = 1;
let worker;
let common;

const opfs = {
    async getDirectoryHandle() { return this; },
    async *entries() { for (const entry of temporary) yield entry; },
    async removeEntry(name) { temporary.delete(name); },
    async getFileHandle(name) {
        temporary.set(name, []);
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
    for (const listener of workerListeners.get('message') || []) listener({data, ports, source: client});
}};
async function workerFetch(input, init = {}) {
    const request = new Request(new URL(String(input), 'https://cloud.example'), init);
    let response;
    for (const listener of workerListeners.get('fetch') || []) {
        listener({request, clientId: client.id, respondWith(value) { response = Promise.resolve(value); }});
    }
    assert(response, 'virtual encrypted bytes must be handled by the service worker');
    return response;
}
async function envelope(active, record) {
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const wrapped = await webcrypto.subtle.encrypt({name: 'AES-GCM', iv,
        additionalData: new TextEncoder().encode(`frontiercloud:key-envelope:v1:${active.id}:${record.meta.file_id}`)},
    active.wrapKey, record.raw);
    return {iv: common.encode(iv), wrapped_key: common.encode(wrapped), expires_at: active.expires};
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
        const pair = await webcrypto.subtle.generateKey({name: 'ECDH', namedCurve: 'P-256'}, false, ['deriveBits']);
        const clientKey = await webcrypto.subtle.importKey('raw', common.decode(body.public_key),
            {name: 'ECDH', namedCurve: 'P-256'}, false, []);
        const shared = await webcrypto.subtle.deriveBits({name: 'ECDH', public: clientKey}, pair.privateKey, 256);
        const hkdf = await webcrypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
        const salt = new Uint8Array(32).fill(71);
        const id = 'session-' + nextSession++;
        const wrapKey = await webcrypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256', salt,
            info: new TextEncoder().encode('frontiercloud:browser-wrap:v1:' + id)},
        hkdf, {name: 'AES-GCM', length: 256}, false, ['encrypt']);
        const expires = Math.floor(now / 1000) + 90;
        sessions.set(id, {id, wrapKey, expires});
        return Response.json({session_id: id, expires_at: expires, salt: common.encode(salt),
            public_key: common.encode(await webcrypto.subtle.exportKey('raw', pair.publicKey))});
    }
    const active = sessions.get(body.session_id);
    if (!active || active.expires * 1000 <= now) return Response.json({detail: 'expired session'}, {status: 403});
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
        const record = pathRecords.get(body.file_path);
        if (!record) return Response.json({detail: 'missing'}, {status: 404});
        return Response.json({encryption: record.meta, key_envelope: await envelope(active, record),
            source_url: record.source, content_type: 'audio/mpeg', filename: body.file_path.split('/').pop()});
    }
    throw new Error('unexpected crypto API: ' + url);
}

const page = {
    crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, URL, URLSearchParams,
    Blob, Headers, Request, Response, ReadableStream, MessageChannel, Date: Clock,
    atob, btoa, setTimeout, clearTimeout, console, isSecureContext: true,
    location: new URL('https://cloud.example/api/v1/media/admin'),
    document: {getElementById: id => id === 'uploadFiles' ? {} : null,
        createElement() { return {click() {}}; }},
    navigator: {storage: {getDirectory: async () => opfs}, serviceWorker: {controller,
        register: async () => ({}), ready: Promise.resolve({}),
        addEventListener(type, listener) { if (type === 'message') pageMessage = listener; },
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
const bytes = Uint8Array.from({length: 2 * 1048576 + 97}, (_, index) => index % 251);
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

const cryptoKeyConstructor = fileKey.constructor;
worker = {
    crypto: webcrypto, CryptoKey: cryptoKeyConstructor, TextEncoder, TextDecoder, Uint8Array, Uint32Array,
    ArrayBuffer, DataView, URL, URLSearchParams, Headers, Request, Response, ReadableStream, AbortController,
    MessageChannel, Date: Clock, atob, btoa, setTimeout, clearTimeout,
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
        const header = new Headers(init.headers).get('Range');
        cipherRequests.push({url: String(input), range: header});
        const range = /^bytes=(\d+)-(\d+)$/.exec(header);
        assert(range, 'ciphertext fetches must name one exact authenticated chunk');
        const start = Number(range[1]); const end = Number(range[2]);
        assert(end - start + 1 <= 1048576 + 16, 'network reads remain within one ciphertext chunk');
        const payload = record.ciphertext.slice(start, end + 1);
        return new Response(payload, {status: 206, headers: {
            'Content-Range': `bytes ${start}-${end}/${record.ciphertext.length}`,
            'Content-Length': String(payload.length), 'Content-Type': 'application/octet-stream',
        }});
    },
};
worker.self = worker;
vm.createContext(worker);
vm.runInContext(source('media-crypto-sw.js'), worker);
const catalog = [{media_path: 'music/a.mp3', encryption: first.meta}, {media_path: 'music/b.mp3', encryption: second.meta}];
await page.FrontierMediaCrypto.prepareCatalog(catalog);
assert.match(catalog[0].url, /^\/__fc_media\/.*\?object=/);

let response = await workerFetch(catalog[0].url, {headers: {Range: 'bytes=1048541-1048619'}});
assert.equal(response.status, 206);
assert.equal(response.headers.get('Content-Range'), `bytes 1048541-1048619/${bytes.length}`);
assert.equal(response.headers.get('Content-Length'), '79');
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes.subarray(1048541, 1048620));
assert.equal(cipherRequests.length, 2, 'a cross-chunk seek only fetches its two covering chunks');
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
assert.equal(calls.filter(call => call.url.endsWith('/key')).length, 2, 'multiple requests for one file reuse its temporary envelope');

now += 100000;
response = await workerFetch(catalog[1].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), secondBytes);
assert.equal(calls.filter(call => call.url.endsWith('/session')).length, 2, 'expired authorization performs one fresh handshake');

// Recreated workers lose all in-memory keys/capabilities. A valid live tab can
// reauthorize its next seek, without keeping keys in persistent browser storage.
vm.runInContext('capabilities.clear(); grants.clear();', worker);
response = await workerFetch(catalog[1].url);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), secondBytes);

await page.FrontierMediaCrypto.downloadPlan([
    {path: 'music/b.mp3', encryption: second.meta, size_bytes: secondBytes.length},
    {path: 'lyrics/plain.lrc', url: '/plain-lyric', size_bytes: 18},
]);
const zipId = vm.runInContext('[...zipPlans.keys()][0]', worker);
response = await workerFetch('/__fc_zip/' + zipId);
const zip = new Uint8Array(await response.arrayBuffer());
assert.equal(response.headers.get('Content-Type'), 'application/zip');
let cursor = 0;
const archived = [];
for (let file = 0; file < 2; file += 1) {
    const view = new DataView(zip.buffer, cursor);
    assert.equal(view.getUint32(0, true), 0x04034b50);
    const nameLength = view.getUint16(26, true);
    const extraLength = view.getUint16(28, true);
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
assert.equal(new DataView(zip.buffer, cursor).getUint32(0, true), 0x02014b50);
assert.equal(new DataView(zip.buffer, zip.length - 98).getUint32(0, true), 0x06064b50);
assert.equal(Number(new DataView(zip.buffer, zip.length - 98).getBigUint64(24, true)), 2);
assert.equal((await workerFetch('/__fc_zip/' + zipId)).status, 403, 'download plan capability is consumed once');

const oldUrl = catalog[1].url;
const replacement = await prepare(new TextEncoder().encode('replaced'), 'music/b.mp3', second.source);
assert.equal(await page.FrontierMediaCrypto.textFor('music/b.mp3', replacement.meta.file_id), 'replaced',
    'a fresh lyric descriptor must replace a same-path cached key before its authorization expires');
now += 100000;
assert.equal((await workerFetch(oldUrl)).status, 409, 'same-path replacement cannot reuse another object key');
const fresh = [{media_path: 'music/b.mp3', encryption: replacement.meta}];
await page.FrontierMediaCrypto.prepareCatalog(fresh);
response = await workerFetch(fresh[0].url);
assert.equal(new TextDecoder().decode(await response.arrayBuffer()), 'replaced');

replacement.ciphertext[0] ^= 1;
response = await workerFetch(fresh[0].url);
await assert.rejects(response.arrayBuffer(), 'tampered ciphertext cannot return plaintext');
assert(page.FrontierMediaCrypto.failureFor(fresh[0].url), 'tag failures propagate to the playback retry guard');
assert.equal((await workerFetch(fresh[0].url)).status, 422, 'integrity failure must not be retried as a network failure');
console.log('media-crypto-smoke-ok (' + directory + ')');

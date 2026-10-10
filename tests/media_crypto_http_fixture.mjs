// Real WebCrypto browser modules against a disposable Gin HTTP cluster.
// The Go test owns identities, databases, failure injection and disk assertions.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {createHash, webcrypto} from 'node:crypto';
import {MessageChannel} from 'node:worker_threads';
import {performance} from 'node:perf_hooks';

process.on('uncaughtException', error => {
    process.stderr.write(String(error.stack || error) + '\n');
    process.exit(1);
});

const [masterSocket, followerSocket, site] = process.argv.slice(2);
assert(masterSocket && followerSocket && ['primary', 'direct', 'relay'].includes(site));
const source = name => fs.readFileSync(`static/js/compiled/${name}`, 'utf8');
const calls = [];
const ranges = [];
const temporary = new Map();
const listeners = new Map();
let pageMessage;
let worker;
const origin = 'https://master.test';
const client = {id: 'real-http-browser', postMessage(data, ports = []) {
    pageMessage({data, source: controller, ports});
}};
const controller = {postMessage(data, ports = []) {
    for (const listener of listeners.get('message') || []) listener({data, ports, source: client});
}};

async function networkFetch(input, init = {}) {
    let canonical = new URL(String(input), origin);
    const headers = new Headers(init.headers);
    for (let redirects = 0; redirects < 5; redirects += 1) {
        const target = canonical.origin === origin ? masterSocket : followerSocket;
        assert([origin, 'https://follower.test'].includes(canonical.origin), 'unexpected storage origin');
        if (canonical.origin !== origin) headers.set('Origin', origin);
        const response = await fetch(target + canonical.pathname + canonical.search,
            {...init, headers, redirect: 'manual'});
        if ([301, 302, 303, 307, 308].includes(response.status)) {
            canonical = new URL(response.headers.get('Location'), canonical);
            await response.body?.cancel();
            continue;
        }
        if (canonical.pathname.includes('/crypto/')) {
            calls.push({path: canonical.pathname, body: init.body ? JSON.parse(init.body) : null});
        }
        if (headers.has('Range')) {
            ranges.push({origin: canonical.origin, path: canonical.pathname,
                range: headers.get('Range'), status: response.status});
            if (response.status !== 206) {
                throw new Error(`ciphertext Range ${canonical.pathname} status=${response.status}: ${await response.text()}`);
            }
        }
        return response;
    }
    throw new Error('storage redirect loop');
}
async function json(path, body) {
    const response = await networkFetch(path, {method: 'POST',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    const value = await response.json();
    assert.equal(response.status, 200, `${path}: ${JSON.stringify(value)}`);
    return value;
}
const opfs = {
    async getDirectoryHandle() { return this; },
    async *entries() { yield* temporary.entries(); },
    async removeEntry(name) { temporary.delete(name); },
    async getFileHandle(name) {
        temporary.set(name, []);
        return {async createWritable() {
            return {async write(value) { temporary.get(name).push(new Uint8Array(value).slice()); },
                async close() {}, async abort() { temporary.delete(name); }};
        }, async getFile() { return new Blob(temporary.get(name)); }};
    },
};
const page = {
    crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, URL, URLSearchParams,
    Blob, Headers, Request, Response, ReadableStream, MessageChannel, Date, performance,
    atob, btoa, setTimeout, clearTimeout, console, isSecureContext: true,
    location: new URL(origin + '/api/v1/media/admin'),
    document: {getElementById: id => id === 'uploadFiles' ? {} : null},
    navigator: {storage: {getDirectory: async () => opfs}, serviceWorker: {controller,
        register: async () => ({}), ready: Promise.resolve({}),
        addEventListener(type, listener) { if (type === 'message') pageMessage = listener; }}},
    requestHeaders: () => ({'Content-Type': 'application/json'}),
    addEventListener() {}, dispatchEvent() {}, CustomEvent: class {}, fetch: networkFetch,
};
page.window = page;
vm.createContext(page);
vm.runInContext(source('media-crypto-common.js'), page);
vm.runInContext(source('media-crypto.js'), page);
const keyConstructor = (await webcrypto.subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['decrypt'])).constructor;
worker = {
    crypto: webcrypto, CryptoKey: keyConstructor, TextEncoder, TextDecoder, Uint8Array, Uint32Array,
    ArrayBuffer, DataView, URL, URLSearchParams, Headers, Request, Response, ReadableStream, AbortController,
    MessageChannel, Date, performance, atob, btoa, setTimeout, clearTimeout,
    location: new URL(origin + '/media-crypto-sw.js'),
    clients: {get: async id => id === client.id ? client : null, claim: async () => {}},
    skipWaiting: async () => {},
    addEventListener(type, listener) {
        if (!listeners.has(type)) listeners.set(type, []);
        listeners.get(type).push(listener);
    },
    importScripts() { vm.runInContext(source('media-crypto-common.js'), worker); },
    fetch: networkFetch,
};
worker.self = worker;
vm.createContext(worker);
vm.runInContext(source('media-crypto-sw.js'), worker);
async function browserFetch(input, init = {}) {
    const request = new Request(new URL(input, origin), init);
    let response;
    for (const listener of listeners.get('fetch') || []) {
        listener({request, clientId: client.id, respondWith(value) { response = Promise.resolve(value); }});
    }
    assert(response, 'encrypted virtual URL bypassed the browser service worker');
    return response;
}

const directory = `music/Browser-${site}`;
const renamedDirectory = `music/Browser-renamed-${site}`;
const records = [];
for (const [index, size] of [1048576 + 97, 61].entries()) {
    const plain = Uint8Array.from({length: size}, (_, offset) => (offset * 13 + index * 7) % 251);
    const file = {name: `browser-${index}.mp3`, size, slice(start, end) {
        assert(end - start <= 1048576, 'browser read beyond one plaintext chunk');
        return {async arrayBuffer() { return plain.slice(start, end).buffer; }};
    }, async arrayBuffer() { throw new Error('whole plaintext read forbidden'); }};
    const prepared = await page.FrontierMediaCrypto.encryptFile(file);
    const cipher = new Uint8Array(await prepared.file.arrayBuffer());
    assert.equal(cipher.length, prepared.encryption.ciphertext_size);
    assert.notDeepEqual(cipher.subarray(0, 61), plain.subarray(0, 61));
    const ticket = await json('/api/v1/media/admin/upload/session', {
        storage_mode: 'encrypted', site_type: site, target_dir: directory, filename: file.name,
        size_bytes: cipher.length, encryption: prepared.encryption,
        preparation_token: prepared.preparation_token,
    });
    const response = await networkFetch(ticket.upload_url, {method: 'PUT', body: cipher});
    assert.equal(response.status, 200, await response.text());
    const record = {ticket, encryption: prepared.encryption, cipher_sha256: createHash('sha256').update(cipher).digest('hex'),
        plaintext_sha256: createHash('sha256').update(plain).digest('hex'), plain};
    if (site === 'direct' && index === 0) {
        // A real successful storage PUT loses its finalize reply/operation.
        await json('/__fixture/expire-and-recover', record);
    } else if (site === 'direct') {
        await json(`/api/v1/media/admin/upload/session/${ticket.upload_id}/finalize`, {});
    }
    await json('/__fixture/check', {...record, plain: undefined, phase: 'published', path: ticket.path});
    await prepared.cleanup();
    records.push(record);
}
assert.equal(temporary.size, 0);
assert.equal(calls.filter(call => call.path.endsWith('/session')).length, 1,
    'multiple actual HTTP upload preparations did not reuse the browser ECDH session');

async function verify(record, path) {
    const entries = [{media_path: path, encryption: record.encryption}];
    await page.FrontierMediaCrypto.prepareCatalog(entries);
    const full = await browserFetch(entries[0].url);
    assert.equal(full.status, 200);
    assert.deepEqual(new Uint8Array(await full.arrayBuffer()), record.plain, 'browser full decryption mismatch');
    const start = record.plain.length > 1048576 ? 1048541 : 7;
    const end = Math.min(record.plain.length - 1, start + 80);
    const partial = await browserFetch(entries[0].url, {headers: {Range: `bytes=${start}-${end}`}});
    assert.equal(partial.status, 206);
    assert.equal(partial.headers.get('Content-Range'), `bytes ${start}-${end}/${record.plain.length}`);
    assert.deepEqual(new Uint8Array(await partial.arrayBuffer()), record.plain.subarray(start, end + 1),
        'browser seek across authenticated chunks mismatch');
    const download = await browserFetch(page.FrontierMediaCrypto.virtualUrl(path, true, record.encryption.file_id));
    assert.match(download.headers.get('Content-Disposition'), /attachment/);
    assert.equal(createHash('sha256').update(new Uint8Array(await download.arrayBuffer())).digest('hex'),
        record.plaintext_sha256, 'download produced ciphertext or corrupted plaintext');
}
for (const record of records) await verify(record, record.ticket.path);
await json('/api/v1/media/admin/directory/rename', {path: directory, new_name: renamedDirectory.split('/').pop()});
for (const record of records) {
    record.path = `${renamedDirectory}/${record.ticket.path.split('/').pop()}`;
    await json('/__fixture/check', {...record, plain: undefined, phase: 'published'});
    await verify(record, record.path);
}
assert.equal(calls.filter(call => call.path.endsWith('/session')).length, 1,
    'play/download/rename key requests renewed a valid ECDH session');
assert.equal(calls.filter(call => call.path.endsWith('/key')).length, 4,
    'each of two files must receive a wrapped grant before and after rename');
assert(ranges.every(range => range.status === 206));
assert(ranges.some(range => range.origin === (site === 'direct' ? 'https://follower.test' : origin)),
    'media used an unexpected primary/direct/relay delivery path');

await json('/__fixture/fail-delete', {});
const deletion = await json('/api/v1/media/admin/delete', {paths: [renamedDirectory]});
assert.equal(deletion.pending_delete.length, 2, 'uncertain storage deletion refunded or forgot encrypted objects');
for (const record of records) await json('/__fixture/check', {...record, plain: undefined, phase: 'pending_delete'});
await json('/__fixture/recover-delete', {});
for (const record of records) await json('/__fixture/check', {...record, plain: undefined, phase: 'deleted'});
process.stdout.write(JSON.stringify({site, files: records.length, http_key_grants: 4,
    browser_handshakes: 1, ciphertext_range_requests: ranges.length,
    plaintext_bytes: records.reduce((sum, record) => sum + record.plain.length, 0)}) + '\n');

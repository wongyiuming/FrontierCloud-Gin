import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';

// Exercise the actual bounded browser uploader with real SHA256, Blob slices
// and concurrent provider requests. No provider URL or credential is logged.
const source = fs.readFileSync('static/js/admin-upload-integrity.js', 'utf8');
const uploader = source.slice(source.indexOf('const S3_PART_BYTES'), source.indexOf('\nrunUploadTask ='));
const partBytes = 8 * 1024 * 1024;
const bytes = new Uint8Array(partBytes + 17); bytes.fill(37);
const file = new Blob([bytes]);
const checksum = async value => Buffer.from(await webcrypto.subtle.digest('SHA-256', value)).toString('base64');
const checksums = [await checksum(bytes.subarray(0, partBytes)), await checksum(bytes.subarray(partBytes))];
let state, requests, transfers, active, peak, failTransfer, badHeaders;
const context = {
    console, crypto: webcrypto, URL, AbortController, Uint8Array, Blob,
    btoa: value => Buffer.from(value, 'binary').toString('base64'),
    setTimeout, clearTimeout, uploadInterrupted: false, uploadRunning: false,
    window: {addEventListener() {}}, document: {getElementById() { return null; }}, $() { return null; },
    requestHeaders: () => ({'X-CSRF-Token': 'only-control'}),
    setUploadControlsDisabled() {}, renderTree: async () => {},
    async api(url, options = {}) {
        requests.push({url, method: options.method || 'GET', body: options.body ? JSON.parse(options.body) : null});
        assert(url.startsWith('/api/v1/media/admin/upload/s3/u1'));
        if (url.endsWith('/begin')) { assert.equal(state.state, 'reserved'); state.state = 'created'; }
        const part = /\/parts\/(\d+)\/(grant|confirm)$/.exec(url);
        if (part) {
            const number = Number(part[1]);
            if (part[2] === 'grant') {
                const body = JSON.parse(options.body);
                assert.deepEqual(Object.keys(body).sort(), ['checksum_sha256', 'size_bytes']);
                assert.equal(body.checksum_sha256, checksums[number - 1]);
                state.parts = state.parts.filter(value => value.number !== number);
                state.parts.push({number, ...body, confirmed: false});
                return {url: `https://objects.example/part/${number}?signature=private`, expires_at: 2000000000,
                    headers: badHeaders ? {'X-CSRF-Token': 'must-not-send'} : {'X-Amz-Checksum-Sha256': body.checksum_sha256,
                        'Content-Length': String(body.size_bytes)}};
            }
            assert.deepEqual(JSON.parse(options.body), {}, 'client never supplies ETag or provider proof');
            state.parts.find(value => value.number === number).confirmed = true;
        }
        if (url.endsWith('/finalize')) return {path: 'music/a/test.mp3'};
        return structuredClone(state);
    },
    async fetch(url, options) {
        active += 1; peak = Math.max(peak, active);
        try {
            assert.equal(options.method, 'PUT'); assert.equal(options.credentials, 'omit');
            assert.equal(options.mode, 'cors'); assert.equal(options.redirect, 'error');
            assert.equal(options.referrerPolicy, 'no-referrer');
            assert(!Object.keys(options.headers).some(name => /csrf|cookie|authorization|content-length/i.test(name)));
            assert(options.body.byteLength <= partBytes);
            transfers.push(url);
            await new Promise(resolve => setTimeout(resolve, 4));
            if (failTransfer) throw new Error('provider URL is intentionally private');
            return {status: 200, body: {async cancel() {}}};
        } finally { active -= 1; }
    },
};
vm.createContext(context); vm.runInContext(uploader, context);
function reset() {
    state = {state: 'reserved', reservation: {expected_bytes: file.size}, parts: []};
    requests = []; transfers = []; active = 0; peak = 0; failTransfer = false; badHeaders = false;
}
reset();
const progress = [];
const result = await context.uploadS3Parts({upload_id: 'u1'}, file, value => progress.push(value));
assert.equal(result.path, 'music/a/test.mp3'); assert.equal(peak, 2); assert.equal(active, 0);
assert.equal(transfers.length, 2); assert.equal(progress.at(-1), 1);
assert.equal(requests.filter(item => item.url.endsWith('/begin')).length, 1);
assert(requests.find(item => item.url.endsWith('/touch')));

reset(); state.state = 'created';
state.parts = [{number: 1, size_bytes: partBytes, checksum_sha256: checksums[0], confirmed: true}];
await context.uploadS3Parts({upload_id: 'u1'}, file, () => {});
assert.equal(transfers.length, 1, 'confirmed bytes are validated then skipped');
assert(!requests.some(item => item.url.endsWith('/begin')), 'resume never replays CreateMultipart');

reset(); state.state = 'created';
state.parts = [{number: 1, size_bytes: partBytes, checksum_sha256: 'different-bytes', confirmed: true}];
await assert.rejects(context.uploadS3Parts({upload_id: 'u1'}, file, () => {}), /不一致/);
assert.equal(transfers.length, 0); assert(!requests.some(item => item.url.endsWith('/grant')));

reset(); state.state = 'create_unknown';
await assert.rejects(context.uploadS3Parts({upload_id: 'u1'}, file, () => {}), /核验/);
assert.equal(requests.length, 1, 'ambiguous creation is retained without a new mutation');

reset(); failTransfer = true;
await assert.rejects(context.uploadS3Parts({upload_id: 'u1'}, file, () => {}), /可恢复/);
assert.equal(active, 0, 'both workers settle before returning an error');
assert(!requests.some(item => item.method === 'DELETE' || item.url.endsWith('/finalize')));

reset(); badHeaders = true;
await assert.rejects(context.uploadS3Parts({upload_id: 'u1'}, file, () => {}), /请求头/);
assert.equal(transfers.length, 0);
assert(!source.includes('/session/${encodeURIComponent(reservation.upload_id)}/s3'));

// Independent tabs share durable records, never one tab's in-memory snapshot.
const shared = new Map();
let storageDenied = false, tail = Promise.resolve();
const storage = {
    getItem: key => shared.get(key) ?? null,
    setItem(key, value) { if (storageDenied) throw new Error('quota'); shared.set(key, value); },
};
const locks = {request(_name, callback) {
    const result = tail.then(callback); tail = result.catch(() => {}); return result;
}};
const tabs = [];
function tab() {
    const listeners = new Map(), cleaned = [];
    const value = {console, URL, AbortController, Uint8Array, Blob, crypto: webcrypto,
        window: {localStorage: storage, navigator: {locks},
            addEventListener(name, callback) { listeners.set(name, callback); },
            FrontierMediaCrypto: {async forgetRetainedUpload(name) { cleaned.push(name); }}},
        document: {getElementById() { return null; }}, $() { return null; },
        uploadInterrupted: false, uploadRunning: false,
    };
    vm.createContext(value); vm.runInContext(uploader, value);
    value.listeners = listeners; value.cleaned = cleaned; tabs.push(value); return value;
}
const task = id => ({id, name: `${id}.mp3`, originalSize: 1, hashes: [checksums[0]], cipherName: `123-${id}`});
async function put(value, entry) {
    value.entry = structuredClone(entry);
    return vm.runInContext('s3Tasks.set(entry.id, entry); saveS3Tasks({put: entry})', value);
}
const key = 'frontiercloud-s3-upload-resume-v1';
const stored = () => JSON.parse(storage.getItem(key) || '[]');
const a = tab(), b = tab();
await Promise.all([put(a, task('a')), put(b, task('b'))]);
assert.deepEqual(stored().map(value => value.id).sort(), ['a', 'b'], 'one tab must not erase another tab recovery record');
await vm.runInContext("saveS3Tasks({cancel: 'a'})", a);
await put(b, task('c'));
assert.equal(stored().find(value => value.id === 'a').cancel_requested, true, 'stale tabs preserve cancellation');
await vm.runInContext("forgetS3Task('a')", a);
await vm.runInContext("saveS3Tasks({cancel: 'a'})", b);
assert.deepEqual(stored().map(value => value.id).sort(), ['b', 'c'], 'stale mutations never resurrect a removed task');
assert.deepEqual(a.cleaned, ['123-a']);
const reloaded = tab();
assert.equal(vm.runInContext('s3Tasks.size', reloaded), 2, 'reload preserves both remaining recovery records');
storageDenied = true;
await assert.rejects(vm.runInContext("forgetS3Task('b')", a), /保存恢复/);
assert(stored().some(value => value.id === 'b'));
assert(!a.cleaned.includes('123-b'), 'failed persistence must retain resumable ciphertext');
storageDenied = false;
for (const id of ['d', 'e', 'f', 'g', 'h', 'i']) await put(a, task(id));
await assert.rejects(put(b, task('j')), /8 个/, 'the limit is checked against the current shared records');
assert.equal(stored().length, 8);
b.listeners.get('storage')?.({key, storageArea: storage});
assert.equal(vm.runInContext('s3Tasks.size', b), 8, 'storage changes refresh other tabs');
const noLock = tab(); noLock.window.navigator.locks = undefined;
await assert.rejects(put(noLock, task('k')), /锁/, 'unsupported synchronization fails before erasing records');
assert.equal(stored().length, 8);
const corrupt = storage.getItem(key); storage.setItem(key, '{broken');
await assert.rejects(vm.runInContext("saveS3Tasks({cancel: 'b'})", a), /恢复信息/);
assert.equal(storage.getItem(key), '{broken', 'invalid shared metadata is never overwritten by a stale tab');
storage.setItem(key, corrupt);
console.log('s3-frontend-smoke-ok (bounded two-part upload, durable resume, failure retention, no credential relay)');

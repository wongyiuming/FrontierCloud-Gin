import assert from 'node:assert/strict';
import {createHash, randomUUID, webcrypto} from 'node:crypto';
import fs from 'node:fs';
import vm from 'node:vm';

class Element {
    constructor() {
        this.children = []; this.dataset = {}; this.value = ''; this.listeners = new Map();
        this.classList = {add() {}, remove() {}, toggle() {}};
    }
    get options() { return this.children; }
    append(...items) { this.children.push(...items); }
    appendChild(item) { this.append(item); }
    replaceChildren(...items) { this.children = items; }
    setAttribute() {}
    addEventListener(type, listener) { this.listeners.set(type, listener); }
    showModal() { this.open = true; }
    close() { this.open = false; }
    remove() { this.removed = true; }
    click() { this.clicks = (this.clicks || 0) + 1; }
    querySelector() { return null; }
}
const nodes = new Map();
const node = id => {
    if (!nodes.has(id)) nodes.set(id, new Element());
    return nodes.get(id);
};
const memberID = 'a'.repeat(32);
let destinations = [{member_id: memberID, site_type: 'primary', address:'https://master.test', writable:true}];
const body = new Element();
const alerts = [];
const requests = [];
const transfers = [];
const results = [];
let encryptedCalls = 0;
let cleanupCalls = 0;
let encryptionFails = false;
let serverFails = false;
let ticketMemberID = memberID;
let interrupted = false;
let selectedProtocol = false;
let selectedTransport = 'Direct';
let loseOwnerResponse = false;
let loseCompleteResponse = false;
let savedOwnerReceipt;
let unexpectedTicket = false;
let losePrepareResponse = false;
let s3Status = 'published';
let denyRecoveryWrite = false;
const recoveryRecords = new Map();
const recoveryKey = 'frontiercloud-s3-upload-resume-v1';
const storedS3 = () => JSON.parse(recoveryRecords.get(recoveryKey) || '[]');
const retained = new Set();
const selectedTransfers = [];
const downloadPlans = [];
let releaseInitialPool;
let initialPool = new Promise(resolve => { releaseInitialPool = resolve; });
class TestFormData {
    constructor() { this.fields = new Map(); }
    append(name, value) { this.fields.set(name, value); }
}
const context = {
    document: {getElementById: node, createElement: () => new Element(), body, querySelectorAll: () => []},
    $: node, alert: message => alerts.push(message), FormData: TestFormData, URL, AbortController,
    crypto: {randomUUID, subtle: webcrypto.subtle}, Uint8Array,
    btoa: value => Buffer.from(value, 'binary').toString('base64'),
    activeUploadRequests: new Set(), location: {origin: 'https://master.test'},
    localStorage: {
        getItem: key => recoveryRecords.get(key) ?? null,
        setItem(key, value) {
            if (denyRecoveryWrite) throw new Error('storage quota');
            recoveryRecords.set(key, value);
        },
    },
    navigator: {locks: {request: async (_name, callback) => callback()}},
    currentPath: 'music/category', clusterUpload: false, uploadRunning: false, uploadInterrupted: false,
    uploadLimits: {max_upload_task_files: 5000, max_upload_file_size: 1000000, max_lyric_file_size: 100000},
    selected: new Set(), selectionKind: 'file', visibleMediaItems: [], console,
    sealedMediaDownload: null, selectedItemResourceIDs: new Map(), selectedItemKinds: new Map(),
    requestHeaders: () => ({'X-CSRF-Token': 'fixture-csrf'}), formatSize: String,
    setProgress() {}, setUploadControlsDisabled(value) { context.uploadRunning = value; },
    renderTree: async () => {}, refreshStoragePool: async () => {}, loadLyricCatalog: async () => {},
    addUploadResult(...result) { results.push(result); },
    showModal() {}, clearMediaSelection() {},
    async api(url, options = {}) {
        requests.push({url, body: options.body ? JSON.parse(options.body) : undefined});
        if (url.endsWith('/storage-pool')) {
            if (initialPool) await initialPool;
            return {standalone: !context.clusterUpload, upload_destinations: destinations, selected_upload: selectedProtocol};
        }
        if (url.endsWith('/download/plan')) {
            assert.equal(options.method, 'POST');
            return {items: [{path: 'music/category/a.mp3'}], force_zip: true};
        }
        if (url.includes('/upload/s3/')) {
            const id = url.split('/').at(-1);
            assert(storedS3().some(task => task.id === id), 'S3 control uses the original durable upload ID');
            return {state: s3Status, reservation: {expected_bytes: 516}, parts: []};
        }
        if (url.includes('/upload/selected/')) {
            const last = requests.findLast(request => request.url.endsWith('/selected/prepare'));
            const id = last.body.upload_id;
            if (url.endsWith('/prepare') && selectedTransport === 'S3') {
                const task = storedS3().find(value => value.id === id);
                assert(task?.selected && retained.has(task.cipherName), 'ciphertext and recovery record precede prepare');
                if (losePrepareResponse) throw new Error('prepare response lost');
            }
            const prefix = selectedTransport === 'Direct' ? 'https://direct.example/api/v1/node/selected-upload'
                : `/api/v1/media/admin/upload/selected/${id}`;
            if (url.endsWith('/complete')) {
                if (savedOwnerReceipt && options.body === JSON.stringify(savedOwnerReceipt)) return {state: 'completed'};
                if (loseCompleteResponse) throw new Error('completion response lost');
                return {state: 'completed'};
            }
            if (url.endsWith('/status')) return savedOwnerReceipt ? {state: 'pending', ...savedOwnerReceipt} : {state: 'completed'};
            return {
                upload_id: id, member_id: unexpectedTicket ? 'd'.repeat(32) : last.body.storage_member_id,
                transport: selectedTransport,
                upload_url: selectedTransport === 'Direct' ? prefix : prefix + '/bytes',
                recovery_url: prefix + '/recover',
                ...(selectedTransport === 'Direct' ? {capability: 'fixture-owner-capability'} : {}),
            };
        }
        if (url.endsWith('/upload/session')) return {member_id: ticketMemberID, upload_id: 'reservation', transport: 'Direct',
            upload_url: 'https://direct.example/upload', path: 'music/category/a.mp3'};
        if (url.endsWith('/finalize')) return {path: 'music/category/a.mp3'};
        return {};
    },
    async uploadOne(form, progress, endpoint) {
        transfers.push({form, endpoint}); progress(1);
        if (interrupted) { context.uploadInterrupted = true; throw new Error('上传已取消'); }
        if (serverFails) throw new Error('storage rejected ciphertext');
        return {path: 'music/category/a.mp3'};
    },
    async uploadRaw(url, file, progress) { transfers.push({url, file}); progress(1); },
    async fetch(url, options) {
        selectedTransfers.push({url: url.href, options});
        if (loseOwnerResponse && options.method === 'PUT') throw new Error('Owner response lost');
        return {ok: true, async json() { return {receipt: {blob_id: 'opaque'}, signature: 'fixture-signature'}; }};
    },
};
context.window = context;
context.FrontierMediaCrypto = {
    async encryptUploadFile(file) {
        encryptedCalls += 1;
        if (encryptionFails) throw new Error('browser encryption failed');
        const retainedName = `fixture-cipher-${encryptedCalls}`;
        return {file: Object.assign(new Blob([new Uint8Array(file.size + 16).fill(23)]), {name: 'temporary-ciphertext'}),
            encryption: {file_id: 'f'.repeat(32)}, preparation_token: 'signed-preparation', retainedName,
            retain() { retained.add(retainedName); },
            async cleanup() { retained.delete(retainedName); cleanupCalls += 1; }};
    },
    async forgetRetainedUpload(name) { retained.delete(name); },
    async downloadPlan(items, zip) { downloadPlans.push({items, zip}); },
};
vm.createContext(context);
vm.runInContext(fs.readFileSync('static/js/upload-sha256.js', 'utf8'), context);
vm.runInContext(fs.readFileSync('static/js/admin-upload-integrity.js', 'utf8'), context);
const lyricFile = {name: 'early.lrc', size: 20};
assert.equal(node('uploadLyrics').disabled, true, 'lyric upload waits for protocol discovery');
await context.runUploadTask([lyricFile], null, true);
assert.equal(encryptedCalls, 0, 'an unknown upload protocol never sends lyrics to a legacy route');
assert.equal(transfers.length, 0);
alerts.length = 0;

const folder = 'music/category';
const resourceID = 'b'.repeat(64);
context.selected.add(folder);
context.selectedItemResourceIDs.set(folder, resourceID);
context.selectedItemKinds.set(folder, 'directory');
await node('download').onclick();
assert.equal(requests.some(request => request.url.includes('/download')), false, 'download waits for protocol discovery');
assert.equal(downloadPlans.length, 0);
alerts.length = 0;

releaseInitialPool();
initialPool = null;
selectedProtocol = true;
await context.refreshStoragePool();
context.sealedMediaDownload = false;
await node('download').onclick();
assert.equal(requests.some(request => request.url.includes('/download')), false, 'a sealed upload pool forbids legacy download fallback');
assert.equal(downloadPlans.length, 0);
alerts.length = 0;

context.sealedMediaDownload = true;
await node('download').onclick();
assert.deepEqual(requests.find(request => request.url.endsWith('/download/plan')).body,
    {targets: [{path: folder, resource_id: resourceID, kind: 'directory'}]});
assert.deepEqual(downloadPlans, [{items: [{path: 'music/category/a.mp3'}], zip: true}]);
context.selected.clear();
selectedProtocol = false;
await context.refreshStoragePool();
assert.equal(node('uploadSiteType').value, '', 'target selection starts empty');

const file = {name: 'a.mp3', size: 500};
await context.runUploadTask([file]);
assert.equal(alerts.length, 1, 'an upload without a destination is refused');
assert.equal(transfers.length, 0);
node('uploadSiteType').value = memberID;
node('uploadFiles').onclick();
assert.equal(node('fileInput').clicks, 1);
assert.equal(body.children.length, 0, 'file picker opens without a mode dialog');
encryptionFails = true;
await node('fileInput').onchange({target: Object.assign(node('fileInput'), {files: [file]})});
assert.equal(transfers.length, 0, 'encryption failure never submits plaintext');
assert.match(results.at(-1)[2], /browser encryption failed/);

encryptionFails = false;
serverFails = true;
await node('fileInput').onchange({target: Object.assign(node('fileInput'), {files: [file]})});
assert.equal(cleanupCalls, 1, 'failed storage upload cleans the ciphertext temporary file');
assert.equal(transfers[0].form.fields.get('storage_mode'), 'encrypted');
assert.equal(transfers[0].form.fields.get('file').name, 'temporary-ciphertext');
assert.equal(transfers[0].form.fields.get('preparation_token'), 'signed-preparation');

serverFails = false;
await context.runUploadTask([{name: 'a.lrc', size: 20}], null, true);
assert.equal(transfers.at(-1).endpoint, '/api/v1/media/admin/upload/lyric');
assert.equal(transfers.at(-1).form.fields.get('storage_mode'), 'encrypted');
assert.equal(cleanupCalls, 2);

context.clusterUpload = true;
const before = requests.length;
await context.runUploadTask([file, {...file, name: 'b.mp3'}]);
const reservations = requests.slice(before).filter(request => request.url.endsWith('/upload/session'));
assert.equal(reservations.length, 2);
assert(reservations.every(request => request.body.storage_mode === 'encrypted' && request.body.size_bytes === 516));
assert(reservations.every(request => request.body.preparation_token === 'signed-preparation'));
assert(reservations.every(request => request.body.storage_member_id === memberID), 'every file remains bound to the selected owner');
assert.equal(transfers.at(-1).file.name, 'temporary-ciphertext');
assert.equal(cleanupCalls, 4, 'successful direct uploads also remove ciphertext temporary files');

context.clusterUpload = false;
interrupted = true;
const transferredBeforeInterrupt = transfers.length;
await context.runUploadTask([file, {...file, name: 'not-started.mp3'}]);
assert.equal(transfers.length, transferredBeforeInterrupt + 1, 'offline task must not start another file');
assert.equal(cleanupCalls, 5, 'interruption cleans the prepared ciphertext');
assert.equal(node('uploadSummary').textContent, '已中断：成功 0，失败 1，未上传 1');

context.navigator.onLine = false;
const beforeOfflineRetry = {transfers:transfers.length,encryption:encryptedCalls};
await context.runUploadTask([file, {...file, name:'still-offline.mp3'}]);
assert.equal(transfers.length,beforeOfflineRetry.transfers);
assert.equal(encryptedCalls,beforeOfflineRetry.encryption,'offline retry must not prepare ciphertext');
assert.equal(context.uploadInterrupted,true);
assert.match(alerts.at(-1),/离线/);
context.navigator.onLine=true;
interrupted=false;
await context.runUploadTask([file]);
assert.equal(context.uploadInterrupted,false);
assert.equal(node('uploadSummary').textContent,'完成：成功 1，失败 0');

for (const [button, input] of [['uploadFolder', 'folderInput'], ['uploadLyrics', 'lyricsInput'], ['uploadLyricsFolder', 'lyricsFolderInput']]) {
    node(button).onclick();
    assert.equal(node(input).clicks, 1, `${button} opens its own file picker`);
}
const otherID = 'b'.repeat(32);
destinations = [
    {member_id:memberID,site_type:'direct',address:'https://first.test',writable:true},
    {member_id:otherID,site_type:'direct',address:'https://chosen.test',writable:true},
];
await context.refreshStoragePool();
node('uploadSiteType').value = otherID;
await context.runUploadTask([file]);
assert.equal(transfers.at(-1).form.fields.get('storage_member_id'), otherID);
assert(node('uploadSiteType').options.some(option => option.value === otherID && option.textContent.includes('https://chosen.test')));
destinations[1].writable = false;
await context.refreshStoragePool();
assert.equal(node('uploadSiteType').value, '', 'unavailable previous selection is cleared without selecting a replacement');
assert.equal(node('uploadFiles').disabled, true);
const noFallbackTransfers = transfers.length;
await context.runUploadTask([file]);
assert.equal(transfers.length,noFallbackTransfers,'another ready node must not receive the upload');
context.clusterUpload = true;
node('uploadSiteType').value = memberID;
ticketMemberID = otherID;
const mismatchStart = requests.length;
await context.runUploadTask([file]);
assert.equal(transfers.length,noFallbackTransfers,'a ticket for another owner never receives bytes');
assert.match(results.at(-1)[2],/所选节点不一致/);
assert(requests.slice(mismatchStart).some(request=>request.url.endsWith('/upload/session/reservation')),
    'a mismatched reservation is cancelled through the existing lifecycle');

const checksum = vm.runInContext('uploadSHA256', context);
for (const size of [0, 1, 55, 56, 63, 64, 65, 1024 * 1024 + 121]) {
    const input = Uint8Array.from({length: size}, (_, index) => index % 237);
    assert.equal(await checksum(new Blob([input])), createHash('sha256').update(input).digest('hex'));
}
selectedProtocol = true;
await context.refreshStoragePool();
node('uploadSiteType').value = memberID;
loseOwnerResponse = true;
loseCompleteResponse = true;
const selectedStart = requests.length;
await context.runUploadTask([file], ['album/a.mp3']);
const selectedRequests = requests.slice(selectedStart);
const prepare = selectedRequests.find(request => request.url.endsWith('/selected/prepare')).body;
assert.equal(prepare.parent_path, 'music/category/album');
assert.equal(prepare.storage_member_id, memberID);
assert.equal(prepare.cipher_sha256, createHash('sha256').update(new Uint8Array(516).fill(23)).digest('hex'));
assert(selectedRequests.some(request => request.url.endsWith('/resume')));
assert(selectedRequests.some(request => request.url.endsWith('/status')));
assert.equal(results.at(-1)[1], 'ok');
assert.equal(transfers.length, noFallbackTransfers, 'selected upload never uses the old upload interface');
assert.deepEqual(selectedTransfers.map(({options}) => options.method), ['PUT', 'POST']);
for (const {options} of selectedTransfers) {
    assert.equal(options.credentials, 'omit');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers['X-CSRF-Token'], undefined);
    assert.equal(options.headers['X-Fc-Selected-Upload'], 'fixture-owner-capability');
}
assert.equal(context.activeUploadRequests.size, 0);

selectedTransport = 'Relay';
loseOwnerResponse = false;
savedOwnerReceipt = {receipt: {blob_id: 'saved-owner-blob'}, signature: 'saved-owner-signature'};
const replayStart = requests.length;
const relayTransferStart = selectedTransfers.length;
await context.runUploadTask([file]);
assert.deepEqual(requests.slice(replayStart).filter(request => request.url.endsWith('/complete')).map(request => request.body), [
    {receipt: {blob_id: 'opaque'}, signature: 'fixture-signature'}, savedOwnerReceipt,
]);
assert.equal(selectedTransfers.length, relayTransferStart + 1, 'completion recovery does not resend the file');
savedOwnerReceipt = undefined;
loseCompleteResponse = false;
const relay = selectedTransfers.at(-1);
assert.match(relay.url, /^https:\/\/master\.test\/api\/v1\/media\/admin\/upload\/selected\/[a-f0-9]{32}\/bytes$/);
assert.equal(relay.options.credentials, 'same-origin');
assert.equal(relay.options.headers['X-CSRF-Token'], 'fixture-csrf');
assert.equal(relay.options.headers['X-Fc-Selected-Upload'], undefined);
assert.equal(results.at(-1)[1], 'ok');

unexpectedTicket = true;
const selectedTransferCount = selectedTransfers.length;
await context.runUploadTask([file]);
assert.equal(selectedTransfers.length, selectedTransferCount, 'mismatched ticket receives no request');
assert.equal(transfers.length, noFallbackTransfers, 'mismatched ticket cannot select the legacy route');
assert.match(results.at(-1)[2], /所选节点不一致/);

unexpectedTicket = false;
selectedTransport = 'Local';
const lyric = Object.assign(new Blob(['[00:01.00]test']), {name: 'test.lrc'});
const masterMemberID = 'c'.repeat(32);
destinations.push({member_id: masterMemberID, site_type: 'primary', address: 'https://master.test', writable: true});
await context.refreshStoragePool();
node('uploadSiteType').value = '';
const beforeLyric = requests.length;
await context.runUploadTask([lyric], ['album/test.lrc'], true);
assert.equal(requests.length, beforeLyric, 'lyrics require an explicitly selected Master destination');
assert.match(alerts.at(-1), /请选择主站/);
node('uploadSiteType').value = memberID;
await context.runUploadTask([lyric], ['album/test.lrc'], true);
assert.equal(requests.length, beforeLyric, 'a Direct destination cannot receive lyrics');
node('uploadSiteType').value = masterMemberID;
await context.runUploadTask([lyric], ['album/test.lrc'], true);
const lyricPrepare = requests.slice(beforeLyric).find(request => request.url.endsWith('/selected/prepare')).body;
assert.equal(lyricPrepare.parent_path, 'lyrics/album');
assert.equal(lyricPrepare.storage_member_id, masterMemberID);
assert.equal(lyricPrepare.filename, 'test.lrc');
assert.equal(results.at(-1)[1], 'ok');
assert.equal(transfers.length, noFallbackTransfers, 'sealed lyrics never use the old lyric upload interface');

selectedTransport = 'S3';
const s3Member = 'e'.repeat(32);
const s3File = Object.assign(new Blob([new Uint8Array(500)]), {name: 's3.mp3'});
destinations.push({member_id: s3Member, site_type: 's3', address: 'https://objects.example', writable: true});
await context.refreshStoragePool();
node('uploadSiteType').value = s3Member;
const beforeLostPrepare = requests.length;
const beforeLostCleanup = cleanupCalls;
losePrepareResponse = true;
await context.runUploadTask([s3File]);
const lost = storedS3()[0];
assert.match(results.at(-1)[2], /prepare response lost/);
assert.equal(lost.id, requests[beforeLostPrepare].body.upload_id);
assert.equal(cleanupCalls, beforeLostCleanup);
assert(retained.has(lost.cipherName));
assert(!recoveryRecords.get(recoveryKey).includes('signed-preparation'));

losePrepareResponse = false;
denyRecoveryWrite = true;
const beforeDeniedPrepare = requests.length;
await context.runUploadTask([s3File]);
assert.equal(requests.slice(beforeDeniedPrepare).filter(request => request.url.includes('/upload/')).length, 0);
assert.match(results.at(-1)[2], /保存恢复信息/);
assert.equal(cleanupCalls, beforeLostCleanup + 1);
assert.deepEqual(storedS3(), [lost]);

denyRecoveryWrite = false;
unexpectedTicket = true;
const beforeWrongS3 = requests.length;
await context.runUploadTask([s3File]);
assert.deepEqual(requests.slice(beforeWrongS3).filter(request => request.url.includes('/upload/')).map(request => request.url),
    ['/api/v1/media/admin/upload/selected/prepare']);
assert.match(results.at(-1)[2], /所选节点不一致/);
const pending = storedS3();
assert.equal(pending.length, 2);
assert(pending.every(task => retained.has(task.cipherName)));

unexpectedTicket = false;
await context.runUploadTask([s3File]);
assert.equal(results.at(-1)[1], 'ok');
assert.deepEqual(storedS3(), pending, 'authenticated publication removes only the published task');
assert.deepEqual([...retained], pending.map(task => task.cipherName));
assert.equal(transfers.length, noFallbackTransfers, 'selected S3 never falls back to a different owner');
console.log('admin-crypto-upload-smoke-ok');

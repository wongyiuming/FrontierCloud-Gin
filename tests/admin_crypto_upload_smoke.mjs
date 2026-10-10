import assert from 'node:assert/strict';
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
node('uploadSiteType').value = 'primary';
const body = new Element();
const alerts = [];
const requests = [];
const transfers = [];
const results = [];
let encryptedCalls = 0;
let cleanupCalls = 0;
let encryptionFails = false;
let serverFails = false;
class TestFormData {
    constructor() { this.fields = new Map(); }
    append(name, value) { this.fields.set(name, value); }
}
const context = {
    document: {getElementById: node, createElement: () => new Element(), body, querySelectorAll: () => []},
    $: node, alert: message => alerts.push(message), FormData: TestFormData,
    currentPath: 'music/category', clusterUpload: false, uploadRunning: false,
    uploadLimits: {max_upload_task_files: 5000, max_upload_file_size: 1000000, max_lyric_file_size: 100000},
    selected: new Set(), selectionKind: 'file', console,
    requestHeaders: () => ({}), formatSize: String,
    setProgress() {}, setUploadControlsDisabled(value) { context.uploadRunning = value; },
    renderTree: async () => {}, refreshStoragePool: async () => {}, loadLyricCatalog: async () => {},
    addUploadResult(...result) { results.push(result); },
    showModal() {}, clearMediaSelection() {}, runUploadTask() {},
    async api(url, options = {}) {
        requests.push({url, body: options.body ? JSON.parse(options.body) : undefined});
        if (url.endsWith('/storage-pool')) return {standalone: !context.clusterUpload};
        if (url.endsWith('/upload/session')) return {upload_id: 'reservation', transport: 'Direct',
            upload_url: 'https://direct.example/upload', path: 'music/category/a.mp3'};
        if (url.endsWith('/finalize')) return {path: 'music/category/a.mp3'};
        return {};
    },
    async uploadOne(form, progress, endpoint) {
        transfers.push({form, endpoint}); progress(1);
        if (serverFails) throw new Error('storage rejected ciphertext');
        return {path: 'music/category/a.mp3'};
    },
    async uploadRaw(url, file, progress) { transfers.push({url, file}); progress(1); },
};
context.window = context;
context.FrontierMediaCrypto = {async encryptFile(file) {
    encryptedCalls += 1;
    if (encryptionFails) throw new Error('browser encryption failed');
    return {file: {name: 'temporary-ciphertext', size: file.size + 16},
        encryption: {file_id: 'f'.repeat(32)}, preparation_token: 'signed-preparation',
        async cleanup() { cleanupCalls += 1; }};
}};
vm.createContext(context);
vm.runInContext(fs.readFileSync('static/js/admin-upload-integrity.js', 'utf8'), context);
await new Promise(resolve => setTimeout(resolve, 0));

const file = {name: 'a.mp3', size: 500};
await context.runUploadTask([file]);
assert.equal(alerts.length, 1, 'a selection with no fresh storage choice is refused');
assert.equal(transfers.length, 0);
node('uploadFiles').onclick();
let dialog = body.children.at(-1);
assert.equal(dialog.open, true);
assert.deepEqual(dialog.children[2].children.map(button => button.textContent), ['加密落盘', '明文落盘']);
assert.equal(node('fileInput').dataset.storageMode, undefined, 'the new selection has no default storage mode');
dialog.children[2].children[1].listeners.get('click')();
assert.equal(node('fileInput').dataset.storageMode, 'plain');
assert.equal(node('fileInput').clicks, 1);
await node('fileInput').onchange({target: Object.assign(node('fileInput'), {files: [file]})});
assert.equal(transfers[0].form.fields.get('storage_mode'), 'plain');
assert.equal(transfers[0].form.fields.get('file'), file);
assert.equal(node('fileInput').dataset.storageMode, undefined, 'mode is consumed by exactly this picker selection');
assert.equal(encryptedCalls, 0);

node('uploadFiles').onclick();
dialog = body.children.at(-1);
assert.equal(node('fileInput').dataset.storageMode, undefined, 'previous plaintext choice is never reused');
dialog.children[2].children[0].listeners.get('click')();
encryptionFails = true;
await node('fileInput').onchange({target: Object.assign(node('fileInput'), {files: [file]})});
assert.equal(transfers.length, 1, 'encryption failure never submits plaintext');
assert.match(results.at(-1)[2], /browser encryption failed/);
assert.equal(node('fileInput').dataset.storageMode, undefined);

encryptionFails = false;
serverFails = true;
await context.runUploadTask([file], null, false, 'encrypted');
assert.equal(cleanupCalls, 1, 'failed storage upload cleans the ciphertext temporary file');
assert.equal(transfers[1].form.fields.get('storage_mode'), 'encrypted');
assert.equal(transfers[1].form.fields.get('file').name, 'temporary-ciphertext');
assert.equal(transfers[1].form.fields.get('preparation_token'), 'signed-preparation');

serverFails = false;
await context.runUploadTask([{name: 'a.lrc', size: 20}], null, true, 'encrypted');
assert.equal(transfers.at(-1).endpoint, '/api/v1/media/admin/upload/lyric');
assert.equal(transfers.at(-1).form.fields.get('storage_mode'), 'encrypted');
assert.equal(cleanupCalls, 2);

context.clusterUpload = true;
const before = requests.length;
await context.runUploadTask([file, {...file, name: 'b.mp3'}], null, false, 'encrypted');
const reservations = requests.slice(before).filter(request => request.url.endsWith('/upload/session'));
assert.equal(reservations.length, 2);
assert(reservations.every(request => request.body.storage_mode === 'encrypted' && request.body.size_bytes === 516));
assert(reservations.every(request => request.body.preparation_token === 'signed-preparation'));
assert.equal(transfers.at(-1).file.name, 'temporary-ciphertext');
assert.equal(cleanupCalls, 4, 'successful direct uploads also remove ciphertext temporary files');

for (const button of ['uploadFolder', 'uploadLyrics', 'uploadLyricsFolder']) {
    node(button).onclick();
    assert.equal(body.children.at(-1).children[2].children.length, 2, `${button} requires its own explicit choice`);
}
console.log('admin-crypto-upload-smoke-ok');

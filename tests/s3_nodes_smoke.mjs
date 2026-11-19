import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const elements = new Map();
class Element {
    constructor(tag = 'div') {
        this.tagName = tag.toUpperCase(); this.children = []; this.attributes = {}; this.value = '';
        this.classList = {toggle() {}, contains: () => false}; this.textContent = '';
    }
    set id(value) { this._id = value; elements.set(value, this); }
    get id() { return this._id; }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    before(value) { panel.append(value); }
    after(value) { panel.append(value); }
    setAttribute(name, value) { this.attributes[name] = value; }
    addEventListener() {}
    contains() { return false; }
    querySelector(selector) { return selector === '.nodes-table-scroll' ? table : heading; }
}
const node = id => { if (!elements.has(id)) { const value = new Element(); value.id = id; } return elements.get(id); };
const panel = node('nodesPanel'), table = new Element(), heading = new Element();
const requests = [];
const member = {member_id: 'private-storage-id', member_kind: 'S3', transport: 'S3', name: '上海对象存储', location: {
    endpoint: 'https://s3.example.cn', region: 'cn-region-1', bucket: 'media', prefix: 'frontier/', style: 'path'},
    revision: 7, storage_enabled: false, allocated_bytes: 1073741824, used_bytes: 50, reserved_bytes: 8,
    probe_state: 'ready', secret_key: 'malicious-response-must-never-populate'};
const GiB = 1073741824;
const native = {member_id: 'native-local', member_kind: 'MasterLocal', transport: 'Local',
    physical_total_bytes: 8 * GiB, physical_free_bytes: 2 * GiB, allocated_bytes: 3 * GiB, used_bytes: GiB};
let pool = {members: [native, member], physical_total_bytes: null, physical_free_bytes: null,
    physical_capacity_known: false, current_allocated_bytes: 4 * GiB, project_used_bytes: GiB};
let s3Unavailable = false;
let s3Gate = null;
let s3Mode = 'legacy';
const context = {document: {getElementById: id => id === 'nodeS3Creation' ? (elements.get(id) || null) : node(id), createElement: tag => new Element(tag), createTextNode: text => ({textContent: text})},
    console, Date, Map, Set, AbortController, setTimeout, setInterval, clearInterval,
    requestHeaders: () => ({'X-CSRF-Token': 'control-only'}), window: {confirm: () => true},
    async api(url, options = {}) {
        requests.push({url, ...options});
        if (url.endsWith('/nodes')) return {role: 'Master', node_id: 'private-master-id', app_version: '1', protocol: 1,
            endpoint: 'https://master.example', relationships: [], storage_pool: pool};
        if (url.endsWith('/observability')) return {members: []};
        if (url.endsWith('/s3') && !options.method) {
            if (s3Unavailable) throw new Error('S3 操作未完成，请查看节点状态后重试');
            if (s3Gate) return await new Promise((resolve, reject) => { s3Gate.resolve = resolve; s3Gate.reject = reject; });
            return {members: [member], configuration_mode: s3Mode};
        }
        return {};
    },
};
vm.createContext(context); vm.runInContext(fs.readFileSync('static/js/nodes.js', 'utf8'), context);
await node('nodesRefresh').onclick();
const walk = element => [element, ...(element.children || []).flatMap(walk)];
const all = () => walk(panel).concat(...[...elements.values()].map(walk));
const storageOverview = () => node('nodeFleetOverview').children.find(value => value.children[0]?.textContent === 'Storage');
const storageValue = () => storageOverview().children[1].textContent;
assert.equal(storageValue(), '物理容量未知', 'a pool containing a disabled S3 member must not claim zero physical capacity');
assert.equal(node('storagePoolSummary').textContent,
    'Storage Pool · 物理容量未知 · 已使用 / 已分配 1.00 GiB / 4.00 GiB',
    'unknown aggregate physical capacity must retain independent logical usage and allocation');
assert(!node('nodeIdentity').textContent.includes('private-master-id'));
const card = node('nodeRelationships').children.find(value => walk(value).some(child => child.textContent === '上海对象存储'));
assert(walk(card).some(value => value.textContent === '上海对象存储'));
assert(walk(card).some(value => value.textContent === 'https://s3.example.cn'));
assert(!walk(card).some(value => value.textContent?.includes('private-storage-id')));
const toggle = walk(card).find(value => value.className === 'node-details-toggle');
assert.equal(toggle.attributes['aria-expanded'], 'false'); toggle.onclick();
assert.equal(toggle.attributes['aria-expanded'], 'true');
assert(walk(card).some(value => value.textContent?.includes('物理容量未知')));
assert(walk(card).some(value => value.textContent === '外部流量'));
const form = walk(card).find(value => value.tagName === 'FORM');
const inputs = walk(form).filter(value => value.tagName === 'INPUT');
const passwordInputs = inputs.filter(value => value.type === 'password');
assert(passwordInputs.every(value => value.value === ''), 'server data cannot refill credentials');
passwordInputs[0].value = 'new-access'; passwordInputs[1].value = 'new-secret';
form.onsubmit({preventDefault() {}});
await new Promise(resolve => setTimeout(resolve, 0));
const update = requests.find(value => value.method === 'PATCH');
assert(update); const body = JSON.parse(update.body);
assert.equal(body.revision, 7); assert.equal(body.credentials.secret_key, 'new-secret');
assert.equal(body.location.endpoint, member.location.endpoint); assert.equal(body.enabled, false);
assert(passwordInputs.every(value => value.value === ''), 'password fields clear immediately on submission');
assert.equal(node('nodeS3Creation').hidden, false);
assert(!all().some(value => value.textContent?.includes('malicious-response-must-never-populate')));

s3Unavailable = true;
await node('nodesRefresh').onclick();
assert(node('nodeIdentity').textContent.startsWith('Master ·'), 'S3 failure must not block the native node identity');
assert(node('storagePoolSummary').textContent.startsWith('Storage Pool ·'), 'S3 failure must not block native pool status');
assert(node('nodeRelationships').children.some(value => walk(value).some(child => child.textContent?.includes('Local'))), 'native storage card remains visible');
assert.equal(node('nodeS3Creation').children[0].textContent, 'S3 状态暂不可用，请刷新后重试');
assert.equal(node('nodeS3Creation').children[1].hidden, true, 'S3 creation is unavailable while its state is unknown');
assert(!node('nodeRelationships').children.some(value => walk(value).some(child => child.textContent === '上海对象存储')), 'unknown S3 members are not presented as current');
s3Unavailable = false;
await node('nodesRefresh').onclick();
assert.equal(node('nodeS3Creation').children[0].textContent, '添加 S3 存储');
assert.equal(node('nodeS3Creation').children[1].hidden, false);
assert(node('nodeRelationships').children.some(value => walk(value).some(child => child.textContent === '上海对象存储')), 'S3 management recovers after a successful refresh');

const delayed = {};
s3Gate = delayed;
await node('nodesRefresh').onclick();
assert(node('nodeIdentity').textContent.startsWith('Master ·'), 'a pending S3 request must not block native node rendering');
assert.equal(node('nodeS3Creation').children[0].textContent, 'S3 状态加载中');
assert.equal(node('nodeS3Creation').children[1].hidden, true);
s3Gate = null;
await node('nodesRefresh').onclick();
assert.equal(node('nodeS3Creation').children[0].textContent, '添加 S3 存储');
delayed.reject(new Error('old request failed'));
await new Promise(resolve => setTimeout(resolve, 0));
assert.equal(node('nodeS3Creation').children[0].textContent, '添加 S3 存储', 'an old failed request must not overwrite a newer successful refresh');

member.storage_enabled = true;
await node('nodesRefresh').onclick();
assert.equal(storageValue(), '物理容量未知', 'enabling S3 cannot make provider physical capacity known');
pool = {...pool, physical_total_bytes: 0, physical_free_bytes: 0};
await node('nodesRefresh').onclick();
assert.equal(storageValue(), '物理容量未知', 'an explicit unknown flag takes priority over numeric placeholder fields');

pool = {members: [], physical_total_bytes: 8 * GiB, physical_free_bytes: 2 * GiB,
    current_allocated_bytes: 4 * GiB, project_used_bytes: GiB};
await node('nodesRefresh').onclick();
assert.equal(storageValue(), '6.00 GiB / 8.00 GiB', 'legacy native observations without a known flag remain supported');
assert.equal(node('storagePoolSummary').textContent,
    'Storage Pool · 物理 used / all 6.00 GiB / 8.00 GiB · 已使用 / 已分配 1.00 GiB / 4.00 GiB');

pool = {...pool, physical_total_bytes: 0, physical_free_bytes: 0, physical_capacity_known: true};
await node('nodesRefresh').onclick();
assert.equal(storageValue(), '0.00 GiB / 0.00 GiB', 'a known zero observation differs from an unknown provider');
pool = {...pool, physical_total_bytes: null, physical_free_bytes: null};
delete pool.physical_capacity_known;
await node('nodesRefresh').onclick();
assert.equal(storageValue(), '物理容量未知', 'null observations must not become numeric zeros when no flag is present');
const creation = node('nodeS3Creation').children[1];
const creationInputs = walk(creation).filter(value => value.tagName === 'INPUT');
assert(!creationInputs.some(value => value.type === 'checkbox'), 'new members always start disabled');
for (const [label, value] of Object.entries({'显示名称': '新节点', 'HTTPS 服务地址': member.location.endpoint,
    '存储桶': 'new-bucket', '区域': 'us-east-1', 'Access Key': 'fixture-access', 'Secret Key': 'fixture-secret'})) {
    creationInputs.find(input => input.attributes['aria-label'] === label).value = value;
}
creation.onsubmit({preventDefault() {}});
await new Promise(resolve => setTimeout(resolve, 0));
const add = requests.find(value => value.method === 'POST' && value.url.endsWith('/s3'));
assert.equal(JSON.parse(add.body).enabled, false);

s3Mode = 'sealed';
member.storage_enabled = false;
const selectedS3Details = async () => {
    await node('nodesRefresh').onclick();
    const row = node('nodeRelationships').children.find(value => walk(value).some(child => child.textContent === member.name));
    const detailsToggle = walk(row).find(value => value.className === 'node-details-toggle');
    if (detailsToggle.attributes['aria-expanded'] === 'false') detailsToggle.onclick();
    return walk(row);
};
let sealed = await selectedS3Details();
assert(!sealed.some(value => value.tagName === 'FORM'), 'sealed members have no credential or location editors');
assert(sealed.some(value => value.textContent === '上次检查通过'));
assert(sealed.some(value => value.textContent?.includes('重启后需重新检查')));
assert(sealed.some(value => value.textContent === '检查连接与读写'));
assert(sealed.some(value => value.textContent === '移除配置'));
assert(!sealed.find(value => value.textContent === '启用新上传').disabled);
await sealed.find(value => value.textContent === '启用新上传').onclick();
const enable = requests.filter(value => value.method === 'PATCH').at(-1);
assert.deepEqual(JSON.parse(enable.body), {revision: member.revision, name: member.name, location: member.location,
    allocated_bytes: member.allocated_bytes, enabled: true});
member.storage_enabled = true;
sealed = await selectedS3Details();
assert(sealed.find(value => value.textContent === '停用新上传').disabled, 'existing data or reservations prevent disable');
member.used_bytes = 0; member.reserved_bytes = 0;
sealed = await selectedS3Details();
assert(!sealed.find(value => value.textContent === '停用新上传').disabled);
await sealed.find(value => value.textContent === '停用新上传').onclick();
const disable = requests.filter(value => value.method === 'PATCH').at(-1);
assert.deepEqual(JSON.parse(disable.body), {...JSON.parse(enable.body), enabled: false});
s3Mode = undefined;
const unknown = await selectedS3Details();
assert(unknown.some(value => value.textContent?.includes('配置能力待确认')));
assert(!unknown.some(value => value.tagName === 'FORM' || value.textContent === '停用新上传'));
console.log('s3-nodes-smoke-ok (native collapsed cards, address identity, write-only credentials, revision-bound configuration, truthful physical capacity)');

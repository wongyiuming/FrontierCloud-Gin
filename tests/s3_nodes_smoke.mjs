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
const context = {document: {getElementById: node, createElement: tag => new Element(tag), createTextNode: text => ({textContent: text})},
    console, Date, Map, Set, setTimeout, setInterval, clearInterval,
    requestHeaders: () => ({'X-CSRF-Token': 'control-only'}), window: {confirm: () => true},
    async api(url, options = {}) {
        requests.push({url, ...options});
        if (url.endsWith('/nodes')) return {role: 'Master', node_id: 'private-master-id', app_version: '1', protocol: 1,
            endpoint: 'https://master.example', relationships: [], storage_pool: pool};
        if (url.endsWith('/observability')) return {members: []};
        if (url.endsWith('/s3') && !options.method) return {members: [member]};
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
console.log('s3-nodes-smoke-ok (native collapsed cards, address identity, write-only credentials, revision-bound configuration, truthful physical capacity)');

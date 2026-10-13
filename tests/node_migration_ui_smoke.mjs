import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
class Element {
    constructor(tag) { this.tag = tag; this.children = []; this.dataset = {}; this.style = {}; this.classList = {contains: () => false, toggle() {}}; }
    append(...items) { this.children.push(...items); }
    replaceChildren(...items) { this.children = items; }
    setAttribute() {}
    querySelector() { return {addEventListener() {}}; }
    set innerHTML(value) { if (value !== '') throw new Error('untrusted HTML rendering'); this.children = []; }
}
const elements = new Map();
const document = {
    getElementById(id) { if (!elements.has(id)) elements.set(id, new Element('div')); return elements.get(id); },
    querySelector: () => null, head: new Element('head'),
    createElement: tag => new Element(tag), createTextNode: text => ({textContent: text}),
};
const task = {task_id: '1'.repeat(32), source_id: '2'.repeat(32), target_id: '3'.repeat(32), revision: 7, state: 'failed', error_code: 'target_unavailable', object_count: 18, total_bytes: 100, committed_bytes: 40};
const page = () => ({tasks: [{...task}], complete: false, next_time: 123, next_id: task.task_id});
const calls = [];
let confirm = false;
let prompted = "wrong-source";
const context = vm.createContext({document, window: {confirm: () => confirm, prompt: () => prompted}, Date, console, setTimeout, setInterval, clearInterval,
    requestHeaders: () => ({'X-CSRF-Token': 'fixture'}),
    api: async (path, options = {}) => {
        calls.push({path, options});
        if (options.method === 'POST') { if (!path.endsWith('/release-drain')) { task.revision++; task.state = 'queued'; task.error_code = ''; } return {...task}; }
        if (path === '/api/v1/media/admin/nodes') return {role: 'Master', storage_pool: {members: []}};
        if (path === '/api/v1/media/admin/nodes/observability') return {};
        if (path.includes(`/migrations/${task.task_id}`)) return {task: {...task}, objects: [{physical_path: '<img src=x onerror=alert(1)>', state: 'published', verified_bytes: 10, size_bytes: 10}], object_stages: [{state: 'published', count: 1, verified_bytes: 10, size_bytes: 10}], unit_stages: [{state: 'pending', count: 1, size_bytes: 100}], complete: false, next: 'a'.repeat(64)};
        if (path.includes('/nodes/migrations')) return page();
        throw new Error(`unexpected API ${path}`);
    },
});
const source = fs.readFileSync('static/js/nodes.js', 'utf8');
vm.runInContext(source.replace(/\}\)\(\);\s*$/, 'window.testMigrationPanel = migrationPanel;})();'), context);
const all = element => [element, ...element.children.flatMap(all)];
const text = element => all(element).map(item => item.textContent || '').join('\n');
const button = (element, label) => all(element).find(item => item.tag === 'button' && item.textContent === label);
let panel = context.window.testMigrationPanel(page());
assert.match(text(panel), /失败原因：target_unavailable/);
assert.match(text(panel), /已提交 \/ 全部/);
assert.match(text(panel), /取消保留已提交资源/);
assert(!button(panel, '恢复'));
const before = calls.filter(call => call.options.method === 'POST').length;
await button(panel, '取消任务').onclick();
assert.equal(calls.filter(call => call.options.method === 'POST').length, before);
assert.match(text(document.getElementById('nodeRelationships')), /target_unavailable/);
await button(panel, '重试').onclick();
const request = calls.find(call => call.options.method === 'POST');
assert.match(request.path, /\/migrations\/[a-f0-9]{32}\/control$/);
const payload = JSON.parse(request.options.body);
assert.equal(payload.action, 'retry'); assert.equal(payload.revision, 7);
assert.equal(payload.confirm_source_id, task.source_id); assert.equal(payload.confirm_target_id, task.target_id);
assert.equal(request.options.headers['X-CSRF-Token'], 'fixture');
const rendered = document.getElementById('nodeRelationships');
assert.match(text(rendered), /对象 published/);
assert.match(text(rendered), /归属单元 pending/);
assert.equal(all(rendered).filter(item => item.textContent?.startsWith('<img')).length, 1);
panel = context.window.testMigrationPanel(page());
await button(panel, '下一页对象').onclick();
assert(calls.some(call => call.path.includes(`?after=${'a'.repeat(64)}`)));
await button(panel, '下一页任务').onclick();
assert(calls.some(call => call.path.includes(`after_time=123&after_id=${task.task_id}`)));
task.state = 'completed';
panel = context.window.testMigrationPanel(page());
const count = calls.filter(call => call.options.method === 'POST').length;
await button(panel, '明确解除本任务排空').onclick();
assert.equal(calls.filter(call => call.options.method === 'POST').length, count);
prompted = task.source_id;
await button(panel, '明确解除本任务排空').onclick();
const release = calls.filter(call => call.options.method === 'POST').at(-1);
assert.match(release.path, /\/release-drain$/);
assert.equal(JSON.parse(release.options.body).confirm_source_id, task.source_id);
assert.equal(JSON.parse(release.options.body).revision, task.revision);
console.log('node-migration-ui-smoke-ok (DOM fixture; native browser acceptance remains external)');

import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
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
const plan = {plan_id: '5'.repeat(32), request_id: '6'.repeat(32), state: 'ready', source: {member_id: task.source_id, transport: 'Direct'}, target: {member_id: task.target_id, transport: 'Relay'}, review_sha256: 'a'.repeat(64), unit_count: 1, object_count: 1, total_bytes: 10, verified_objects: 1, verified_bytes: 10, objects: [{resource_kind: 'media', physical_path: '<plan onerror=alert(1)>', parent_path: 'music/unit', size_bytes: 10}], blockers: [], source_residuals: [], complete: true};
let confirm = false;
let prompted = "wrong-source";
let execution = null;
const context = vm.createContext({document, window: {confirm: () => confirm, prompt: () => prompted}, crypto: webcrypto, Uint8Array, Date, console, setTimeout, setInterval, clearInterval,
    requestHeaders: () => ({'X-CSRF-Token': 'fixture'}),
    api: async (path, options = {}) => {
        calls.push({path, options});
        if (path.includes('/migration-plans')) {
            if (path.endsWith('/start')) plan.state = 'starting';
            return {...plan};
        }
        if (options.method === 'POST') { if (!path.endsWith('/release-drain')) { task.revision++; task.state = 'queued'; task.error_code = ''; } return {...task}; }
        if (path === '/api/v1/media/admin/nodes') return {role: 'Master', storage_pool: {members: []}};
        if (path === '/api/v1/media/admin/nodes/observability') return {};
        if (path.includes(`/migrations/${task.task_id}`)) return {task: {...task}, execution, queue_position: 1, objects: [{physical_path: '<img src=x onerror=alert(1)>', state: 'published', verified_bytes: 10, size_bytes: 10}], object_stages: [{state: 'published', count: 1, verified_bytes: 10, size_bytes: 10}], unit_stages: [{state: 'pending', count: 1, size_bytes: 100}], complete: false, next: 'a'.repeat(64)};
        if (path.includes('/nodes/migrations')) return page();
        throw new Error(`unexpected API ${path}`);
    },
});
assert(!fs.readFileSync('static/js/nodes.js', 'utf8').includes('/migration-plans'));
assert(!fs.readFileSync('static/js/nodes.js', 'utf8').includes('/nodes/migrations'));
const source = fs.readFileSync('static/js/node-migrations.js', 'utf8');
vm.runInContext(source.replace(/\}\)\(\);\s*$/, 'window.testMigrationPanel = migrationPanel; window.testMigrationPlanPanel = migrationPlanPanel;})();'), context);
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
assert.match(text(document.getElementById('migrationContent')), /target_unavailable/);
await button(panel, '重试').onclick();
const request = calls.find(call => call.options.method === 'POST');
assert.match(request.path, /\/migrations\/[a-f0-9]{32}\/control$/);
const payload = JSON.parse(request.options.body);
assert.equal(payload.action, 'retry'); assert.equal(payload.revision, 7);
assert.equal(payload.confirm_source_id, task.source_id); assert.equal(payload.confirm_target_id, task.target_id);
assert.equal(request.options.headers['X-CSRF-Token'], 'fixture');
const rendered = document.getElementById('migrationContent');
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
const nodes = {relationships: [{peer_id: task.source_id, state: 'active'}, {peer_id: task.target_id, state: 'active'}, {peer_id: '8'.repeat(32), state: 'retiring'}], storage_pool: {members: [
    {member_id: task.source_id, member_kind: 'Follower', transport: 'Direct', health: 'online', storage_enabled: 1, writable: 1},
    {member_id: task.target_id, member_kind: 'Follower', transport: 'Relay', health: 'online', storage_enabled: 1, writable: 1},
    {member_id: '9'.repeat(32), member_kind: 'Local', transport: 'Local', health: 'online'},
    {member_id: '8'.repeat(32), member_kind: 'Follower', transport: 'Direct', health: 'online', storage_enabled: 1, writable: 1},
]}};
let planning = context.window.testMigrationPlanPanel(nodes);
assert.match(text(planning), /Master Local 不支持/);
assert.match(text(planning), /退役处理中/);
assert(all(planning).filter(item => item.tag === 'option' && item.value === '8'.repeat(32)).every(item => item.disabled));
assert(all(planning).filter(item => item.tag === 'option' && item.value === task.target_id).every(item => !item.disabled));
const selects = all(planning).filter(item => item.tag === 'select');
selects[0].value = task.source_id; selects[0].onchange();
selects[1].value = task.target_id; selects[1].onchange();
await button(planning, '生成只读迁移计划').onclick();
const creation = calls.find(call => call.path.endsWith('/migration-plans') && call.options.method === 'POST');
assert(creation); assert.deepEqual(Object.keys(JSON.parse(creation.options.body)).sort(), ['request_id', 'source_id', 'target_id']);
planning = context.window.testMigrationPlanPanel(nodes);
assert.match(text(planning), /Direct → Relay/);
assert.equal(all(planning).filter(item => item.textContent?.includes('<plan')).length, 1);
prompted = 'wrong confirmation';
let starts = calls.filter(call => call.path.endsWith('/start')).length;
await button(planning, '确认并开始迁移').onclick();
assert.equal(calls.filter(call => call.path.endsWith('/start')).length, starts);
prompted = `${task.source_id} -> ${task.target_id}`;
await button(planning, '确认并开始迁移').onclick();
const start = calls.filter(call => call.path.endsWith('/start')).at(-1);
assert.deepEqual(Object.keys(JSON.parse(start.options.body)).sort(), ['confirm_source_id', 'confirm_target_id', 'review_sha256']);
assert.equal(JSON.parse(start.options.body).review_sha256, plan.review_sha256);
assert.equal(start.options.headers['X-CSRF-Token'], 'fixture');
plan.state = 'failed'; plan.error_code = 'physical_observation_changed_or_unavailable'; plan.error_stage = 'source_content';
planning = context.window.testMigrationPlanPanel(nodes);
await button(planning, '刷新计划').onclick();
planning = context.window.testMigrationPlanPanel(nodes);
assert.match(text(planning), /源文件校验失败：physical_observation_changed_or_unavailable/);
assert(!button(planning, '确认并开始迁移'));
plan.error_stage = '<img src=x onerror=alert(1)>';
await button(planning, '刷新计划').onclick();
planning = context.window.testMigrationPlanPanel(nodes);
assert.match(text(planning), /计划观察失败/);
assert(!text(planning).includes('<img'));
task.state = 'copying'; task.error_code = 'waiting_business_traffic';
execution = {state: 'waiting_traffic', object_id: 'f'.repeat(64), current_bytes: 25, current_total_bytes: 100, bytes_per_second: 0, waiting_node_id: task.source_id, traffic: [{node_id: task.source_id, role: 'source', traffic: {state:'high_traffic',can_run:false, ingress_bytes_per_second:300000,egress_bytes_per_second:0,recent_bytes_per_second:300000,high_bytes_per_second:262144,low_bytes_per_second:65536,low_interval_seconds:30}}]};
panel = context.window.testMigrationPanel(page());
await button(panel, '更新检查点').onclick();
panel = context.window.testMigrationPanel(page());
assert.match(text(panel), /队列位置/);
assert.match(text(panel), /等待业务低峰/);
assert.match(text(panel), /当前对象已复制/);
assert.match(text(panel), /源节点业务流量/);
assert.match(text(panel), /业务高峰，等待流量下降/);
assert(!text(panel).includes('失败原因：waiting_business_traffic'));
assert(button(panel, '暂停'));
assert(!button(panel, '恢复'));
console.log('node-migration-ui-smoke-ok (DOM fixture; native browser acceptance remains external)');

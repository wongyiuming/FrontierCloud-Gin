import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

class Element {
    constructor(tag) { this.tag = tag; this.children = []; this.dataset = {}; this.style = {}; this.classList = {contains: () => false, toggle() {}}; }
    append(...items) { this.children.push(...items); }
    setAttribute() {}
    querySelector() { return {addEventListener() {}}; }
    replaceWith(value) { this.replacement = value; }
    set innerHTML(_) { throw new Error('untrusted HTML rendering'); }
}
const elements = new Map();
const document = {
    getElementById(id) { if (!elements.has(id)) elements.set(id, new Element('div')); return elements.get(id); },
    querySelector: () => null, head: new Element('head'),
    createElement: tag => new Element(tag), createTextNode: text => ({textContent: text}),
};
let respond;
const calls = [];
const context = vm.createContext({document, window: {}, Date, console, setTimeout, setInterval, clearInterval,
    requestHeaders: () => ({'X-CSRF-Token': 'fixture'}),
    api: async (path, options) => { calls.push({path, options}); return await respond(); },
});
// Execute the complete module; expose only the panel factory in this fixture.
const source = fs.readFileSync('static/js/nodes.js', 'utf8');
vm.runInContext(source.replace(/\}\)\(\);\s*$/, 'window.testRetirementPanel = retirementPanel; window.testDisableRefresh = () => { refresh = async () => {}; };})();'), context);
const panelFor = () => context.window.testRetirementPanel({member_id: '2'.repeat(32)}, {relationship_id: '1'.repeat(32)});
const all = element => [element, ...element.children.flatMap(all)];
const text = element => all(element).map(item => item.textContent || '').join('\n');
let release;
respond = () => new Promise(resolve => { release = resolve; });
let panel = panelFor();
const button = all(panel).find(item => item.tag === 'button');
const pending = button.onclick();
assert.equal(button.disabled, true);
release({preflight_only: true, observation_complete: true, physical_entries: 91, logical_bytes: 273, expected_items: 1,
    volumes: [{scope: "media", retained_entries: 3, entries: 90, logical_bytes: 273, free_bytes: 1024, in_data_root: false}],
    master: {blockers: []}, peer: {blockers: []}, concerns: [{code: 'physical_unmanaged_file', count: 90, samples: Array(20).fill('<img src=x onerror=alert(1)>')}, {code: 'backup_retention_required', count: 1, samples: ['backup']}],
});
await pending;
panel = panel.replacement;
assert.equal(calls[0].options.method, 'POST');
assert.equal(calls[0].options.headers['X-CSRF-Token'], 'fixture');
assert.equal(JSON.parse(calls[0].options.body).member_id, '2'.repeat(32));
assert.match(calls[0].path, /\/retire\/check$/);
assert.match(text(panel), /历史观察，需重新检查/);
assert.match(text(panel), /先验证替代恢复点/);
assert.match(text(panel), /不能相加作为可用容量/);
assert.match(text(panel), /未验证/);
assert.match(text(panel), /保留原生状态/);
assert.equal(all(panel).filter(item => item.textContent === '<img src=x onerror=alert(1)>').length, 8);
assert.equal(all(panel).filter(item => item.tag === 'button').length, 1);
assert.match(text(panelFor()), /physical_unmanaged_file/);
respond = () => { const error = new Error('检查未完成'); error.responseData = {report: {preflight_only: true, observation_complete: false, concerns: [{code: 'expected_missing', count: 1, samples: ['lost.mp3']}]}}; throw error; };
await all(panel).find(item => item.tag === 'button').onclick();
panel = panel.replacement;
assert.match(text(panel), /检查未完成/);
assert.match(text(panel), /lost\.mp3/);
assert.match(text(panel), /缺失文件需要恢复/);
assert.equal(all(panel).find(item => item.tag === 'button').disabled, undefined);
assert(!text(panel).includes('撤销已获准'));
context.window.testDisableRefresh();
const retiring = () => context.window.testRetirementPanel({member_id: '2'.repeat(32)}, {relationship_id: '1'.repeat(32), state: 'retiring'});
panel = retiring();
assert.match(text(panel), /持久写入隔离已生效/);
let apply = all(panel).find(item => item.textContent === '重试完成安全退役');
assert(apply);
context.window.prompt = () => 'wrong-node';
const before = calls.length;
await apply.onclick();
assert.equal(calls.length, before, 'mismatched NodeID must not call apply');
context.window.prompt = () => '2'.repeat(32);
respond = () => ({member_id: '2'.repeat(32), completed_at: 1});
await apply.onclick();
assert.equal(calls.length, before + 1);
assert.match(calls.at(-1).path, /\/retire\/apply$/);
assert.equal(calls.at(-1).options.method, 'POST');
assert.equal(calls.at(-1).options.headers['X-CSRF-Token'], 'fixture');
assert.deepEqual(JSON.parse(calls.at(-1).options.body), {member_id: '2'.repeat(32), confirm_member_id: '2'.repeat(32)});
panel = context.window.testRetirementPanel({member_id: '2'.repeat(32)}, {relationship_id: '1'.repeat(32), state: 'revoked', summary: {retirement: {completed_at: 1}}});
assert.match(text(panel), /已安全退役/);
assert.match(text(panel), /旧工作凭据已失效/);
assert.equal(all(panel).filter(item => item.tag === 'button').length, 0);
console.log('node-retirement-ui-smoke-ok (DOM fixture; native browser acceptance remains external)');

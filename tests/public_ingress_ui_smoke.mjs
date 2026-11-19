import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

class Element {
    constructor(tag) { this.tag = tag; this.children = []; this.dataset = {}; this.style = {}; this.classList = {contains: () => false, toggle() {}}; }
    append(...items) { this.children.push(...items); }
    setAttribute() {}
    querySelector() { return {addEventListener() {}}; }
    set innerHTML(_) { throw new Error('untrusted HTML rendering'); }
}
const elements = new Map();
const document = {
    getElementById(id) { if (!elements.has(id)) elements.set(id, new Element('div')); return elements.get(id); },
    querySelector: () => null, head: new Element('head'),
    createElement: tag => new Element(tag), createTextNode: text => ({textContent: text}),
};
const calls = [];
const confirmations = [];
let confirmSwitch = false;
const context = vm.createContext({document, window: {confirm: text => { confirmations.push(text); return confirmSwitch; }}, Date, console, setTimeout, setInterval, clearInterval,
    requestHeaders: () => ({'X-CSRF-Token': 'fixture'}),
    api: async (path, options) => { calls.push({path, options}); return path.endsWith('/check') ? {origin: 'https://candidate.test'} : path.endsWith('/select') ? {public_origin: 'https://candidate.test'} : path.endsWith('2'.repeat(32)) ? {state: 'blocked'} : {}; },
});
const source = fs.readFileSync('static/js/nodes.js', 'utf8');
vm.runInContext(source.replace(/\}\)\(\);\s*$/, 'window.panel = transportPolicyPanel; refresh = async () => {};})();'), context);
const all = element => [element, ...element.children.flatMap(all)];
const text = element => all(element).map(item => item.textContent || '').join('\n');
const master = {member_id: '1'.repeat(32), member_kind: 'MasterLocal'};
const peer = {member_id: '2'.repeat(32), member_kind: 'Follower'};
const ingress = {node_id: master.member_id, public_origin: 'https://master.test'};
let panel = context.window.panel(master, {configured_transport: '', applied_transport: '', legacy_transport: '', effective_transport: 'Local', state: 'confirmation_required', revision: 0}, ingress);
assert.match(text(panel), /当前有效访问方式[\s\S]*Local/);
assert.match(text(panel), /非入口时的配置策略[\s\S]*待选择/);
assert.match(text(panel), /不会更改当前路径/);
let select = all(panel).find(item => item.tag === 'select');
select.value = 'Relay';
await all(panel).find(item => item.tag === 'button').onclick();
assert.match(calls[0].path, /\/public-routing\/transport\/1{32}$/);
assert.equal(calls[0].options.headers['X-CSRF-Token'], 'fixture');
assert.deepEqual(JSON.parse(calls[0].options.body), {configured_transport: 'Relay', revision: 0});
panel = context.window.panel(master, {configured_transport: 'Relay', applied_transport: '', effective_transport: 'Local', state: 'retained', peer_application_status: 'pending', revision: 1}, ingress);
assert.match(text(panel), /节点应用状态[\s\S]*非入口时待确认/);

panel = context.window.panel(peer, {configured_transport: 'Direct', applied_transport: '', legacy_transport: 'Direct', effective_transport: 'Direct', state: 'confirmation_required', revision: 0}, ingress);
assert.match(text(panel), /节点确认的策略[\s\S]*尚未验证/);
select = all(panel).find(item => item.tag === 'select');
assert.equal(select.disabled, false);
assert.match(text(panel), /实际访问方式及链路验证仍需分别确认/);
select.value = 'Relay';
await all(panel).find(item => item.tag === 'button').onclick();
assert.deepEqual(JSON.parse(calls[1].options.body), {configured_transport: 'Relay', revision: 0});
assert.match(elements.get('nodeOperationStatus').textContent, /已保存但尚未生效/);
assert.equal(calls.length, 2);
panel = context.window.panel(peer, {configured_transport: 'Relay', applied_transport: 'Relay', legacy_transport: 'Direct', effective_transport: 'Direct', state: 'applied', peer_application_status: 'applied', revision: 2}, ingress);
assert.match(text(panel), /当前有效访问方式[\s\S]*Direct/);
assert.match(text(panel), /节点确认的策略[\s\S]*Relay/);
assert.match(text(panel), /节点应用状态[\s\S]*节点已确认/);
assert.match(text(panel), /配置版本[\s\S]*2/);
panel = context.window.panel(peer, {configured_transport: 'Relay', applied_transport: '', effective_transport: 'Direct', state: 'blocked', peer_application_status: 'failed', revision: 3}, ingress);
assert.match(text(panel), /节点暂不能应用/);
panel = context.window.panel(peer, {configured_transport: 'Direct', applied_transport: 'Direct', applied_origin: 'https://resource.example', effective_transport: 'Relay', state: 'applied', peer_application_status: 'applied', revision: 4}, ingress);
assert.match(text(panel), /节点确认的资源地址[\s\S]*https:\/\/resource\.example/);
await all(panel).find(item => item.tag === 'button' && item.textContent === '检查入口候选').onclick();
assert.match(calls[2].path, /\/public-routing\/candidates\/2{32}\/check$/);
assert.match(elements.get('nodeOperationStatus').textContent, /代理链检查通过[\s\S]*尚未开放/);
assert.equal(all(panel).find(item => item.tag === 'button' && item.textContent === '选择为公共入口').disabled, true);
panel = context.window.panel(peer, {configured_transport: 'Direct', effective_transport: 'Direct', state: 'applied', revision: 4}, {...ingress, generation: 7}, true, 'https://candidate.test');
const selectIngress = all(panel).find(item => item.tag === 'button' && item.textContent === '选择为公共入口');
assert.equal(selectIngress.disabled, false);
await selectIngress.onclick();
assert.equal(calls.length, 3, 'cancel must not contact the selection API');
assert.match(confirmations[0], /当前入口 https:\/\/master\.test[\s\S]*目标入口 https:\/\/candidate\.test/);
confirmSwitch = true;
await selectIngress.onclick();
assert.equal(calls.length, 4);
assert.deepEqual(JSON.parse(calls[3].options.body), {member_id: peer.member_id, generation: 7, public_origin: 'https://candidate.test'});
console.log('public-ingress-ui-smoke-ok (DOM fixture; browser acceptance remains external)');

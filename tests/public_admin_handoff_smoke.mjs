import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const html = fs.readFileSync('static/media/index.html', 'utf8');
const script = html.match(/<script>\s*([\s\S]*?)<\/script>/)?.[1];
assert.ok(script, 'public homepage script exists');

async function fixture(publicOrigin, adminOrigin) {
    const clicks = new Map(), listeners = new Map(), requests = [], messages = [];
    const popup = {closed: false, close() { this.closed = true; }, postMessage(value, origin) { messages.push({value, origin}); }};
    const location = {origin: publicOrigin, href: '', assign(value) { this.href = value; }};
    const window = {open(url) { requests.push({popup: url}); return popup; },
        addEventListener(type, fn) { listeners.set(type, fn); },
        removeEventListener(type, fn) { if (listeners.get(type) === fn) listeners.delete(type); }};
    const context = {window, location, document: {getElementById(id) { return {addEventListener(type, fn) { clicks.set(id, fn); }}; }},
        prompt: () => 'admin-secret', alert(message) { throw new Error(message); }, URLSearchParams,
        setTimeout() { return 1; }, clearTimeout() {},
        async fetch(url, options) { requests.push({url, options}); return {ok: true, async json() {
            return url.endsWith('/authorize') ? {ticket: 'b'.repeat(43)} : {redirect: '/api/v1/media/admin'};
        }}; }};
    const body = script.replace('{{STUN_URLS_JSON}}', '[]').replace('{{WEBRTC_INTERVAL_MS}}', '1000')
        .replace('{{MEDIA_PREFETCH_ASSETS_JSON}}', '[]').replace('{{ADMIN_ORIGIN_JSON}}', JSON.stringify(adminOrigin));
    vm.runInNewContext(body, context);
    const click = clicks.get('elevateHotspot');
    for (let i = 0; i < 5; i++) click({preventDefault() {}});
    await new Promise(resolve => setImmediate(resolve));
    return {popup, requests, messages, listeners, location};
}

const same = await fixture('https://master.test', 'https://master.test');
assert.equal(same.requests[0].url, '/api/v1/media/admin/elevate');
assert.equal(same.location.href, '/api/v1/media/admin');

const cross = await fixture('https://entry.test', 'https://master.test');
assert.equal(cross.requests[0].popup, 'https://master.test/api/v1/media/admin/handoff/start');
const listener = cross.listeners.get('message');
const challenge = 'a'.repeat(43);
await listener({source: cross.popup, origin: 'https://forged.test', data: {type: 'frontiercloud-admin-flow', challenge}});
await listener({source: {}, origin: 'https://master.test', data: {type: 'frontiercloud-admin-flow', challenge}});
assert.equal(cross.requests.length, 1, 'forged messages do not transmit the key');
await listener({source: cross.popup, origin: 'https://master.test', data: {type: 'frontiercloud-admin-flow', challenge}});
assert.equal(cross.requests[1].url, '/api/v1/media/admin-handoff/authorize');
assert.equal(cross.requests[1].options.credentials, 'omit');
assert.deepEqual(JSON.parse(cross.requests[1].options.body), {challenge, key: 'admin-secret'});
assert.equal(cross.messages.length, 1);
assert.equal(cross.messages[0].origin, 'https://master.test');
assert.equal(cross.messages[0].value.challenge, challenge);
assert.equal(cross.messages[0].value.ticket, 'b'.repeat(43));
assert.equal(cross.listeners.has('message'), false, 'flow is consumed once');
console.log('public-admin-handoff-smoke-ok (DOM fixture; browser acceptance remains external)');

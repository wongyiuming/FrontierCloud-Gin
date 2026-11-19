import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

// Run the complete scripts with controlled DOM and same-origin API doubles.
const files = ['static/js/admin.js', 'static/js/admin-upload-integrity.js', 'static/js/admin-visibility-integrity.js'];
const sources = files.map(file => fs.readFileSync(new URL(`../${file}`, import.meta.url), 'utf8'));
const addresses = ['https://objects.example.test/bucket/', 'https://direct.example.test',
    'https://relay.example.test:8443', null, null];
const displays = ['objects.example.test/bucket', 'direct.example.test',
    'relay.example.test:8443', '地址不可用', 'admin.example.test'];
const siteTypes = ['direct', 'direct', 'relay', '', 'primary'];
const payload = ['Direct', 'Direct', 'Relay', 'Unknown', 'Local'].map((transport, index) => ({
    kind: 'file', name: `${transport}-${index}.mp3`, path: `music/album/${transport}-${index}.mp3`, size: 8493465,
    media: true, hideable: false, encrypted: index !== 1, transport,
    storage_address: addresses[index], storage_address_local: transport === 'Local',
}));
const destinations = [
    {member_id: '1'.repeat(32), site_type: 'primary', address: 'https://master.example.test', writable: true},
    {member_id: '2'.repeat(32), site_type: 'direct', address: 'https://direct.example.test', writable: true},
    {member_id: '3'.repeat(32), site_type: 'relay', address: 'https://relay.example.test:8443', writable: false},
    {member_id: '4'.repeat(32), site_type: 's3', address: 'https://s3.example.test/bucket', writable: true},
];
for (const [index, destination] of [...destinations, {member_id: '5'.repeat(32)}].entries()) {
    const name = `sealed-${index}.mp3`;
    payload.push({kind: 'file', name, path: `music/album/${name}`, size: 8493465, media: true,
        storage_member_id: destination.member_id, storage_address: null, storage_address_local: false});
    displays.push(destination.address?.slice('https://'.length) || '地址不可用');
    siteTypes.push(destination.site_type || '');
}
function matches(node, selector) {
    if (selector === '.tree-row[data-path]') return node.classList.contains('tree-row') && 'path' in node.dataset;
    if (/^\.[a-z-]+$/.test(selector)) return node.classList.contains(selector.slice(1));
    return false;
}
function element(tag = 'div') {
    const node = {tagName: tag.toUpperCase(), children: [], dataset: {}, value: '', className: '',
        disabled: false, textContent: '', parentNode: null, addEventListener() {},
        appendChild(child) { child.parentNode = this; this.children.push(child); return child; },
        append(...children) { children.forEach(child => this.appendChild(child)); },
        replaceChildren(...children) { this.children = []; this.append(...children); },
        remove() { this.parentNode.children = this.parentNode.children.filter(child => child !== this); },
        setAttribute(name, value) { this[name] = String(value); },
        querySelectorAll(selector) { return this.children.flatMap(child => [
            ...(matches(child, selector) ? [child] : []), ...child.querySelectorAll(selector)]); },
        querySelector(selector) { return this.querySelectorAll(selector)[0] || null; },
    };
    node.classList = {contains: name => node.className.split(' ').includes(name),
        add: name => { if (!node.classList.contains(name)) node.className += ` ${name}`; },
        remove: name => { node.className = node.className.split(' ').filter(value => value !== name).join(' '); },
        toggle: (name, force) => { (force ?? !node.classList.contains(name)) ? node.classList.add(name) : node.classList.remove(name); }};
    Object.defineProperty(node, 'options', {get: () => node.children});
    Object.defineProperty(node, 'innerHTML', {set(value) {
        this.children = [];
        // Only the real tree row's three direct markup children are needed.
        if (this.className.startsWith('tree-row') && value) {
            for (const className of ['kind', 'tree-label']) {
                const child = element('span'); child.className = className; this.append(child);
            }
            const size = value.match(/<small>([\s\S]*?)<\/small>/);
            if (size) { const child = element('small'); child.textContent = size[1]; this.append(child); }
        }
    }, get() { return ''; }});
    return node;
}
const flush = async () => { for (let count = 0; count < 12; count++) await new Promise(resolve => setImmediate(resolve)); };
function fixture(holdTree) {
    const elements = new Map(), listeners = new Map(), requests = [], intervals = [];
    const byId = id => { if (id === 'usersPanel') return null;
        if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
    const document = {cookie: '', hidden: false, readyState: 'loading', body: element(), getElementById: byId,
        createElement: element, querySelector() { return null; },
        addEventListener(name, callback, options = {}) {
            if (!listeners.has(name)) listeners.set(name, []);
            listeners.get(name).push({callback, once: options.once});
        },
        querySelectorAll(selector) { return byId('tree').querySelectorAll(selector); }};
    let releaseStatus, releaseTree;
    let poolDestinations = destinations;
    let poolGate = null;
    const status = new Promise(resolve => { releaseStatus = resolve; });
    const gate = new Promise(resolve => { releaseTree = resolve; });
    const response = data => ({status: 200, ok: true, json: async () => data});
    const context = vm.createContext({document, location: {origin: 'https://admin.example.test', href: 'https://admin.example.test/admin'},
        URL, URLSearchParams, AbortController, console, setTimeout, clearTimeout,
        setInterval: (_callback, delay) => { intervals.push(delay); return intervals.length; }, clearInterval() {},
        alert: text => { throw new Error(text); },
        fetch: async url => { const value = String(url); requests.push(value);
            if (value.endsWith('/admin/status')) return response(await status);
            if (value.includes('/admin/tree')) { if (holdTree) await gate; return response({path: 'music/album', items: payload}); }
            if (value.endsWith('/storage-pool')) {
                if (poolGate) await poolGate;
                return response({standalone: false, members: [], upload_destinations: poolDestinations});
            }
            return response({items: []}); },
    });
    context.addEventListener = () => {};
    context.window = context;
    const run = text => vm.runInContext(text, context);
    const load = index => {
        const deleteAction = byId('delete').onclick;
        vm.runInContext(sources[index], context, {filename: files[index]});
        if (index !== 0) assert.equal(byId('delete').onclick, deleteAction, `${files[index]} replaced the sealed delete handler`);
    };
    load(0);
    // Seed a media scope before the controlled startup request resumes.
    run("currentPath='music/album'");
    const ready = () => {
        document.readyState = 'interactive';
        for (const listener of [...(listeners.get('DOMContentLoaded') || [])]) {
            if (listener.once) listeners.set('DOMContentLoaded', listeners.get('DOMContentLoaded').filter(value => value !== listener));
            listener.callback();
        }
    };
    return {run, load, byId, requests, intervals, ready,
        setDestinations: value => { poolDestinations = value; },
        holdPool() {
            let resolve, reject;
            poolGate = new Promise((done, fail) => { resolve = done; reject = fail; });
            return {resolve, reject};
        },
        releaseStatus: () => releaseStatus({node_role: 'Master', credential_kind: 'persistent',
            csrf_cookie_name: 'fixture-csrf', limits: {max_upload_file_size: 1234}}), releaseTree};
}
function assertRows(f, phase) {
    const rows = f.byId('tree').children.filter(row => row.dataset.path);
    assert.equal(rows.length, payload.length, `${phase}: all files must be rendered`);
    for (const row of rows) {
        const classes = row.children.map(child => child.className);
        const size = row.children.findIndex(child => child.tagName === 'SMALL' && !child.className);
        const address = classes.indexOf('media-node-address');
        assert.ok(size >= 0 && size < address, `${phase}: size/address order for ${row.dataset.path}`);
        const index = payload.findIndex(item => item.path === row.dataset.path);
        assert.equal(row.children[size].textContent, '8.1 MB');
        assert.equal(row.children[address].textContent, displays[index]);
        const badges = row.children.filter(child => child.classList.contains('media-site-badge'));
        const expectedBadge = siteTypes[index] ? [`media-site-badge site-${siteTypes[index]}`] : [];
        assert.deepEqual(badges.map(child => child.className), expectedBadge, `${phase}: owner for ${row.dataset.path}`);
        assert.ok(!classes.includes('media-encryption-badge'));
        assert.equal(classes.filter(value => value === 'media-node-address').length, 1);
    }
}
for (const order of ['responses-ready-before-hooks', 'hooks-before-status', 'tree-response-delayed']) {
    const f = fixture(order === 'tree-response-delayed');
    if (order !== 'hooks-before-status') { f.releaseStatus(); await flush(); }
    assert.equal(f.requests.filter(url => /\/admin\/(?:status|tree)/.test(url)).length, 0,
        `${order}: startup must wait for DOMContentLoaded while ordinary hook scripts are still loading`);
    f.load(1); f.load(2);
    for (const address of ['https://secret:pass@direct.example.test', 'https://direct.example.test/?token=secret',
        'https://direct.example.test/#secret', 'javascript:alert(1)', '//direct.example.test']) {
        assert.equal(f.run(`mediaStorageAddress({storage_address:${JSON.stringify(address)}})`), '', 'unsafe addresses must not render');
    }
    assert.equal(f.run('mediaStorageAddress({storage_address_local:false})'), '', 'unknown owner cannot fall back to Master');
    f.ready();
    await flush();
    if (order === 'hooks-before-status') f.releaseStatus();
    if (order === 'tree-response-delayed') {
        assert.ok(f.requests.some(url => url.includes('/admin/tree?')));
        assert.equal(f.byId('tree').children.length, 0);
        f.releaseTree();
    }
    await flush();
    assertRows(f, `${order}:initial`);
    assert.equal(f.run('csrfCookieName'), 'fixture-csrf');
    assert.equal(f.run('uploadLimits.max_upload_file_size'), 1234);
    assert.deepEqual(f.intervals, [10000, 15000], 'storage and security polling must remain intact');
    f.ready(); await flush();
    assert.equal(f.requests.filter(url => url.endsWith('/admin/status')).length, 1, 'initialization must run once');
    await f.run('renderTree()'); assertRows(f, `${order}:refresh`);
    f.byId('mediaSearch').value = 'mp3';
    await f.run('renderTree()'); assertRows(f, `${order}:search`);
    assert.ok(f.requests.some(url => url.includes('/tree/search?q=mp3&path=music%2Falbum')));
    f.setDestinations(destinations.map(destination => destination.site_type === 'relay'
        ? {...destination, address: 'https://relay-renamed.example.test:8443'} : destination));
    const treeRequests = f.requests.filter(url => url.includes('/admin/tree')).length;
    await f.run('refreshUploadSiteTypes()');
    const relayRow = f.byId('tree').children.find(row => row.dataset.path === 'music/album/sealed-2.mp3');
    assert.equal(relayRow.querySelector('.media-node-address').textContent, 'relay-renamed.example.test:8443');
    assert.equal(f.requests.filter(url => url.includes('/admin/tree')).length, treeRequests);
    if (order === 'hooks-before-status') {
        const select = f.byId('uploadSiteType');
        select.value = destinations[1].member_id;
        select.onchange();
        const held = f.holdPool();
        const count = f.requests.filter(url => url.endsWith('/storage-pool')).length;
        const refresh = f.run('refreshUploadSiteTypes()');
        assert.equal(f.run('refreshUploadSiteTypes()'), refresh, 'poll requests share one in-flight response');
        assert.equal(f.requests.filter(url => url.endsWith('/storage-pool')).length, count + 1);
        assert.equal(select.value, destinations[1].member_id);
        assert.equal(f.byId('uploadFiles').disabled, false);
        held.reject(new Error('temporary failure'));
        await assert.rejects(refresh, /temporary failure/);
        assert.equal(select.value, destinations[1].member_id);
        const next = f.holdPool();
        const recovery = f.run('refreshUploadSiteTypes()');
        f.setDestinations(destinations.map(destination => destination.site_type === 'direct'
            ? {...destination, writable: false} : destination));
        next.resolve();
        await recovery;
        assert.equal(select.value, '', 'revoke an unavailable exact destination without choosing another');
        assert.equal(f.byId('uploadFiles').disabled, true);
    }
}
{
    const f = fixture(false);
    const pool = f.holdPool();
    f.load(1); f.load(2); f.ready(); f.releaseStatus();
    await flush();
    assert.ok(f.requests.some(url => url.includes('/admin/tree?')), 'a pending pool must not block the initial tree request');
    assert.equal(f.byId('tree').children.filter(row => row.dataset.path).length, payload.length);
    assert.equal(f.byId('uploadFiles').disabled, true);
    pool.reject(new Error('storage pool is unavailable'));
    await flush();
    assert.equal(f.byId('tree').children.filter(row => row.dataset.path).length, payload.length);
    const recovery = f.holdPool();
    const refreshed = f.run('refreshUploadSiteTypes()');
    recovery.resolve();
    await refreshed;
    assertRows(f, 'pool recovery without page reload');
}
console.log('admin-media-address-smoke-ok: startup, refresh, search, sealed placement, unknown owners and pool updates');

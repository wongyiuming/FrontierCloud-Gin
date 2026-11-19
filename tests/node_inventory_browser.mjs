// Real Chromium exercises the shipped node inventory with deterministic API data.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';

const require = createRequire(import.meta.url);
const {chromium} = require(process.env.FC_PLAYWRIGHT_MODULE || 'playwright');
const output = process.argv[2];
assert.ok(output, 'provide an output directory for the screenshots');
fs.mkdirSync(output, {recursive: true});
const markup = fs.readFileSync('static/media/admin.html', 'utf8')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<link\b[^>]*>/gi, '');
const origin = 'https://node-inventory.fixture.invalid';
const master = '1'.repeat(32), direct = '2'.repeat(32), relay = '3'.repeat(32), s3 = '4'.repeat(32);
const directRelation = 'a'.repeat(32), relayRelation = 'b'.repeat(32);
const gib = 1073741824;
const endpoint = 'https://direct.fixture.invalid';
const nodes = {
    role: 'Master', node_id: master, app_version: 'development', protocol: 2, endpoint: origin, retirement_inventory_available: false,
    relationships: [
        {relationship_id: directRelation, peer_id: direct, peer_endpoint: endpoint, status: 'online', state: 'active', direction: 'downstream', mode: 'Direct', rtt_ms: 18},
        {relationship_id: relayRelation, peer_id: relay, peer_endpoint: 'https://relay.fixture.invalid', status: 'offline', state: 'active', direction: 'downstream', mode: 'Relay'},
    ],
    storage_pool: {allocated_bytes: 60*gib, used_bytes: 18*gib, physical_total_bytes: 120*gib, physical_free_bytes: 86*gib, members: [
        {member_id: master, member_kind: 'MasterLocal', transport: 'Local', allocated_bytes: 10*gib, used_bytes: 2*gib},
        {member_id: direct, member_kind: 'Follower', relationship_id: directRelation, transport: 'Direct', storage_enabled: 1, allocated_bytes: 30*gib, used_bytes: 11*gib, backup: {enabled: true, health: 'healthy'}},
        {member_id: relay, member_kind: 'Follower', relationship_id: relayRelation, transport: 'Relay', storage_enabled: 1, allocated_bytes: 20*gib, used_bytes: 5*gib, backup: {enabled: true, health: 'stale'}},
    ]},
};
const objects = {configuration_mode: 'sealed', members: [
    {member_id: s3, name: '归档对象存储', location: {endpoint: 'https://objects.fixture.invalid', bucket: 'archive'}, storage_enabled: 1, allocated_bytes: 50*gib, used_bytes: 2*gib, probe_state: 'ready'},
]};
const observations = {members: [
    {member_id: direct, observed: {host_usage: {cpu_percent: 0, memory_used_bytes: 3*gib, memory_total_bytes: 8*gib}}},
]};
const browser = await chromium.launch({headless: true, executablePath: process.env.FC_CHROME_EXECUTABLE || undefined,
    args: ['--no-sandbox', '--disable-background-networking']});
try {
    const page = await browser.newPage({viewport: {width: 1440, height: 1050}, reducedMotion: 'reduce'});
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', route => route.request().url() === `${origin}/`
        ? route.fulfill({contentType: 'text/html; charset=utf-8', body: markup}) : route.abort());
    await page.goto(`${origin}/`);
    for (const asset of ['admin.css', 'admin-system-modules.css', 'nodes-observability.css']) {
        await page.addStyleTag({content: fs.readFileSync(`static/css/${asset}`, 'utf8')});
    }
    await page.evaluate(({nodes, objects, observations, direct, endpoint}) => {
        window.calls = [];
        window.nodeFixture = {nodes, observations};
        window.api = async pathname => {
            window.calls.push(pathname);
            const results = {'/api/v1/media/admin/nodes': nodes, '/api/v1/media/admin/nodes/observability': observations,
                '/api/v1/media/admin/nodes/public-routing': {ingress: {node_id: direct, generation: 9, public_origin: endpoint}},
                '/api/v1/media/admin/nodes/s3': objects};
            if (!(pathname in results)) throw Error(`unexpected request ${pathname}`);
            return results[pathname];
        };
        document.querySelectorAll('.admin-module > .module-heading').forEach(heading => { heading.onclick = event => event.currentTarget.parentElement.classList.toggle('expanded'); });
    }, {nodes, objects, observations, direct, endpoint});
    for (const asset of ['nodes.js', 'admin-focus.js']) await page.addScriptTag({content: fs.readFileSync(`static/js/${asset}`, 'utf8')});
    await page.locator('#adminModuleLinks button[data-module-target="nodes"]').click();
    const count = async (shown, total = 4) => page.waitForFunction(text => document.querySelector('#nodeInventoryCount').textContent === text, `显示 ${shown} / ${total} 个节点`);
    const search = page.locator('#nodeInventorySearch');
    const type = page.locator('#nodeInventoryType');
    const status = page.locator('#nodeInventoryStatus');
    const visibleRows = page.locator('#nodeRelationships .node-card-row:visible');
    await count(4);
    assert.equal(await page.locator('#nodeIngressAddress').textContent(), endpoint);
    assert.equal(await page.locator('#nodeIngressStatus').textContent(), '路由版本 9');
    assert.match(await visibleRows.nth(1).innerText(), /当前入口/);
    const directBadge = visibleRows.nth(1).locator('.node-pill.transport-direct');
    const relayBadge = visibleRows.nth(2).locator('.node-pill.transport-relay');
    assert.equal(await directBadge.textContent(), 'Direct');
    assert.equal(await relayBadge.textContent(), 'Relay');
    assert.notEqual(await directBadge.evaluate(el => getComputedStyle(el).color),
        await relayBadge.evaluate(el => getComputedStyle(el).color));
    assert.equal(await page.locator('#nodeRelationships .node-card-grid').count(), 0);
    await page.screenshot({path: path.join(output, 'nodes-desktop.png')});
    assert.equal(await page.locator('#nodesPanel .node-resource-panel.backup').count(), 0);
    assert.equal(await page.locator('#nodeBackupsPanel .node-module-card').count(), 2);
    await page.locator('#adminModuleLinks button[data-module-target="nodeBackups"]').click();
    await page.locator('#nodeBackupsPanel .node-module-card summary').first().click();
    await page.screenshot({path:path.join(output,'backups-desktop.png')});
    await page.locator('#adminModuleLinks button[data-module-target="nodeSettings"]').click();
    assert.equal(await page.locator('#nodeSettingsPanel #nodePairingSetup').count(),1);
    await page.locator('#adminModuleLinks button[data-module-target="nodes"]').click();

    await search.fill(direct);
    await count(1);
    assert.match(await visibleRows.first().innerText(), /direct\.fixture\.invalid/);
    await visibleRows.first().locator('.node-card-title strong').click();
    assert.equal(await visibleRows.first().locator('.node-card-header').getAttribute('aria-expanded'), 'true');
    await visibleRows.first().locator('.node-card-header').focus();
    await page.keyboard.press('Space');
    assert.equal(await visibleRows.first().locator('.node-card-header').getAttribute('aria-expanded'), 'false');
    await page.keyboard.press('Enter');
    assert.equal(await visibleRows.first().locator('.node-card-header').getAttribute('aria-expanded'), 'true');
    assert.match(await visibleRows.first().innerText(), /整机 CPU\s+0%/);
    assert.match(await visibleRows.first().innerText(), /整机内存（已用 \/ 总量）\s+3\.00 GiB \/ 8\.00 GiB/);
    await page.locator('#nodesRefresh').click();
    await count(1);
    await page.waitForFunction(() => document.querySelector('#nodeRelationships tr:not([hidden]) .node-card-header[aria-expanded="true"]'));
    assert.equal(await search.inputValue(), direct);
    // A focused refresh button must not freeze telemetry; use the real 10s poll.
    const previousPoll = await page.evaluate(() => window.calls.filter(p => p.endsWith('/observability')).length);
    await page.evaluate(() => { window.nodeFixture.observations.members[0].observed.host_usage.cpu_percent = 37; });
    await page.waitForFunction(n => window.calls.filter(p => p.endsWith('/observability')).length > n, previousPoll, {timeout:14000});
    await page.waitForFunction(() => document.querySelector('#nodeRelationships tr:not([hidden])').innerText.includes('37%'));
    assert.equal(await search.inputValue(), direct);

    await visibleRows.first().locator('.node-details-toggle').click();
    await search.clear();
    await status.selectOption('offline');
    await count(1);
    assert.match(await visibleRows.first().innerText(), /relay\.fixture\.invalid/);
    await visibleRows.first().locator('.node-details-toggle').click();
    assert.doesNotMatch(await visibleRows.first().innerText(), /整机 CPU|整机内存/);
    await visibleRows.first().locator('.node-details-toggle').click();
    await type.selectOption('s3');
    await count(0);
    assert.match(await page.locator('#nodeInventoryEmpty').textContent(), /没有符合条件/);
    await status.selectOption('all');
    await count(1);
    assert.match(await visibleRows.first().innerText(), /归档对象存储/);
    assert.ok(!(await visibleRows.first().innerText()).includes(s3));
    await type.selectOption('all');
    await count(4);

    await page.locator('#adminModuleLinks button[data-module-target="nodeSettings"]').click();
    await page.locator('#nodeSettingsPanel .node-module-card').filter({hasText:endpoint}).locator('summary').click();
    assert.match(await page.locator('#nodeSettingsPanel').innerText(), /未知文件不能作为清理依据/);
    assert.equal(await page.getByRole('button', {name:'执行只读退役检查',exact:true}).count(),0);
    const capacity = page.locator('#nodeSettingsPanel .node-module-card[open] input[type="number"]').first();
    await capacity.fill('17');
    const whileEditing = await page.evaluate(() => window.calls.filter(p => p.endsWith('/observability')).length);
    await page.waitForTimeout(11000);
    assert.equal(await capacity.inputValue(), '17', 'background refresh must preserve an active configuration edit');
    assert.equal(await page.evaluate(() => window.calls.filter(p => p.endsWith('/observability')).length), whileEditing);
    await page.locator('#adminModuleLinks button[data-module-target="nodeBackups"]').click();
    const health = page.locator('#nodeBackupsPanel .node-resource-panel.backup').first();
    const grid = health.locator('..');
    assert.ok(await health.evaluate(el => el.getBoundingClientRect().width / el.parentElement.getBoundingClientRect().width > .95), 'single backup card should use its module width');
    await page.screenshot({path:path.join(output,'backups-wide.png')});
    await page.locator('#adminModuleLinks button[data-module-target="nodes"]').click();
    await page.setViewportSize({width: 390, height: 900});
    await page.locator('.node-command').scrollIntoViewIfNeeded();
    assert.ok(await page.locator('.node-inventory').evaluate(el => el.scrollWidth <= el.clientWidth + 1), 'mobile inventory must fit without horizontal scrolling');
    await page.screenshot({path: path.join(output, 'nodes-mobile.png')});
    assert.deepEqual(errors, []);
    assert.ok(!(await page.evaluate(() => window.calls)).some(request => request.includes('/migrations')));
    console.log('PASS: desktop/mobile Chromium, current ingress, ID search, type/status filters, and persistent disclosure');
} finally {
    await browser.close();
}

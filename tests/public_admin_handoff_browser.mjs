// Real Chromium popup and cookie isolation against in-memory route fixtures.
// The served scripts are the repository homepage and Master handoff template;
// route handlers simulate the server and do not establish application E2E.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRequire} from 'node:module';

const require = createRequire(import.meta.url);
const {chromium} = require(process.env.FC_PLAYWRIGHT_MODULE || 'playwright');
const publicOrigin = 'https://entry.test';
const adminOrigin = 'https://master.test';
const challenge = 'a'.repeat(43), ticket = 'b'.repeat(43);
const secret = 'fixture-admin-secret';
const nonce = 'fixture-nonce';
const csp = `default-src 'self'; script-src 'self' 'nonce-${nonce}'; script-src-attr 'none'; style-src 'self' 'unsafe-inline'; connect-src 'self' https:; img-src 'self' data: blob: https:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`;

const homepage = fs.readFileSync('static/media/index.html', 'utf8')
    .replaceAll('{{STUN_URLS_JSON}}', '[]').replaceAll('{{WEBRTC_INTERVAL_MS}}', '1000')
    .replaceAll('{{MEDIA_PREFETCH_ASSETS_JSON}}', '[]').replaceAll('{{ADMIN_ORIGIN_JSON}}', JSON.stringify(adminOrigin))
    .replaceAll('{{MEDIA_BROWSER_JS_URL}}', '/fixture-media-browser.js')
    .replaceAll('{{NETWORK_OBSERVATION_JS_URL}}', '/fixture-network-observation.js')
    .replaceAll('<script', `<script nonce="${nonce}"`);
const source = fs.readFileSync('internal/httpapi/admin_handoff.go', 'utf8');
const raw = source.match(/page := `([\s\S]*?)`\s*\n\s*serveTrustedHTML/)?.[1];
assert.ok(raw, 'Master popup template must exist');
const masterPage = raw.replace('` + jsonString(binding.PublicOrigin) + `', JSON.stringify(publicOrigin))
    .replace('` + jsonString(challenge) + `', JSON.stringify(challenge))
    .replaceAll('<script', `<script nonce="${nonce}"`);
assert.ok(!masterPage.includes('jsonString('), 'all popup template expressions must be resolved');

const browser = await chromium.launch({headless: true, executablePath: process.env.FC_CHROME_EXECUTABLE || undefined,
    args: ['--no-sandbox', '--disable-background-networking']});
const context = await browser.newContext();
const requests = [];
let authorized = 0, redeemed = 0, releaseStart;
const waitForStart = new Promise(resolve => { releaseStart = resolve; });
try {
    await context.addInitScript(() => {
        const original = window.open.bind(window);
        window.open = (...args) => { const popup = original(...args); window.fixturePopup = popup; return popup; };
    });
    context.on('request', request => { requests.push({url: request.url(), method: request.method()}); });
    await context.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url());
        assert.ok(!request.url().includes(secret), 'credential must never occur in a URL');
        assert.ok([publicOrigin, adminOrigin].includes(url.origin), `unexpected external request: ${url.origin}`);
        const headers = {'Cache-Control': 'no-store', 'Content-Security-Policy': csp};
        if (url.origin === publicOrigin && url.pathname === '/api/v1/media') {
            await route.fulfill({status: 200, headers: {...headers, 'Content-Type': 'text/html; charset=utf-8'}, body: homepage});
        } else if (url.origin === adminOrigin && url.pathname === '/api/v1/media/admin/handoff/start') {
            await waitForStart;
            await route.fulfill({status: 200, headers: {...headers, 'Content-Type': 'text/html; charset=utf-8',
                'Set-Cookie': '__Host-frontiercloud-admin-flow=flow-cookie; Path=/; Secure; HttpOnly; SameSite=Strict'}, body: masterPage});
        } else if (url.origin === publicOrigin && url.pathname === '/api/v1/media/admin-handoff/authorize') {
            assert.equal(request.method(), 'POST');
            assert.equal(request.headers().origin, publicOrigin);
            assert.equal(request.headers().cookie, undefined, 'public authorization omits browser cookies');
            assert.deepEqual(request.postDataJSON(), {challenge, key: secret});
            authorized++;
            await route.fulfill({status: 200, headers: {...headers, 'Content-Type': 'application/json'}, body: JSON.stringify({ticket})});
        } else if (url.origin === adminOrigin && url.pathname === '/api/v1/media/admin/handoff/redeem') {
            assert.equal(request.method(), 'POST');
            assert.equal(request.headers().origin, adminOrigin);
            assert.match(request.headers().cookie || '', /__Host-frontiercloud-admin-flow=flow-cookie/);
            assert.deepEqual(request.postDataJSON(), {ticket});
            redeemed++;
            await route.fulfill({status: 200, headers: {...headers, 'Content-Type': 'application/json',
                'Set-Cookie': '__Host-admin_session=fixture-session; Path=/; Secure; HttpOnly; SameSite=Strict'}, body: '{"status":"ok"}'});
        } else if (url.origin === adminOrigin && url.pathname === '/api/v1/media/admin') {
            await route.fulfill({status: 200, headers: {...headers, 'Content-Type': 'text/html'}, body: '<title>fixture admin</title>'});
        } else {
            await route.fulfill({status: 204, headers});
        }
    });
    const page = await context.newPage();
    page.on('dialog', dialog => dialog.accept(secret));
    await page.goto(publicOrigin + '/api/v1/media');
    const popupReady = page.waitForEvent('popup');
    popupReady.catch(() => {}); // Preserve the original failure if an earlier step aborts.
    for (let i = 0; i < 5; i++) await page.locator('#elevateHotspot').click({force: true});
    assert.equal(await page.evaluate(() => !!window.fixturePopup), true, 'handoff opened a popup');
    await page.evaluate(({challenge, adminOrigin}) => {
        const data = {type: 'frontiercloud-admin-flow', challenge};
        window.dispatchEvent(new MessageEvent('message', {origin: 'https://forged.test', source: window.fixturePopup, data}));
        window.dispatchEvent(new MessageEvent('message', {origin: adminOrigin, source: window, data}));
    }, {challenge, adminOrigin});
    await page.waitForTimeout(100);
    assert.equal(authorized, 0, 'forged origin or source must not transmit the credential');
    releaseStart();
    const popup = await popupReady;
    await popup.waitForURL(adminOrigin + '/api/v1/media/admin', {timeout: 10000});
    assert.equal(authorized, 1);
    assert.equal(redeemed, 1);
    const publicCookies = await context.cookies(publicOrigin);
    const adminCookies = await context.cookies(adminOrigin);
    assert.equal(publicCookies.some(cookie => cookie.name.includes('admin')), false, 'public origin must not receive admin cookies');
    const session = adminCookies.find(cookie => cookie.name === '__Host-admin_session');
    assert.ok(session && session.httpOnly && session.secure && session.sameSite === 'Strict');
    assert.equal(await popup.evaluate(() => document.cookie.includes('__Host-admin_session')), false, 'session must be HttpOnly');
    assert.ok(requests.some(request => request.url === adminOrigin + '/api/v1/media/admin'));
    console.log('public-admin-handoff-browser-ok (real Chromium; server, TLS and ingress authority simulated)');
} finally {
    releaseStart();
    await context.close();
    await browser.close();
}

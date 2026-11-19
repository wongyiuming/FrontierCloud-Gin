// Opt-in development-host test. Real Chromium, Service Worker, WebCrypto,
// TLS sockets and Go API/reader; ingress selection/applied state are fixtures.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';

const [publicPort, resourcePort] = process.argv.slice(2);
assert.match(publicPort || '', /^\d+$/);
assert.match(resourcePort || '', /^\d+$/);
assert.ok(process.env.FC_CHROME_EXECUTABLE && process.env.FC_PLAYWRIGHT_MODULE);
const require = createRequire(import.meta.url);
const {chromium} = require(process.env.FC_PLAYWRIGHT_MODULE);
const entry = 'https://entry.test', resource = 'https://resource.test';
const mapping = `MAP entry.test:443 127.0.0.1:${publicPort}, MAP evil.test:443 127.0.0.1:${publicPort}, MAP resource.test:443 127.0.0.1:${resourcePort}`;
const browser = await chromium.launch({headless: true, executablePath: process.env.FC_CHROME_EXECUTABLE,
    args: ['--no-sandbox', '--no-proxy-server', '--ignore-certificate-errors', '--disable-background-networking', `--host-resolver-rules=${mapping}`]});
const context = await browser.newContext({ignoreHTTPSErrors: true});
try {
    await context.addCookies([{name: 'resource-private-cookie', value: 'do-not-forward', domain: 'resource.test', path: '/', secure: true, sameSite: 'None'}]);
    await context.addInitScript(() => {
        const original = window.fetch.bind(window);
        window.fetch = async (...args) => {
            const response = await original(...args);
            if (String(args[0]).endsWith('/api/v1/media/crypto/key') && response.ok) {
                window.fixtureGrant = await response.clone().json();
            }
	        if (String(args[0]).endsWith('/api/v1/media/crypto/native/source') && response.ok) {
	            window.fixturePlainGrant = await response.clone().json();
	        }
            return response;
        };
    });
    const page = await context.newPage();
    await page.goto(entry + '/fixture');
    await page.evaluate(async () => { await navigator.serviceWorker.register('/media-crypto-sw.js', {scope:'/'}); await navigator.serviceWorker.ready; });
    await page.reload();
    await page.waitForFunction(() => !!navigator.serviceWorker.controller);
    const items = await page.evaluate(() => fetch('/fixture/items').then(r => r.json()));
    const first = await page.evaluate(async item => {
        const entries = [{media_path:item.path, encryption:item.encryption}];
        await window.FrontierMediaCrypto.prepareCatalog(entries);
        const response = await fetch(entries[0].url, {headers:{Range:'bytes=0-8'}});
        return {status:response.status, body:await response.text(), grant:window.fixtureGrant};
    }, items[0]);
    assert.equal(first.status, 206);
    assert.equal(first.body, items[0].expected.slice(0, 9));
    assert.equal(first.grant.source_origin, resource);
    assert.equal(first.grant.source_transport, 'Direct');
    assert.ok(first.grant.source_headers['X-Media-Capability']);
    assert.ok(Number.isInteger(first.grant.source_expires_in) && first.grant.source_expires_in > 0 && first.grant.source_expires_in <= 300);
    assert.ok(first.grant.source_expires_at <= first.grant.key_envelope.expires_at, 'Direct grant cannot outlive its browser session');
    assert.equal(new URL(first.grant.source_url).search, '', 'bearer must not appear in URL');
    const token = first.grant.source_headers['X-Media-Capability'];

    const plain = await page.evaluate(async item => {
        const catalog = await fetch('/api/v1/media/catalog/media?media_type=music&path=music%2Fartist&playback_session_id=fixture').then(r => r.json());
        const selected = catalog.entries.find(value => value.media_path === item.path);
        if (!selected?.native_source || selected.resource_id !== item.resource_id || selected.object_id !== item.object_id) throw new Error('native catalog descriptor missing');
        const entries = [selected];
        await window.FrontierMediaCrypto.prepareCatalog(entries);
        const response = await fetch(entries[0].url, {headers:{Range:'bytes=1-4'}});
        return {status:response.status, body:await response.text(), grant:window.fixturePlainGrant};
    }, items[3]);
    assert.equal(plain.status, 206);
    assert.equal(plain.body, items[3].expected.slice(1, 5));
    assert.equal(plain.grant.source_transport, 'Direct');
    assert.equal(plain.grant.source_origin, resource);
    assert.equal(new URL(plain.grant.source_url).search, '');
    const lyric = await page.evaluate(async item => {
        const response = await fetch('/api/v1/media/lyrics/content?track=' + encodeURIComponent(item.path));
        const text = await response.text();
        const metadata = JSON.parse(text);
        return {status:response.status, metadata, text, body:await window.FrontierMediaCrypto.plainTextFor(metadata), grant:window.fixturePlainGrant};
    }, items[3]);
    assert.equal(lyric.status, 200);
    assert.equal(lyric.metadata.native_lyric, true);
    assert.ok(!lyric.text.includes(items[4].expected), 'business metadata must not include lyric body');
    assert.equal(lyric.body, items[4].expected);
    assert.equal(lyric.grant.source_transport, 'Direct');

    const evil = await context.newPage();
    await evil.goto('https://evil.test/fixture');
    const rejected = await evil.evaluate(async ({url, token}) => {
        try { await fetch(url, {headers:{'X-Media-Capability':token, Range:'bytes=0-8'}, credentials:'omit'}); return false; }
        catch (_) { return true; }
    }, {url:first.grant.source_url, token});
    assert.equal(rejected, true, 'wrong browser origin must fail CORS preflight');

    await page.evaluate(() => fetch('/fixture/redirect', {method:'POST'}));
    const redirected = await page.evaluate(async item => {
        const entries = [{media_path:item.path, encryption:item.encryption}];
        await window.FrontierMediaCrypto.prepareCatalog(entries);
        try { const response = await fetch(entries[0].url, {headers:{Range:'bytes=0-8'}}); await response.arrayBuffer(); return false; }
        catch (_) { return true; }
    }, items[1]);
    assert.equal(redirected, true, 'Direct ciphertext read must reject a redirect');
    await page.evaluate(() => fetch('/fixture/redirect', {method:'DELETE'}));

    await page.evaluate(() => fetch('/fixture/unavailable', {method:'POST'}));
    const unavailable = await page.evaluate(async item => {
        const entries = [{media_path:item.path, encryption:item.encryption}];
        await window.FrontierMediaCrypto.prepareCatalog(entries);
        try { const response = await fetch(entries[0].url, {headers:{Range:'bytes=0-8'}}); await response.arrayBuffer(); return false; }
        catch (_) { return true; }
    }, items[2]);
    assert.equal(unavailable, true, 'Direct network failure must not silently fall back to Relay');
    await page.evaluate(() => fetch('/fixture/unavailable', {method:'DELETE'}));

    const revoked = await page.evaluate(() => fetch('/api/v1/media/crypto/revoke', {method:'POST',
        headers:{'Content-Type':'application/json'}, body:'{}'}).then(r => r.status));
    assert.equal(revoked, 200);
    const replay = await page.evaluate(async ({url, token}) => {
        try { const r = await fetch(url, {headers:{'X-Media-Capability':token, Range:'bytes=0-8'}, credentials:'omit', redirect:'error'}); return r.status; }
        catch (_) { return 'cors-denied'; }
    }, {url:first.grant.source_url, token});
    assert.equal(replay, 403, 'browser must observe revoked session as authorization failure');

    const stats = await page.evaluate(() => fetch('/fixture/stats').then(r => r.json()));
    assert.ok(stats.some(r => r.Method === 'OPTIONS' && r.Origin === entry && r.Status === 204), 'real browser preflight reached Go reader');
    assert.ok(stats.some(r => r.Method === 'GET' && r.Origin === entry && r.Status === 206 && r.Capability && r.Range), 'real Go reader served ciphertext Range');
    assert.ok(stats.some(r => r.Method === 'OPTIONS' && r.Origin === 'https://evil.test' && r.Status === 403), 'wrong origin preflight rejected');
    assert.ok(stats.some(r => r.Method === 'GET' && r.Origin === entry && r.Status === 302 && r.Capability), 'redirect fixture exercised');
    assert.ok(stats.some(r => r.Method === 'GET' && r.Origin === entry && r.Status === 503 && r.Capability), 'unavailable Direct fixture exercised');
    assert.ok(stats.some(r => r.Method === 'GET' && r.Origin === entry && r.Status === 403 && r.Capability), 'session revocation reached real reader');
    assert.equal(stats.some(r => r.Path === '/fixture/trap'), false, 'Direct redirect was not followed');
    assert.equal(stats.some(r => r.Path === '/api/v1/media/stream'), false, 'Direct failure did not use ingress Relay');
    for (const r of stats) assert.equal(r.Query || r.Cookie, '', 'resource request must contain no query bearer or cookie');
    console.log('master-direct-browser-ok (real Chromium, WebCrypto, Service Worker and Go TLS; selection/applied state simulated)');
} finally {
    await context.close();
    await browser.close();
}

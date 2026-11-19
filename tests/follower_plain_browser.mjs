// Isolated Chromium fixture: real browser, TLS and Go handlers. Ingress
// selection and resource readiness are deliberately injected by the Go test.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';

const [publicPort, resourcePort, expectedMode] = process.argv.slice(2);
assert.match(publicPort || '', /^\d+$/);
assert.match(resourcePort || '', /^\d+$/);
assert.ok(['Local', 'Direct', 'Relay'].includes(expectedMode));
const require = createRequire(import.meta.url);
const {chromium} = require(process.env.FC_PLAYWRIGHT_MODULE);
const mapping = `MAP entry.test:443 127.0.0.1:${publicPort}, MAP resource.test:443 127.0.0.1:${resourcePort}`;
const browser = await chromium.launch({headless: true, executablePath: process.env.FC_CHROME_EXECUTABLE,
    args: ['--no-sandbox', '--no-proxy-server', '--ignore-certificate-errors', '--disable-background-networking', `--host-resolver-rules=${mapping}`]});
const context = await browser.newContext({ignoreHTTPSErrors: true});
try {
    const page = await context.newPage();
    await page.addInitScript(() => {
        const original = window.fetch.bind(window);
        window.fetch = async (...args) => {
            const response = await original(...args);
            if (String(args[0]).endsWith('/api/v1/media/crypto/native/source') && response.ok) {
                window.fixtureGrant = await response.clone().json();
            }
            return response;
        };
    });
    await page.goto('https://entry.test/fixture');
    await page.evaluate(async () => { await navigator.serviceWorker.register('/media-crypto-sw.js', {scope: '/'}); await navigator.serviceWorker.ready; });
    await page.reload();
    await page.waitForFunction(() => !!navigator.serviceWorker.controller);
    const item = await page.evaluate(() => fetch('/fixture/item').then(r => r.json()));
    const result = await page.evaluate(async item => {
        const entries = [{media_path: item.path, native_source: true, resource_id: item.resource_id,
            object_id: item.object_id, size_bytes: item.size_bytes}];
        await window.FrontierMediaCrypto.prepareCatalog(entries);
        const response = await fetch(entries[0].url, {headers: {Range: 'bytes=1-4'}});
        return {status: response.status, body: await response.text(), grant: window.fixtureGrant};
    }, item);
    assert.equal(result.status, 206);
    assert.equal(result.body, item.expected.slice(1, 5));
    assert.equal(result.grant.source_transport, expectedMode);
    assert.equal(new URL(result.grant.source_url).search, '');
    assert.ok(result.grant.source_headers[expectedMode === 'Relay' ? 'X-Media-Relay' : 'X-Media-Capability']);
    if (expectedMode === 'Direct') assert.equal(result.grant.source_origin, 'https://resource.test');
    console.log(`follower-plain-browser-${expectedMode.toLowerCase()}-ok`);
} finally {
    await context.close();
    await browser.close();
}

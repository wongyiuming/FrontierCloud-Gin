"""Real Chromium against an isolated loopback Gin/Nginx HTTPS fixture only."""
import argparse
import json
import os
import urllib.parse

from playwright.sync_api import sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--maintenance-only', action='store_true')
    args = parser.parse_args()
    parsed = urllib.parse.urlsplit(args.base_url)
    if parsed.scheme != 'https' or parsed.hostname != 'business.fixture.localhost' or parsed.port not in (None,443):
        raise SystemExit('Only a fresh loopback HTTPS fixture is allowed')
    base = args.base_url.rstrip('/')
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(
            executable_path=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE'),
            headless=True, args=['--no-sandbox', '--autoplay-policy=no-user-gesture-required'])
        context = browser.new_context(ignore_https_errors=True)
        if not args.maintenance_only:
            sitemap = context.request.get(base + '/sitemap.xml')
            assert sitemap.status == 200
            assert base + '/api/v1/media' in sitemap.text()
            robots = context.request.get(base + '/robots.txt')
            assert 'Sitemap: ' + base + '/sitemap.xml' in robots.text()
            contact = context.request.get(base + '/.well-known/security.txt')
            assert contact.status == 200, (contact.status, contact.text())
            assert 'Canonical: ' + base + '/.well-known/security.txt' in contact.text()
        context.add_init_script("""window.cspViolations=[];document.addEventListener('securitypolicyviolation',e=>window.cspViolations.push(e.effectiveDirective));""")
        page = context.new_page()
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        protocols = []
        session = context.new_cdp_session(page)
        session.send('Network.enable')
        session.on('Network.responseReceived', lambda event: protocols.append(event['response'].get('protocol')))
        if args.maintenance_only:
            response = page.goto(base + '/api/v1/media', wait_until='load')
            assert response.status == 503
            before = page.locator('#countdown').inner_text()
            page.wait_for_function("(previous) => document.getElementById('countdown').textContent !== previous", arg=before)
            assert page.evaluate('window.cspViolations') == []
            assert errors == []
            assert 'sha256-' in response.headers['content-security-policy']
            assert response.headers['x-frame-options'] == 'DENY'
            print('PASS: hashed maintenance script and CSS, security headers on real 503')
            browser.close()
            return
        for route in ('/api/v1/media', '/api/v1/media/music'):
            response = page.goto(base + route, wait_until='networkidle')
            assert response.status == 200
            assert "'nonce-" in response.headers['content-security-policy']
            assert page.evaluate('window.cspViolations') == [], (route, page.evaluate('window.cspViolations'))
        page.locator('#categoryGrid .card').first.wait_for(state='visible')
        page.goto(base + '/api/v1/media/music/category?path=music%2Fsecurity-fixture', wait_until='networkidle')
        page.locator('#mediaList .media-item').nth(1).wait_for(state='visible')
        assert page.evaluate('window.cspViolations') == []
        page.locator('#mediaList .media-item').nth(1).click()
        page.wait_for_function('() => currentIndex === 1 && art && art.currentTime > 0.1')
        assert page.evaluate("(document.permissionsPolicy||document.featurePolicy).allowsFeature('microphone')") is False
        # Untrusted inline JS and inline event attributes must actually be
        # blocked by Chromium, not just absent from a configuration string.
        page.evaluate("""() => {
          const script=document.createElement('script');script.textContent='window.injectedScriptExecuted=true';document.body.append(script);
          const marker=document.createElement('script');marker.setAttribute('nonce','{{FRONTIERCLOUD_CSP_NONCE}}');marker.textContent='window.injectedMarkerExecuted=true';document.body.append(marker);
          const button=document.createElement('button');button.setAttribute('onclick','window.injectedHandlerExecuted=true');document.body.append(button);button.click();
        }""")
        page.wait_for_function('() => window.cspViolations.length >= 3')
        assert page.evaluate('!!window.injectedScriptExecuted || !!window.injectedHandlerExecuted || !!window.injectedMarkerExecuted') is False
        catalog = context.request.get(base + '/api/v1/media/catalog/media?media_type=music&path=music%2Fsecurity-fixture&playback_session_id=security-smoke').json()
        media_id = catalog['entries'][0]['karaoke_id']
        page.goto(base + '/karaoke/?media=' + urllib.parse.quote(media_id), wait_until='networkidle')
        assert 'no-store' in context.request.get(base + '/karaoke/').headers['cache-control']
        assert page.evaluate('window.cspViolations') == []
        assert page.evaluate("(document.permissionsPolicy||document.featurePolicy).allowsFeature('microphone')") is True
        response = context.request.post(base + '/api/v1/media/admin/elevate', form={'token': os.environ['ADMIN_KEY']})
        if response.status != 200:
            try:
                detail = str(response.json().get('detail', 'missing error detail'))
            except Exception:
                detail = 'non-JSON error response'
            detail = detail.replace(os.environ['ADMIN_KEY'], '<redacted>')[:512]
            raise AssertionError(('Admin elevation', response.status, detail))
        # Follow the real login destination. A relative canonical redirect
        # must preserve the ephemeral public HTTPS port.
        redirect = context.request.get(base + '/api/v1/media/admin?security_probe=1', max_redirects=0)
        if redirect.status in (301, 302, 307, 308):
            target = urllib.parse.urlsplit(redirect.headers['location'])
            assert target.path == '/api/v1/media/admin/'
            assert target.query == 'security_probe=1'
            assert not target.scheme and not target.netloc
            print('Admin canonical redirect:', redirect.status, target.path, 'port', target.port)
        page.goto(base + '/api/v1/media/admin', wait_until='networkidle')
        assert page.url == base + '/api/v1/media/admin/'
        page.locator('#customKeyForm').wait_for(state='attached')
        assert page.evaluate('window.cspViolations') == []
        assert errors == [], errors
        assert 'h2' in protocols, protocols
        # Exercise the certificate panel in real Chromium with bounded node facts.
        # Native signed ownership and the real Unix/TLS lifecycle have separate tests.
        operations = []
        facts = {'hostname': 'storage.fixture.test', 'state': 'DEGRADED', 'enabled': True,
                 'not_after': 1900000000, 'managed': True, 'auto_renew': True, 'validation': 'temporary_port80',
                 'controller_running': True, 'https_ready': True, 'serving_matches': False,
                 'last_error': 'port80_busy', 'job': {'state': 'DEGRADED', 'port80_active': False}}
        member = {'member_id': 'storage-fixture', 'member_kind': 'Follower', 'transport': 'Direct',
                  'storage_enabled': True, 'allocated_bytes': 1073741824}
        relation = {'relationship_id': 'certificate-fixture', 'peer_id': 'storage-fixture',
                    'peer_endpoint': 'https://storage.fixture.test', 'direction': 'downstream',
                    'state': 'active', 'status': 'online', 'mode': 'Direct',
                    'summary': {'certificate': facts}}
        def certificate_route(route):
            path = urllib.parse.urlsplit(route.request.url).path
            if path.endswith('/certificate'):
                if route.request.method == 'POST':
                    assert route.request.headers.get('x-csrf-token'), 'certificate GUI omitted CSRF'
                    value = route.request.post_data_json
                    operations.append(value)
                    raise AssertionError('read-only status fixture received a management operation: '+str(value))
                route.fulfill(status=202 if route.request.method == 'POST' else 200,
                              content_type='application/json', body=json.dumps(facts))
            elif path.endswith('/observability'):
                route.fulfill(content_type='application/json', body=json.dumps({'members': []}))
            elif path.endswith('/nodes'):
                route.fulfill(content_type='application/json', body=json.dumps({
                    'role': 'Master', 'node_id': 'master-fixture', 'app_version': 'fixture', 'protocol': 2,
                    'relationships': [relation], 'storage_pool': {'members': [member]}}))
            else:
                route.continue_()
        page.route('**/api/v1/media/admin/nodes**', certificate_route)
        page.locator('#nodesPanel .module-heading').click()
        panel = page.locator('.node-resource-panel').filter(has_text='存储节点证书')
        panel.get_by_role('button', name='查询证书', exact=True).click()
        panel.get_by_text('80 端口被占用', exact=False).wait_for(state='visible')
        assert panel.get_by_role('button').all_text_contents() == ['查询证书','下载证书及私钥']
        assert panel.get_by_role('button', name='下载证书及私钥', exact=True).is_disabled()
        assert operations == [], operations
        for width in (1280, 390):
            page.set_viewport_size({'width': width, 'height': 900})
            assert panel.is_visible()
            assert panel.evaluate('(e) => e.scrollWidth <= e.clientWidth + 2'), 'certificate panel overflow'
        assert page.evaluate('window.cspViolations') == []
        assert errors == [], errors
        print('PASS: Chromium read-only certificate facts, no manual management, inactive export disabled, port conflict text and desktop/mobile layout')
        print('PASS: real HTTP/2, home/category/player/Admin/karaoke CSP; click playback; malicious inline JS blocked; microphone scope preserved')
        browser.close()


if __name__ == '__main__':
    main()

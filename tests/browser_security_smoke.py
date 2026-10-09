"""Real Chromium against an isolated loopback Gin/Nginx HTTPS fixture only."""
import argparse
import os
import urllib.parse

from playwright.sync_api import sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--maintenance-only', action='store_true')
    args = parser.parse_args()
    parsed = urllib.parse.urlsplit(args.base_url)
    if parsed.scheme != 'https' or parsed.hostname != '127.0.0.1' or not parsed.port:
        raise SystemExit('Only a fresh loopback HTTPS fixture is allowed')
    base = args.base_url.rstrip('/')
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(
            executable_path=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE'),
            headless=True, args=['--no-sandbox', '--autoplay-policy=no-user-gesture-required'])
        context = browser.new_context(ignore_https_errors=True)
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
        assert response.status == 200
        page.goto(base + '/api/v1/media/admin', wait_until='networkidle')
        page.locator('#customKeyForm').wait_for(state='attached')
        assert page.evaluate('window.cspViolations') == []
        assert errors == [], errors
        assert 'h2' in protocols, protocols
        print('PASS: real HTTP/2, home/category/player/Admin/karaoke CSP; click playback; malicious inline JS blocked; microphone scope preserved')
        browser.close()


if __name__ == '__main__':
    main()

"""Real Chromium against the runner's disposable Compose fixture only."""
import argparse
import json
import pathlib
import time
from playwright.sync_api import sync_playwright
from admin_focus_browser import verify_live_navigation

parser = argparse.ArgumentParser()
parser.add_argument('--base-url', required=True)
parser.add_argument('--key-file', type=pathlib.Path, required=True)
parser.add_argument('--output', type=pathlib.Path, required=True)
args = parser.parse_args()
assert args.base_url == 'http://127.0.0.60:8000'
key = args.key_file.read_text().strip()
args.output.mkdir(parents=True, exist_ok=True)
proof = []


def call(page, route, body=None):
    return page.evaluate('''async ({route,body}) => api('/api/v1/media/admin/'+route,
        body ? {method:'POST',headers:requestHeaders(),body:JSON.stringify(body)} : {})''', {'route': route, 'body': body})


def open_scope(page, scope):
    page.evaluate('scope => { priorityScope=scope; priorityPage=1; $("prioritySearch").value=""; return loadMediaPriority(true); }', scope)
    page.wait_for_function('() => !priorityLoading')


def names(page, kind='media'):
    return page.locator(f'[data-priority-kind="{kind}"]').evaluate_all('(rows)=>rows.map(row=>row.dataset.priorityPath.split("/").pop())')


def reset(page):
    for name, value in [('a', 100), ('b', 100), ('c', 101), ('d', 99)]:
        call(page, 'media-priority', {'media_path': f'music/drag/{name}.mp3', 'value': value})
    open_scope(page, 'music/drag')
    assert names(page) == ['c.mp3', 'a.mp3', 'b.mp3', 'd.mp3']


def row(page, name, kind='media'):
    return page.locator(f'[data-priority-kind="{kind}"][data-priority-path$="/{name}"]')


def wait_saved(page):
    page.wait_for_function('() => !document.querySelector("#priorityPanel").hasAttribute("aria-busy") && /已保存/.test(document.querySelector("#prioritySaveState").textContent)')


def mouse_move(page, name, before, cancel=False):
    page.wait_for_timeout(220)
    source = row(page, name).locator('.priority-drag-handle').bounding_box()
    destination = row(page, before).bounding_box()
    page.mouse.move(source['x'] + source['width'] / 2, source['y'] + source['height'] / 2)
    page.mouse.down()
    page.mouse.move(source['x'] + source['width'] / 2, destination['y'] + 4, steps=16)
    page.wait_for_timeout(100)
    if cancel:
        page.keyboard.press('Escape')
    page.mouse.up()


with sync_playwright() as driver:
    browser = driver.chromium.launch()
    context = browser.new_context(viewport={'width': 1360, 'height': 900})
    assert context.request.post(args.base_url + '/api/v1/media/admin/elevate', form={'token': key}).ok
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(args.base_url + '/api/v1/media/admin/')
    page.wait_for_function('() => !!window.FrontierPriorityDrag')
    assert page.locator('#systemVersionPanel, #systemReleaseUpgrade, #systemReleaseRollback').count() == 0
    for endpoint in ('nodes/release', 'nodes/release/history', 'nodes/release/upgrade', 'nodes/release/rollback'):
        response = context.request.get(args.base_url + '/api/v1/media/admin/' + endpoint)
        assert response.status == 404
    assert not any('release-admin.js' in value or 'release-version-ui.js' in value for value in page.locator('script[src]').evaluate_all('(items)=>items.map(item=>item.src)'))
    site_status = call(page, 'site/maintenance')
    assert site_status['maintenance'] is False and 'release' not in site_status
    # This loopback fixture is HTTP. Maintenance mutation must keep its HTTPS
    # requirement; successful TLS changes are exercised by the native API test.
    csrf = page.evaluate('() => csrf()')
    response = context.request.post(args.base_url + '/api/v1/media/admin/site/maintenance',
                                    data={'enabled': True}, headers={'X-CSRF-Token': csrf})
    assert response.status == 403
    proof.append('retired-upgrade-routes-and-UI-with-independent-site-maintenance')
    page.locator('[data-module-target="priority"]').click()
    page.wait_for_timeout(400)
    reset(page)
    page.screenshot(path=str(args.output / 'before-drag.png'))
    mouse_move(page, 'c.mp3', 'b.mp3')
    wait_saved(page)
    assert names(page) == ['a.mp3', 'c.mp3', 'b.mp3', 'd.mp3']
    order = call(page, 'priority-order?scope=music/drag&kind=media')
    assert [(i['path'].split('/')[-1], i['preference']) for i in order['items']] == [('a.mp3', 101), ('c.mp3', 101), ('b.mp3', 100), ('d.mp3', 99)]
    public_order = page.evaluate('''async () => (await api('/api/v1/media/catalog/media?media_type=music&path=music/drag&playback_session_id=20512c3b-5340-4185-b76d-20402279482a')).entries.map(item=>item.media_path.split('/').pop())''')
    assert public_order == ['a.mp3', 'c.mp3', 'b.mp3', 'd.mp3']
    page.reload()
    page.wait_for_function('() => !!window.FrontierPriorityDrag')
    page.locator('[data-module-target="priority"]').click()
    open_scope(page, 'music/drag')
    assert names(page) == public_order
    expected_modules = ['media','priority','lyrics','users','security','network','nodes','site','key','brand']
    assert page.locator('.admin-console > .admin-module').evaluate_all('(modules)=>modules.map(module=>module.dataset.adminModule)') == expected_modules
    assert page.locator('#adminModuleLinks button').evaluate_all('(buttons)=>buttons.map(button=>button.dataset.moduleTarget)') == expected_modules
    proof.append('mouse-drag-equal-priority-and-99-neighbour')
    page.screenshot(path=str(args.output / 'desktop.png'))
    row(page, 'b.mp3').locator('.priority-drag-handle').focus()
    page.keyboard.press('ArrowUp')
    wait_saved(page)
    assert names(page) == ['a.mp3', 'b.mp3', 'c.mp3', 'd.mp3']
    before = call(page, 'priority-order?scope=music/drag&kind=media')['revision']
    mouse_move(page, 'a.mp3', 'd.mp3', cancel=True)
    assert call(page, 'priority-order?scope=music/drag&kind=media')['revision'] == before
    assert names(page) == ['a.mp3', 'b.mp3', 'c.mp3', 'd.mp3']
    assert page.locator('.priority-drag-ghost').count() == 0
    proof.append('keyboard-move-and-Escape-cancel')

    # A real competing Admin update invalidates this page's full-scope revision.
    call(page, 'media-priority', {'media_path': 'music/drag/d.mp3', 'value': 7})
    mouse_move(page, 'c.mp3', 'a.mp3')
    page.wait_for_function('() => /排序已被修改/.test(document.querySelector("#prioritySaveState").textContent)')
    assert names(page) == ['a.mp3', 'b.mp3', 'c.mp3', 'd.mp3']
    assert call(page, 'priority-order?scope=music/drag&kind=media')['items'][-1]['preference'] == 7
    proof.append('real-stale-409-display-rollback')
    reset(page)
    page.route('**/admin/priority-order', lambda route: route.abort() if route.request.method == 'POST' else route.continue_())
    mouse_move(page, 'c.mp3', 'b.mp3')
    page.wait_for_function('() => /恢复显示顺序/.test(document.querySelector("#prioritySaveState").textContent)')
    assert names(page) == ['c.mp3', 'a.mp3', 'b.mp3', 'd.mp3']
    page.unroute('**/admin/priority-order')
    proof.append('network-failure-display-rollback')

    numeric = row(page, 'b.mp3').locator('input[type="number"]')
    numeric.fill('500000')
    numeric.press('Tab')
    page.wait_for_function('''() => !priorityLoading && document.querySelector('[data-priority-path="music/drag/b.mp3"] input[type=number]').value==='500000' ''')
    assert call(page, 'priority-order?scope=music/drag&kind=media')['items'][0]['preference'] == 500000
    open_scope(page, 'music')
    assert page.locator('.priority-directory-row .priority-drag-handle').count() >= 2
    row(page, 'zz-folder', 'directory').locator('input[type="number"]').fill('500000')
    row(page, 'zz-folder', 'directory').locator('input[type="number"]').press('Tab')
    page.wait_for_function('() => !priorityLoading && document.querySelector("[data-priority-kind=directory]").dataset.priorityPath==="music/zz-folder"')
    row(page, 'aa-folder', 'directory').locator('.priority-drag-handle').focus()
    page.keyboard.press('ArrowUp')
    wait_saved(page)
    proof.append('media-and-directory-exact-500000-entry-and-directory-keyboard')

    open_scope(page, 'music/pages')
    assert len(names(page)) == 100
    state = call(page, 'priority-order?scope=music/pages&kind=media')
    assert len(state['items']) == 205
    handle = row(page, '0000.mp3').locator('.priority-drag-handle').bounding_box()
    bounds = page.locator('#priorityList').bounding_box()
    page.mouse.move(handle['x'] + 10, handle['y'] + 15); page.mouse.down()
    page.mouse.move(handle['x'] + 10, bounds['y'] + bounds['height'] - 4, steps=12)
    page.wait_for_timeout(500)
    assert page.locator('#priorityList').evaluate('(list)=>list.scrollTop') > 0
    page.keyboard.press('Escape'); page.mouse.up()
    assert call(page, 'priority-order?scope=music/pages&kind=media')['revision'] == state['revision']
    page.locator('#prioritySearch').fill('000')
    page.locator('#priorityFilterForm button[type="submit"]').click()
    page.wait_for_function('() => !priorityLoading && document.querySelector("#priorityDragHint").textContent.includes("搜索")')
    assert page.locator('.priority-drag-handle').count() == 0
    proof.append('off-page-snapshot-edge-autoscroll-cancel-search-boundary')

    # Touch uses real Chrome touch input, including pointer capture and scrolling.
    mobile = browser.new_context(viewport={'width': 390, 'height': 844}, has_touch=True, is_mobile=True, reduced_motion='reduce')
    assert mobile.request.post(args.base_url + '/api/v1/media/admin/elevate', form={'token': key}).ok
    phone = mobile.new_page(); phone.on('pageerror', lambda error: errors.append(str(error)))
    phone.goto(args.base_url + '/api/v1/media/admin/')
    phone.wait_for_function('() => !!window.FrontierPriorityDrag')
    phone.locator('#adminNavigationToggle').click()
    phone.locator('[data-module-target="priority"]').click()
    phone.wait_for_timeout(300)
    reset(phone)
    source = row(phone, 'c.mp3').locator('.priority-drag-handle').bounding_box()
    destination = row(phone, 'b.mp3').bounding_box()
    client = mobile.new_cdp_session(phone)
    x, y = source['x'] + 12, source['y'] + 18
    client.send('Input.dispatchTouchEvent', {'type': 'touchStart', 'touchPoints': [{'x': x, 'y': y}]})
    for i in range(1, 13):
        target = y + (destination['y'] + 4 - y) * i / 12
        client.send('Input.dispatchTouchEvent', {'type': 'touchMove', 'touchPoints': [{'x': x, 'y': target}]})
        phone.wait_for_timeout(16)
    client.send('Input.dispatchTouchEvent', {'type': 'touchEnd', 'touchPoints': []})
    wait_saved(phone)
    assert names(phone) == ['a.mp3', 'c.mp3', 'b.mp3', 'd.mp3']
    assert phone.evaluate('document.documentElement.scrollWidth<=innerWidth')
    assert phone.evaluate('''() => [...document.querySelectorAll('[data-priority-kind]')].every(row=>{
        const r=row.getBoundingClientRect(), control=row.querySelector('.priority-control').getBoundingClientRect();
        return control.top>=r.top && control.bottom<=r.bottom+1;
    })'''), 'mobile priority controls must remain inside their complete row'
    assert phone.locator('#adminNavigationToggle').bounding_box()['y'] < 56
    assert phone.locator('#priorityPanel .module-heading').bounding_box()['y'] >= 56, 'toolbar must not cover the module title'
    assert phone.locator('[data-module-target="priority"]').get_attribute('aria-current') == 'true'
    phone.screenshot(path=str(args.output / 'mobile.png'))
    proof.append('real-touch-drag-mobile-layout-and-reduced-motion')
    verify_live_navigation(page)
    verify_live_navigation(phone)
    proof.append('bidirectional-live-module-navigation-desktop-and-mobile')
    assert not errors, errors
    context.close(); mobile.close(); browser.close()
pathlib.Path(args.output, 'result.json').write_text(json.dumps({'passed': proof, 'browser_errors': errors}, ensure_ascii=False, indent=2))
print(json.dumps({'passed': len(proof), 'browser_errors': errors}))

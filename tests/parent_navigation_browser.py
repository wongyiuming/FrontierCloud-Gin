"""Loopback real category HTML/CSS/JS. Cached Chromium simulation, no hardware claim."""
import argparse
import hashlib
import html
import json
import pathlib
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from playwright.sync_api import sync_playwright

PC = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
TESLA = PC + " Tesla/2026.38.6"
ANDROID = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36"
IPAD = "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1"
PATH = "music/達明一派/萬歲萬歲萬萬歲"
LONG_PATH = "music/" + "環球音樂與達明一派的經典錄音珍藏" * 5 + "/" + "ThisIsAVeryLongAlbumPathWithoutSpaces" * 5
SCENARIOS = [
    ("pc-1280", PC, 1280, PATH, False), ("tesla-1280", TESLA, 1280, PATH, False),
    ("android-1280", ANDROID, 1280, PATH, False), ("ipad-1280", IPAD, 1280, PATH, False),
    ("unknown-1280", "Unknown Browser", 1280, PATH, False), ("navigator-undefined", PC, 1280, PATH, True),
    ("pc-375", PC, 375, PATH, False), ("pc-768", PC, 768, PATH, False),
    ("pc-long", PC, 1280, LONG_PATH, False), ("tesla-long", TESLA, 1280, LONG_PATH, False),
    ("android-375-long", ANDROID, 375, LONG_PATH, False), ("ipad-768-long", IPAD, 768, LONG_PATH, False),
]


def render(root, path):
    template = (root / "static/media/category.html").read_text(encoding="utf-8")
    parent = path.rsplit("/", 1)[0] if "/" in path else "music"
    back = "/api/v1/media/music/category?" + urllib.parse.urlencode({"path": parent})
    entries = [{"name": n, "url": "/api/v1/media/music/category?" + urllib.parse.urlencode({"path": path + "/" + n})}
               for n in ["意難平", "你還愛我嗎", "石頭記", "萬歲萬歲萬萬歲", "神經", "達明一派", "The Story", "迷惘夜車", "今天應該很高興", "音樂珍藏"]]
    values = {"PAGE_TITLE": html.escape("前沿音乐 - " + path.rsplit("/", 1)[-1], quote=True), "BACK_URL": html.escape(back, quote=True),
              "CATALOG_CONFIG_JSON": json.dumps({"bootstrap": entries, "url": "", "cacheKey": ""}, ensure_ascii=False),
              "STUN_URLS_JSON": "[]", "WEBRTC_INTERVAL_MS": "30000", "DIRECTORY_GLOBE_CSS_URL": "/static/css/directory-globe.css",
              "DIRECTORY_GLOBE_JS_URL": "/static/js/directory-globe.js", "MEDIA_BROWSER_JS_URL": "/static/js/media-browser.js", "NETWORK_OBSERVATION_JS_URL": "/fixture-observation.js"}
    for key, value in values.items():
        template = template.replace("{{" + key + "}}", value)
    assert "{{" not in template
    return template.encode(), back, parent


def geometry(page):
    return page.evaluate("""() => {
        const box=e=>{const r=e.getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height,right:r.right,bottom:r.bottom};};
        const touch=e=>{if(!e)return null;const b=box(e);return {box:b,href:e.getAttribute('href'),points:[[0,0],[-20,-20],[20,-20],[-20,20],[20,20]].map(([dx,dy])=>{const x=b.x+b.width/2+dx,y=b.y+b.height/2+dy;return {x,y,hit:document.elementFromPoint(x,y)?.closest('.back-btn')===e};})};};
        const header=document.querySelector('.header'),brand=document.getElementById('pageBrandLogo'),hint=document.getElementById('globeHint'),left=document.querySelector('.path-navigation > .back-btn');
        return {header:box(header),logo:box(brand),headerBack:touch(header.querySelector('.back-btn')),leftBack:touch(left),hint:box(hint),toggle:box(document.getElementById('globeToggle')),
            hintText:hint.textContent,anchorCount:document.querySelectorAll('.back-btn').length,logoNaturalWidth:brand.naturalWidth,logoSrc:brand.getAttribute('src'),
            sharedNativeWrapper:!!left&&left.parentElement===hint.parentElement&&left.parentElement.className==='path-navigation',uaClassPresent:document.documentElement.classList.contains('tesla-browser'),
            horizontalOverflow:document.documentElement.scrollWidth>innerWidth,cards:[...document.querySelectorAll('#categoryGrid .card')].slice(0,3).map(box)};
    }""")


def assert_layout(value, back):
    assert value["anchorCount"] == 2 and value["sharedNativeWrapper"], "two native parent anchors required"
    assert value["logoNaturalWidth"] > 1 and value["logoSrc"] == "/api/v1/media/brand/logo/music", "real WebP logo unavailable"
    assert not value["horizontalOverflow"] and not value["uaClassPresent"]
    for field in ("headerBack", "leftBack"):
        action = value[field]
        assert action and action["href"] == back, "parent href changed"
        assert action["box"]["width"] >= 48 and action["box"]["height"] >= 48, "touch target below 48 CSS pixels"
        assert all(p["hit"] for p in action["points"]), "parent action obstructed or outside viewport"
    assert value["leftBack"]["box"]["right"] <= value["hint"]["x"] - 8, "left parent overlaps following path"
    assert value["hint"]["right"] <= value["toggle"]["x"] - 8, "path overlaps view toggle"
    assert value["hint"]["y"] >= value["logo"]["bottom"], "path/navigation overlap logo"


def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "baseline", "output"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    parser.add_argument("--chromium", required=True)
    args = parser.parse_args(); args.output.mkdir(exist_ok=False); requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path); params = urllib.parse.parse_qs(parsed.query)
            root = args.baseline if self.headers.get("X-Fixture-Baseline") == "1" else args.source
            requests.append({"path": self.path, "baseline": root == args.baseline})
            if parsed.path == "/api/v1/media/music/category":
                payload, _, _ = render(root, params.get("path", [PATH])[0]); kind = "text/html; charset=utf-8"
            elif parsed.path == "/fixture-observation.js":
                payload, kind = b"/* independent observation is outside this UI fixture */", "application/javascript"
            elif parsed.path == "/api/v1/media/brand/logo/music":
                payload, kind = (root / "static/brand/frontier-music.webp").read_bytes(), "image/webp"
            elif parsed.path in ["/static/js/media-browser.js", "/static/js/directory-globe.js", "/static/css/directory-globe.css"]:
                payload = (root / parsed.path.lstrip("/")).read_bytes(); kind = "text/css" if parsed.path.endswith(".css") else "application/javascript"
            else:
                self.send_error(404); return
            self.send_response(200); self.send_header("Content-Type", kind); self.send_header("Cache-Control", "no-store"); self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    origin = "http://127.0.0.1:" + str(server.server_port); rows = []; baseline_geometry = {}
    report = {"scope": "native HTML dual parent links; cached desktop Chromium UA/viewport simulation, no real vehicle/mobile hardware claim", "production_accessed": False, "external_install": False,
              "requirement_change": "All devices retain header right parent link. The second parent link precedes the path below the logo, per final user instruction. UA relocation and full-PC pixel equality explicitly cancelled.", "cases": rows}
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=args.chromium, headless=True, args=["--no-sandbox", "--disable-background-networking", "--disable-component-update"])
            report["chromium_version"] = browser.version
            for width in (1280, 768, 375):
                for label, path in (("normal", PATH), ("long", LONG_PATH)):
                    context = browser.new_context(viewport={"width": width, "height": 800}, user_agent=PC, device_scale_factor=1, reduced_motion="reduce", extra_http_headers={"X-Fixture-Baseline": "1"})
                    page = context.new_page(); page.goto(origin + "/api/v1/media/music/category?" + urllib.parse.urlencode({"path": path}), wait_until="networkidle")
                    page.locator("#categoryGrid .card").first.wait_for(state="visible"); page.wait_for_function("document.getElementById('pageBrandLogo').naturalWidth > 1"); page.evaluate("document.fonts.ready")
                    baseline_geometry[(width, label)] = geometry(page); context.close()
            for name, ua, width, path, no_navigator in SCENARIOS:
                row = {"name": name, "user_agent": ua, "viewport": {"width": width, "height": 800}, "path": path, "navigator_undefined": no_navigator, "page_errors": [], "blocked_external_requests": []}; rows.append(row)
                context = browser.new_context(viewport=row["viewport"], user_agent=ua, device_scale_factor=1, reduced_motion="reduce")
                page = context.new_page(); page.on("pageerror", lambda error, row=row: row["page_errors"].append(str(error)))
                def route(control, request, row=row):
                    if urllib.parse.urlsplit(request.url).hostname == "127.0.0.1": control.continue_()
                    else: row["blocked_external_requests"].append(request.url); control.abort()
                page.route("**/*", route)
                if no_navigator: page.add_init_script("Object.defineProperty(globalThis,'navigator',{value:undefined,configurable:true});")
                initial = origin + "/api/v1/media/music/category?" + urllib.parse.urlencode({"path": path})
                def open_initial():
                    page.goto(initial, wait_until="networkidle", timeout=8000); page.locator("#categoryGrid .card").first.wait_for(state="visible", timeout=3000)
                    page.wait_for_function("document.getElementById('pageBrandLogo').naturalWidth > 1"); page.evaluate("document.fonts.ready"); page.wait_for_timeout(100)
                try:
                    open_initial(); value = geometry(page); row["layout"] = value
                    image = args.output / (name + ".png"); page.screenshot(path=str(image), animations="disabled", caret="hide")
                    row["screenshot"] = str(image); row["screenshot_sha256"] = hashlib.sha256(image.read_bytes()).hexdigest()
                    _, back, parent = render(args.source, path); assert_layout(value, back)
                    baseline = baseline_geometry[(width, "long" if path == LONG_PATH else "normal")]
                    row["original_header_geometry_equal"] = all(value[k] == baseline[k] for k in ("header", "logo", "headerBack"))
                    assert row["original_header_geometry_equal"], "original header geometry changed"
                    page.locator("#globeToggle").click(); assert page.locator("#globeToggle").get_attribute("aria-pressed") == "true"; assert_layout(geometry(page), back)
                    page.screenshot(path=str(args.output / (name + "-list.png")), animations="disabled", caret="hide")
                    page.locator("#globeToggle").click(); assert_layout(geometry(page), back)
                    assert geometry(page)["hintText"] == value["hintText"]; row["grid_list_roundtrip_passed"] = True
                    row["scroll_bottom"] = page.evaluate("() => {scrollTo(0,document.body.scrollHeight);return document.scrollingElement.scrollTop;}")
                    page.evaluate("scrollTo(0,0)"); assert_layout(geometry(page), back); row["scroll_restore_passed"] = True
                    clicks = []
                    for selector in (".header > .back-btn", ".path-navigation > .back-btn"):
                        open_initial(); page.locator(selector).click(); page.wait_for_url(origin + back, timeout=5000)
                        assert geometry(page)["hintText"] == parent.replace("music", "音乐", 1).replace("/", " / ")
                        clicks.append({"selector": selector, "url": page.url, "passed": True})
                    row["parent_clicks"] = clicks
                    assert not row["page_errors"] and not row["blocked_external_requests"]; row["passed"] = True
                except Exception as error:
                    row["error"] = type(error).__name__ + ": " + str(error); row["passed"] = False
                finally:
                    context.close()
            same_size = [r for r in rows if r["name"] in ["pc-1280", "tesla-1280", "android-1280", "ipad-1280", "unknown-1280", "navigator-undefined"]]
            report["same_1280_layout_across_uas"] = len(same_size) == 6 and all(r.get("layout") == same_size[0].get("layout") for r in same_size)
            if not report["same_1280_layout_across_uas"]:
                rows[0]["passed"] = False; rows[0]["error"] = "UA altered shared layout"
            browser.close()
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
        report["requests"] = requests; report["passed"] = len(rows) == len(SCENARIOS) and all(r.get("passed") for r in rows)
        (args.output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "cases": len(rows), "failures": [{"name": r["name"], "error": r.get("error")} for r in rows if not r.get("passed")]}, ensure_ascii=False))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()

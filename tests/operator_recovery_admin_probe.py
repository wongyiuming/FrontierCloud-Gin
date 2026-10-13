"""Ephemeral loopback HTTP client, never a resident product/Python service."""
import http.cookiejar
import json
from pathlib import Path
import sys
import urllib.parse
import urllib.request

jar = http.cookiejar.CookieJar()
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
base = 'http://127.0.0.1:8000'
key = Path('/run/frontiercloud-secrets/admin_key').read_text().strip()
data = urllib.parse.urlencode({'token': key}).encode()
with client.open(urllib.request.Request(base + '/api/v1/media/admin/elevate', data=data,
                                        headers={'Content-Type': 'application/x-www-form-urlencoded'}), timeout=10) as response:
    assert response.status == 200
with client.open(base + '/api/v1/media/admin/status', timeout=10) as response:
    status = json.load(response)
csrf = next(cookie.value for cookie in jar if cookie.name == status['csrf_cookie_name'])
if sys.argv[1] == 'set':
    data = json.dumps({'path': 'music/fixture', 'value': 77}).encode()
    with client.open(urllib.request.Request(base + '/api/v1/media/admin/directory-priority', data=data,
                                            headers={'Content-Type': 'application/json', 'X-CSRF-Token': csrf}), timeout=10) as response:
        assert response.status == 200 and json.load(response)['preference'] == 77
else:
    with client.open(base + '/api/v1/media/admin/directory-priorities?scope=music', timeout=10) as response:
        assert b'"preference":77' in response.read()
print(json.dumps({'authenticated_loopback_api': True, 'priority': 77}))

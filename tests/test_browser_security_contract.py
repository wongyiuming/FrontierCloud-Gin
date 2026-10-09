"""Lightweight policy contracts; real Gin/Nginx/Chromium run on the dev host."""
import base64
import hashlib
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BrowserSecurityContractTests(unittest.TestCase):
    def test_fixed_maintenance_inline_code_matches_csp_hashes(self):
        page = (ROOT / 'nginx/maintenance.html').read_text(encoding='utf-8')
        config = (ROOT / 'nginx/nginx.conf').read_text(encoding='utf-8')
        for _, body in re.findall(r'<(style|script)>(.*?)</\1>', page, re.S):
            digest = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
            self.assertIn(f"'sha256-{digest}'", config)
        gate = (ROOT / 'nginx/maintenance-gate.conf').read_text(encoding='utf-8')
        self.assertIn('include /etc/nginx/security-headers.conf;', gate)
        self.assertIn('/__maintenance.html $edge_csp;', config)

    def test_tls_default_server_uses_the_same_modern_policy(self):
        policy = (ROOT / 'nginx/transport/https/tls-policy.conf').read_text(encoding='utf-8')
        self.assertIn('ssl_protocols TLSv1.2 TLSv1.3;', policy)
        self.assertIn('http2 on;', policy)
        self.assertIn('ssl_session_tickets off;', policy)
        self.assertNotIn('HIGH:', policy)
        for name in ('public-tls.conf', 'extra-servers.conf'):
            self.assertIn('include /etc/nginx/transport/https/tls-policy.conf;',
                          (ROOT / 'nginx/transport/https' / name).read_text(encoding='utf-8'))

    def test_player_has_no_inline_event_handler_or_eval(self):
        for page in (ROOT / 'static/media').glob('*.html'):
            self.assertNotRegex(page.read_text(encoding='utf-8'), r'\bon(?:click|error|load)\s*=')
        player = (ROOT / 'static/js/player.js').read_text(encoding='utf-8')
        self.assertNotIn('onclick=', player)
        self.assertIn("listContainer.addEventListener('click'", player)
        self.assertNotRegex(player, r'\beval\(|new Function\(')

    def test_edge_preserves_nonce_policy_without_duplicate_headers(self):
        config = (ROOT / 'nginx/nginx.conf').read_text(encoding='utf-8')
        self.assertIn('server_tokens off;', config)
        self.assertIn('proxy_hide_header Content-Security-Policy;', config)
        for name in ('security-headers.conf', 'karaoke-security-headers.conf'):
            headers = (ROOT / 'nginx' / name).read_text(encoding='utf-8')
            self.assertIn('add_header Content-Security-Policy $frontiercloud_csp always;', headers)


if __name__ == '__main__':
    unittest.main()

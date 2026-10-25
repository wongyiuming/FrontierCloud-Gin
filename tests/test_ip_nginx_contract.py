"""Native edge identity and bounded internal relay path contracts."""
from pathlib import Path
import hashlib
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class IPNginxContract(unittest.TestCase):
    def test_relay_patterns_accept_canonical_brackets_without_injection(self):
        config = (ROOT / 'nginx/nginx.conf').read_text(encoding='utf-8')
        for kind, length in [('media', 64), ('recording', 32)]:
            match = re.search(r'location ~ "(\^/_relay_' + kind + r'/[^"\n]+)" \{(.*?)\n        }', config, re.S)
            self.assertIsNotNone(match)
            # Nginx quoted strings reduce a doubled backslash before PCRE.
            pattern = match[1].replace('\\\\', '\\')
            pattern = re.sub(r'\(\?<([^>]+)>', r'(?P<\1>', pattern)
            compiled = re.compile(pattern)
            for host in ('relay.example.test', '124.220.156.46', '[2606:4700:4700::1111]'):
                path = f'/_relay_{kind}/{host}/8443/' + 'a' * length + '/valid_token-1'
                result = compiled.fullmatch(path)
                self.assertIsNotNone(result, path)
                self.assertEqual(result['relay_host'], host)
            for host in ('2606:4700:4700::1111', '[fe80::1%eth0]', '[::1]/other', 'user@relay.test', '[2606::1]:8443', '[[2606::1]]'):
                path = f'/_relay_{kind}/{host}/8443/' + 'a' * length + '/token'
                self.assertIsNone(compiled.fullmatch(path), path)
            block = match[2]
            self.assertIn('internal;', block)
            self.assertIn('proxy_pass https://$relay_host:$relay_port/', block)
            self.assertIn('proxy_set_header Host $relay_host:$relay_port;', block)
            self.assertIn('proxy_ssl_verify on;', block)
            self.assertIn('proxy_ssl_name $relay_host;', block)
            self.assertIn('proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;', block)

    def test_native_nginx_builder_copies_shared_subject_validation(self):
        dockerfile = (ROOT / 'nginx/Dockerfile').read_text(encoding='utf-8')
        self.assertIn('COPY internal/certificate ./internal/certificate', dockerfile)

    def test_ip_san_patch_is_bound_to_exact_upstream_and_build_input(self):
        dockerfile = (ROOT / 'nginx/Dockerfile').read_text(encoding='utf-8')
        patch = (ROOT / 'nginx/patches/0001-verified-ip-san.patch').read_bytes()
        self.assertIn(hashlib.sha256(patch).hexdigest() + '  /build/verified-ip-san.patch', dockerfile)
        self.assertIn('patch --batch --forward --fuzz=0 -p1', dockerfile)
        self.assertIn('src/event/ngx_event_openssl.c" | sha256sum -c -', dockerfile)
        self.assertIn('objs/nginx /usr/sbin/nginx', dockerfile)
        self.assertIn('X509_check_ip(cert, (u_char *) &addr4, 4, 0)', patch.decode())
        self.assertIn('X509_check_ip(cert, addr6, 16, 0)', patch.decode())
        self.assertIn('nginx/patches/*.patch text eol=lf', (ROOT / '.gitattributes').read_text())

    def test_ip_san_patch_has_no_context_or_trailing_whitespace(self):
        # A context-only blank line contains one space in a unified diff. Keep
        # this shipped build input valid under the repository whitespace gate.
        patch = (ROOT / 'nginx/patches/0001-verified-ip-san.patch').read_bytes()
        lines = patch.splitlines()
        self.assertEqual(lines[:2], [
            b'--- a/src/event/ngx_event_openssl.c',
            b'+++ b/src/event/ngx_event_openssl.c',
        ])
        self.assertTrue(any(line.startswith(b'@@ ') for line in lines[2:]))
        for line in lines:
            self.assertEqual(line, line.rstrip(), line)
        for line in lines[2:]:
            self.assertTrue(line.startswith((b'@@ ', b'+', b'-')), line)


if __name__ == '__main__':
    unittest.main()

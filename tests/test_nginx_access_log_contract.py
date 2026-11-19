"""Source guards plus opt-in evidence from real isolated Nginx access logs."""
import json
import os
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
USER_AGENT = 'Tesla Browser "quote" \\slash'


class NginxAccessLogContract(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / "nginx/nginx.conf").read_text(encoding="utf-8")
        self.format = re.search(
            r"log_format structured escape=json\s+(.*?);", self.source, re.S
        ).group(1)

    def test_user_agent_and_protocol_are_escaped_string_fields(self):
        for field, variable in (
            ("user_agent", "http_user_agent"),
            ("http_protocol", "server_protocol"),
            ("tls_protocol", "ssl_protocol"),
        ):
            self.assertIn(f'"{field}":"${variable}"', self.format)

    def test_upstream_measurements_accept_missing_and_multi_hop_values(self):
        for field, variable in (
            ("upstream_connect_seconds", "upstream_connect_time"),
            ("upstream_header_seconds", "upstream_header_time"),
            ("upstream_response_seconds", "upstream_response_time"),
        ):
            self.assertIn(f'"{field}":"${variable}"', self.format)
        self.assertIn('"duration_seconds":$request_time', self.format)
        self.assertIn('"request_completion":"$request_completion"', self.format)
        self.assertIn('"upstream_status":"$upstream_status"', self.format)

    def test_credentials_queries_and_internal_capability_paths_stay_excluded(self):
        self.assertIn('"path":"$logged_path"', self.format)
        self.assertNotIn('"~^([^?]*)" $1;', self.source)
        self.assertIn('default /other;', self.source)
        self.assertIn('~^/static/ /static/*;', self.source)
        self.assertIn('~^/api/v1/media/ /api/v1/media/*;', self.source)
        self.assertIn('http {\n    # Request error', self.source)
        self.assertIn('error_log /dev/null crit;', self.source.split('http {', 1)[1].split('fc_business_traffic;', 1)[0])
        self.assertIn('~^/_relay_media/ /api/v1/media/stream;', self.source)
        self.assertIn('~^/_relay_recording/ /api/v1/karaoke/recordings;', self.source)
        variables = set(re.findall(r"\$\{?([a-zA-Z_][a-zA-Z_0-9]*)", self.format))
        self.assertTrue(variables.isdisjoint({
            "request", "request_uri", "args", "query_string", "http_cookie",
            "http_authorization", "http_referer", "http_forwarded",
            "http_x_forwarded_for", "relay_token",
        }))
        self.assertNotIn("$arg_", self.format)
        self.assertIn("access_log syslog:server=unix:/run/frontiercloud-project-logs/collector.sock,tag=nginx,nohostname structured if=$access_loggable;", self.source)
        self.assertNotIn("access_log /dev/stdout", self.source)

    def test_legacy_capability_routes_do_not_log_error_request_lines(self):
        for marker in ('location ~ "^/_relay_media/', 'location ~ "^/_relay_recording/',
                       'location ^~ /internal/v1/media/', 'location ^~ /internal/v1/recordings/',
                       'location ^~ /internal/v1/storage/'):
            section = self.source.split(marker, 1)[1].split('proxy_pass ', 1)[0]
            self.assertIn('error_log /dev/null crit;', section, marker)
        direct = self.source.split('location ^~ /internal/v1/media/', 1)[1].split(
            'location ^~ /internal/v1/backup/', 1)[0]
        self.assertIn('proxy_next_upstream off;', direct)
        self.assertIn('proxy_pass http://frontiercloud_web;', direct)
        for marker in ('location ^~ /_protected_cipher/', 'location ^~ /_protected_media/',
                       'location ~ "^/_protected_recordings/'):
            section = self.source.split(marker, 1)[1].split('alias ', 1)[0]
            self.assertIn('error_log /dev/null crit;', section, marker)

    def test_observation_has_only_a_scoped_sixteen_kib_limit(self):
        exact = self.source.split(
            'location = /_fc_public_proxy/api/v1/media/network-observation {', 1
        )[1].split('\n        }', 1)[0]
        generic = self.source.split('location ^~ /_fc_public_proxy/ {', 1)[1].split(
            '\n        }', 1)[0]
        self.assertIn('client_max_body_size 16k;', exact)
        self.assertIn('client_body_buffer_size 16k;', exact)
        self.assertIn('client_max_body_size 8k;', generic)
        for required in ('proxy_pass http://frontiercloud_web;',
                         'proxy_set_header X-Forwarded-For "";',
                         'proxy_set_header Forwarded "";',
                         'proxy_next_upstream off;'):
            self.assertIn(required, exact)
            self.assertIn(required, generic)


@unittest.skipUnless(os.environ.get("FRONTIERCLOUD_NGINX_LOG_CAPTURE"),
                     "real Nginx log fixture runs only on the development host")
class NginxAccessLogRuntime(unittest.TestCase):
    def test_real_json_escaping_timings_and_query_redaction(self):
        raw = Path(os.environ["FRONTIERCLOUD_NGINX_LOG_CAPTURE"]).read_text(encoding="utf-8")
        self.assertNotIn("SECRET_QUERY_TOKEN", raw)
        for secret in ("INERT_LOCAL_TOKEN", "INERT_LYRIC_TOKEN", "1" * 64, "2" * 64):
            self.assertNotIn(secret, raw)
        entries = [json.loads(line) for line in raw.splitlines() if line.startswith("{")]
        local_errors = [entry for entry in entries
                        if entry.get("path") == "/api/v1/media/*"
                        and entry.get("status") in (403, 502)]
        self.assertCountEqual([entry["status"] for entry in local_errors], [403, 502])
        for agent, status in (("fc-observation-exact", 200),
                              ("fc-observation-over", 413),
                              ("fc-other-over", 413)):
            matching = [entry for entry in entries if entry.get("user_agent") == agent]
            self.assertEqual(len(matching), 1, agent)
            self.assertEqual(matching[0]["status"], status, agent)
        selected = [entry for entry in entries
                    if entry.get("path") == "/api/v1/media/music/category"]
        self.assertEqual(len(selected), 1)
        entry = selected[0]
        self.assertEqual(entry["user_agent"], USER_AGENT)
        self.assertEqual(entry["status"], 200)
        self.assertEqual(entry["http_protocol"], "HTTP/1.1")
        self.assertIsInstance(entry["tls_protocol"], str)
        self.assertGreaterEqual(entry["duration_seconds"], 0)
        for field in ("upstream_connect_seconds", "upstream_header_seconds",
                      "upstream_response_seconds"):
            self.assertRegex(entry[field], r"^\d+\.\d{3}$")
        static = next(entry for entry in entries if entry.get("path") == "/other")
        for field in ("upstream_connect_seconds", "upstream_header_seconds",
                      "upstream_response_seconds"):
            # JSON escaping can emit an empty variable; classic log escaping
            # uses a dash. Both mean no upstream, never a numeric measurement.
            self.assertIn(static[field], ("", "-"))


if __name__ == "__main__":
    unittest.main()

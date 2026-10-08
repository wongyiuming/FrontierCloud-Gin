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

    def test_credentials_queries_and_internal_capability_paths_stay_excluded(self):
        self.assertIn('"path":"$logged_path"', self.format)
        self.assertIn('"~^([^?]*)" $1;', self.source)
        self.assertIn('~^/_relay_media/ /api/v1/media/stream;', self.source)
        variables = set(re.findall(r"\$\{?([a-zA-Z_][a-zA-Z_0-9]*)", self.format))
        self.assertTrue(variables.isdisjoint({
            "request", "request_uri", "args", "query_string", "http_cookie",
            "http_authorization", "http_referer", "http_forwarded",
            "http_x_forwarded_for", "relay_token",
        }))
        self.assertNotIn("$arg_", self.format)
        self.assertIn("access_log /dev/stdout structured if=$access_loggable;", self.source)


@unittest.skipUnless(os.environ.get("FRONTIERCLOUD_NGINX_LOG_CAPTURE"),
                     "real Nginx log fixture runs only on the development host")
class NginxAccessLogRuntime(unittest.TestCase):
    def test_real_json_escaping_timings_and_query_redaction(self):
        raw = Path(os.environ["FRONTIERCLOUD_NGINX_LOG_CAPTURE"]).read_text(encoding="utf-8")
        self.assertNotIn("SECRET_QUERY_TOKEN", raw)
        entries = [json.loads(line) for line in raw.splitlines() if line.startswith("{")]
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
        static = next(entry for entry in entries if entry.get("path") == "/fixture-ready")
        for field in ("upstream_connect_seconds", "upstream_header_seconds",
                      "upstream_response_seconds"):
            # JSON escaping can emit an empty variable; classic log escaping
            # uses a dash. Both mean no upstream, never a numeric measurement.
            self.assertIn(static[field], ("", "-"))


if __name__ == "__main__":
    unittest.main()

"""Offline tests for ip-reputation-checker. No live network access.

HTTP is faked with stub openers; the offline demo path reads only the
bundled sample data. Run: python3 -m unittest discover -s tests -v
"""
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from ip_reputation_checker.checker import (
    NetworkError,
    RateLimitError,
    cache_get,
    cache_put,
    lookup,
    lookup_offline,
    summarise,
    validate_ip,
)
from ip_reputation_checker.cli import main


class FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_ip_api_opener(payload):
    def opener(request, timeout=15):
        return FakeResponse(payload)
    return opener


class TestValidation(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertEqual(str(validate_ip("8.8.8.8")), "8.8.8.8")

    def test_valid_ipv6(self):
        self.assertEqual(str(validate_ip("2001:4860:4860::8888")), "2001:4860:4860::8888")

    def test_rejects_garbage(self):
        for bad in ["", "  ", "999.999.999.999", "not-an-ip", "8.8.8"]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    validate_ip(bad)

    def test_strips_whitespace(self):
        self.assertEqual(str(validate_ip("  1.1.1.1  ")), "1.1.1.1")


class TestSummarise(unittest.TestCase):
    def test_abuse_score_drives_verdict(self):
        self.assertEqual(summarise("203.0.113.45", {}, {"abuseConfidenceScore": 87})["verdict"], "High")
        self.assertEqual(summarise("1.2.3.4", {}, {"abuseConfidenceScore": 50})["verdict"], "Medium")
        self.assertEqual(summarise("1.2.3.4", {}, {"abuseConfidenceScore": 0})["verdict"], "Low")

    def test_no_abuse_data_is_zero_not_evidence(self):
        result = summarise("8.8.8.8", {"country": "United States"}, None)
        self.assertEqual(result["score"], 0)
        self.assertIn("no abuse signal", result["score_source"])

    def test_score_clamped(self):
        self.assertEqual(summarise("x", {}, {"abuseConfidenceScore": 150})["score"], 100)


class TestCache(unittest.TestCase):
    def test_round_trip_and_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cache.json"
            cache_put(path, "8.8.8.8", {"ip": "8.8.8.8", "score": 0}, now=1000.0)
            self.assertIsNotNone(cache_get(path, "8.8.8.8", ttl=3600, now=2000.0))
            # Past TTL -> expired, must not be served.
            self.assertIsNone(cache_get(path, "8.8.8.8", ttl=3600, now=10000.0))
            self.assertIsNone(cache_get(path, "9.9.9.9", ttl=3600, now=2000.0))

    def test_lookup_uses_cache_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cache.json"
            cache_put(path, "8.8.8.8", {"ip": "8.8.8.8", "score": 0, "verdict": "Low"})

            def exploding_opener(request, timeout=15):
                raise AssertionError("network should not be called on a cache hit")

            result = lookup("8.8.8.8", cache_path=path, opener=exploding_opener)
            self.assertTrue(result["cached"])


class TestRateLimitAndNetwork(unittest.TestCase):
    def test_http_429_becomes_rate_limit_error(self):
        def opener_429(request, timeout=15):
            raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", {"Retry-After": "60"}, None)

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RateLimitError) as ctx:
                lookup("8.8.8.8", use_cache=False, cache_path=Path(tmp) / "c.json", opener=opener_429)
            self.assertEqual(ctx.exception.retry_after, "60")

    def test_network_error_is_clear(self):
        def opener_down(request, timeout=15):
            raise urllib.error.URLError("connection refused")

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(NetworkError):
                lookup("8.8.8.8", use_cache=False, cache_path=Path(tmp) / "c.json", opener=opener_down)

    def test_live_lookup_with_mocked_source(self):
        payload = {"status": "success", "country": "United States", "city": "Ashburn",
                   "isp": "Google LLC", "org": "Google LLC", "query": "8.8.8.8"}
        with tempfile.TemporaryDirectory() as tmp:
            result = lookup("8.8.8.8", use_cache=False, cache_path=Path(tmp) / "c.json",
                            opener=fake_ip_api_opener(payload))
            self.assertEqual(result["country"], "United States")
            self.assertEqual(result["verdict"], "Low")


class TestOfflineAndCli(unittest.TestCase):
    def test_offline_known_sample(self):
        result = lookup_offline("203.0.113.45")
        self.assertEqual(result["score"], 87)
        self.assertEqual(result["verdict"], "High")
        self.assertEqual(result["mode"], "offline-demo")

    def test_offline_unknown_ip_still_works(self):
        result = lookup_offline("9.9.9.9")
        self.assertEqual(result["mode"], "offline-demo")

    def test_cli_offline_json(self):
        with patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(main(["8.8.8.8", "--no-network", "--json"]), 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["ip"], "8.8.8.8")

    def test_cli_rejects_bad_ip(self):
        with patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(main(["not-an-ip", "--no-network"]), 2)


if __name__ == "__main__":
    unittest.main()

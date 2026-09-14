"""Tests for live host detection module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class TestNormalizeUrl:
    def test_bare_domain(self):
        from pipeline.recon.live_hosts import normalize_url
        assert normalize_url("example.com") == "https://example.com"

    def test_already_has_scheme(self):
        from pipeline.recon.live_hosts import normalize_url
        assert normalize_url("http://example.com") == "http://example.com"

    def test_https_url(self):
        from pipeline.recon.live_hosts import normalize_url
        assert normalize_url("https://example.com/path") == "https://example.com/path"


class TestExtractHost:
    def test_from_url(self):
        from pipeline.recon.live_hosts import extract_host
        assert extract_host("https://example.com:8080/path") == "example.com"

    def test_bare_host(self):
        from pipeline.recon.live_hosts import extract_host
        assert extract_host("example.com") == "example.com"


class TestCheckLive:
    def test_unreachable_target(self):
        from pipeline.recon.live_hosts import check_live
        result = check_live("http://127.0.0.1:1", timeout=2)
        assert result.reachable is False
        assert result.status_code is None

    def test_result_has_required_fields(self):
        from pipeline.recon.live_hosts import check_live
        result = check_live("http://127.0.0.1:1", timeout=2)
        assert hasattr(result, "url")
        assert hasattr(result, "host")
        assert hasattr(result, "reachable")
        assert hasattr(result, "response_time_ms")
        assert hasattr(result, "https_supported")

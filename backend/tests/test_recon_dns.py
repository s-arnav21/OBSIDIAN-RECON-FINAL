"""Tests for DNS resolution module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.recon.dns import resolve, resolve_a, resolve_all, _looks_like_ip


class TestResolveA:
    def test_localhost(self):
        ip = resolve_a("localhost")
        assert ip == "127.0.0.1"

    def test_invalid_host(self):
        ip = resolve_a("this-host-definitely-does-not-exist-xyz123.invalid")
        assert ip is None


class TestResolveAll:
    def test_localhost(self):
        ips = resolve_all("localhost")
        assert "127.0.0.1" in ips

    def test_invalid_host(self):
        ips = resolve_all("this-host-definitely-does-not-exist-xyz123.invalid")
        assert ips == []


class TestResolveFull:
    def test_localhost(self):
        result = resolve("localhost")
        assert result.hostname == "localhost"
        assert result.primary_ip == "127.0.0.1"
        assert result.resolution_status == "resolved"
        assert "127.0.0.1" in result.all_ips

    def test_invalid_hostname(self):
        result = resolve("this-host-definitely-does-not-exist-xyz123.invalid")
        assert result.hostname == "this-host-definitely-does-not-exist-xyz123.invalid"
        assert result.primary_ip is None
        assert result.resolution_status == "failed"

    def test_ip_passthrough(self):
        result = resolve("127.0.0.1")
        assert result.hostname == "127.0.0.1"
        assert result.primary_ip == "127.0.0.1"
        assert result.resolution_status == "ip_passthrough"
        assert result.all_ips == ["127.0.0.1"]

    def test_empty_host(self):
        result = resolve("")
        assert result.resolution_status == "error"

    def test_to_dict(self):
        result = resolve("localhost")
        d = result.to_dict()
        assert d["hostname"] == "localhost"
        assert d["primary_ip"] == "127.0.0.1"
        assert isinstance(d["all_ips"], list)


class TestLooksLikeIp:
    def test_valid_ip(self):
        assert _looks_like_ip("127.0.0.1") is True

    def test_invalid_ip(self):
        assert _looks_like_ip("not-an-ip") is False

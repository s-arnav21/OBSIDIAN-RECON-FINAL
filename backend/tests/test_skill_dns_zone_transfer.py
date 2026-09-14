"""Tests for the dns-zone-transfer skill (SKILL-R01)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.recon.dns_zone_transfer import (
    DnsZoneTransferSkill,
    _extract_host,
    _is_ip,
    _ns_ip,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return DnsZoneTransferSkill()


def _ctx(host="example.com", target_url=None):
    return SkillContext(
        target_url=target_url or f"https://{host}",
        host=host,
    )


class TestHelpers:
    def test_is_ip_v4(self):
        assert _is_ip("192.168.56.101") is True

    def test_is_ip_v6(self):
        assert _is_ip("2001:db8::1") is True

    def test_is_ip_hostname(self):
        assert _is_ip("example.com") is False

    def test_extract_host_from_context(self):
        assert _extract_host(_ctx(host="Example.COM")) == "example.com"
        assert _extract_host(SkillContext(target_url="https://alt.example", host="")) == "alt.example"

    def test_ns_ip_resolves_hostname(self):
        ip = _ns_ip("localhost")
        assert ip == "127.0.0.1"

    def test_ns_ip_passthrough(self):
        assert _ns_ip("127.0.0.1") == "127.0.0.1"

    def test_ns_ip_bogus(self):
        assert _ns_ip("this-ns-does-not-exist-xyz.invalid") is None


class TestSkillMetadata:
    def test_registered_by_name(self):
        from skills import get_skill
        assert get_skill("dns-zone-transfer").name == "dns-zone-transfer"

    def test_category(self, skill):
        assert skill.category == SkillCategory.RECON

    def test_trigger_conditions_empty(self, skill):
        assert skill.requires_all == []
        assert skill.requires_any == []

    def test_describe(self, skill):
        d = skill.describe()
        assert d["name"] == "dns-zone-transfer"
        assert d["category"] == "recon"
        assert d["description"]


class TestShouldRun:
    def test_hostname_runs(self, skill):
        assert skill.should_run(_ctx(host="example.com")) is True

    def test_ip_skipped(self, skill):
        assert skill.should_run(_ctx(host="192.168.56.101")) is False

    def test_empty_host_skipped(self, skill):
        assert skill.should_run(_ctx(host="", target_url="")) is False


class TestRunNoNameservers:
    def test_ip_host_returns_no_findings(self, skill):
        result = skill.run(_ctx(host="10.0.0.1"))
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["osint"]["zone_transfer_skipped"] is True

    def test_no_ns_records_returns_no_findings(self, skill, monkeypatch):
        monkeypatch.setattr("skills.recon.dns_zone_transfer._ns_for", lambda d: [])
        result = skill.run(_ctx())
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["osint"]["nameservers"] == []


class TestRunAxfr:
    def test_transfer_succeeds_emits_critical_finding(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.dns_zone_transfer._ns_for",
            lambda d: ["ns1.example.com", "ns2.example.com"],
        )
        monkeypatch.setattr(
            "skills.recon.dns_zone_transfer._ns_ip",
            lambda ns: {"ns1.example.com": "10.0.0.1",
                        "ns2.example.com": "10.0.0.2"}.get(ns),
        )

        def _fake_axfr(ns_ip, domain):
            if ns_ip == "10.0.0.1":
                return True, ["www", "api", "mail", "internal-host"]
            return False, []

        monkeypatch.setattr(
            "skills.recon.dns_zone_transfer._try_axfr", _fake_axfr)

        result = skill.run(_ctx())
        assert result.success is True
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.scanner_template_id == "zone-transfer-enabled"
        assert f.severity == "critical"
        assert f.host == "example.com"
        assert f.raw["record_count"] == 4
        assert f.raw["nameserver"] == "ns1.example.com"
        assert "www" in f.raw["sample_records"]
        assert result.context_updates["osint"]["records"] == [
            "www", "api", "mail", "internal-host"]

    def test_refused_transfers_emit_no_finding(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.dns_zone_transfer._ns_for",
            lambda d: ["ns1.example.com"],
        )
        monkeypatch.setattr(
            "skills.recon.dns_zone_transfer._ns_ip",
            lambda ns: "10.0.0.1",
        )
        monkeypatch.setattr(
            "skills.recon.dns_zone_transfer._try_axfr",
            lambda ns_ip, domain: (False, []),
        )

        result = skill.run(_ctx())
        assert result.success is True
        assert result.findings == []

    def test_unresolvable_nameserver_skipped(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.dns_zone_transfer._ns_for",
            lambda d: ["ns-bogus.invalid"],
        )
        monkeypatch.setattr(
            "skills.recon.dns_zone_transfer._ns_ip",
            lambda ns: None,
        )

        result = skill.run(_ctx())
        assert result.success is True
        assert result.findings == []
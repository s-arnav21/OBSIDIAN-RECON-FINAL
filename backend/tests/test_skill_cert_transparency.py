"""Tests for the cert-transparency skill (SKILL-R04)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.recon.cert_transparency import (
    CertTransparencySkill,
    _extract_host,
    _is_internal,
    _is_ip,
    _parse_sans,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return CertTransparencySkill()


def _ctx(host="example.com", target_url=None):
    return SkillContext(
        target_url=target_url or f"https://{host}",
        host=host,
    )


def _certs(*names):
    return [{"name_value": "\n".join(names)}]


class TestHelpers:
    def test_is_ip_v4(self):
        assert _is_ip("192.168.56.101") is True

    def test_is_ip_hostname(self):
        assert _is_ip("example.com") is False

    def test_extract_host(self):
        assert _extract_host(_ctx(host="Example.COM")) == "example.com"
        assert _extract_host(SkillContext(target_url="https://alt.example", host="")) == "alt.example"

    def test_is_internal_heuristics(self):
        assert _is_internal("staging.example.com") is True
        assert _is_internal("10.0.0.5") is True
        assert _is_internal("192.168.1.1") is True
        assert _is_internal("mail.internal.corp") is True
        assert _is_internal("www.example.com") is False
        assert _is_internal("8.8.8.8") is False

    def test_parse_sans_filters_wildcards_and_ips(self):
        certs = _certs(
            "www.example.com",
            "*.example.com",
            "example.com",
            "api.example.com",
            "10.0.0.9",
            "8.8.8.8",
        )
        subs, ips = _parse_sans(certs, "example.com")
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "*.example.com" not in subs
        assert "example.com" not in subs
        assert subs == sorted(subs)
        assert set(ips) == {"8.8.8.8", "10.0.0.9"}

    def test_parse_sans_ignores_unrelated_domains(self):
        subs, _ = _parse_sans(_certs("other.org", "evil.net"), "example.com")
        assert subs == []

    def test_parse_sans_non_dict_rows_ignored(self):
        subs, ips = _parse_sans(["bogus", {"name_value": ""}], "example.com")
        assert subs == [] and ips == []


class TestSkillMetadata:
    def test_registered_by_name(self):
        from skills import get_skill
        assert get_skill("cert-transparency").name == "cert-transparency"

    def test_category(self, skill):
        assert skill.category == SkillCategory.RECON

    def test_trigger_conditions_empty(self, skill):
        assert skill.requires_all == []
        assert skill.requires_any == []

    def test_describe(self, skill):
        d = skill.describe()
        assert d["name"] == "cert-transparency"
        assert d["category"] == "recon"
        assert d["description"]


class TestShouldRun:
    def test_hostname_runs(self, skill):
        assert skill.should_run(_ctx(host="example.com")) is True

    def test_ip_skipped(self, skill):
        assert skill.should_run(_ctx(host="192.168.56.101")) is False

    def test_empty_host_skipped(self, skill):
        assert skill.should_run(_ctx(host="", target_url="")) is False


class TestRun:
    def test_ip_host_returns_no_findings(self, skill):
        result = skill.run(_ctx(host="10.0.0.1"))
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["osint"]["crt_skipped"] is True

    def test_api_failure_no_findings(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.cert_transparency._cert_names", lambda d: [])
        result = skill.run(_ctx())
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["subdomains"] == []

    def test_sans_merged_and_context_updates(self, skill, monkeypatch):
        certs = _certs("www.example.com", "api.example.com", "8.8.8.8")
        monkeypatch.setattr(
            "skills.recon.cert_transparency._cert_names", lambda d: certs)
        result = skill.run(_ctx())
        assert result.findings == []
        assert result.context_updates["subdomains"] == [
            "api.example.com", "www.example.com"]
        assert result.context_updates["osint"]["cert_ip_sans"] == ["8.8.8.8"]

    def test_already_known_subdomains_not_duplicated(self, skill, monkeypatch):
        certs = _certs("www.example.com", "api.example.com")
        monkeypatch.setattr(
            "skills.recon.cert_transparency._cert_names", lambda d: certs)
        result = skill.run(SkillContext(
            target_url="https://example.com", host="example.com",
            subdomains=["www.example.com"]))
        assert result.context_updates["subdomains"] == ["api.example.com"]

    def test_internal_san_emits_medium(self, skill, monkeypatch):
        certs = _certs("www.example.com", "staging.example.com", "10.0.0.5")
        monkeypatch.setattr(
            "skills.recon.cert_transparency._cert_names", lambda d: certs)
        result = skill.run(_ctx())
        ids = [f.scanner_template_id for f in result.findings]
        assert ids == ["internal-host-in-cert"]
        assert result.findings[0].severity == "medium"
        assert result.findings[0].raw["san_name"] == "staging.example.com"

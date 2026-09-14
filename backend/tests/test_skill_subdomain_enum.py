"""Tests for the subdomain-enum skill (SKILL-R07)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.recon.subdomain_enum import (
    SubdomainEnumSkill,
    _extract_host,
    _is_ip,
    _parse_title,
    _probe_tech,
    _registrable,
    _under_domain,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return SubdomainEnumSkill()


def _ctx(host="example.com", target_url=None):
    return SkillContext(
        target_url=target_url or f"https://{host}",
        host=host,
    )


def _live(hostname, status=200, title="X"):
    return (hostname, {"ip": "1.2.3.4", "status": status,
                       "title": title, "tech": ["nginx"]})


class TestHelpers:
    def test_is_ip_v4(self):
        assert _is_ip("192.168.56.101") is True

    def test_is_ip_hostname(self):
        assert _is_ip("example.com") is False

    def test_extract_host(self):
        assert _extract_host(_ctx(host="Example.COM")) == "example.com"
        assert _extract_host(SkillContext(target_url="https://alt.example", host="")) == "alt.example"

    def test_registrable(self):
        assert _registrable("example.com") == "example.com"
        assert _registrable("a.b.example.com") == "example.com"
        assert _registrable("co.uk") == "co.uk"
        assert _registrable("portal.svkm.ac.in") == "svkm.ac.in"
        assert _registrable("bvicam.ac.in") == "bvicam.ac.in"

    def test_under_domain(self):
        assert _under_domain("www.example.com", "example.com") is True
        assert _under_domain("example.com", "example.com") is True
        assert _under_domain("evilexample.com", "example.com") is False
        assert _under_domain("portal.svkm.ac.in", "svkm.ac.in") is True
        assert _under_domain("abie.ac.in", "svkm.ac.in") is False

    def test_parse_title(self):
        assert _parse_title("<html><title>  Hello   World </title></html>") == "Hello World"
        assert _parse_title("<b>no title</b>") == ""

    def test_probe_tech(self):
        headers = {"Server": "nginx/1.18", "Set-Cookie": "PHPSESSID=abc"}
        tech = _probe_tech(headers)
        assert "nginx" in tech
        assert "phpsessid" in tech


class TestSkillMetadata:
    def test_registered_by_name(self):
        from skills import get_skill
        assert get_skill("subdomain-enum").name == "subdomain-enum"

    def test_category(self, skill):
        assert skill.category == SkillCategory.RECON

    def test_trigger_conditions_empty(self, skill):
        assert skill.requires_all == []
        assert skill.requires_any == []

    def test_describe(self, skill):
        d = skill.describe()
        assert d["name"] == "subdomain-enum"
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
        assert result.context_updates["osint"]["subdomain_enum_skipped"] is True

    def test_no_candidates_no_findings(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.subdomain_enum._collect_candidates", lambda r: [])
        monkeypatch.setattr(
            "skills.recon.subdomain_enum._probe_live", lambda h: [])
        result = skill.run(_ctx())
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["subdomains"] == []

    def test_live_subdomain_emits_info_and_context(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.subdomain_enum._collect_candidates",
            lambda r: ["www.example.com", "api.example.com"])
        monkeypatch.setattr(
            "skills.recon.subdomain_enum._probe_live",
            lambda h: [_live("www.example.com"), _live("api.example.com", status=301)])
        result = skill.run(_ctx())
        assert len(result.findings) == 2
        f = result.findings[0]
        assert f.scanner_template_id == "live-subdomain"
        assert f.severity == "info"
        assert f.host == "www.example.com"
        assert f.raw["status"] == 200
        assert result.context_updates["subdomains"] == [
            "www.example.com", "api.example.com"]
        assert result.context_updates["osint"]["subdomain_count"] == 2

    def test_known_subdomains_not_duplicated(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.subdomain_enum._collect_candidates",
            lambda r: ["www.example.com"])
        monkeypatch.setattr(
            "skills.recon.subdomain_enum._probe_live",
            lambda h: [_live("www.example.com")])
        result = skill.run(SkillContext(
            target_url="https://example.com", host="example.com",
            subdomains=["www.example.com"]))
        assert result.context_updates["subdomains"] == []

    def test_dead_candidates_excluded_from_context(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.subdomain_enum._collect_candidates",
            lambda r: ["live.example.com", "dead.example.com"])
        monkeypatch.setattr(
            "skills.recon.subdomain_enum._probe_live",
            lambda h: [_live("live.example.com")])
        result = skill.run(_ctx())
        assert result.context_updates["subdomains"] == ["live.example.com"]
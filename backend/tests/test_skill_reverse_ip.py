"""Tests for the reverse-ip skill (SKILL-R05)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.recon.reverse_ip import (
    ReverseIpSkill,
    _extract_host,
    _is_ip,
    _parse_response,
    _resolve_ip,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return ReverseIpSkill()


def _ctx(host="example.com", target_url=None):
    return SkillContext(
        target_url=target_url or f"https://{host}",
        host=host,
    )


def _text_hosts(*hosts):
    return list(hosts)


class TestHelpers:
    def test_is_ip_v4(self):
        assert _is_ip("192.168.56.101") is True

    def test_is_ip_hostname(self):
        assert _is_ip("example.com") is False

    def test_extract_host(self):
        assert _extract_host(_ctx(host="Example.COM")) == "example.com"
        assert _extract_host(SkillContext(target_url="https://alt.example", host="")) == "alt.example"

    def test_resolve_ip_localhost(self):
        assert _resolve_ip("localhost") == "127.0.0.1"

    def test_parse_response_lines(self):
        text = "A.com\n  b.org \nExample.com\n"
        assert _parse_response(text) == ["a.com", "b.org", "example.com"]

    def test_parse_response_empty(self):
        assert _parse_response("") == []

    def test_parse_response_error(self):
        assert _parse_response("error API count exceeded\n") == []


class TestSkillMetadata:
    def test_registered_by_name(self):
        from skills import get_skill
        assert get_skill("reverse-ip").name == "reverse-ip"

    def test_category(self, skill):
        assert skill.category == SkillCategory.RECON

    def test_trigger_conditions_empty(self, skill):
        assert skill.requires_all == []
        assert skill.requires_any == []

    def test_describe(self, skill):
        d = skill.describe()
        assert d["name"] == "reverse-ip"
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
        assert result.context_updates["osint"]["reverse_ip_skipped"] is True

    def test_unresolvable_host_no_findings(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.reverse_ip._resolve_ip", lambda h: None)
        monkeypatch.setattr(
            "skills.recon.reverse_ip._query_hosts", lambda h: [])
        result = skill.run(_ctx())
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["osint"]["neighbors"] == []

    def test_shared_hosting_emits_info(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.reverse_ip._resolve_ip", lambda h: "1.2.3.4")
        monkeypatch.setattr(
            "skills.recon.reverse_ip._query_hosts",
            lambda h: ["a.com", "b.org", "example.com"])
        result = skill.run(_ctx())
        ids = [f.scanner_template_id for f in result.findings]
        assert ids == ["shared-hosting-detected"]
        f = result.findings[0]
        assert f.severity == "info"
        assert f.raw["neighbor_count"] == 2
        assert "a.com" in f.raw["neighbors"]
        assert result.context_updates["osint"]["neighbors"] == ["a.com", "b.org"]

    def test_single_neighbor_no_finding(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.reverse_ip._resolve_ip", lambda h: "1.2.3.4")
        monkeypatch.setattr(
            "skills.recon.reverse_ip._query_hosts",
            lambda h: ["a.com"])
        result = skill.run(_ctx())
        assert result.findings == []
        assert result.context_updates["osint"]["neighbors"] == ["a.com"]

    def test_no_neighbors_no_finding(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.reverse_ip._resolve_ip", lambda h: "1.2.3.4")
        monkeypatch.setattr(
            "skills.recon.reverse_ip._query_hosts", lambda h: [])
        result = skill.run(_ctx())
        assert result.findings == []

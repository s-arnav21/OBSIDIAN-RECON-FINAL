"""Tests for the origin-hunt skill (SKILL-R09)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.recon.origin_hunt import (
    OriginHuntSkill,
    _extract_host,
    _is_ip,
    _is_routable,
    _public_ip,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return OriginHuntSkill()


def _ctx(host="example.com", waf=False, provider=None, scheme="https"):
    return SkillContext(
        target_url=f"{scheme}://{host}", host=host,
        waf_detected=waf, waf_provider=provider,
        scheme=scheme)


class TestHelpers:
    def test_is_ip_v4(self):
        assert _is_ip("192.168.56.101") is True

    def test_is_ip_hostname(self):
        assert _is_ip("example.com") is False

    def test_extract_host(self):
        assert _extract_host(_ctx(host="Example.COM")) == "example.com"
        assert _extract_host(SkillContext(target_url="https://alt.example", host="")) == "alt.example"

    def test_is_routable(self):
        assert _is_routable("8.8.8.8") is True
        assert _is_routable("10.0.0.1") is False
        assert _is_routable("192.168.1.1") is False
        assert _is_routable("172.16.0.1") is False
        assert _is_routable("127.0.0.1") is False
        assert _is_routable("224.0.0.1") is False

    def test_public_ip(self):
        assert _public_ip("localhost") is None
        assert _public_ip("this-host-does-not-exist.invalid") is None


class TestSkillMetadata:
    def test_registered_by_name(self):
        from skills import get_skill
        assert get_skill("origin-hunt").name == "origin-hunt"

    def test_category(self, skill):
        assert skill.category == SkillCategory.RECON

    def test_requires_any_waf(self, skill):
        assert skill.requires_all == []
        assert skill.requires_any == ["waf_detected"]

    def test_describe(self, skill):
        d = skill.describe()
        assert d["name"] == "origin-hunt"
        assert d["category"] == "recon"
        assert d["description"]


class TestShouldRun:
    def test_runs_when_waf_detected(self, skill):
        assert skill.should_run(_ctx(waf=True, provider="Cloudflare")) is True

    def test_skipped_no_waf(self, skill):
        assert skill.should_run(_ctx()) is False

    def test_skipped_empty_host(self, skill):
        assert skill.should_run(SkillContext(target_url="", host="",
                                             waf_detected=True)) is False


class TestRun:
    def test_no_waf_returns_skipped(self, skill, monkeypatch):
        result = skill.run(_ctx())
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["osint"]["origin_hunt_skipped"] is True

    def test_no_candidates_no_findings(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.origin_hunt._candidate_ips_from_spf", lambda h: set())
        monkeypatch.setattr(
            "skills.recon.origin_hunt._candidate_ips_from_ct", lambda h: set())
        monkeypatch.setattr(
            "skills.recon.origin_hunt._candidate_ips_from_history", lambda h: set())
        monkeypatch.setattr(
            "skills.recon.origin_hunt._fingerprint",
            lambda u: {"title": "T", "sha": "abc", "length": 1})
        result = skill.run(_ctx(waf=True, provider="Cloudflare"))
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["osint"]["origin_candidates"] == []
        assert result.context_updates["osint"]["origin_ip"] == []

    def test_unreachable_public_no_findings(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.origin_hunt._candidate_ips_from_spf",
            lambda h: {"1.2.3.4"})
        monkeypatch.setattr(
            "skills.recon.origin_hunt._candidate_ips_from_ct", lambda h: set())
        monkeypatch.setattr(
            "skills.recon.origin_hunt._candidate_ips_from_history", lambda h: set())
        monkeypatch.setattr(
            "skills.recon.origin_hunt._fingerprint", lambda u: None)
        result = skill.run(_ctx(waf=True, provider="Cloudflare"))
        assert result.findings == []

    def test_fingerprint_match_emits_high(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.origin_hunt._candidate_ips_from_spf",
            lambda h: {"1.2.3.4"})
        monkeypatch.setattr(
            "skills.recon.origin_hunt._candidate_ips_from_ct", lambda h: set())
        monkeypatch.setattr(
            "skills.recon.origin_hunt._candidate_ips_from_history",
            lambda h: {"5.6.7.8"})

        def _fp(url):
            return {"title": "Same", "sha": "deadbeef", "length": 100} \
                if url == "https://example.com" or "1.2.3.4" in url else None

        monkeypatch.setattr(
            "skills.recon.origin_hunt._fingerprint", _fp)
        result = skill.run(_ctx(waf=True, provider="Cloudflare"))
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.scanner_template_id == "origin-ip-exposed"
        assert f.severity == "high"
        assert f.raw["origin_ip"] == "1.2.3.4"
        assert f.raw["provider"] == "Cloudflare"
        assert result.context_updates["osint"]["origin_ip"] == ["1.2.3.4"]

    def test_nonmatching_ip_no_finding(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.origin_hunt._candidate_ips_from_spf",
            lambda h: {"1.2.3.4"})
        monkeypatch.setattr(
            "skills.recon.origin_hunt._candidate_ips_from_ct", lambda h: set())
        monkeypatch.setattr(
            "skills.recon.origin_hunt._candidate_ips_from_history", lambda h: set())

        def _fp(url):
            if url == "https://example.com":
                return {"title": "A", "sha": "aaaa", "length": 1}
            return {"title": "B", "sha": "bbbb", "length": 2}

        monkeypatch.setattr(
            "skills.recon.origin_hunt._fingerprint", _fp)
        result = skill.run(_ctx(waf=True, provider="Cloudflare"))
        assert result.findings == []
        assert result.context_updates["osint"]["origin_ip"] == []
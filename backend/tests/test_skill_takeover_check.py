"""Tests for the takeover-check skill (SKILL-R08)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.recon.takeover_check import (
    TakeoverCheckSkill,
    _extract_host,
    _is_ip,
    _matches_signature,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return TakeoverCheckSkill()


def _ctx(host="example.com", subdomains=None):
    return SkillContext(
        target_url=f"https://{host}", host=host,
        subdomains=subdomains or [])


class TestHelpers:
    def test_is_ip_v4(self):
        assert _is_ip("192.168.56.101") is True

    def test_is_ip_hostname(self):
        assert _is_ip("example.com") is False

    def test_extract_host(self):
        assert _extract_host(_ctx(host="Example.COM")) == "example.com"
        assert _extract_host(SkillContext(target_url="https://alt.example", host="")) == "alt.example"

    def test_signature_matches(self):
        assert _matches_signature("myrepo.github.io") == "github.io"
        assert _matches_signature("bucket.s3.amazonaws.com") == "s3.amazonaws.com"
        assert _matches_signature("app.herokuapp.com") == "herokuapp.com"
        assert _matches_signature("unrelated.cdn.com") is None


class TestSkillMetadata:
    def test_registered_by_name(self):
        from skills import get_skill
        assert get_skill("takeover-check").name == "takeover-check"

    def test_category(self, skill):
        assert skill.category == SkillCategory.RECON

    def test_requires_any(self, skill):
        assert skill.requires_all == []
        assert skill.requires_any == ["subdomain_found"]

    def test_describe(self, skill):
        d = skill.describe()
        assert d["name"] == "takeover-check"
        assert d["category"] == "recon"
        assert d["description"]


class TestShouldRun:
    def test_runs_when_subdomains_exist(self, skill):
        assert skill.should_run(_ctx(subdomains=["www.example.com"])) is True

    def test_skipped_when_no_subdomains(self, skill):
        assert skill.should_run(_ctx(subdomains=[])) is False

    def test_skipped_empty_host(self, skill):
        assert skill.should_run(SkillContext(target_url="", host="",
                                             subdomains=["www.example.com"])) is False


class TestRun:
    def test_no_subdomains_no_findings(self, skill):
        result = skill.run(_ctx(subdomains=[]))
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["osint"]["takeover_checked"] == 0

    def test_no_cname_no_findings(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.takeover_check._cname_target", lambda s: None)
        result = skill.run(_ctx(subdomains=["www.example.com"]))
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["osint"]["takeover_checked"] == 0

    def test_dangling_sig_emits_high(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.takeover_check._cname_target",
            lambda s: "release-2020.github.io")
        monkeypatch.setattr(
            "skills.recon.takeover_check._resolves", lambda c: False)
        result = skill.run(_ctx(subdomains=["www.example.com"]))
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.scanner_template_id == "subdomain-takeover-possible"
        assert f.severity == "high"
        assert f.raw["signature"] == "github.io"
        assert f.host == "www.example.com"

    def test_resolving_sig_no_finding(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.takeover_check._cname_target",
            lambda s: "live-app.herokuapp.com")
        monkeypatch.setattr(
            "skills.recon.takeover_check._resolves", lambda c: True)
        result = skill.run(_ctx(subdomains=["app.example.com"]))
        assert result.findings == []
        assert result.context_updates["osint"]["takeover_cnames"] == [{
            "subdomain": "app.example.com",
            "cname": "live-app.herokuapp.com",
            "signature": "herokuapp.com",
        }]

    def test_non_signature_cname_no_finding(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.takeover_check._cname_target",
            lambda s: "target.example.com")
        monkeypatch.setattr(
            "skills.recon.takeover_check._resolves", lambda c: False)
        result = skill.run(_ctx(subdomains=["www.example.com"]))
        assert result.findings == []

    def test_only_first_confirmed_emitted(self, skill, monkeypatch):
        cnames = {
            "a.example.com": "gone.s3.amazonaws.com",
            "b.example.com": "gone2.github.io",
        }
        monkeypatch.setattr(
            "skills.recon.takeover_check._cname_target",
            lambda s: cnames.get(s))
        monkeypatch.setattr(
            "skills.recon.takeover_check._resolves", lambda c: False)
        result = skill.run(_ctx(subdomains=["a.example.com", "b.example.com"]))
        assert len(result.findings) == 1
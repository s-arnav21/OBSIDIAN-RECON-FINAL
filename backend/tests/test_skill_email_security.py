"""Tests for the email-security skill (SKILL-R02)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.recon.email_security import (
    EmailSecuritySkill,
    _extract_host,
    _is_ip,
    _spf_quality,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return EmailSecuritySkill()


def _ctx(host="example.com", target_url=None):
    return SkillContext(
        target_url=target_url or f"https://{host}",
        host=host,
    )


class TestHelpers:
    def test_is_ip_v4(self):
        assert _is_ip("192.168.56.101") is True

    def test_is_ip_hostname(self):
        assert _is_ip("example.com") is False

    def test_extract_host(self):
        assert _extract_host(_ctx(host="Example.COM")) == "example.com"
        assert _extract_host(SkillContext(target_url="https://alt.example", host="")) == "alt.example"

    def test_spf_quality_missing(self):
        assert _spf_quality("") == "missing"

    def test_spf_quality_hardfail_ok(self):
        assert _spf_quality("v=spf1 ip4:1.2.3.4 -all") == "ok"

    def test_spf_quality_softfail_permissive(self):
        assert _spf_quality("v=spf1 ip4:1.2.3.4 ~all") == "permissive"

    def test_spf_quality_neutral_permissive(self):
        assert _spf_quality("v=spf1 ?all") == "permissive"


class TestSkillMetadata:
    def test_registered_by_name(self):
        from skills import get_skill
        assert get_skill("email-security").name == "email-security"

    def test_category(self, skill):
        assert skill.category == SkillCategory.RECON

    def test_trigger_conditions_empty(self, skill):
        assert skill.requires_all == []
        assert skill.requires_any == []

    def test_describe(self, skill):
        d = skill.describe()
        assert d["name"] == "email-security"
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
    def test_no_records_emits_spf_missing(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.email_security._txt_record", lambda d: "")
        monkeypatch.setattr(
            "skills.recon.email_security._dmarc_record", lambda d: "")
        monkeypatch.setattr(
            "skills.recon.email_security._dkim_signers", lambda d: [])

        result = skill.run(_ctx())
        assert result.success is True
        ids = [f.scanner_template_id for f in result.findings]
        assert ids == ["spf-missing"]
        assert result.findings[0].severity == "medium"
        assert result.context_updates["osint"]["spf"] == ""

    def test_permissive_spf_emits_high(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.email_security._txt_record",
            lambda d: "v=spf1 ip4:1.2.3.4 ~all")
        monkeypatch.setattr(
            "skills.recon.email_security._dmarc_record", lambda d: "")
        monkeypatch.setattr(
            "skills.recon.email_security._dkim_signers", lambda d: [])

        result = skill.run(_ctx())
        ids = [f.scanner_template_id for f in result.findings]
        assert ids == ["spf-permissive"]
        assert result.findings[0].severity == "high"

    def test_dmarc_none_emits_low(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.email_security._txt_record",
            lambda d: "v=spf1 -all")
        monkeypatch.setattr(
            "skills.recon.email_security._dmarc_record",
            lambda d: "v=DMARC1; p=none; rua=mailto:dmarc@example.com")
        monkeypatch.setattr(
            "skills.recon.email_security._dkim_signers", lambda d: [])

        result = skill.run(_ctx())
        ids = [f.scanner_template_id for f in result.findings]
        assert ids == ["dmarc-policy-none"]
        assert result.findings[0].severity == "low"

    def test_secure_setup_emits_nothing(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.email_security._txt_record",
            lambda d: "v=spf1 ip4:1.2.3.4 -all")
        monkeypatch.setattr(
            "skills.recon.email_security._dmarc_record",
            lambda d: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
        monkeypatch.setattr(
            "skills.recon.email_security._dkim_signers", lambda d: ["default"])

        result = skill.run(_ctx())
        assert result.findings == []
        assert result.context_updates["osint"]["dkim_selectors"] == ["default"]

    def test_ip_host_returns_no_findings(self, skill):
        result = skill.run(_ctx(host="10.0.0.1"))
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["osint"]["email_security_skipped"] is True

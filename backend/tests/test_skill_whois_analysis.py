"""Tests for the whois-analysis skill (SKILL-R03)."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.recon.whois_analysis import (
    WhoisAnalysisSkill,
    _days_since,
    _days_until,
    _extract_host,
    _first_dt,
    _is_ip,
    _is_privacy,
)

NOW = datetime.now(timezone.utc)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return WhoisAnalysisSkill()


def _ctx(host="example.com", target_url=None):
    return SkillContext(
        target_url=target_url or f"https://{host}",
        host=host,
    )


def _simple_whois(**overrides):
    data = {
        "registrar": "Some Registrar",
        "creation_date": NOW - timedelta(days=1000),
        "expiration_date": NOW + timedelta(days=365),
        "name_servers": ["ns1.example.com"],
        "status": ["clientTransferProhibited"],
    }
    data.update(overrides)
    return data


class TestHelpers:
    def test_is_ip_v4(self):
        assert _is_ip("192.168.56.101") is True

    def test_is_ip_hostname(self):
        assert _is_ip("example.com") is False

    def test_extract_host(self):
        assert _extract_host(_ctx(host="Example.COM")) == "example.com"
        assert _extract_host(SkillContext(target_url="https://alt.example", host="")) == "alt.example"

    def test_first_dt_variants(self):
        dt = datetime(2020, 1, 2, 3, 4)
        naive = _first_dt(dt)
        assert naive.tzinfo is not None
        assert _first_dt([dt, dt]).year == 2020
        assert _first_dt("2021-05-06") is not None
        assert _first_dt(None) is None
        assert _first_dt("bogus") is None

    def test_days_until_and_since(self):
        assert _days_until(NOW + timedelta(days=5), now=NOW) == 5
        assert _days_since(NOW - timedelta(days=5), now=NOW) == 5

    def test_privacy_detection_plain(self):
        assert _is_privacy(_simple_whois()) is False

    def test_privacy_detection_marker(self):
        assert _is_privacy(_simple_whois(registrar="Domains By Proxy LLC")) is True
        assert _is_privacy(_simple_whois(org="Whois Privacy Service")) is True


class TestSkillMetadata:
    def test_registered_by_name(self):
        from skills import get_skill
        assert get_skill("whois-analysis").name == "whois-analysis"

    def test_category(self, skill):
        assert skill.category == SkillCategory.RECON

    def test_trigger_conditions_empty(self, skill):
        assert skill.requires_all == []
        assert skill.requires_any == []

    def test_describe(self, skill):
        d = skill.describe()
        assert d["name"] == "whois-analysis"
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
        assert result.context_updates["osint"]["whois_skipped"] is True

    def test_lookup_failure_no_findings(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.whois_analysis._whois_lookup", lambda h: None)
        result = skill.run(_ctx())
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["osint"]["whois"] is None

    def test_expiring_emits_high(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.whois_analysis._whois_lookup",
            lambda h: _simple_whois(
                expiration_date=NOW + timedelta(days=10)))
        result = skill.run(_ctx())
        ids = [f.scanner_template_id for f in result.findings]
        assert ids == ["domain-expiring-critical"]
        assert result.findings[0].severity == "high"

    def test_newly_registered_emits_medium(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.whois_analysis._whois_lookup",
            lambda h: _simple_whois(
                creation_date=NOW - timedelta(days=30)))
        result = skill.run(_ctx())
        ids = [f.scanner_template_id for f in result.findings]
        assert ids == ["newly-registered"]
        assert result.findings[0].severity == "medium"

    def test_healthy_domain_no_findings(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.whois_analysis._whois_lookup",
            lambda h: _simple_whois())
        result = skill.run(_ctx())
        assert result.findings == []
        assert result.context_updates["osint"]["whois"]["registrar"] == "Some Registrar"

    def test_both_flags_emit_two_findings(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.whois_analysis._whois_lookup",
            lambda h: _simple_whois(
                creation_date=NOW - timedelta(days=20),
                expiration_date=NOW + timedelta(days=5)))
        result = skill.run(_ctx())
        ids = [f.scanner_template_id for f in result.findings]
        assert ids == ["domain-expiring-critical", "newly-registered"]

    def test_missing_dates_no_crash(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.whois_analysis._whois_lookup",
            lambda h: _simple_whois(creation_date=None, expiration_date=None))
        result = skill.run(_ctx())
        assert result.findings == []
        assert result.success is True

"""Tests for the wayback-harvest skill (SKILL-R06)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.recon.wayback_harvest import (
    WaybackHarvestSkill,
    _extract_host,
    _is_ip,
    _parse_urls,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return WaybackHarvestSkill()


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

    def test_parse_urls_extracts_subdomains_and_paths(self):
        urls = [
            "https://example.com/",
            "https://www.example.com/about",
            "https://api.example.com/v1/users?id=5",
            "https://other.org/x",  # unrelated host -> ignored
        ]
        subs, paths, sensitive, _ = _parse_urls(urls, "example.com")
        assert subs == ["api.example.com", "www.example.com"]
        assert "/" in paths
        assert "/about" in paths
        assert "/v1/users?id=5" in paths
        assert sensitive == []

    def test_parse_urls_flags_sensitive_paths(self):
        urls = [
            "https://example.com/",
            "https://example.com/.env",
            "https://example.com/wp-config.php",
            "https://example.com/backup/db.sql",
        ]
        subs, paths, sensitive, _ = _parse_urls(urls, "example.com")
        assert sensitive, "expected a sensitive hit"
        assert any(".env" in s for s in sensitive)
        assert any("db.sql" in s for s in sensitive)

    def test_parse_urls_caps_sensitive(self):
        urls = [f"https://example.com/{i}/.env" for i in range(10)]
        _, _, sensitive, _ = _parse_urls(urls, "example.com")
        assert len(sensitive) == 5

    def test_parse_urls_dedupes_paths(self):
        urls = ["https://example.com/a", "https://example.com/a",
                "http://example.com/a"]
        _, paths, _, _ = _parse_urls(urls, "example.com")
        assert paths.count("/a") == 1

    def test_parse_urls_extracts_query_params(self):
        urls = [
            "https://example.com/search?q=hello&page=2",
            "https://example.com/items?id=4",
            "https://example.com/static/noquery.html",
        ]
        _, _, _, params = _parse_urls(urls, "example.com")
        names = [c["param"] for c in params]
        assert "q" in names and "page" in names and "id" in names
        assert all(c["trigger"] == "wayback_param" for c in params)
        # the search URL carries both q and page
        search = next(c for c in params if c["param"] == "q")
        assert "?q=hello&page=2" in search["url"]


class TestSkillMetadata:
    def test_registered_by_name(self):
        from skills import get_skill
        assert get_skill("wayback-harvest").name == "wayback-harvest"

    def test_category(self, skill):
        assert skill.category == SkillCategory.RECON

    def test_trigger_conditions_empty(self, skill):
        assert skill.requires_all == []
        assert skill.requires_any == []

    def test_describe(self, skill):
        d = skill.describe()
        assert d["name"] == "wayback-harvest"
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
        assert result.context_updates["osint"]["wayback_skipped"] is True

    def test_empty_cdx_no_findings(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.wayback_harvest._fetch_cdx", lambda h: [])
        result = skill.run(_ctx())
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["subdomains"] == []
        assert result.context_updates["discovered_paths"] == []

    def test_harvest_merges_context(self, skill, monkeypatch):
        urls = [
            "https://example.com/home",
            "https://www.example.com/api/v1?id=1",
        ]
        monkeypatch.setattr(
            "skills.recon.wayback_harvest._fetch_cdx", lambda h: urls)
        result = skill.run(_ctx())
        assert result.findings == []
        assert result.context_updates["subdomains"] == ["www.example.com"]
        assert "/home" in result.context_updates["discovered_paths"]
        assert "/api/v1?id=1" in result.context_updates["discovered_paths"]

    def test_known_context_not_duplicated(self, skill, monkeypatch):
        urls = ["https://example.com/env", "https://www.example.com/x"]
        monkeypatch.setattr(
            "skills.recon.wayback_harvest._fetch_cdx", lambda h: urls)
        result = skill.run(SkillContext(
            target_url="https://example.com", host="example.com",
            discovered_paths=["/env"], subdomains=["www.example.com"]))
        assert "www.example.com" not in result.context_updates["subdomains"]
        assert "/env" not in result.context_updates["discovered_paths"]
        assert "/x" in result.context_updates["discovered_paths"]

    def test_sensitive_path_emits_low(self, skill, monkeypatch):
        urls = ["https://example.com/.env"]
        monkeypatch.setattr(
            "skills.recon.wayback_harvest._fetch_cdx", lambda h: urls)
        result = skill.run(_ctx())
        ids = [f.scanner_template_id for f in result.findings]
        assert ids == ["historical-sensitive-path"]
        assert result.findings[0].severity == "low"
        assert ".env" in result.findings[0].raw["url"]

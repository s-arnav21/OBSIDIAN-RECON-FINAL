"""Tests for the tech-fingerprint skill (SKILL-R10)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.recon.tech_fingerprint import (
    TechFingerprintSkill,
    _cookie_names,
    _detect_from_cookies,
    _detect_technologies,
    _error_page_detect,
    _extract_host,
    _favicon_urls,
    _is_ip,
    _meta_generator,
    _robots_detect,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return TechFingerprintSkill()


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

    def test_favicon_urls_extracts_and_resolves(self):
        html = '<link rel="shortcut icon" href="/static/fav.png">'
        urls = _favicon_urls(html, "https://example.com")
        assert urls[0] == "https://example.com/static/fav.png"
        urls = _favicon_urls("<html></html>", "https://example.com")
        assert urls == ["https://example.com/favicon.ico"]

    def test_meta_generator(self):
        html = '<meta name="generator" content="WordPress 6.1">'
        assert _meta_generator(html) == "WordPress 6.1"
        assert _meta_generator("<html></html>") == ""

    def test_cookie_names(self):
        headers = {"server": "nginx", "set-cookie": "PHPSESSID=abc; path=/"}
        assert _cookie_names(headers) == ["phpsessid"]

    def test_detect_from_cookies(self):
        headers = {"set-cookie": "PHPSESSID=x", "server": "nginx"}
        assert "php" in _detect_from_cookies(headers)

    def test_robots_detect(self):
        txt = "User-agent: *\nDisallow: /wp-admin/\nDisallow: /wp-json"
        assert "wordpress" in _robots_detect(txt)
        assert _robots_detect("User-agent: *") == []

    def test_error_page_detect(self):
        assert "asp.net" in _error_page_detect("ASP.NET Version 4.0.30319.1")
        assert "tomcat" in _error_page_detect("Apache Tomcat 9.0")
        assert _error_page_detect("generic 404") == []

    def test_detect_technologies_combines(self):
        headers = {"server": "nginx/1.18", "x-powered-by": "Express"}
        body = '<meta name="generator" content="WordPress">'
        techs = _detect_technologies(headers, body, None, [], [], "")
        names = dict(techs)
        assert "nginx" in names
        assert "express" in names
        assert "wordpress" in names

    def test_detect_technologies_extra_sources(self):
        techs = _detect_technologies(
            {}, "", "django-admin", ["php"], ["wordpress"], ["tomcat"])
        names = dict(techs)
        assert names["django-admin"] == "favicon hash"
        assert names["php"] == "cookie"
        assert names["wordpress"] == "robots.txt"
        assert names["tomcat"] == "error page"


class TestSkillMetadata:
    def test_registered_by_name(self):
        from skills import get_skill
        assert get_skill("tech-fingerprint").name == "tech-fingerprint"

    def test_category(self, skill):
        assert skill.category == SkillCategory.RECON

    def test_trigger_conditions_empty(self, skill):
        assert skill.requires_all == []
        assert skill.requires_any == []

    def test_describe(self, skill):
        d = skill.describe()
        assert d["name"] == "tech-fingerprint"
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
        assert result.context_updates["osint"]["fingerprint_skipped"] is True

    def test_unreachable_page_no_findings(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.tech_fingerprint._fetch", lambda u: None)
        monkeypatch.setattr(
            "skills.recon.tech_fingerprint._favicon_hash", lambda u: None)
        result = skill.run(_ctx())
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["technologies"] == []

    def test_technologies_emitted_and_merged(self, skill, monkeypatch):
        page = ({"server": "nginx", "x-powered-by": "Express"},
                '<html><meta name="generator" content="WordPress"></html>')
        robots = ({}, "")

        def _fetch(url):
            if url.endswith("/robots.txt"):
                return robots
            if "nonexistent" in url:
                return None
            return page

        monkeypatch.setattr(
            "skills.recon.tech_fingerprint._fetch", _fetch)
        monkeypatch.setattr(
            "skills.recon.tech_fingerprint._favicon_hash", lambda u: None)
        result = skill.run(_ctx())
        ids = [f.scanner_template_id for f in result.findings]
        assert ids == ["tech-identified"] * 3
        assert result.findings[0].severity == "info"
        assert result.context_updates["technologies"] == [
            "nginx", "wordpress", "express"]
        assert result.context_updates["osint"]["generator"] == "WordPress"

    def test_favicon_tech_detected(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.tech_fingerprint._fetch",
            lambda u: ({"server": "nginx"}, "<html><body>x</body></html>")
            if "nonexistent" not in u and not u.endswith("/robots.txt")
            else (None if u.endswith("/robots.txt") else None))
        favicon_md5 = "f420dc2c7d90d7873a90d82cd7fde315"
        monkeypatch.setattr(
            "skills.recon.tech_fingerprint._favicon_hash",
            lambda u: favicon_md5)
        result = skill.run(_ctx())
        techs = result.context_updates["technologies"]
        assert "nginx" in techs
        assert "wordpress" in techs
        assert result.context_updates["osint"]["favicon"]["md5"] == favicon_md5

    def test_known_tech_not_duplicated(self, skill, monkeypatch):
        page = ({"server": "nginx"}, "<html></html>")
        monkeypatch.setattr(
            "skills.recon.tech_fingerprint._fetch",
            lambda u: page if not u.endswith("/robots.txt")
            and "nonexistent" not in u else None)
        monkeypatch.setattr(
            "skills.recon.tech_fingerprint._favicon_hash", lambda u: None)
        result = skill.run(SkillContext(
            target_url="https://example.com", host="example.com",
            technologies=["nginx"]))
        assert "nginx" not in result.context_updates["technologies"]
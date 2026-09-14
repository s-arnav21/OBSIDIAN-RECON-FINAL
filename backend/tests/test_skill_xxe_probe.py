"""Tests for the xxe-probe exploit skill (SKILL-E04)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.selector import select_skills
from skills.exploit.xxe_probe import (
    XxeProbeSkill,
    _candidate_endpoints,
    _passwd_leaked,
)

PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return XxeProbeSkill()


def _ctx(host="10.0.0.5", paths=None):
    return SkillContext(target_url=f"http://{host}/", host=host, ip=host,
                        port=80, open_ports=[80], discovered_paths=paths or [])


class TestHelpers:
    def test_passwd_leaked(self):
        assert _passwd_leaked(PASSWD)
        assert not _passwd_leaked("<html>error: entity undeclared</html>")
        assert not _passwd_leaked("")
        assert not _passwd_leaked(None)

    def test_candidate_endpoints(self):
        eps = _candidate_endpoints(_ctx(paths=["/api/v1/", "/graphql"]))
        assert eps[:2] == ["/api/v1/", "/graphql"]
        assert "/api" in eps and "/soap" in eps

    def test_candidate_endpoints_dedupe(self):
        eps = _candidate_endpoints(_ctx(paths=["/api"]))
        assert eps.count("/api") == 1


class TestSkillMetadata:
    def test_identity(self, skill):
        assert skill.name == "xxe-probe"
        assert skill.category == SkillCategory.EXPLOIT

    def test_trigger(self, skill):
        assert skill.requires_any == ["api_found"]


class TestSelector:
    def test_gated_on_api_found(self):
        ctx = SkillContext(target_url="http://10.0.0.5", host="10.0.0.5",
                           open_ports=[80], discovered_paths=["/api/v1"])
        names = {s.name for s in select_skills(ctx, "exploit")}
        assert "xxe-probe" in names

    def test_blocked_without_api(self):
        names = {s.name for s in select_skills(
            SkillContext(target_url="http://10.0.0.5", host="10.0.0.5",
                         open_ports=[80]), "exploit")}
        assert "xxe-probe" not in names


class TestRun:
    def test_run_skips_without_target(self):
        r = XxeProbeSkill().run(SkillContext(target_url="", host=""))
        assert r.success is True and r.findings == []

    def test_run_confirms_xxe(self, monkeypatch):
        import skills.exploit.xxe_probe as xp

        def fake_post(url):
            if "/api" in url:
                return f"<result>{PASSWD}</result>"
            return "<error>cannot parse</error>"

        monkeypatch.setattr(xp, "_post_xml", fake_post)
        r = XxeProbeSkill().run(_ctx(paths=["/api"]))
        ids = {f.scanner_template_id for f in r.findings}
        assert ids == {"xxe-confirmed"}
        f = next(iter(r.findings))
        assert f.severity == "critical"
        assert f.raw["entity"] == "file:///etc/passwd"
        assert r.context_updates["osint"]["xxe_scan"] == "confirmed"

    def test_run_clean(self, monkeypatch):
        import skills.exploit.xxe_probe as xp

        monkeypatch.setattr(xp, "_post_xml",
                            lambda url: "<error>failed to parse entity</error>")
        r = XxeProbeSkill().run(_ctx(paths=["/soap"]))
        assert r.findings == []
        assert r.context_updates["osint"]["xxe_scan"] == "clean"

    def test_run_unreachable(self, monkeypatch):
        import skills.exploit.xxe_probe as xp

        monkeypatch.setattr(xp, "_post_xml", lambda url: None)
        r = XxeProbeSkill().run(_ctx(paths=["/api"]))
        assert r.findings == []
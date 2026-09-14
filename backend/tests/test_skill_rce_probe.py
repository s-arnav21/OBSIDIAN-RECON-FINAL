"""Tests for the rce-probe exploit skill (SKILL-E03)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.selector import select_skills
from skills.exploit.rce_probe import (
    RceProbeSkill,
    _CANARY,
    _ignition_signal,
    _is_phpinfo,
    _is_webshell,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return RceProbeSkill()


def _ctx(host="10.0.0.5"):
    return SkillContext(target_url=f"http://{host}/", host=host, ip=host,
                        port=80, open_ports=[80])


class TestHelpers:
    def test_is_phpinfo(self):
        assert _is_phpinfo("<title>phpinfo()</title>")
        assert _is_phpinfo("<h1>PHP Version 8.1</h1><p>Configuration</p>")
        assert not _is_phpinfo("<html>homepage</html>")

    def test_is_webshell(self):
        assert _is_webshell("http://x/shell.php",
                            "<?php system($_GET['cmd']); ?>")
        assert _is_webshell("http://x/c99.php", "// c99shell by r57")
        assert not _is_webshell("http://x/shell.php", "<p>normal page</p>")

    def test_ignition_signal(self):
        assert _ignition_signal("Malformed or unsupported named solution")
        assert not _ignition_signal("")
        assert not _ignition_signal("<html>ok</html>")


class TestSkillMetadata:
    def test_identity(self, skill):
        assert skill.name == "rce-probe"
        assert skill.category == SkillCategory.EXPLOIT

    def test_trigger(self, skill):
        assert skill.requires_any == ["sql_error_found", "tech_php",
                                      "tech_node", "admin_path_found"]


class TestSelector:
    def test_gated_on_tech_php(self):
        names = {s.name for s in select_skills(
            SkillContext(target_url="http://10.0.0.5", host="10.0.0.5",
                         open_ports=[80], technologies=["PHP 8.1"]), "exploit")}
        assert "rce-probe" in names

    def test_gated_on_sql_error(self):
        from app.models.scanner import RawFinding

        f = RawFinding(scanner="task",
                       scanner_template_id="sqli-error-signal",
                       severity="high", url="http://x/")
        names = {s.name for s in select_skills(
            SkillContext(target_url="http://10.0.0.5", host="10.0.0.5",
                         open_ports=[80], raw_findings=[f]), "exploit")}
        assert "rce-probe" in names

    def test_blocked_otherwise(self):
        names = {s.name for s in select_skills(
            SkillContext(target_url="http://10.0.0.5", host="10.0.0.5",
                         open_ports=[80]), "exploit")}
        assert "rce-probe" not in names


class TestRun:
    def test_run_skips_without_target(self):
        r = RceProbeSkill().run(SkillContext(target_url="", host=""))
        assert r.success is True and r.findings == []

    def test_run_phpunit_canary(self, monkeypatch):
        import skills.exploit.rce_probe as rp

        def fake_post(url, content):
            if "eval-stdin.php" in url:
                return f"<pre>{_CANARY}</pre>"
            return "not found"

        monkeypatch.setattr(rp, "_get", lambda url: "<html>index</html>")
        monkeypatch.setattr(rp, "_post", fake_post)
        r = RceProbeSkill().run(_ctx())
        signals = [f for f in r.findings
                   if f.scanner_template_id == "rce-signal"]
        assert signals and signals[0].raw["kind"] == "phpunit"
        assert signals[0].severity == "critical"
        assert r.context_updates["osint"]["rce_scan"] == "signals"

    def test_run_ignition_signal(self, monkeypatch):
        import skills.exploit.rce_probe as rp

        def fake_post(url, content):
            if "execute-solution" in url:
                return ("Facade\\Ignition\\Exceptions\\UnableToHandle"
                        "Malformed or unsupported named solution")
            return "not found"

        monkeypatch.setattr(rp, "_get", lambda url: "<html>index</html>")
        monkeypatch.setattr(rp, "_post", fake_post)
        r = RceProbeSkill().run(_ctx())
        signals = [f for f in r.findings
                   if f.scanner_template_id == "rce-signal"]
        assert signals and signals[0].raw["kind"] == "ignition"

    def test_run_webshell(self, monkeypatch):
        import skills.exploit.rce_probe as rp

        def fake_get(url):
            if url.endswith("shell.php"):
                return "<?php system($_GET['cmd']); ?>"
            return "<html>index</html>"

        monkeypatch.setattr(rp, "_get", fake_get)
        monkeypatch.setattr(rp, "_post", lambda u, c: "not found")
        r = RceProbeSkill().run(_ctx())
        signals = [f for f in r.findings
                   if f.scanner_template_id == "rce-signal"]
        assert signals and signals[0].raw["kind"] == "webshell"
        assert signals[0].url.endswith("shell.php")

    def test_run_phpinfo_exposure(self, monkeypatch):
        import skills.exploit.rce_probe as rp

        def fake_get(url):
            if url.endswith("phpinfo.php"):
                return "<title>phpinfo()</title>current config</html>"
            return "<html>index</html>"

        monkeypatch.setattr(rp, "_get", fake_get)
        monkeypatch.setattr(rp, "_post", lambda u, c: "not found")
        r = RceProbeSkill().run(_ctx())
        ids = {f.scanner_template_id for f in r.findings}
        assert "phpinfo-exposed" in ids
        f = next(f for f in r.findings
                 if f.scanner_template_id == "phpinfo-exposed")
        assert f.severity == "medium"

    def test_run_clean(self, monkeypatch):
        import skills.exploit.rce_probe as rp

        monkeypatch.setattr(rp, "_get", lambda url: "<html>index</html>")
        monkeypatch.setattr(rp, "_post", lambda u, c: "404 no such file")
        r = RceProbeSkill().run(_ctx())
        assert r.findings == []
        assert r.context_updates["osint"]["rce_scan"] == "clean"

    def test_run_unreachable(self, monkeypatch):
        import skills.exploit.rce_probe as rp

        monkeypatch.setattr(rp, "_get", lambda url: None)
        monkeypatch.setattr(rp, "_post", lambda u, c: None)
        r = RceProbeSkill().run(_ctx())
        assert r.findings == []
"""Tests for the sqli-error exploit skill (SKILL-E01)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.selector import derive_conditions, select_skills
from skills.exploit.sqli_error import (
    SqliErrorSkill,
    _candidate_params,
    _scan_markers,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return SqliErrorSkill()


def _ctx(host="10.0.0.5", target="http://10.0.0.5/", ports=(80,)):
    return SkillContext(target_url=target, host=host, ip=host, port=80,
                        open_ports=list(ports))


class TestHelpers:
    def test_candidate_params_from_query(self):
        params, base = _candidate_params(
            "http://x/items?id=4&cat=toys")
        assert params == {"id": "4", "cat": "toys"}
        assert base == "http://x/items"

    def test_candidate_params_common(self):
        params, base = _candidate_params("https://x/")
        assert "id" in params and "search" in params
        assert base == "https://x/"

    def test_candidate_targets_uses_param_candidates(self):
        from skills.exploit.sqli_error import _candidate_targets

        ctx = SkillContext(target_url="http://10.0.0.5/", host="10.0.0.5",
                           port=80, open_ports=[80],
                           param_candidates=[
                               {"url": "http://10.0.0.5/items?id=4",
                                "param": "id", "injectable": False,
                                "trigger": "wayback_param"},
                               {"url": "http://10.0.0.5/token.asp",
                                "param": None, "injectable": True,
                                "trigger": "500_on_dynamic"},
                           ])
        targets = _candidate_targets(ctx)
        pairs = {(b, tuple(sorted(p))) for b, p in targets}
        assert ("http://10.0.0.5/items", ("id",)) in pairs
        # param-less injectable candidate URL -> common-param fallback
        common = [(b, p) for b, p in targets
                  if b == "http://10.0.0.5/token.asp"]
        assert common and "id" in common[0][1]

    def test_candidate_targets_uses_discovered_asp_paths(self):
        from skills.exploit.sqli_error import _candidate_targets

        ctx = SkillContext(target_url="https://x/", host="x", port=443,
                           open_ports=[443],
                           discovered_paths=["/register.asp", "/v1/users?id=5"])
        targets = _candidate_targets(ctx)
        reg = [(b, p) for b, p in targets if b == "https://x/register.asp"]
        assert reg and "id" in reg[0][1]
        v1 = [(b, p) for b, p in targets if b == "https://x/v1/users"]
        assert v1 and v1[0][1] == {"id": "5"}

    def test_candidate_targets_dedupes(self):
        from skills.exploit.sqli_error import _candidate_targets

        ctx = SkillContext(target_url="http://10.0.0.5/items?id=4",
                           host="10.0.0.5", port=80, open_ports=[80],
                           discovered_paths=["/items?id=4"])
        targets = [b for b, _ in _candidate_targets(ctx)]
        assert targets.count("http://10.0.0.5/items") == 1

    def test_scan_markers(self):
        assert "you have an error in your sql syntax" in _scan_markers(
            "<b>Warning: You have an error in your SQL syntax near '1</b>")
        assert "syntax error at or near" in _scan_markers(
            'ERROR: syntax error at or near "id"')
        assert "no such table" in _scan_markers(
            "sqlite3.OperationalError: no such table: users")
        assert "unclosed quotation mark" in _scan_markers(
            'Unclosed quotation mark after the character string')

    def test_scan_markers_clean(self):
        assert _scan_markers("<html>nothing here</html>") == set()


class TestSkillMetadata:
    def test_identity(self, skill):
        assert skill.name == "sqli-error"
        assert skill.category == SkillCategory.EXPLOIT

    def test_trigger(self, skill):
        assert skill.requires_any == ["port_80_open", "port_443_open",
                                      "port_8080_open"]


class TestSelector:
    def test_gated_on_web_ports(self):
        names = {s.name for s in select_skills(
            SkillContext(target_url="http://10.0.0.5", host="10.0.0.5",
                         open_ports=[80]), "exploit")}
        assert "sqli-error" in names

    def test_blocked_without_web_port(self):
        names = {s.name for s in select_skills(
            SkillContext(target_url="ftp://10.0.0.5", host="10.0.0.5",
                         open_ports=[21]), "exploit")}
        assert "sqli-error" not in names

    def test_sql_error_found_condition(self):
        from app.models.scanner import RawFinding

        f = RawFinding(scanner="task", scanner_template_id="sqli-error-signal",
                       severity="high", url="http://x/")
        ctx = SkillContext(target_url="http://x", host="x", open_ports=[80],
                           raw_findings=[f])
        assert "sql_error_found" in derive_conditions(ctx)


class TestRun:
    def test_run_skips_without_target(self):
        r = SqliErrorSkill().run(SkillContext(target_url="", host=""))
        assert r.success is True and r.findings == []

    def test_run_finds_sqli(self, monkeypatch):
        import skills.exploit.sqli_error as sq

        bodies = {
            "http://10.0.0.5/?id=1":
                "<html>product list</html>",
            "http://10.0.0.5/?id=%27":
                "<html>You have an error in your SQL syntax near '''</html>",
            "http://10.0.0.5/?id=%22":
                "<html>product list</html>",
            "http://10.0.0.5/?id=%27%29":
                "<html>product list</html>",
        }

        monkeypatch.setattr(sq, "_probe", lambda url: bodies.get(url, None))
        r = SqliErrorSkill().run(_ctx(target="http://10.0.0.5/?id=1"))
        ids = {f.scanner_template_id for f in r.findings}
        assert ids == {"sqli-error-signal"}
        f = next(iter(r.findings))
        assert f.severity == "high"
        assert f.raw["param"] == "id"
        assert f.raw["payload"] == "'"
        assert f.url == "http://10.0.0.5/?id=%27"
        assert "sql syntax" in f.description
        assert "sql syntax" in f.description
        assert r.context_updates["osint"]["sqli_scan"] == "error-signals"

    def test_run_clean(self, monkeypatch):
        import skills.exploit.sqli_error as sq

        monkeypatch.setattr(sq, "_probe",
                            lambda url: "<html>clean page</html>")
        r = SqliErrorSkill().run(_ctx(target="http://10.0.0.5/?id=7"))
        assert r.findings == []
        assert r.context_updates["osint"]["sqli_scan"] == "clean"

    def test_run_error_page_baseline_not_flagged(self, monkeypatch):
        import skills.exploit.sqli_error as sq

        # The app's error page always mentions 'database error'.
        monkeypatch.setattr(sq, "_probe",
                            lambda url: "<title>database error page</title>")
        r = SqliErrorSkill().run(_ctx())
        assert r.findings == []

    def test_run_unreachable(self, monkeypatch):
        import skills.exploit.sqli_error as sq

        monkeypatch.setattr(sq, "_probe", lambda url: None)
        r = SqliErrorSkill().run(_ctx())
        assert r.findings == []
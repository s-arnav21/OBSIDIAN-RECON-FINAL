"""Tests for the lfi-probe exploit skill (SKILL-E02)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.selector import select_skills
from skills.exploit.lfi_probe import (
    LfiProbeSkill,
    _base_urls,
    _classify,
    _decoded_php_filter,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return LfiProbeSkill()


def _ctx(host="10.0.0.5", target="http://10.0.0.5/", paths=None):
    return SkillContext(target_url=target, host=host, ip=host, port=80,
                        open_ports=[80], discovered_paths=paths or [])


class TestHelpers:
    def test_base_urls_query(self):
        bases, params = _base_urls(_ctx(target="http://x/view.php?file=a"))
        assert bases[0][0] == "http://x/view.php"
        assert bases[0][1] == "view.php"
        assert params == {"file": "a"}

    def test_base_urls_common_params(self):
        bases, params = _base_urls(_ctx(target="http://x/"))
        assert "file" in params and "lang" in params
        assert bases[0][0] == "http://x/"

    def test_base_urls_discovered_paths(self):
        ctx = _ctx(target="http://x/", paths=["/download", "/render.php"])
        bases, _ = _base_urls(ctx)
        urls = [b for b, _ in bases]
        assert urls == ["http://x/", "http://x/download"]

    def test_classify_passwd(self):
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        m = _classify(body)
        assert m is not None and m["kind"] == "passwd"

    def test_classify_winini(self):
        m = _classify("; for 16-bit app support\n[fonts]")
        assert m is not None and m["kind"] == "winini"

    def test_classify_payload_echo_is_not_confirmed(self):
        assert _classify("file not found: ../../../../etc/passwd") is None
        assert _classify("") is None
        assert _classify(None) is None

    def test_decoded_php_filter(self):
        import base64

        b64 = base64.b64encode(b"<?php echo 'hi'; ?>").decode()
        out = _decoded_php_filter(b64)
        assert out is not None and "<?php" in out

    def test_decoded_php_filter_rejects_junk(self):
        assert _decoded_php_filter("notbase64!!!") is None
        assert _decoded_php_filter("abc") is None


class TestSkillMetadata:
    def test_identity(self, skill):
        assert skill.name == "lfi-probe"
        assert skill.category == SkillCategory.EXPLOIT

    def test_trigger(self, skill):
        assert skill.requires_any == ["port_80_open", "port_443_open"]


class TestSelector:
    def test_gated_on_web_ports(self):
        names = {s.name for s in select_skills(
            SkillContext(target_url="http://10.0.0.5", host="10.0.0.5",
                         open_ports=[443]), "exploit")}
        assert "lfi-probe" in names

    def test_blocked_without_web_port(self):
        names = {s.name for s in select_skills(
            SkillContext(target_url="ssh://10.0.0.5", host="10.0.0.5",
                         open_ports=[22]), "exploit")}
        assert "lfi-probe" not in names


class TestRun:
    def test_run_skips_without_target(self):
        r = LfiProbeSkill().run(SkillContext(target_url="", host=""))
        assert r.success is True and r.findings == []

    def test_run_finds_passwd(self, monkeypatch):
        import skills.exploit.lfi_probe as lf

        def fake_probe(url):
            if "passwd" in url:
                return ("root:x:0:0:root:/root:/bin/bash\n"
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
            return "<html>index</html>"

        monkeypatch.setattr(lf, "_probe", fake_probe)
        r = LfiProbeSkill().run(_ctx(target="http://10.0.0.5/?file=x"))
        ids = {f.scanner_template_id for f in r.findings}
        assert ids == {"lfi-confirmed"}
        f = next(iter(r.findings))
        assert f.severity == "critical"
        assert f.raw["param"] == "file"
        assert f.raw["kind"] == "passwd"
        assert r.context_updates["osint"]["lfi_scan"] == "confirmed"
        assert r.context_updates["osint"]["lfi_params"] == ["file"]

    def test_run_finds_php_filter(self, monkeypatch):
        import base64
        import skills.exploit.lfi_probe as lf

        b64 = base64.b64encode(b"<?php $x = 1;").decode()

        def fake_probe(url):
            if "resource" in url:
                return b64
            return "plain"

        monkeypatch.setattr(lf, "_probe", fake_probe)
        r = LfiProbeSkill().run(_ctx(target="http://10.0.0.5/index.php"))
        ids = {f.scanner_template_id for f in r.findings}
        assert ids == {"lfi-confirmed"}
        f = next(iter(r.findings))
        assert f.raw["kind"] == "php-filter"

    def test_run_clean(self, monkeypatch):
        import skills.exploit.lfi_probe as lf

        monkeypatch.setattr(lf, "_probe",
                            lambda url: "<p>nothing to read here</p>")
        r = LfiProbeSkill().run(_ctx())
        assert r.findings == []
        assert r.context_updates["osint"]["lfi_scan"] == "clean"

    def test_run_unreachable(self, monkeypatch):
        import skills.exploit.lfi_probe as lf

        monkeypatch.setattr(lf, "_probe", lambda url: None)
        r = LfiProbeSkill().run(_ctx())
        assert r.findings == []
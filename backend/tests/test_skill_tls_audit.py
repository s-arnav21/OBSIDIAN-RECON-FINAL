"""Tests for the tls-audit skill (SKILL-R12)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.recon.tls_audit import (
    TlsAuditSkill,
    _build_command,
    _extract_host,
    _heartbleed_vulnerable,
    _split_script_output,
    _subsection,
    _tls_ports,
    _weak_ciphers,
    _weak_protocols,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return TlsAuditSkill()


def _ctx(host="example.com", ports=None, port=443, url=None):
    return SkillContext(
        target_url=url or f"https://{host}", host=host,
        port=port, open_ports=ports or [])


SAMPLE = """\
Starting Nmap 7.98 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
PORT     STATE  SERVICE VERSION
443/tcp  open   ssl/https nginx 1.18.0
| ssl-cert: Subject: example.com
| ssl-enum-ciphers:
|   SSLv3:
|     ciphers:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA - strong
|   TLSv1.0:
|     ciphers:
|       TLS_RSA_WITH_RC4_128_SHA - strong
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 - strong
| ssl-heartbleed:
|   VULNERABLE:
|   The Heartbleed bug allows...
"""


class TestHelpers:
    def test_extract_host(self):
        assert _extract_host(_ctx(host="Example.COM")) == "example.com"
        assert _extract_host(SkillContext(target_url="https://alt.example", host="")) == "alt.example"

    def test_split_script_output_groups_by_port(self):
        sections = _split_script_output(SAMPLE)
        assert 443 in sections
        assert "ssl-enum-ciphers" in sections[443]
        assert "ssl-heartbleed" in sections[443]

    def test_subsection(self):
        section = _subsection(SAMPLE, "ssl-enum-ciphers")
        assert "SSLv3" in section
        assert "TLSv1.0" in section

    def test_weak_protocols_detects_old(self):
        weak = _weak_protocols(SAMPLE)
        assert "SSLv3" in weak
        assert "TLSv1.0" in weak
        assert "TLSv1.2" not in weak

    def test_weak_ciphers_detects_markers(self):
        weak = _weak_ciphers(SAMPLE)
        assert "3des" in weak
        assert "rc4" in weak

    def test_heartbleed_vulnerable(self):
        assert _heartbleed_vulnerable(SAMPLE) is True

    def test_heartbleed_not_vulnerable(self):
        safe = "| ssl-heartbleed:\n|   not vulnerable."
        assert _heartbleed_vulnerable(safe) is False

    def test_build_command(self):
        cmd = _build_command("nmap", "example.com", [443, 8443])
        assert "--script" in cmd
        assert "ssl-cert,ssl-enum-ciphers,ssl-heartbleed" in cmd
        assert "443,8443" in cmd
        assert cmd[-1] == "example.com"

    def test_tls_ports_from_open(self):
        ctx = _ctx(ports=[22, 443, 8080, 8443, 5000])
        assert _tls_ports(ctx) == [443, 8443]

    def test_tls_ports_fallback(self):
        ctx = _ctx(ports=[22], port=8443)
        assert _tls_ports(ctx) == [8443]


class TestSkillMetadata:
    def test_registered_by_name(self):
        from skills import get_skill
        assert get_skill("tls-audit").name == "tls-audit"

    def test_category(self, skill):
        assert skill.category == SkillCategory.RECON

    def test_requires_any_tls_ports(self, skill):
        assert skill.requires_any == ["port_443_open", "port_8443_open"]

    def test_describe(self, skill):
        d = skill.describe()
        assert d["name"] == "tls-audit"
        assert d["category"] == "recon"
        assert d["description"]


class TestShouldRun:
    def test_runs_on_443(self, skill):
        assert skill.should_run(_ctx(ports=[443])) is True

    def test_runs_on_8443(self, skill):
        assert skill.should_run(_ctx(ports=[8443])) is True

    def test_skipped_no_tls(self, skill):
        assert skill.should_run(_ctx(ports=[22, 80])) is False

    def test_skipped_empty_host(self, skill):
        ctx = SkillContext(target_url="", host="", open_ports=[443])
        assert skill.should_run(ctx) is False


class TestRun:
    def test_no_tls_port_skipped(self, skill):
        result = skill.run(_ctx(ports=[22, 80]))
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["osint"]["tls_skipped"] is True

    def test_missing_nmap_degrades(self, skill, monkeypatch):
        monkeypatch.setattr("skills.recon.tls_audit._nmap_binary", lambda: None)
        result = skill.run(_ctx(ports=[443]))
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["osint"]["reason"] == "no nmap binary"

    def test_emits_weak_protocol_poodle_heartbleed(self, skill, monkeypatch):
        monkeypatch.setattr("skills.recon.tls_audit._nmap_binary",
                            lambda: "/usr/bin/nmap")
        monkeypatch.setattr("skills.recon.tls_audit._run_nmap", lambda cmd: SAMPLE)
        result = skill.run(_ctx(ports=[443]))
        ids = [f.scanner_template_id for f in result.findings]
        assert ids.count("tls-weak-protocol") == 2  # SSLv3 + TLSv1.0
        assert "poodle-ssl3" in ids
        assert "heartbleed" in ids
        hb = [f for f in result.findings if f.scanner_template_id == "heartbleed"]
        assert hb[0].severity == "critical"
        wp = [f for f in result.findings
              if f.scanner_template_id == "tls-weak-protocol"]
        assert all(f.severity == "high" for f in wp)
        assert result.context_updates["osint"]["heartbleed_ports"] == [443]

    def test_clean_server_no_findings(self, skill, monkeypatch):
        clean = """\
443/tcp open ssl/https nginx
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_AES_256_GCM_SHA384 - strong
| ssl-heartbleed:
|   not vulnerable.
"""
        monkeypatch.setattr("skills.recon.tls_audit._nmap_binary",
                            lambda: "/usr/bin/nmap")
        monkeypatch.setattr("skills.recon.tls_audit._run_nmap", lambda cmd: clean)
        result = skill.run(_ctx(ports=[443]))
        assert result.findings == []
        assert "TLSv1.2" not in result.context_updates["osint"]["tls_weak_protocols"]
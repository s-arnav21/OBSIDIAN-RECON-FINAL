"""Tests for the port-scan skill (SKILL-R11)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))

import pytest

from skills import load_all_skills
from skills.base import SkillCategory, SkillContext
from skills.recon.port_scan import (
    PortScanSkill,
    _discovery_command,
    _banner_command,
    _extract_host,
    _nmap_binary,
    _os_detect_command,
    _parse_output,
)


@pytest.fixture(scope="module", autouse=True)
def _load():
    load_all_skills()


@pytest.fixture
def skill():
    return PortScanSkill()


def _ctx(host="example.com", target_url=None):
    return SkillContext(
        target_url=target_url or f"https://{host}",
        host=host,
    )


SAMPLE_NMAP = """\
Starting Nmap 7.98 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up (0.0010s latency).
PORT     STATE    SERVICE    VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (protocol 2.0)
| ssh-hostkey: 3072 aa:bb:cc
80/tcp   open  http    nginx 1.18.0
| http-title: Example Domain
443/tcp  open  https   nginx 1.18.0
Warning: OSScan results may be unreliable
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.4.0-72-generic
"""


class TestHelpers:
    def test_extract_host(self):
        assert _extract_host(_ctx(host="Example.COM")) == "example.com"
        assert _extract_host(SkillContext(target_url="https://alt.example", host="")) == "alt.example"

    def test_nmap_binary_found(self):
        assert _nmap_binary() is not None

    def test_discovery_command_full_scan(self):
        cmd = _discovery_command("nmap", "example.com")
        assert "nmap" in cmd
        assert "-p-" in cmd
        assert "--min-rate" in cmd
        assert "--open" in cmd
        # Phase 1 is a fast sweep — no version/script/OS detection flags yet.
        assert "-sV" not in cmd and "-sC" not in cmd and "-O" not in cmd
        assert cmd[-1] == "example.com"

    def test_os_detect_command(self):
        cmd = _os_detect_command("nmap", "example.com")
        assert "-O" in cmd and "--osscan-guess" in cmd
        assert cmd[-1] == "example.com"

    def test_discovery_command_explicit_ports(self):
        cmd = _discovery_command("nmap", "example.com", "22,80,443")
        assert "22,80,443" in cmd
        assert cmd[-3] == "-p"
        assert cmd[-2] == "22,80,443"
        assert cmd[-1] == "example.com"

    def test_discovery_command_top_ports_uses_equals_form(self):
        cmd = _discovery_command("nmap", "example.com", "--top-ports 1000")
        assert "--top-ports=1000" in cmd
        assert cmd[-1] == "example.com"

    def test_banner_command_scripts_and_ports(self):
        cmd = _banner_command("nmap", "example.com", [22, 80, 443])
        assert "-sC" in cmd and "-sV" in cmd
        assert cmd[-3] == "-p"
        assert cmd[-2] == "22,80,443"
        assert cmd[-1] == "example.com"

    def test_banner_command_scripts_off(self):
        cmd = _banner_command("nmap", "example.com", [80], scripts=False)
        assert "-sV" in cmd
        assert "-sC" not in cmd

    def test_parse_output_ports_and_os(self):
        ports, os_details = _parse_output(SAMPLE_NMAP)
        assert len(ports) == 3
        assert ports[0]["port"] == 22
        assert ports[0]["service"] == "ssh"
        assert ports[0]["version"] == "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (protocol 2.0)"
        assert ports[1]["service"] == "http"
        assert ports[2]["service"] == "https"
        assert "Linux 5.X" in os_details
        assert "Linux 5.4.0-72-generic" in os_details


class TestOsConfidenceFilter:
    """Bogus low-confidence OS guesses (>=95% kept, flagged guesses dropped)."""

    BOGUS = """\
Nmap scan report for 192.168.1.108
Warning: OSScan results may be unreliable
Aggressive OS guesses: Linux 3.2 (93%), Cisco 3660 router (IOS 12.2) (91%), \
Nokia N90 phone (89%), Sony Ericsson W710i phone (88%)
No exact OS matches for host (test conditions non-ideal).
OS: Cisco 3660 router (IOS 12.2(15)JZ1) (89%)
OS: Linux 3.2 (93%)
OS: Sony Ericsson W710i (85%)
Running: Linux 3.2
OS details: Linux 3.2
"""

    CONFIDENT = """\
Warning: OSScan results may be unreliable
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.4.0-72-generic
"""

    GUESSED_HIGH = """\
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 2.6.32 - 2.6.35 (95%), \
Linux 2.6.24 (92%)
No exact OS matches for host (test conditions non-ideal).
Running: Linux 2.6.32
OS details: Linux 2.6.32
"""

    def test_bogus_low_confidence_guesses_dropped(self):
        from skills.recon.port_scan import _os_details_from_output
        os_details = _os_details_from_output(self.BOGUS)
        assert os_details == []

    def test_confident_match_kept(self):
        from skills.recon.port_scan import _os_details_from_output
        os_details = _os_details_from_output(self.CONFIDENT)
        assert "Linux 5.X" in os_details
        assert "Linux 5.4.0-72-generic" in os_details

    def test_high_confidence_guesses_kept_low_dropped(self):
        from skills.recon.port_scan import _os_details_from_output
        os_details = _os_details_from_output(self.GUESSED_HIGH)
        assert "Linux 2.6.32" in os_details
        assert "Linux 2.6.32 - 2.6.35" in os_details
        assert "Linux 2.6.24" not in os_details


class TestSkillMetadata:
    def test_registered_by_name(self):
        from skills import get_skill
        assert get_skill("port-scan").name == "port-scan"

    def test_category(self, skill):
        assert skill.category == SkillCategory.RECON

    def test_trigger_conditions_empty(self, skill):
        assert skill.requires_all == []
        assert skill.requires_any == []

    def test_requires_tools_nmap(self, skill):
        assert skill.requires_tools == ["nmap"]

    def test_describe(self, skill):
        d = skill.describe()
        assert d["name"] == "port-scan"
        assert d["category"] == "recon"
        assert d["description"]


class TestShouldRun:
    def test_hostname_runs(self, skill):
        assert skill.should_run(_ctx(host="example.com")) is True

    def test_empty_host_skipped(self, skill):
        assert skill.should_run(_ctx(host="", target_url="")) is False


class TestRun:
    def test_empty_host_no_crash(self, skill):
        result = skill.run(_ctx(host="", target_url=""))
        assert result.success is True
        assert result.findings == []
        assert result.error  # reported via SkillResult.error

    def test_missing_nmap_degrades(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.port_scan._nmap_binary", lambda: None)
        result = skill.run(_ctx())
        assert result.success is True
        assert result.findings == []
        assert result.context_updates["osint"]["reason"] == "no nmap binary"

    def test_populates_findings_and_context(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.port_scan._nmap_binary", lambda: "/usr/bin/nmap")
        monkeypatch.setattr(
            "skills.recon.port_scan._run_nmap", lambda cmd, timeout=None, cancel_event=None: SAMPLE_NMAP)
        result = skill.run(_ctx())
        ids = [f.scanner_template_id for f in result.findings]
        assert ids.count("port-open") == 3
        assert ids.count("service-detected") == 3
        assert ids.count("os-detected") >= 1
        assert result.context_updates["open_ports"] == [22, 80, 443]
        assert "ssh" in result.context_updates["technologies"]
        assert "http" in result.context_updates["technologies"]
        assert result.context_updates["osint"]["port_count"] == 3

    def test_empty_scan_no_findings(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.port_scan._nmap_binary", lambda: "/usr/bin/nmap")
        monkeypatch.setattr(
            "skills.recon.port_scan._run_nmap", lambda cmd, timeout=None, cancel_event=None: "")
        result = skill.run(_ctx())
        assert result.findings == []
        assert result.context_updates["open_ports"] == []
        assert result.context_updates["technologies"] == []

    def test_known_ports_and_techs_not_duplicated(self, skill, monkeypatch):
        monkeypatch.setattr(
            "skills.recon.port_scan._nmap_binary", lambda: "/usr/bin/nmap")
        monkeypatch.setattr(
            "skills.recon.port_scan._run_nmap", lambda cmd, timeout=None, cancel_event=None: SAMPLE_NMAP)
        result = skill.run(SkillContext(
            target_url="https://example.com", host="example.com",
            open_ports=[22, 80], technologies=["ssh"]))
        assert 22 not in result.context_updates["open_ports"]
        assert 80 not in result.context_updates["open_ports"]
        assert 443 in result.context_updates["open_ports"]
        assert "ssh" not in result.context_updates["technologies"]
        assert "http" in result.context_updates["technologies"]
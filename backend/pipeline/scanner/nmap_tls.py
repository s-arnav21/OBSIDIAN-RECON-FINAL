"""Nmap TLS posture scanner — TLS protocol/cipher/certificate health checks.

Runs `nmap --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed` against the TLS
ports of a target and turns the script output into findings:
    - outdated TLS protocol versions (SSLv2/SSLv3/TLSv1.0/TLSv1.1)
    - weak/expired certificate issues
    - Heartbleed vulnerability

Zero extra installs: everything ships with nmap. The scan only starts on ports
the machine reports as open (from the parent nmap scanner when available, else
a bounded default TLS port list including the target's own URL port), so it
never probes random closed ports.
"""
from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from typing import List, Optional
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from pipeline.scanner import base

DEFAULT_TLS_PORTS = "443,8443,4280,9443"
_OLD_PROTOCOLS = ("sslv2", "sslv3", "tlsv1.0", "tlsv1.1")
_PROTOCOL_NAMES = {"sslv2": "SSLv2", "sslv3": "SSLv3", "tlsv1.0": "TLSv1.0", "tlsv1.1": "TLSv1.1"}
_WEAK_CIPHER_MARKERS = ("rc4", "des", "3des")


def _extract_scan_host(target: str) -> str:
    target = target.strip()
    if "://" in target:
        return urlparse(target).hostname or target
    if ":" in target and not target.startswith("["):
        return target.split(":")[0]
    return target


def _url_port(target: str) -> Optional[int]:
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        port = parsed.port
        if port is not None:
            return port
        scheme = (parsed.scheme or "").lower()
        return 443 if scheme == "https" else 80
    _, port = target.rpartition(":")
    try:
        return int(port)
    except ValueError:
        return None


def _tls_ports(target: str, ports: Optional[str]) -> str:
    """Effective TLS port list: explicit override, else a bounded default
    seeded with the target's own URL port so the entry point is never missed.
    """
    if ports:
        return ports
    explicit = _url_port(target)
    base_ports = DEFAULT_TLS_PORTS.split(",")
    if explicit is not None and str(explicit) not in base_ports:
        base_ports.append(str(explicit))
    return ",".join(sorted(set(base_ports), key=int))


@base.register
class NmapTlsScanner(base.Scanner):
    name = "nmap_tls"
    executable = "nmap"

    def __init__(self) -> None:
        self.warning: Optional[str] = None
        self.detail: Optional[dict] = None

    def scan(self, target: str, ports: Optional[str] = None,
             timeout: int = 120) -> List[RawFinding]:
        """Scan TLS posture on the effective TLS port list."""
        self.warning = None
        self.detail = None
        host = _extract_scan_host(target)
        effective = _tls_ports(target, ports)
        self.detail = {"ports": effective.split(",")}

        nmap_bin = self.resolved_path or "nmap"
        cmd = [
            nmap_bin, "-T4", "--host-timeout", f"{timeout}s",
            "-p", effective, "-sV",
            "--script", "ssl-cert,ssl-enum-ciphers,ssl-heartbleed",
            host,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise base.ScanError(f"nmap_tls timed out after {timeout}s: {exc}") from exc
        except FileNotFoundError as exc:
            raise base.ScanError("nmap binary not found") from exc

        return self._parse_output(proc.stdout, host)

    def _parse_output(self, output: str, target: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        sections = self._split_script_output(output)

        for port, text in sections.items():
            if not text:
                continue
            findings.extend(self._cert_findings(port, text, target))
            findings.extend(self._protocol_findings(port, text, target))
            findings.extend(self._cipher_findings(port, text, target))
            findings.extend(self._heartbleed_findings(port, text, target))

        return findings

    @staticmethod
    def _split_script_output(output: str) -> dict[int, str]:
        """Group nmap script output by port.

        nmap's -sV --script output has the form:
            443/tcp  open  ssl/http  nginx
            | ssl-cert: Subject: ...
            | ssl-enum-ciphers: ...
            8080/tcp open  ssl/http ...
        """
        port: Optional[int] = None
        sections: dict[int, str] = {}
        for line in output.splitlines():
            stripped = line.strip()
            if "open" in stripped and "/tcp" in stripped:
                try:
                    port = int(stripped.split("/tcp")[0])
                    sections.setdefault(port, "")
                except ValueError:
                    port = None
                continue
            if port is not None and stripped.startswith("|"):
                sections[port] += stripped + "\n"
        return sections

    def _cert_findings(self, port: int, text: str, target: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        cert_section = _subsection(text, "ssl-cert")
        valid_from = _date_after(cert_section, "Not valid before:")
        valid_to = _date_after(cert_section, "Not valid after:")
        now = datetime.now(UTC)

        if valid_to:
            if valid_to < now:
                findings.append(self._make_finding(
                    port, target, "ssl-cert-expired", "high",
                    "TLS certificate is EXPIRED",
                    {"expiry": valid_to.isoformat(), "port": port},
                ))
            elif valid_to - now < timedelta(days=30):
                findings.append(self._make_finding(
                    port, target, "ssl-cert-expiring", "low",
                    f"TLS certificate expires soon ({valid_to.isoformat()})",
                    {"expiry": valid_to.isoformat(), "port": port},
                ))
        if valid_from and valid_from > now:
            findings.append(self._make_finding(
                port, target, "ssl-cert-not-yet-valid", "low",
                "TLS certificate is not yet valid (clock skew or mis-issued)",
                {"valid_from": valid_from.isoformat(), "port": port},
            ))

        subject = _line_after(cert_section, "Subject:")
        if subject:
            findings.append(self._make_finding(
                port, target, "ssl-cert-subject", "info",
                "TLS certificate subject", {"subject": subject, "port": port},
            ))
        return findings

    def _protocol_findings(self, port: int, text: str, target: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        ciphers_section = _subsection(text, "ssl-enum-ciphers")
        present = sorted(_matched_protocols(ciphers_section))
        if not present:
            return findings
        for proto in present:
            findings.append(self._make_finding(
                port, target, "ssl-outdated-protocol", "low",
                f"outdated TLS/SSL protocol offered: {proto}",
                {"protocol": proto, "port": port},
            ))
        return findings

    def _cipher_findings(self, port: int, text: str, target: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        ciphers_section = _subsection(text, "ssl-enum-ciphers")
        weak = [m for m in _WEAK_CIPHER_MARKERS if m in ciphers_section.lower()]
        if weak:
            findings.append(self._make_finding(
                port, target, "ssl-weak-cipher", "low",
                "weak cipher suite(s) offered",
                {"weak_markers": weak, "port": port},
            ))
        return findings

    def _heartbleed_findings(self, port: int, text: str, target: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        hb = _subsection(text, "ssl-heartbleed")
        if "not vulnerable" in hb.lower():
            return findings
        if "vulnerable" in hb.lower():
            findings.append(self._make_finding(
                port, target, "ssl-heartbleed", "high",
                "OpenSSL Heartbleed (CVE-2014-0160) vulnerable",
                {"port": port},
            ))
        return findings

    @staticmethod
    def _make_finding(port: int, target: str, tid: str, severity: str,
                      description: str, raw: dict) -> RawFinding:
        return RawFinding(
            scanner="nmap_tls",
            scanner_template_id=tid,
            target=target,
            host=target,
            port=port,
            service="ssl",
            severity=severity,
            description=description,
            raw=raw,
        )


def _subsection(text: str, name: str) -> str:
    """Return the '| script-name:' block starting from the marker line."""
    sections: dict[str, str] = {}
    current: Optional[str] = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("| _"):
            if current:
                sections[current] += "\n" + line[3:]
            current = None
            continue
        if line.startswith("|"):
            rest = line.lstrip("| ")
            for key in ("ssl-cert", "ssl-enum-ciphers", "ssl-heartbleed"):
                if rest.startswith(key + ":"):
                    current = key
                    sections.setdefault(current, "")
                    sections[current] += rest.split(":", 1)[1] + "\n"
                    break
            else:
                if current:
                    sections[current] += line.lstrip("| ") + "\n"
    return sections.get(name, "")


def _has_protocol(section: str, proto: str) -> bool:
    """A protocol version line looks like 'TLSv1.0:' inside the section."""
    proto = proto.lower()
    for raw in section.splitlines():
        line = raw.strip().rstrip(":")
        if line.strip().lower() == proto:
            return True
        if line.lower().startswith(proto + ":"):
            return True
    return False


def _matched_protocols(section: str) -> list[str]:
    """Return the _OLD_PROTOCOLS present in a cipher section, in report form."""
    present: set[str] = set()
    for raw in section.splitlines():
        line = raw.strip().rstrip(":")
        low = line.lower()
        for proto in _OLD_PROTOCOLS:
            if low == proto:
                present.add(_PROTOCOL_NAMES[proto])
    return present


def _date_after(section: str, prefix: str) -> Optional[datetime]:
    value = _line_after(section, prefix)
    if not value:
        return None
    try:
        parsed = value.strip()
        if "T" in parsed:
            dt = datetime.fromisoformat(parsed[:19])
        else:
            dt = datetime.strptime(parsed[:25], "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    except (ValueError, TypeError):
        return None


def _line_after(section: str, prefix: str) -> Optional[str]:
    for raw in section.splitlines():
        line = raw.strip()
        low = line.lower()
        if low.startswith(prefix.lower()):
            return line[len(prefix):].strip()
    return None
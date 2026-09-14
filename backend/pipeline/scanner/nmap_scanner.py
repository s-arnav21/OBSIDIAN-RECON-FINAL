"""Nmap scanner — comprehensive host/port/service discovery with full-port scan.

Phase 1: fast open-port DISCOVERY over the port plan (all 65535 ports by
default) with no -sV/-sC, using -T4 + a --min-rate floor so a slow/remote
host cannot stall the sweep.
Phase 2: -sV version detection + -sC default scripts run ONLY against the
open ports found in Phase 1, keeping the expensive work bounded.
Phase 3: OS fingerprinting with -O --osscan-guess for OS detection.

The two-phase split means a full-port pull of a slow target no longer times
out at a single fixed deadline. If the port discovery cannot finish inside
its share of the scan budget, nmap is retried down a plan ladder
(--top-ports 10000 → 1000 → 200) so the host is always scanned to
completion with results; the degradation is recorded in ``self.warning`` and
the actual plan used is surfaced in ``self.detail``.

Time budget: ``settings.NMAP_SCAN_TIMEOUT`` (default 900s) unless the
request supplies an explicit per-scan ``timeout``.

Requires nmap to be installed. Produces RawFinding objects (open ports +
services + OS detection) that feed the reachability/reconnaissance layer
of the pipeline.

Port plan transparency: when the operator does not supply an explicit port
list, nmap intends to scan ALL 65535 ports for maximum coverage. The
scanner records exactly which ports were requested vs. what the actual
(possibly degraded) plan scanned as ``self.detail``, surfaced in the report
so the UI can show where a port came from.

Edge/CDN context: services that sit in front of the origin (Cloudflare,
Fastly, reverse proxies) are flagged so findings state they describe EDGE
infrastructure, not necessarily open origin ports.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from typing import List, Optional
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from pipeline._errors import ScanCancelled
from pipeline.scanner import base

# Default port discovery breadth. When the operator gives no explicit port
# list we intend to scan ALL 65535 ports for maximum coverage; the -T4 timing
# plus a --min-rate floor keep it fast, and the plan ladder below guarantees
# the sweep still completes within the scan budget.
DEFAULT_PORT_PLAN = "-p-"

# Degradation ladder: if the full-port sweep cannot finish inside its budget
# slice, retry with progressively smaller plan so a slow/remote host still
# gets scanned to completion instead of a hard timeout failure.
PLAN_LADDER = ["-p-", "--top-ports 10000", "--top-ports 1000", "--top-ports 200"]

_PORT_LINE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(.*)$")

# How often (seconds) the cancel-aware wait re-checks the process/cancel state.
_WAIT_POLL = 0.2


def _kill_tree(proc: "subprocess.Popen") -> None:
    """Kill a subprocess and its whole process group (nmap spawns children).

    Best-effort: the process group is a separate session so killing it cannot
    touch our own process.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _run_cmd_cancelable(cmd: list, timeout: int, cancel_event,
                        label: str = "nmap") -> "subprocess.CompletedProcess":
    """run() a subprocess with per-interval cancel/timeout checks.

    On cancel: kills the process tree and raises ScanCancelled (propagates up
    so the scan job is marked 'cancelled', never 'failed').
    On timeout: kills the process tree and raises ScanError (callers degrade).
    """
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True,
                                start_new_session=True)
    except FileNotFoundError as exc:
        raise base.ScanError("nmap binary not found") from exc

    deadline = time.monotonic() + timeout
    while True:
        try:
            returncode = proc.wait(timeout=_WAIT_POLL)
        except subprocess.TimeoutExpired:
            if cancel_event is not None and cancel_event.is_set():
                _kill_tree(proc)
                raise ScanCancelled() from None
            if time.monotonic() >= deadline:
                _kill_tree(proc)
                raise base.ScanError(f"{label} timed out after {timeout}s") from None
            continue
        out, err = proc.communicate()
        return subprocess.CompletedProcess(cmd, returncode, out, err)

# Service banners that indicate edge/CDN/proxy infrastructure rather than a
# directly exposed origin service.
_EDGE_MARKERS = (
    "cloudflare",
    "cloudfront",
    "fastly",
    "akamai",
    "cdn",
    "proxy",
    "varnish",
    "nginx..reverse proxy",
)


def _extract_scan_host(target: str) -> str:
    """Extract a bare host/IP from a URL or host:port for nmap target.

    nmap cannot parse 'host:port' as a host; the port is supplied via -p.
    """
    target = target.strip()
    if "://" in target:
        return urlparse(target).hostname or target
    if ":" in target and not target.startswith("["):
        return target.split(":")[0]
    return target


def _url_port(target: str) -> Optional[int]:
    """Return the explicit port from a URL, or None."""
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        port = parsed.port
        if port is not None:
            return port
        scheme = (parsed.scheme or "").lower()
        if scheme in ("http", "https"):
            return 80 if scheme == "http" else 443
        return None
    _, port = target.rpartition(":")
    try:
        return int(port)
    except ValueError:
        return None


def _is_explicit_list(port_arg: str) -> bool:
    """True when the port plan is an explicit comma list (operator-named ports);
    False for the full-port plan or a --top-ports sweep."""
    return port_arg != "-p-" and not port_arg.startswith("--top-ports")


def _plan_arg(plan: str) -> str:
    """Normalize a port-plan token into a single nmap argument.

    nmap expects '--top-ports=N' (one token); the pipeline carries the plan as
    '--top-ports N', so the pair must be joined before it reaches the CLI.
    """
    if plan.startswith("--top-ports "):
        return "--top-ports=" + plan.split(" ", 1)[1]
    return plan


@base.register
class NmapScanner(base.Scanner):
    name = "nmap"
    executable = "nmap"

    def __init__(self) -> None:
        self.warning: Optional[str] = None
        self.detail: Optional[dict] = None

    def scan(self, target: str, ports: Optional[str] = None,
             timeout: Optional[int] = None, service_detect: bool = True,
             scripts: bool = True, os_detect: bool = True,
             start_plan: Optional[str] = None,
             cancel_event=None) -> List[RawFinding]:
        """Full-surface nmap scan. Returns raw findings (open ports + versions).

        Two bounded phases keep a full-port pull of a slow/remote host from
        hard-timing-out:

          Phase 1 (discovery): fast open-port sweep (no -sV/-sC, --min-rate).
          Phase 2 (banner): -sV [-sC] version/service pass on OPEN ports only.

        If the full-port discovery cannot finish inside its share of the
        budget, the scan degrades down PLAN_LADDER so it always completes and
        returns results; `self.warning` records the degradation and
        `self.detail` records the plan actually scanned.

        The time budget is `settings.NMAP_SCAN_TIMEOUT` by default; an
        explicit per-scan `timeout` (seconds) overrides it.

        Phase 1 never silently fails — if nmap cannot even run, that is a real
        ScanError. If a later phase fails or times out, whatever was captured
        is still returned and `self.warning` records the problem.
        """
        self.warning = None
        self.detail = None
        host = _extract_scan_host(target)

        port_arg, source = self._port_plan(target, ports, default=start_plan)
        budget = self._budget(timeout)
        self.detail = self._ports_detail(ports, port_arg, source)
        self.detail["budget_s"] = budget

        if _is_explicit_list(port_arg):
            # Operator named exact ports -> single -sV/-sC pass over them.
            findings = self._run_nmap(host, port_arg, budget,
                                      use_sv=True, scripts=scripts,
                                      cancel_event=cancel_event)
            self.detail["scanned"] = port_arg
        else:
            findings = self._plan_scan(host, port_arg, budget, scripts,
                                       service_detect=service_detect,
                                       cancel_event=cancel_event)

        if os_detect and findings:
            try:
                findings += self._os_detect(host, budget,
                                            nmap_bin=self.resolved_path,
                                            cancel_event=cancel_event)
            except base.ScanError:
                pass

        return findings

    @staticmethod
    def _budget(timeout: Optional[int]) -> int:
        """Resolve the per-scan time budget (seconds)."""
        if timeout is not None:
            return max(15, int(timeout))
        from app.core.config import settings
        return max(15, int(settings.NMAP_SCAN_TIMEOUT))

    def _plan_scan(self, host: str, start_plan: str, budget: int,
                   scripts: bool, service_detect: bool = True,
                   cancel_event=None) -> List[RawFinding]:
        """Two-phase scan with graceful plan degradation.

        Phase 1 discovers open ports fast (no -sV/-sC, --min-rate); Phase 2
        runs version/script detection on those open ports only. If Phase 1 or
        2 cannot finish inside its budget slice, we move down the plan ladder
        so the target is still scanned to completion.
        """
        ladder = PLAN_LADDER if start_plan == "-p-" else [start_plan]
        per_attempt = max(60, budget // len(ladder))

        for plan in ladder:
            try:
                discovered = self._discover(host, plan, per_attempt,
                                            cancel_event=cancel_event)
            except base.ScanError:
                continue  # discovery exceeded its budget slice -> degrade plan
            open_ports = sorted({f.port for f in discovered})
            self._note_discovery(plan, open_ports)
            if plan != start_plan:
                self._mark_degraded(start_plan, plan)
            if not open_ports or not service_detect:
                return discovered
            try:
                return self._run_nmap(
                    host, ",".join(str(p) for p in open_ports),
                    per_attempt, use_sv=True, scripts=scripts,
                    cancel_event=cancel_event)
            except base.ScanError:
                continue  # banner phase exceeded its budget slice -> degrade

        # Every plan in the ladder timed out; surface it, never return silence.
        raise base.ScanError(
            f"nmap did not finish within {budget}s across port plans "
            f"{', '.join(ladder)}")

    def _discover(self, host: str, plan: str, timeout: int,
                  cancel_event=None) -> List[RawFinding]:
        """Phase 1 — fast open-port sweep. No -sV/-sC: the expensive version
        and script pass runs on discovered open ports only (see _plan_scan)."""
        from app.core.config import settings
        nmap_bin = self.resolved_path or "nmap"
        cmd = [nmap_bin, "-Pn", "-T4", "--min-rate",
               str(settings.NMAP_MIN_RATE), "--open",
               "--host-timeout", str(settings.NMAP_HOST_TIMEOUT),
               "--max-retries", "2"]
        cmd.append(_plan_arg(plan))
        cmd.append(host)

        proc = _run_cmd_cancelable(cmd, timeout, cancel_event,
                                   label="nmap discovery")
        return self._parse_output((proc.stdout or "") + (proc.stderr or ""), host)

    def _note_discovery(self, plan: str, open_ports: List[int]) -> None:
        """Record the plan actually scanned + open-port count in detail."""
        if plan == "-p-":
            base_label = "all 65535 ports (-p-)"
        elif plan.startswith("--top-ports"):
            base_label = plan
        else:
            base_label = plan
        if open_ports:
            self.detail["scanned"] = (
                f"{base_label} + -sV/-sC on "
                f"{len(open_ports)} open port(s)")
        else:
            self.detail["scanned"] = base_label
        self.detail["open_ports_found"] = len(open_ports)

    def _mark_degraded(self, start_plan: str, used_plan: str) -> None:
        self.warning = (
            f"{start_plan} full-port scan exceeded its time budget; "
            f"result degraded to plan '{used_plan}'")

    @staticmethod
    def _port_plan(target: str, ports: Optional[str], default: Optional[str] = None):
        """Decide the port plan. Returns (nmap -p arg, source label).

        `default` lets the scan profile choose full -p- coverage (VMs) vs a
        fast --top-ports sweep (web targets); an explicit operator port list
        or a URL-wrapped port always takes precedence."""
        default = default or DEFAULT_PORT_PLAN
        if ports:
            return ports, "user"
        explicit = _url_port(target)
        if explicit is None:
            return default, "default"
        return default, "default+entry"

    @staticmethod
    def _ports_detail(requested: Optional[str], port_arg: str, source: str) -> dict:
        """Record the port plan so the report can explain every port scanned."""
        if port_arg == DEFAULT_PORT_PLAN:
            return {"requested": requested, "scanned": "all 65535 ports (-p-)",
                    "added": [], "source": source}
        if port_arg.startswith("--top-ports"):
            return {"requested": requested, "scanned": port_arg, "added": [],
                    "source": source}
        scanned = port_arg.replace("-p ", "").split(",")
        if not requested:
            return {"requested": None, "scanned": scanned, "added": [],
                    "source": source}
        requested_ports = [p.strip() for p in requested.split(",") if p.strip()]
        added = [p for p in scanned if p not in set(requested_ports)]
        return {"requested": requested_ports, "scanned": scanned, "added": added,
                "source": source}

    def _run_nmap(self, host: str, ports: str, timeout: int, use_sv: bool,
                  scripts: bool, cancel_event=None) -> List[RawFinding]:
        nmap_bin = self.resolved_path or "nmap"
        cmd = [nmap_bin, "-T4", "--host-timeout", f"{timeout}s"]
        if scripts:
            cmd.append("-sC")
        if use_sv:
            cmd.append("-sV")
        if ports.startswith("--top-ports"):
            # --top-ports N must reach the CLI as the single token --top-ports=N.
            cmd.append(_plan_arg(ports))
        elif ports == "-p-":
            # -p- (all 65535 ports) is a self-contained nmap argument.
            cmd.append(ports)
        else:
            cmd += ["-p", ports]
        cmd.append(host)

        proc = _run_cmd_cancelable(cmd, timeout, cancel_event)
        return self._parse_output(proc.stdout, host)

    @staticmethod
    def _os_detect(host: str, timeout: int, nmap_bin: Optional[str] = None,
                   cancel_event=None) -> List[RawFinding]:
        """Optional -O OS fingerprint, returned as an info finding.

        Runs nmap in --osscan-guess mode and keeps only confident fingerprints
        (see skills.recon.port_scan._os_details_from_output): against
        firewalled/virtualized hosts nmap reports plausible-but-wrong guesses
        (Cisco routers, old phones) at 89-93% confidence, which are dropped.
        """
        from skills.recon.port_scan import _os_details_from_output
        nmap_path = nmap_bin or "nmap"
        try:
            proc = _run_cmd_cancelable(
                [nmap_path, "-O", "--osscan-guess",
                 "--host-timeout", f"{min(timeout, 60)}s", host],
                min(timeout, 60), cancel_event, label="nmap OS detect")
        except (base.ScanError, FileNotFoundError):
            return []
        text = proc.stdout or ""
        found = sorted(_os_details_from_output(text))
        if not found:
            return []
        return [RawFinding(
            scanner="nmap",
            scanner_template_id="os-detection",
            vulnerability_type="reconnaissance",
            target=host,
            host=host,
            severity="info",
            description="detected OS fingerprint: " + " | ".join(found),
            raw={"os_details": found},
        )]

    def _parse_output(self, output: str, target: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        # Track the port block we're inside so -sC script results attach to a port.
        current_port: Optional[int] = None

        for line in output.splitlines():
            stripped = line.strip()

            # Track which port the following script lines belong to.
            pm = _PORT_LINE.match(stripped)
            if pm:
                current_port = int(pm.group(1))
                port, proto, service_info = pm.groups()
                service_tokens = service_info.split()
                service = service_tokens[0] if service_tokens else None
                version = " ".join(service_tokens[1:]) if len(service_tokens) > 1 else None
                edge = self._edge_annotation(service_info)
                description = f"open port {port}/{proto}: {service_info.strip()}"
                if edge:
                    description += (f" — routed through {edge['type']} "
                                    f"({edge['name']}); this is EDGE "
                                    "infrastructure, not necessarily the origin")
                raw = {"protocol": proto, "service_version": version}
                if edge:
                    raw["edge"] = edge
                findings.append(RawFinding(
                    scanner="nmap", scanner_template_id="open-port",
                    target=target, host=target, port=int(port), service=service,
                    severity="info", description=description, raw=raw,
                ))
                continue

            # -sC script output lines like:  | http-title: Example
            s = self._script_finding(stripped)
            if s:
                s.port = current_port
                # Script rows carry no target of their own — attach the scan
                # target so downstream triage/normalization always sees a
                # non-empty identity (Finding requires target/host).
                s.target = s.host = target
                findings.append(s)

        return findings

    @staticmethod
    def _script_finding(stripped: str) -> Optional[RawFinding]:
        """Convert a nmap -sC script output line into a RawFinding, or None."""
        if not stripped.startswith("|"):
            return None
        parts = stripped[1:].strip().split(":", 1)
        if len(parts) != 2:
            return None
        script = parts[0].strip().lower()
        value = parts[1].strip()
        if not value or script.startswith(("_", "|")):
            return None
        # Interesting scripts worth surfacing as findings.
        interesting = {
            "http-title": "http-title",
            "http-server-header": "http-header",
            "http-security-headers": "http-security-headers",
            "http-methods": "http-methods",
            "http-cookies": "http-cookies",
            "http-headers": "http-headers",
            "ssl-cert": "ssl-cert",
            "ssh-hostkey": "ssh-hostkey",
            "banner": "service-banner",
        }
        tmpl = interesting.get(script)
        if tmpl is None:
            return None
        return RawFinding(
            scanner="nmap",
            scanner_template_id=tmpl,
            vulnerability_type="reconnaissance",
            target=None,
            host=None,
            service=None,
            severity="info",
            description=f"{script}: {value}",
            raw={"script": script, "value": value},
        )

    @staticmethod
    def _edge_annotation(service_info: str) -> Optional[dict]:
        """Return edge/CDN context for a service banner, or None.

        Service banners like 'Cloudflare http proxy' mean the port is fronted
        by edge infrastructure. This distinguishes what the scanner sees from
        what the origin actually exposes.
        """
        low = service_info.lower()
        if "cloudflare" in low:
            return {"type": "cdn", "name": "Cloudflare"}
        if "cloudfront" in low:
            return {"type": "cdn", "name": "CloudFront"}
        if "fastly" in low:
            return {"type": "cdn", "name": "Fastly"}
        if "akamai" in low:
            return {"type": "cdn", "name": "Akamai"}
        if "varnish" in low:
            return {"type": "cache", "name": "Varnish"}
        if "proxy" in low:
            return {"type": "proxy", "name": service_info.strip()}
        return None
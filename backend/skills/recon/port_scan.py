"""Port Scan — nmap full-surface discovery: -p- --open -sV -sC -O.

The workhorse recon pass. Runs nmap against the target host in two bounded
phases so a slow/remote host is scanned to completion instead of timing out:

  Phase 1 (discovery): fast open-port sweep over all 65535 ports with
    -Pn -T4 --min-rate and --open, no -sV/-sC.
  Phase 2 (banner): -sV -sC run ONLY against the ports discovered open.

If the full-port sweep cannot finish inside its budget slice, the skill
degrades down the plan ladder (--top-ports 10000 -> 1000 -> 200) so the
target always gets scanned; the plan actually used is recorded in osint.

Everything nmap learns is condensed into three finding classes and merged into
the shared context so later skills can gate on it:

  * PORT_OPEN         (INFO)  — one per open port, with banner/service
  * SERVICE_DETECTED  (INFO)  — version info for a detected service
  * OS_DETECTED       (INFO)  — fingerprint of the operating system

Context updates: open_ports (int list), technologies (service names appended,
normalized to lowercase so the selector can match tech_* tokens).

Time budget: `settings.NMAP_SCAN_TIMEOUT` (default 900s).

Requires: the `nmap` binary. If it is missing the selector never runs this
skill (requires_tools), and a missing binary inside run() degrades to no
findings rather than raising.
"""
from __future__ import annotations

import os
import re
import signal
import shutil
import subprocess
import sys
import time
from urllib.parse import urlparse

from app.core.config import settings
from app.models.scanner import RawFinding
from pipeline._errors import ScanCancelled
from skills.base import Skill, SkillCategory, SkillContext, SkillResult
from skills import register

DEFAULT_PORT_PLAN = "-p-"
PLAN_LADDER = ["-p-", "--top-ports 10000", "--top-ports 1000", "--top-ports 200"]

_PORT_LINE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(.*)$")
_HOST_LINE = re.compile(r"^Nmap scan report for (.+)$")

_WAIT_POLL = 0.2


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _nmap_binary() -> str | None:
    candidates = [
        shutil.which("nmap"),
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        f"{sys.prefix}/bin/nmap",
    ]
    for c in candidates:
        if c and c.strip() and os.path.isfile(c):
            return c
    return None


def _plan_arg(plan: str) -> str:
    """Normalize a port-plan token into a single nmap argument."""
    if plan.startswith("--top-ports "):
        return "--top-ports=" + plan.split(" ", 1)[1]
    return plan


def _start_plan(ctx: SkillContext) -> str:
    """Port plan from the scan profile: full -p- for VMs/CTFs, fast
    --top-ports 1000 for web targets (a 65535-port sweep against a CDN-backed
    website burns minutes for nothing)."""
    if ctx.profile is not None:
        return "-p-" if getattr(ctx.profile, "nmap_full_port", True) else "--top-ports 1000"
    return DEFAULT_PORT_PLAN


def _start_plan(ctx: SkillContext) -> str:
    """Port plan from the scan profile: full -p- for VMs/CTFs, fast
    --top-ports 1000 for web targets (a 65535-port sweep against a CDN-backed
    website burns minutes for nothing)."""
    if ctx.profile is not None:
        return "-p-" if getattr(ctx.profile, "nmap_full_port", True) else "--top-ports 1000"
    return DEFAULT_PORT_PLAN


def _discovery_command(nmap_bin: str, host: str,
                       plan: str = DEFAULT_PORT_PLAN) -> list[str]:
    """Phase 1 — fast open-port sweep. No -sV/-sC, --min-rate floor.

    `--host-timeout` bounds Phase 1 per target so a rate-limited/airgapped
    host fails fast and the plan ladder degrades to top-ports instead of
    stalling the whole scan on a 65535-port sweep.
    """
    cmd = [nmap_bin, "-Pn", "-T4", "--min-rate",
           str(settings.NMAP_MIN_RATE), "--open",
           "--host-timeout", str(settings.NMAP_HOST_TIMEOUT),
           "--max-retries", "2"]
    if plan == "-p-" or plan.startswith("--top-ports"):
        cmd.append(_plan_arg(plan))
    else:
        cmd += ["-p", plan]
    cmd.append(host)
    return cmd


def _banner_command(nmap_bin: str, host: str, ports: list[int],
                    scripts: bool = True) -> list[str]:
    """Phase 2 — -sV [-sC] version/service pass on open ports only."""
    cmd = [nmap_bin, "-T4", "--host-timeout", "180s", "-sV"]
    if scripts:
        cmd.append("-sC")
    cmd += ["-p", ",".join(str(p) for p in ports)]
    cmd.append(host)
    return cmd


def _os_detect_command(nmap_bin: str, host: str) -> list[str]:
    return [nmap_bin, "-O", "--osscan-guess",
            "--host-timeout", "60s", host]


def _kill_tree(proc: "subprocess.Popen") -> None:
    """Best-effort kill of a subprocess and its whole process group."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _run_nmap(cmd: list[str], timeout: int | None = None,
              cancel_event=None) -> str:
    """Run nmap and return its combined output.

    A timer expiry re-raises TimeoutExpired so the caller can degrade port
    plans; operator cancellation kills the process tree and raises
    ScanCancelled. Any other failure (missing binary / OSError) returns ''.
    """
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True,
                                start_new_session=True if cancel_event else False)
    except Exception:  # noqa: BLE001 - missing binary / OSError
        return ""

    if cancel_event is None:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            raise
    else:
        deadline = time.monotonic() + (timeout if timeout is not None else 1e9)
        while True:
            try:
                proc.wait(timeout=_WAIT_POLL)
                break
            except subprocess.TimeoutExpired:
                if cancel_event.is_set():
                    _kill_tree(proc)
                    raise ScanCancelled() from None
                if time.monotonic() >= deadline:
                    _kill_tree(proc)
                    raise subprocess.TimeoutExpired(
                        cmd, timeout=(timeout if timeout is not None else 0))
        out, err = proc.communicate()
    return (out or "") + "\n" + (err or "")


def _parse_output(output: str) -> tuple[list[dict], list[str]]:
    """Parse nmap output into (open_ports, os_details).

    open_ports: list of dicts {port, proto, service, version, raw_banner}.
    os_details: list of OS fingerprint strings.
    """
    ports: list[dict] = []
    os_details: list[str] = _os_details_from_output(output)

    for line in output.splitlines():
        stripped = line.strip()
        pm = _PORT_LINE.match(stripped)
        if pm:
            port, proto, service_info = pm.groups()
            tokens = service_info.split()
            service = tokens[0] if tokens else None
            version = " ".join(tokens[1:]) if len(tokens) > 1 else None
            ports.append({
                "port": int(port),
                "proto": proto,
                "service": service,
                "version": version,
                "raw_banner": service_info.strip(),
            })

    return ports, os_details


# nmap prints a confidence percentage next to every candidate when it had to
# *guess* the OS ("OS: <name> (NN%)" per line and "Aggressive OS guesses:"
# summary). A confident fingerprint match instead prints plain lines
# ("Running:", "OS CPE:", "OS details:") with no percentages attached.
_MIN_OS_CONFIDENCE_PCT = 95
_OS_GUESS_PERCENT_LINE = re.compile(r"^\s*OS:\s*(.+?)\s*\((\d{1,3})%\)\s*$", re.M)
_OS_AGGRESSIVE_LINE = re.compile(r"^\s*Aggressive OS guesses:\s*(.+?)\s*$", re.M)
_OS_MARKERS = ("OS details", "OS CPE", "Running")


def _os_details_from_output(output: str) -> list[str]:
    """OS fingerprint strings, discarding low-confidence nmap guesses.

    Against firewalled/virtualized targets nmap fabricates plausible-but-wrong
    fingerprints (Cisco routers, old phones, ...) at ~89-93% confidence and
    still prints the best guess on the unqualified 'Running:'/'OS details:'
    lines. As soon as the output shows nmap resorted to guessing (any
    percentage-tagged candidate), only candidates at or above
    _MIN_OS_CONFIDENCE_PCT are trusted and the unqualified best-guess lines are
    dropped. A clean confident match (no percentage-tagged candidates at all)
    keeps the 'Running:'/'OS CPE:'/'OS details:' lines as-is.
    """
    details: list[str] = []
    guesses: list[tuple[str, int]] = []

    agg = _OS_AGGRESSIVE_LINE.search(output)
    if agg:
        for part in agg.group(1).split(","):
            m = re.match(r"^(.*?)\s*\((\d{1,3})%\)\s*$", part.strip())
            name = m.group(1).strip() if m else ""
            conf = int(m.group(2)) if m else 0
            if name:
                guesses.append((name, conf))
    for m in _OS_GUESS_PERCENT_LINE.finditer(output):
        guesses.append((m.group(1).strip(), int(m.group(2))))

    if guesses:
        # nmap had to guess — keep only confident candidates.
        for name, conf in guesses:
            if conf >= _MIN_OS_CONFIDENCE_PCT and name not in details:
                details.append(name)
        return details

    # No percentage-tagged candidate: a confident match block.
    for line in output.splitlines():
        stripped = line.strip()
        for marker in _OS_MARKERS:
            if stripped.lower().startswith(marker.lower()):
                value = stripped.split(":", 1)[-1].strip()
                if value and value not in details:
                    details.append(value)
                break
    return details


@register
class PortScanSkill(Skill):
    """nmap full-port + service + OS scan of the target."""

    name = "port-scan"
    display_name = "Port Scan (nmap)"
    category = SkillCategory.RECON
    version = "1.0"

    requires_all: list[str] = []
    requires_any: list[str] = []
    requires_tools: list[str] = ["nmap"]

    timeout_seconds = settings.NMAP_SCAN_TIMEOUT
    max_requests = 1

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        findings: list[RawFinding] = []

        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                error="no host to scan",
                context_updates={"osint": {"port_scan_skipped": True}})

        nmap_bin = _nmap_binary()
        if not nmap_bin:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                error="nmap binary not found",
                context_updates={"osint": {"port_scan_skipped": True,
                                           "reason": "no nmap binary"}})

        output, used_plan = self._scan_ladder(nmap_bin, host, ctx.cancel_event,
                                              start_plan=_start_plan(ctx))
        open_ports, os_details = _parse_output(output or "")

        if not os_details:
            # OS detection requires root; run as a separate best-effort phase
            # so the port scan findings survive a non-root abort.
            try:
                os_output = _run_nmap(_os_detect_command(nmap_bin, host), 60,
                                      ctx.cancel_event)
            except subprocess.TimeoutExpired:
                os_output = ""
            _, os_details = _parse_output(os_output or "")

        new_port_numbers: list[int] = []
        for p in open_ports:
            findings.append(self._open_port(host, p))
            if p["port"] not in ctx.open_ports:
                new_port_numbers.append(int(p["port"]))
            if p.get("service"):
                findings.append(self._service_detected(host, p))

        for os_line in os_details:
            findings.append(self._os_detected(host, os_line))

        tech_add = []
        known_techs = set(ctx.technologies)
        for p in open_ports:
            svc = (p.get("service") or "").lower()
            if svc and svc not in known_techs:
                tech_add.append(svc)

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={
                "osint": {
                    "nmap_command": " ".join(_discovery_command(nmap_bin, host)),
                    "nmap_plan": used_plan,
                    "port_count": len(open_ports),
                    "os_details": os_details,
                    "services": [p["service"] for p in open_ports if p.get("service")],
                },
                "open_ports": new_port_numbers,
                "technologies": tech_add,
            })

    def _scan_ladder(self, nmap_bin: str, host: str,
                     cancel_event=None,
                     start_plan: str | None = None) -> tuple[str, str]:
        """Run Phase 1 discovery then Phase 2 banner per plan, degrading down
        the ladder so a slow/remote target always gets scanned.
        Returns (nmap_output, plan_used)."""
        start_plan = start_plan or DEFAULT_PORT_PLAN
        ladder = [start_plan] + [p for p in PLAN_LADDER if p != start_plan]
        per_attempt = max(45, settings.NMAP_SCAN_TIMEOUT // len(ladder))
        last_output = ""
        for plan in ladder:
            try:
                disc = _run_nmap(_discovery_command(nmap_bin, host, plan),
                                 per_attempt, cancel_event)
            except subprocess.TimeoutExpired:
                continue
            ports, _ = _parse_output(disc or "")
            if not ports:
                return disc, plan
            last_output = disc
            banner = self._run_banner(nmap_bin, host,
                                      [p["port"] for p in ports], per_attempt,
                                      cancel_event)
            if banner:
                return banner, plan
        return last_output, ladder[-1]

    def _run_banner(self, nmap_bin: str, host: str, ports: list[int],
                    timeout: int, cancel_event=None) -> str:
        """Phase 2 — -sV -sC banner pass; falls back to -sV only on timeout."""
        try:
            out = _run_nmap(_banner_command(nmap_bin, host, ports,
                                            scripts=True), timeout, cancel_event)
        except subprocess.TimeoutExpired:
            out = ""
        if out:
            return out
        try:
            return _run_nmap(_banner_command(nmap_bin, host, ports,
                                             scripts=False), timeout, cancel_event)
        except subprocess.TimeoutExpired:
            return ""

    def _open_port(self, host: str, port_info: dict) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="port-open",
            vulnerability_type="reconnaissance",
            target=host, host=host,
            port=port_info["port"],
            service=port_info.get("service"),
            severity="info",
            description=(
                f"open port {port_info['port']}/{port_info['proto']}: "
                f"{port_info.get('raw_banner') or 'n/a'}"
            ),
            raw=port_info,
        )

    def _service_detected(self, host: str, port_info: dict) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="service-detected",
            vulnerability_type="reconnaissance",
            target=host, host=host,
            port=port_info["port"],
            service=port_info.get("service"),
            severity="info",
            description=(
                f"service detected on {host}:{port_info['port']} — "
                f"{port_info.get('service')} "
                f"{port_info.get('version') or ''}".rstrip()
            ),
            raw=port_info,
        )

    def _os_detected(self, host: str, os_line: str) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="os-detected",
            vulnerability_type="reconnaissance",
            target=host, host=host,
            severity="info",
            description=f"detected OS fingerprint: {os_line}",
            raw={"host": host, "os_details": os_line},
        )
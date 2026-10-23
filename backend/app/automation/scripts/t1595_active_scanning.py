"""T1595 — Active Scanning.

Service/port discovery against one authorized host. Produces the
``discovered_services`` capability that unlocks every network and web
technique downstream. Uses the exact hostname resolved from the authorized
origin so the scanner cannot be steered off-target by planner input.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from app.automation import register
from app.automation import adapters
from app.automation.base import AutomationContext, TechniqueResult, TechniqueScript, TechniqueStatus
from app.automation.proc import binary_available, run_command
from app.core.config import settings


@register
class ActiveScanning(TechniqueScript):
    """Port and service discovery (MITRE T1595)."""

    technique_id = "T1595"
    name = "Active Scanning"
    tactic = "Reconnaissance"
    description = (
        "Sweep the authorized host for open ports and service banners using "
        "nmap. Establishes the discovered_services capability."
    )
    requires_any = ()
    provides = ("discovered_services",)
    vuln_types = (
        "service-scan",
        "service_scan",
        "open-service-exposure",
        "network-service",
        "discovered-service",
        "http-discovery",
        "reachability",
    )
    allowed_options = ()
    automatic_allowed = True

    def execute(self, ctx: AutomationContext) -> TechniqueResult:
        started = time.time()
        if not binary_available("nmap"):
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.BLOCKED,
                summary="nmap is not installed; active scanning is unavailable.",
                error="missing_binary:nmap",
            )
        try:
            target = adapters.normalize_target(ctx.target)
        except Exception as exc:  # noqa: BLE001
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.BLOCKED,
                summary="target is not an authorized origin",
                error=str(exc),
            )

        host = target.hostname
        cmd = [
            "nmap",
            "-Pn",
            "-sV",
            "--version-light",
            "--max-retries", "1",
            "-T4",
            "--host-timeout", settings.NMAP_HOST_TIMEOUT,
            "--top-ports", "1000",
            "-oX", "-",
            host,
        ]
        rc, stdout, stderr = run_command(cmd, timeout=ctx.timeout_seconds)

        if rc != 0 and not stdout:
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.ERROR,
                summary="nmap did not return usable output.",
                error=(stderr or "nmap_failed")[:512],
                duration_ms=int((time.time() - started) * 1000),
            )

        try:
            from app.scanning.nmap import parse_nmap_discovery

            asset_id = (ctx.finding.asset_id if ctx.finding else "") or "automation"
            discovery = parse_nmap_discovery(stdout, asset_id=asset_id)
            services = list(discovery.services)
            addresses = list(discovery.ip_addresses)
        except Exception as exc:  # noqa: BLE001
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.ERROR,
                summary="nmap output could not be parsed.",
                error=str(exc)[:512],
                duration_ms=int((time.time() - started) * 1000),
            )

        artifact = adapters.write_artifact(ctx, "t1595_nmap.xml", stdout)
        open_ports: List[Dict[str, Any]] = [
            {
                "port": svc.port,
                "protocol": svc.protocol,
                "service": svc.service_name,
                "product": svc.product,
                "version": svc.version,
            }
            for svc in services
        ]
        evidence = {
            "host": host,
            "ip_addresses": addresses,
            "open_port_count": len(open_ports),
            "open_ports": [f"{p['port']}/{p['protocol'] or 'tcp'}" for p in open_ports][:64],
            "services": [
                f"{p['port']}/{p['protocol'] or 'tcp'} {p['service'] or '?'} "
                f"{p['product'] or ''} {p['version'] or ''}".strip()
                for p in open_ports
            ][:32],
        }
        artifacts = (artifact,) if artifact else ()

        if not services:
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.REJECTED,
                summary="no open ports/services were discovered.",
                evidence=evidence,
                artifacts=artifacts,
                duration_ms=int((time.time() - started) * 1000),
            )

        return TechniqueResult(
            technique_id=self.technique_id,
            status=TechniqueStatus.CONFIRMED,
            summary=f"discovered {len(open_ports)} open service(s) on {host}.",
            provides=self.provides,
            evidence=evidence,
            artifacts=artifacts,
            next_techniques=("T1190", "T1078"),
            duration_ms=int((time.time() - started) * 1000),
        )

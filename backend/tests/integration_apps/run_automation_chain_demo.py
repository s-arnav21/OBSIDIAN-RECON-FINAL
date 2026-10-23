"""End-to-end automation demo for the web -> shell -> discovery chain.

Runs the real MITRE technique scripts (T1190 -> T1059.004 -> T1082) through the
automation runner against the local, loopback-only synthetic fixture. The
fixture interprets fixed synthetic tokens and never touches the host OS, so the
whole chain can be demonstrated unattended with no real exploitation.

Run it with::

    python -m tests.integration_apps.run_automation_chain_demo

or::

    python tests/integration_apps/run_automation_chain_demo.py
"""

from __future__ import annotations

from typing import List

from app.automation import runner
from app.automation.base import AutomationContext, TechniqueResult
from app.models.finding import Finding, ValidationStatus
from tests.integration_apps.vulnerable_web_app import LocalVulnerableAppServer


def _finding(origin: str, **overrides) -> Finding:
    values = dict(
        finding_id="demo-finding",
        scan_id="demo-scan",
        asset_id="demo-asset",
        target=origin,
        host="127.0.0.1",
        source="controlled_fixture",
        vulnerability_type="sql_injection",
        endpoint="/items",
        severity="high",
        validation_status=ValidationStatus.DETECTED,
        validation_confidence=0.2,
    )
    values.update(overrides)
    return Finding(**values)


def run_demo() -> List[TechniqueResult]:
    """Run T1190 -> T1059.004 -> T1082 against the fixture; return the results."""
    server = LocalVulnerableAppServer()
    origin = server.start()
    results: List[TechniqueResult] = []
    try:
        sqli = _finding(
            origin,
            finding_id="demo-sqli",
            vulnerability_type="sql_injection",
            validator_id="generic-http-sqli",
            http_method="GET",
            parameter_name="id",
            parameter_location="query",
        )
        results.append(runner.run_technique(
            "T1190",
            AutomationContext(
                target=origin,
                authorized=True,
                finding=sqli,
                capabilities=("discovered_services",),
            ),
        ))

        command = _finding(
            origin,
            finding_id="demo-command",
            vulnerability_type="command_execution",
            validator_id="generic-http-command-execution",
            endpoint="/admin/diagnostics",
            http_method="POST",
            parameter_name="diagnostic_token",
            parameter_location="form",
            severity="critical",
        )
        results.append(runner.run_technique(
            "T1059.004",
            AutomationContext(
                target=origin,
                authorized=True,
                finding=command,
                capabilities=("application_compromise",),
            ),
        ))

        sysinfo = _finding(
            origin,
            finding_id="demo-sysinfo",
            vulnerability_type="system_information_discovery",
            validator_id="controlled-http-system-information-discovery",
            endpoint="/admin/system-information",
            http_method="POST",
            parameter_name="discovery_token",
            parameter_location="form",
            severity="low",
        )
        results.append(runner.run_technique(
            "T1082",
            AutomationContext(
                target=origin,
                authorized=True,
                finding=sysinfo,
                capabilities=("command_execution",),
            ),
        ))
        return results
    finally:
        server.stop()


def main() -> None:
    print("Target: local loopback synthetic fixture (no real exploitation)")
    print("-" * 68)
    for result in run_demo():
        print(f"{result.technique_id:<10} {result.status:<12} {result.summary}")
        if result.capabilities_gained:
            print(f"           grants: {', '.join(result.capabilities_gained)}")


if __name__ == "__main__":
    main()

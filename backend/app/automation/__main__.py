"""Command-line entry point for the MITRE technique automation layer.

Usage examples::

    python -m app.automation catalog
    python -m app.automation run --technique T1190 --target http://10.0.0.5 \
        --authorized --endpoint /items --param id --param-location query
    python -m app.automation chain --target http://10.0.0.5 --authorized \
        --findings findings.json --max-steps 8

Every command requires ``--authorized`` to actually act; without it the CLI
refuses to run so nothing is sent to a target accidentally.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.automation import technique_catalog
from app.automation.base import AutomationContext
from app.automation.runner import run_technique

_EXIT_OK = 0
_EXIT_ERROR = 1
_EXIT_USAGE = 2

_OPTIONAL_FINDING_KEYS = (
    "port",
    "protocol",
    "endpoint",
    "template_id",
    "severity",
    "validation_status",
    "validation_confidence",
    "validator_id",
    "http_method",
    "parameter_name",
    "parameter_location",
    "mitre_technique_id",
    "cwe",
    "owasp_category",
)


def _synthetic_finding(
    target: str,
    *,
    scan_id: str,
    asset_id: str,
    vulnerability_type: str,
    finding_id: Optional[str] = None,
    **overrides: Any,
):
    from app.models.finding import Finding

    host = urlparse(target).hostname or target
    data: Dict[str, Any] = {
        "finding_id": finding_id or f"finding-{scan_id}-0",
        "scan_id": scan_id,
        "asset_id": asset_id,
        "target": target,
        "host": host,
        "source": "automation-cli",
        "vulnerability_type": vulnerability_type,
    }
    for key in _OPTIONAL_FINDING_KEYS:
        if key in overrides and overrides[key] is not None:
            data[key] = overrides[key]
    return Finding(**data)


def _findings_from_file(path: str, target: str, scan_id: str, asset_id: str):
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        raise ValueError("findings file must contain a JSON list")
    findings = []
    for index, entry in enumerate(payload):
        if not isinstance(entry, dict):
            raise ValueError("each finding must be a JSON object")
        findings.append(
            _synthetic_finding(
                target,
                scan_id=scan_id,
                asset_id=asset_id,
                vulnerability_type=entry.get(
                    "vulnerability_type", "service_scan"
                ),
                finding_id=entry.get("finding_id") or f"finding-{scan_id}-{index}",
                **{k: v for k, v in entry.items() if k in _OPTIONAL_FINDING_KEYS},
            )
        )
    return findings


def _cmd_catalog(args: argparse.Namespace) -> int:
    print(json.dumps(technique_catalog(), indent=2, sort_keys=True))
    return _EXIT_OK


def _cmd_run(args: argparse.Namespace) -> int:
    if not args.authorized:
        print(
            "refusing to run without --authorized", file=sys.stderr
        )
        return _EXIT_USAGE

    finding = None
    if args.finding_json:
        with open(args.finding_json, "r", encoding="utf-8") as handle:
            entry = json.load(handle)
        finding = _synthetic_finding(
            args.target,
            scan_id=args.scan_id,
            asset_id=args.asset_id,
            vulnerability_type=entry.get("vulnerability_type", "unknown"),
            finding_id=entry.get("finding_id") or "finding-cli-0",
            **{k: v for k, v in entry.items() if k in _OPTIONAL_FINDING_KEYS},
        )
    elif args.endpoint or args.param:
        finding = _synthetic_finding(
            args.target,
            scan_id=args.scan_id,
            asset_id=args.asset_id,
            vulnerability_type=args.vuln_type,
            endpoint=args.endpoint,
            http_method=args.method,
            parameter_name=args.param,
            parameter_location=args.param_location,
        )

    ctx = AutomationContext(
        target=args.target,
        authorized=args.authorized,
        finding=finding,
        options={},
        capabilities=("discovered_services", "reachable_web_application", "unauthenticated"),
    )
    result = run_technique(args.technique, ctx)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return _EXIT_OK if result.status != "error" else _EXIT_ERROR


def _cmd_chain(args: argparse.Namespace) -> int:
    if not args.authorized:
        print(
            "refusing to run without --authorized", file=sys.stderr
        )
        return _EXIT_USAGE

    from app.agent.models import AgentState
    from app.automation.chain import run_chain

    if args.findings:
        findings = _findings_from_file(
            args.findings, args.target, args.scan_id, args.asset_id
        )
    else:
        # An unconfirmed reachability finding is enough to let the chain begin
        # with active scanning (T1595).
        findings = [
            _synthetic_finding(
                args.target,
                scan_id=args.scan_id,
                asset_id=args.asset_id,
                vulnerability_type="service_scan",
                endpoint="/",
                severity="info",
            )
        ]

    state = AgentState.from_findings(
        scan_id=args.scan_id,
        target=args.target,
        asset_id=args.asset_id,
        authorized=args.authorized,
        findings=findings,
        maximum_steps=args.max_steps,
    )
    result = run_chain(state)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return _EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="app.automation",
        description="Run MITRE ATT&CK technique automation scripts.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    catalog = sub.add_parser("catalog", help="list registered techniques")
    catalog.set_defaults(func=_cmd_catalog)

    run = sub.add_parser("run", help="run a single technique")
    run.add_argument("--technique", required=True)
    run.add_argument("--target", required=True)
    run.add_argument("--authorized", action="store_true")
    run.add_argument("--finding-json", default=None)
    run.add_argument("--vuln-type", default="unknown")
    run.add_argument("--endpoint", default=None)
    run.add_argument("--method", default="GET")
    run.add_argument("--param", default=None)
    run.add_argument("--param-location", default="query")
    run.add_argument("--scan-id", default="cli-scan")
    run.add_argument("--asset-id", default="cli-asset")
    run.set_defaults(func=_cmd_run)

    chain = sub.add_parser("chain", help="run the deterministic technique chain")
    chain.add_argument("--target", required=True)
    chain.add_argument("--authorized", action="store_true")
    chain.add_argument("--findings", default=None)
    chain.add_argument("--max-steps", type=int, default=8)
    chain.add_argument("--scan-id", default="cli-scan")
    chain.add_argument("--asset-id", default="cli-asset")
    chain.set_defaults(func=_cmd_chain)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return _EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 — CLI reports rather than tracebacks
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())

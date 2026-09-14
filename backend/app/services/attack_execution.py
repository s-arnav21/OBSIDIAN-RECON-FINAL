"""Execution layer that actually performs a planned attack.

One of two paths runs per attempt:

- *validator path*: the finding's registered canonical validator sends the real,
  bounded exploit requests (SQLi/XSS/SSRF/command-execution differential
  probes) against the persisted endpoint.
- *command path*: when the plan carries an explicit ``command`` (authored by the
  LLM), the executor runs it bounded (timeout, output cap, target injected via
  environment variables) and captures stdout/stderr/exit code.

The engine never invents tooling; every attempt maps to a concrete outcome.
Commands only ever run after the operator has authorized the attempt on the
API layer, and never with a controlling terminal.
"""
from __future__ import annotations

import os
import subprocess
from typing import Any, Dict, Optional

from app.db.models import FindingORM
from app.services.exploit_planner import ExploitPlan, attempt_validation

_EXEC_TIMEOUT_SECONDS = float(os.getenv("AGENT_EXEC_TIMEOUT", "30"))
_EXEC_OUTPUT_CAP = int(os.getenv("AGENT_EXEC_OUTPUT_CAP", "65536"))

_CMD_VARS = (
    "OBSIDIAN_TARGET",
    "OBSIDIAN_ASSET",
    "OBSIDIAN_ENDPOINT",
    "OBSIDIAN_HTTP_METHOD",
    "OBSIDIAN_PARAMETER",
    "OBSIDIAN_PARAMETER_LOCATION",
    "OBSIDIAN_SCAN_ID",
)


def _execution_env(finding_orm: FindingORM) -> Dict[str, str]:
    env = dict(os.environ)
    for var in _CMD_VARS:
        env.pop(var, None)
    env.update({
        "OBSIDIAN_TARGET": finding_orm.target or "",
        "OBSIDIAN_ASSET": finding_orm.asset_id or "",
        "OBSIDIAN_ENDPOINT": finding_orm.endpoint or "",
        "OBSIDIAN_HTTP_METHOD": finding_orm.http_method or "GET",
        "OBSIDIAN_PARAMETER": finding_orm.parameter_name or "",
        "OBSIDIAN_PARAMETER_LOCATION": finding_orm.parameter_location or "",
        "OBSIDIAN_SCAN_ID": finding_orm.scan_id or "",
    })
    return env


def _run_command(command: str, finding_orm: FindingORM) -> Dict[str, Any]:
    """Run one bounded command and capture the outcome."""
    try:
        completed = subprocess.run(
            ["/bin/sh", "-c", command],
            capture_output=True,
            timeout=_EXEC_TIMEOUT_SECONDS,
            env=_execution_env(finding_orm),
            cwd="/tmp",
            start_new_session=True,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "method": "command",
            "command": command[:2000],
            "exit_code": None,
            "stdout": "",
            "stderr": (
                f"command timed out after {int(_EXEC_TIMEOUT_SECONDS)}s and "
                "was terminated; output truncated."
            ),
        }
    except OSError as exc:
        return {
            "status": "error",
            "method": "command",
            "command": command[:2000],
            "exit_code": None,
            "stdout": "",
            "stderr": f"failed to launch command: {str(exc)[:300]}",
        }

    stdout = completed.stdout.decode("utf-8", errors="replace")[:_EXEC_OUTPUT_CAP]
    stderr = completed.stderr.decode("utf-8", errors="replace")[:_EXEC_OUTPUT_CAP]

    if completed.returncode == 0 and stdout.strip():
        status = "success"
    elif completed.returncode == 0:
        status = "inconclusive"
    else:
        status = "failed"

    return {
        "status": status,
        "method": "command",
        "command": command[:2000],
        "exit_code": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


def execute_planned_attack(
    plan: ExploitPlan,
    finding_orm: FindingORM,
) -> Dict[str, Any]:
    """Execute the plan, preferring an explicit command over the validator.

    The command path runs only when the planner produced a concrete executable.
    Otherwise the registered canonical validator is dispatched (real probes).
    Returns a structured attempt result consumed by the attacks router; the
    attempt was already validated as authorized before this function is called.
    """
    if plan.command and plan.command.strip():
        return _run_command(plan.command.strip(), finding_orm)
    if finding_orm.validator_id:
        attempt = attempt_validation(finding_orm)
        if attempt is not None:
            return attempt
    return {
        "status": "planned",
        "method": "no-executable",
        "stdout": "",
        "stderr": (
            "No concrete command and no registered validator are available for "
            "this finding; the attempt is recorded as planned."
        ),
    }


__all__ = ["execute_planned_attack", "_run_command"]
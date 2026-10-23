"""Execution layer that actually performs a planned attack.

One of two paths runs per attempt:

- *validator path*: the finding's registered canonical validator sends the real,
  bounded exploit requests (SQLi/XSS/SSRF/command-execution differential
  probes) against the persisted endpoint. This path always wins when a
  validator is registered.
- *command path*: only for findings without a registered validator, when the
  plan carries an explicit ``command``. The executor runs it bounded (timeout,
  output cap, target injected via environment variables) and captures
  stdout/stderr/exit code. Exit 0 is recorded as ``observed``, never as proof
  of exploitation.

The engine never invents tooling; every attempt maps to a concrete outcome.
Commands only ever run after the operator has authorized the attempt on the
API layer, and never with a controlling terminal.
"""
from __future__ import annotations

import json
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
        # Exit 0 with output is an OBSERVATION, not proof of exploitation. Only
        # a registered validator's CONFIRMED result can escalate a finding.
        status = "observed"
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
    """Execute the plan, preferring the registered validator over a command.

    A finding with a registered validator is exercised by that validator: it is
    the only path that can confirm the finding. A plan command is used only when
    the finding has no validator (or the validator cannot be dispatched).
    Returns a structured attempt result consumed by the attacks router; the
    attempt was already validated as authorized before this function is called.
    """
    if finding_orm.validator_id:
        attempt = attempt_validation(finding_orm)
        if attempt is not None:
            return _normalize_validator_attempt(attempt)
    if plan.command and plan.command.strip():
        return _run_command(plan.command.strip(), finding_orm)
    return {
        "status": "planned",
        "method": "no-executable",
        "exit_code": None,
        "stdout": "",
        "stderr": (
            "No concrete command and no registered validator are available for "
            "this finding; the attempt is recorded as planned."
        ),
    }


def _normalize_validator_attempt(attempt: Dict[str, Any]) -> Dict[str, Any]:
    """Give a validator result the same shape as a command attempt.

    ``attempt_validation`` reports status/validator/method/decision, while the
    console renders stdout/stderr/exit_code. Missing keys are filled so the
    execution panel always shows the validator's real evidence.
    """
    result = dict(attempt)
    result.setdefault("exit_code", None)
    stdout = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    if not stdout and not stderr:
        rendered = json.dumps(
            {
                "validator": result.get("validator"),
                "status": result.get("status"),
                "confidence": result.get("confidence"),
                "evidence": result.get("evidence"),
            },
            indent=2,
            default=str,
        )
        stdout = rendered
    result["stdout"] = stdout
    result["stderr"] = stderr
    return result


__all__ = ["execute_planned_attack", "_run_command"]
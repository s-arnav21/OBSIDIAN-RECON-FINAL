"""Registered tool/script worker entrypoint.

This module runs inside a hardened worker image that may contain security
tools.  It accepts only an action id and the already-validated argument object;
argument validation and scope enforcement happen in the host before the worker
is launched.  The worker cannot call arbitrary commands.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlsplit


MAX_RESULT_BYTES = 256 * 1024


def _sanitize(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "<truncated>"
    if isinstance(value, dict):
        result = {}
        for key, item in list(value.items())[:64]:
            key_text = str(key)
            if key_text.lower() in {
                "password",
                "passwd",
                "secret",
                "token",
                "cookie",
                "authorization",
                "api_key",
                "credentials",
            }:
                result[key_text] = "<redacted>"
            else:
                result[key_text] = _sanitize(item, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, depth + 1) for item in list(value)[:64]]
    if isinstance(value, str):
        return value[:8000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:1000]


def _write_result(payload: Dict[str, Any]) -> None:
    output = Path("/work/output")
    output.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(_sanitize(payload), default=str, ensure_ascii=False)
    (output / "tool_result.json").write_text(encoded[:MAX_RESULT_BYTES], encoding="utf-8")


def _run_tool(action_id: str, arguments: Dict[str, Any], task: Dict[str, Any]) -> Dict[str, Any]:
    from app.agent.tools import execute_tool

    tool_id = action_id.split(":", 1)[1]
    result = execute_tool(tool_id, dict(arguments))
    return {
        "ok": bool(result.success),
        "tool_id": tool_id,
        "output": (result.output or "")[:16000],
        "raw": (result.raw or "")[:16000],
        "error": (result.error or "")[:2000],
        "shell_obtained": bool(result.shell_obtained),
        "shell_info": result.shell_info,
        "extra": _sanitize(result.extra),
    }


def _run_validator(action_id: str, arguments: Dict[str, Any], task: Dict[str, Any]) -> Dict[str, Any]:
    import requests
    from app.agent.tools import _VALIDATOR_ID_MAP
    from app.models.finding import Finding
    from app.validation.dispatcher import dispatch

    tool_id = action_id.split(":", 1)[1]
    target = str(arguments.get("target") or task.get("target") or "")
    parsed = urlsplit(target)
    host = parsed.hostname or target
    endpoint = arguments.get("endpoint") or (parsed.path or "/")
    if endpoint and not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    finding = Finding(
        finding_id=f"task-{task.get('task_id', 'unknown')}-validator",
        scan_id=str(task.get("task_id", "task-agent")),
        asset_id=str(task.get("task_id", "task-agent")),
        target=target,
        host=host,
        source="task-agent-validator",
        vulnerability_type=tool_id.removeprefix("validate-").replace("-", "_"),
        port=parsed.port,
        protocol=parsed.scheme or "http",
        endpoint=endpoint,
        validator_id=_VALIDATOR_ID_MAP.get(tool_id),
        http_method=str(arguments.get("method") or arguments.get("http_method") or "GET").upper(),
        parameter_name=arguments.get("parameter") or arguments.get("parameter_name"),
        parameter_location=arguments.get("parameter_location"),
    )
    with requests.Session() as session:
        validation = dispatch(finding, session=session)
    return {
        "ok": validation.status in {"confirmed", "rejected"},
        "tool_id": tool_id,
        "validation": validation.to_dict() if hasattr(validation, "to_dict") else str(validation),
        "status": getattr(validation, "status", "inconclusive"),
        "error": getattr(validation, "error", None),
    }


def _run_technique(action_id: str, arguments: Dict[str, Any], task: Dict[str, Any]) -> Dict[str, Any]:
    from app.automation import get_technique
    from app.automation.base import AutomationContext

    technique_id = action_id.split(":", 1)[1]
    target = str(arguments.get("target") or task.get("target") or "")
    options = {
        key: str(value)
        for key, value in arguments.items()
        if key != "target" and isinstance(value, (str, int, float, bool))
    }
    ctx = AutomationContext(
        target=target,
        authorized=True,
        options=options,
        capabilities=(),
        artifact_dir="/work/output",
        timeout_seconds=int(os.getenv("TASK_AGENT_WORKER_TIMEOUT", "120")),
        allow_remote_fetch=False,
        lhost=os.getenv("OBSIDIAN_LHOST", "127.0.0.1"),
        lport=int(os.getenv("OBSIDIAN_LPORT", "4444")),
    )
    script = get_technique(technique_id)
    result = script.execute(ctx)
    return {
        "ok": result.confirmed,
        "technique_id": technique_id,
        "result": result.to_dict(),
    }


def main() -> int:
    try:
        job = json.loads(Path("/work/job.json").read_text(encoding="utf-8"))
        action_id = str(job.get("action_id") or "")
        arguments = job.get("arguments") if isinstance(job.get("arguments"), dict) else {}
        task = job.get("task") if isinstance(job.get("task"), dict) else {}
        if action_id.startswith("tool:"):
            payload = _run_tool(action_id, arguments, task)
        elif action_id.startswith("validator:"):
            payload = _run_validator(action_id, arguments, task)
        elif action_id.startswith("technique:"):
            payload = _run_technique(action_id, arguments, task)
        else:
            raise ValueError("unsupported registered action")
    except BaseException as exc:  # noqa: BLE001
        payload = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}"[:2048],
        }
    _write_result(payload)
    print(json.dumps({"ok": payload.get("ok", False)}, ensure_ascii=False))
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

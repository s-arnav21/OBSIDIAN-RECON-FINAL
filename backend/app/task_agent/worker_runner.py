"""Minimal isolated worker entrypoint.

This module is copied into the generated-code worker image.  It deliberately
does not import the web application.  The host writes a bounded job document and
the generated program; this runner applies OS resource limits, executes it, and
writes a small result document.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import resource
import sys
import traceback
from pathlib import Path


MAX_CAPTURE = 64 * 1024
MAX_RESULT_BYTES = 256 * 1024


def _work_root() -> Path:
    return Path(os.getenv("TASK_AGENT_WORK_ROOT", "/work")).resolve()


class CappedTextIO(io.TextIOBase):
    def __init__(self, limit: int = MAX_CAPTURE) -> None:
        self._buffer = io.StringIO()
        self._limit = limit
        self.truncated = False

    def write(self, value: str) -> int:
        if not isinstance(value, str):
            value = str(value)
        current = self._buffer.tell()
        remaining = self._limit - current
        if remaining <= 0:
            self.truncated = True
            return len(value)
        if len(value) > remaining:
            self._buffer.write(value[:remaining])
            self.truncated = True
            return len(value)
        self._buffer.write(value)
        return len(value)

    def getvalue(self) -> str:
        return self._buffer.getvalue()

    def flush(self) -> None:
        return None


def _limit_resources() -> None:
    limits = (
        (resource.RLIMIT_CPU, 60),
        (resource.RLIMIT_AS, 256 * 1024 * 1024),
        (resource.RLIMIT_FSIZE, 16 * 1024 * 1024),
        (resource.RLIMIT_NOFILE, 64),
        (resource.RLIMIT_NPROC, 32),
    )
    for resource_id, value in limits:
        try:
            soft, hard = resource.getrlimit(resource_id)
            if hard != resource.RLIM_INFINITY and value > hard:
                value = hard
            resource.setrlimit(resource_id, (value, hard))
        except (ValueError, OSError):
            continue


def _write_result(payload: dict) -> None:
    output = _work_root() / "output"
    output.mkdir(parents=True, exist_ok=True)
    target = output / "worker_result.json"
    encoded = json.dumps(payload, default=str, ensure_ascii=False)[:MAX_RESULT_BYTES]
    target.write_text(encoded, encoding="utf-8")


def _read_generated_result() -> object:
    path = _work_root() / "output" / "result.json"
    try:
        if not path.is_file() or path.stat().st_size > MAX_RESULT_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def main() -> int:
    _limit_resources()
    os.environ.pop("AGENT_LLM_API_KEY", None)
    os.environ.pop("POSTGRES_PASSWORD", None)
    os.environ.pop("MSF_RPC_PASSWORD", None)
    work_root = _work_root()
    os.chdir(work_root)
    try:
        job = json.loads((work_root / "job.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print("worker job document is invalid", file=sys.stderr)
        return 2
    kind = job.get("kind")
    stdout = CappedTextIO()
    stderr = CappedTextIO()
    exit_code = 0
    error = None
    result = None
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            if kind == "generated_code":
                code_path = work_root / "code.py"
                code = code_path.read_text(encoding="utf-8", errors="strict")
                namespace = {
                    "__name__": "__main__",
                    "__file__": str(code_path),
                    "__package__": None,
                }
                exec(compile(code, str(code_path), "exec"), namespace, namespace)
                result = _read_generated_result()
            elif kind == "script":
                script_path = str(job.get("script_path") or "")
                if not script_path or not Path(script_path).is_file():
                    raise FileNotFoundError("registered script is missing")
                argv = [script_path, *[str(item) for item in job.get("argv", [])]]
                sys.argv = argv
                import runpy

                runpy.run_path(script_path, run_name="__main__")
                result = _read_generated_result()
            else:
                raise ValueError("unsupported worker job kind")
    except SystemExit as exc:
        try:
            exit_code = int(exc.code) if exc.code is not None else 0
        except (TypeError, ValueError):
            exit_code = 1
    except BaseException as exc:  # noqa: BLE001 - worker reports failure, never leaks host
        exit_code = 1
        error = f"{type(exc).__name__}: {exc}"[:2048]
        traceback.print_exc(limit=5)
    payload = {
        "ok": exit_code == 0 and error is None,
        "kind": kind,
        "exit_code": exit_code,
        "error": error,
        "stdout": stdout.getvalue(),
        "stderr": stderr.getvalue(),
        "stdout_truncated": stdout.truncated,
        "stderr_truncated": stderr.truncated,
        "result": result,
    }
    _write_result(payload)
    return 0 if exit_code == 0 and error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())

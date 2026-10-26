"""Isolated execution for generated code and registered tool workers.

Docker is the production sandbox.  A local subprocess backend exists only for
offline CI and demos when explicitly enabled; it is never reported as Docker
isolation.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence
from uuid import uuid4

from app.core.config import settings


class SandboxError(RuntimeError):
    pass


class SandboxUnavailable(SandboxError):
    pass


class SandboxTimeout(SandboxError):
    pass


@dataclass
class SandboxResult:
    backend: str
    kind: str
    job_id: str
    exit_code: Optional[int]
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    timed_out: bool = False
    output_truncated: bool = False
    result_data: Any = None
    worker_result: Dict[str, Any] = field(default_factory=dict)
    work_dir: str = ""
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return (
            not self.timed_out
            and self.exit_code == 0
            and self.error is None
        )

    @property
    def isolation(self) -> str:
        if self.backend == "docker":
            return "docker"
        return "local-process (not Docker; CI/demo only)"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "isolation": self.isolation,
            "kind": self.kind,
            "job_id": self.job_id,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_seconds": self.duration_seconds,
            "timed_out": self.timed_out,
            "output_truncated": self.output_truncated,
            "result_data": self.result_data,
            "worker_result": self.worker_result,
            "work_dir": self.work_dir,
            "error": self.error,
            "ok": self.ok,
        }


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value)
    return cleaned[:48].strip("-") or "job"


def prepare_work_dir(task_id: str, step_number: int, *, root: Optional[Path] = None) -> Path:
    base = Path(root or settings.TASK_AGENT_ARTIFACT_DIR).expanduser().resolve()
    task_component = _safe_name(task_id)
    path = base / task_component / f"step-{int(step_number):03d}-{uuid4().hex[:8]}"
    (path / "output").mkdir(parents=True, exist_ok=True)
    (path / "inputs").mkdir(parents=True, exist_ok=True)
    # The worker runs as a different unprivileged UID in Docker.
    try:
        os.chmod(path, 0o777)
        os.chmod(path / "output", 0o777)
    except OSError:
        pass
    return path


def prepare_inputs(
    work_dir: Path,
    input_paths: Iterable[str],
    *,
    max_total_bytes: int = 64 * 1024 * 1024,
) -> list[dict]:
    """Copy declared inputs into a dedicated read-only worker mount."""
    destination = work_dir / "inputs"
    destination.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(destination, 0o755)
    except OSError:
        pass
    manifest: list[dict] = []
    total = 0
    for index, value in enumerate(input_paths):
        path = Path(value).expanduser().resolve()
        if not path.is_file():
            raise SandboxError(f"declared input is not a regular file: {value}")
        name = f"{index:03d}-{_safe_name(path.name)}"
        target = destination / name
        size = path.stat().st_size
        total += size
        if total > max_total_bytes:
            raise SandboxError("declared inputs exceed the worker input size limit")
        shutil.copyfile(path, target)
        try:
            os.chmod(target, 0o444)
        except OSError:
            pass
        manifest.append(
            {
                "source": str(path),
                "container": f"/inputs/{name}",
                "size_bytes": size,
            }
        )
    return manifest


def _reader(stream, chunks: list[bytes], state: dict, maximum: int) -> None:
    try:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                chunk = str(chunk).encode("utf-8", errors="replace")
            if state["bytes"] + len(chunk) > maximum:
                remaining = max(0, maximum - state["bytes"])
                if remaining:
                    chunks.append(chunk[:remaining])
                    state["bytes"] += remaining
                state["truncated"] = True
                continue
            chunks.append(chunk)
            state["bytes"] += len(chunk)
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _collect_process(
    process: subprocess.Popen,
    *,
    timeout: int,
    max_output_bytes: int,
    cancel_event: Optional[threading.Event],
    kill_callback=None,
) -> tuple[int, str, str, bool, bool, str]:
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    out_state = {"bytes": 0, "truncated": False}
    err_state = {"bytes": 0, "truncated": False}
    out_thread = threading.Thread(
        target=_reader,
        args=(process.stdout, out_chunks, out_state, max_output_bytes),
        daemon=True,
    )
    err_thread = threading.Thread(
        target=_reader,
        args=(process.stderr, err_chunks, err_state, max_output_bytes),
        daemon=True,
    )
    out_thread.start()
    err_thread.start()
    timed_out = False
    cancelled = False
    deadline = time.monotonic() + max(1, timeout)
    while process.poll() is None:
        if cancel_event is not None and cancel_event.is_set():
            cancelled = True
            if kill_callback:
                kill_callback()
            process.terminate()
            break
        if time.monotonic() >= deadline:
            timed_out = True
            if kill_callback:
                kill_callback()
            process.kill()
            break
        time.sleep(0.1)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    out_thread.join(timeout=5)
    err_thread.join(timeout=5)
    return (
        process.returncode if process.returncode is not None else -1,
        b"".join(out_chunks).decode("utf-8", errors="replace"),
        b"".join(err_chunks).decode("utf-8", errors="replace"),
        timed_out,
        cancelled or out_state["truncated"] or err_state["truncated"],
        "cancelled" if cancelled else "",
    )


def _read_json_limited(path: Path, maximum: int = 256 * 1024) -> Any:
    try:
        if not path.is_file() or path.stat().st_size > maximum:
            return None
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


class BaseSandbox:
    backend_name = "unknown"

    def available(self) -> bool:
        return True

    def run_job(
        self,
        *,
        job: Mapping[str, Any],
        work_dir: Path,
        timeout_seconds: int,
        network: bool = False,
        cancel_event: Optional[threading.Event] = None,
    ) -> SandboxResult:
        raise NotImplementedError


class LocalSandbox(BaseSandbox):
    """Explicitly opt-in local process fallback for offline CI and demos."""

    backend_name = "local"

    def __init__(self) -> None:
        if not settings.TASK_AGENT_ALLOW_LOCAL_SANDBOX:
            raise SandboxUnavailable(
                "local sandbox is disabled; enable TASK_AGENT_ALLOW_LOCAL_SANDBOX "
                "only for offline CI/demos"
            )
        self.runner = Path(__file__).with_name("worker_runner.py")
        if not self.runner.is_file():
            raise SandboxUnavailable("worker_runner.py is unavailable")

    def run_job(
        self,
        *,
        job: Mapping[str, Any],
        work_dir: Path,
        timeout_seconds: int,
        network: bool = False,
        cancel_event: Optional[threading.Event] = None,
    ) -> SandboxResult:
        if network:
            raise SandboxUnavailable(
                "the local demo sandbox cannot provide network isolation for tools"
            )
        job_path = work_dir / "job.json"
        job_path.write_text(json.dumps(dict(job), default=str), encoding="utf-8")
        started = time.monotonic()
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(work_dir / "home"),
            "TMPDIR": str(work_dir / "tmp"),
            "TASK_AGENT_WORK_ROOT": str(work_dir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
        }
        (work_dir / "home").mkdir(exist_ok=True)
        (work_dir / "tmp").mkdir(exist_ok=True)
        command = [sys.executable, str(self.runner)]
        try:
            process = subprocess.Popen(
                command,
                cwd=str(work_dir),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as exc:
            raise SandboxUnavailable(f"local worker could not start: {exc}") from exc
        exit_code, stdout, stderr, timed_out, truncated, cancel_reason = _collect_process(
            process,
            timeout=min(timeout_seconds, settings.TASK_AGENT_LOCAL_SANDBOX_TIMEOUT),
            max_output_bytes=settings.TASK_AGENT_MAX_OUTPUT_BYTES,
            cancel_event=cancel_event,
        )
        worker_result = _read_json_limited(work_dir / "output" / "worker_result.json") or {}
        result_data = (
            worker_result.get("result")
            if isinstance(worker_result, Mapping)
            else None
        )
        error = None
        if cancel_reason:
            error = "cancelled"
        elif timed_out:
            error = "timed out"
        elif not isinstance(worker_result, Mapping) or not worker_result.get("ok"):
            error = str(
                (worker_result or {}).get("error")
                if isinstance(worker_result, Mapping)
                else "worker result missing"
            ) or "worker failed"
        return SandboxResult(
            backend=self.backend_name,
            kind=str(job.get("kind", "")),
            job_id=str(job.get("job_id", "")),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            timed_out=timed_out,
            output_truncated=truncated,
            result_data=result_data,
            worker_result=dict(worker_result) if isinstance(worker_result, Mapping) else {},
            work_dir=str(work_dir),
            error=error,
        )


class DockerSandbox(BaseSandbox):
    backend_name = "docker"

    def __init__(self, docker_binary: Optional[str] = None) -> None:
        self.docker_binary = docker_binary or os.getenv("DOCKER_BINARY", "docker")
        self._available: Optional[bool] = None

    def available(self) -> bool:
        if self._available is not None:
            return self._available
        binary = shutil.which(self.docker_binary)
        if not binary:
            self._available = False
            return False
        try:
            result = subprocess.run(
                [binary, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=8,
            )
            self._available = result.returncode == 0 and bool(result.stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            self._available = False
        return bool(self._available)

    def _network_name(self, network: bool) -> str:
        if not network:
            return "none"
        configured = settings.TASK_AGENT_LAB_NETWORK
        if not configured or configured == "none":
            return "none"
        return configured

    def _image_for(self, kind: str) -> str:
        if kind == "generated_code":
            return settings.TASK_AGENT_WORKER_IMAGE
        return settings.TASK_AGENT_TOOL_WORKER_IMAGE

    def _command_for(self, kind: str, job: Mapping[str, Any]) -> list[str]:
        if kind == "generated_code":
            return ["/opt/worker/runner.py"]
        if kind == "script":
            return [
                str(
                    job.get("container_script_path")
                    or job.get("script_path")
                    or "/app/scripts/validate_planner_dataset.py"
                ),
                *[str(arg) for arg in job.get("argv", [])],
            ]
        return ["-m", "app.task_agent.worker_tool"]

    def run_job(
        self,
        *,
        job: Mapping[str, Any],
        work_dir: Path,
        timeout_seconds: int,
        network: bool = False,
        cancel_event: Optional[threading.Event] = None,
    ) -> SandboxResult:
        if not self.available():
            raise SandboxUnavailable("Docker is not available on this host")
        kind = str(job.get("kind", ""))
        image = self._image_for(kind)
        if not image:
            raise SandboxUnavailable("worker image is not configured")
        job_path = work_dir / "job.json"
        job_path.write_text(json.dumps(dict(job), default=str), encoding="utf-8")
        name = f"obsidian-task-{uuid4().hex[:16]}"
        volume = f"{str(work_dir.resolve())}:/work:rw"
        inputs_volume = f"{str((work_dir / 'inputs').resolve())}:/inputs:ro"
        command = [
            self.docker_binary,
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            self._network_name(network),
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(max(8, settings.TASK_AGENT_WORKER_PIDS)),
            "--memory",
            settings.TASK_AGENT_WORKER_MEMORY,
            "--cpus",
            settings.TASK_AGENT_WORKER_CPUS,
            "--user",
            "65532:65532",
            "--env",
            "TASK_AGENT_WORK_ROOT=/work",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            "PYTHONPATH=/app",
            "--volume",
            volume,
            "--volume",
            inputs_volume,
            "--workdir",
            "/app" if kind != "generated_code" else "/work",
        ]
        if kind != "generated_code":
            command.extend(["--entrypoint", "python", image])
        else:
            command.append(image)
        command.extend(self._command_for(kind, job))
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as exc:
            raise SandboxUnavailable(f"Docker could not start the worker: {exc}") from exc

        def kill() -> None:
            try:
                subprocess.run(
                    [self.docker_binary, "kill", name],
                    capture_output=True,
                    timeout=10,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass

        exit_code, stdout, stderr, timed_out, truncated, cancel_reason = _collect_process(
            process,
            timeout=min(timeout_seconds, settings.TASK_AGENT_WORKER_TIMEOUT),
            max_output_bytes=settings.TASK_AGENT_MAX_OUTPUT_BYTES,
            cancel_event=cancel_event,
            kill_callback=kill,
        )
        worker_result = _read_json_limited(work_dir / "output" / "worker_result.json") or {}
        if not worker_result:
            worker_result = _read_json_limited(work_dir / "output" / "tool_result.json") or {}
        result_data = (
            worker_result.get("result")
            if isinstance(worker_result, Mapping)
            else None
        )
        error = None
        if cancel_reason:
            error = "cancelled"
        elif timed_out:
            error = "timed out"
        elif not isinstance(worker_result, Mapping) or not worker_result.get("ok"):
            error = str(
                (worker_result or {}).get("error")
                if isinstance(worker_result, Mapping)
                else "worker result missing"
            ) or "worker failed"
        return SandboxResult(
            backend=self.backend_name,
            kind=kind,
            job_id=str(job.get("job_id", "")),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            timed_out=timed_out,
            output_truncated=truncated,
            result_data=result_data,
            worker_result=dict(worker_result) if isinstance(worker_result, Mapping) else {},
            work_dir=str(work_dir),
            error=error,
        )


class SandboxManager:
    def __init__(self, backend: Optional[str] = None) -> None:
        self.backend = (backend or settings.TASK_AGENT_SANDBOX_BACKEND).lower()
        self._sandbox: Optional[BaseSandbox] = None
        self._error: Optional[str] = None
        if self.backend == "docker":
            sandbox = DockerSandbox()
            if sandbox.available():
                self._sandbox = sandbox
            else:
                self._error = "Docker is not available"
        elif self.backend == "local":
            try:
                self._sandbox = LocalSandbox()
            except SandboxUnavailable as exc:
                self._error = str(exc)
        else:
            self._error = f"unknown sandbox backend {self.backend!r}"

    @property
    def available(self) -> bool:
        return self._sandbox is not None and self._sandbox.available()

    @property
    def error(self) -> Optional[str]:
        return self._error

    @property
    def isolation(self) -> str:
        if self._sandbox is None:
            return "unavailable"
        if isinstance(self._sandbox, DockerSandbox):
            return "docker"
        return "local-process (not Docker; CI/demo only)"

    def run_job(self, **kwargs) -> SandboxResult:
        if self._sandbox is None:
            raise SandboxUnavailable(self._error or "sandbox is unavailable")
        return self._sandbox.run_job(**kwargs)


__all__ = [
    "BaseSandbox",
    "DockerSandbox",
    "LocalSandbox",
    "SandboxError",
    "SandboxManager",
    "SandboxResult",
    "SandboxTimeout",
    "SandboxUnavailable",
    "prepare_inputs",
    "prepare_work_dir",
]

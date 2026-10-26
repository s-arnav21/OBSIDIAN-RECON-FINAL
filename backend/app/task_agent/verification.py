"""Verification of task observations.

An exit code is never treated as proof of success.  Verification looks for
structured, action-specific evidence and records every failed check.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

from app.task_agent.actions import ActionSpec
from app.task_agent.contracts import (
    PlannerDecision,
    TaskContract,
    VerificationCheck,
    VerificationResult,
    VerificationStatus,
)
from app.task_agent.sandbox import SandboxResult


class TaskVerifier:
    """Deterministic verifier shared by the runner, API, and tests."""

    def verify(
        self,
        action: ActionSpec,
        decision: PlannerDecision,
        result: SandboxResult,
        task: TaskContract,
        *,
        work_dir: Optional[Path] = None,
        artifact_paths: Sequence[str] = (),
        expected_outputs: Sequence[str] = (),
        inspection: Optional[Mapping[str, Any]] = None,
    ) -> VerificationResult:
        checks: list[VerificationCheck] = []
        if result.timed_out:
            checks.append(
                VerificationCheck(
                    "worker_timeout",
                    False,
                    f"worker exceeded {settings_timeout()} seconds",
                )
            )
            return VerificationResult(
                status=VerificationStatus.TIMED_OUT,
                checks=tuple(checks),
                reason="The worker timed out; no result was verified.",
            )
        if result.error == "cancelled":
            checks.append(VerificationCheck("cancelled", False, "operator cancelled"))
            return VerificationResult(
                status=VerificationStatus.BLOCKED,
                checks=tuple(checks),
                reason="Execution was cancelled.",
            )
        checks.append(
            VerificationCheck(
                "worker_exit",
                result.exit_code == 0,
                f"exit_code={result.exit_code}",
                result.exit_code,
            )
        )
        checks.append(
            VerificationCheck(
                "worker_result_document",
                isinstance(result.worker_result, Mapping)
                and bool(result.worker_result),
                "worker_result.json present"
                if result.worker_result
                else "worker_result.json missing",
            )
        )
        if result.backend != "docker":
            checks.append(
                VerificationCheck(
                    "docker_isolation",
                    False,
                    "local process sandbox used; not Docker isolation",
                )
            )
        else:
            checks.append(VerificationCheck("docker_isolation", True, "docker"))

        if action.action_id == "script:inspect-json":
            return self._verify_inspection(checks, inspection or {})
        if action.kind == "generated_code":
            return self._verify_generated(
                checks,
                result,
                work_dir=work_dir,
                artifact_paths=artifact_paths,
                expected_outputs=expected_outputs,
            )
        if action.kind == "script":
            return self._verify_script(checks, action, result, artifact_paths)
        if action.kind == "validator":
            return self._verify_validator(checks, result)
        if action.kind == "technique":
            return self._verify_technique(checks, result)
        if action.kind == "tool":
            return self._verify_tool(checks, action, result)
        return VerificationResult(
            status=VerificationStatus.COMPLETED,
            checks=tuple(checks),
            reason="Action completed but has no action-specific verifier.",
        )

    def _verify_inspection(
        self,
        checks: list[VerificationCheck],
        inspection: Mapping[str, Any],
    ) -> VerificationResult:
        parsed = inspection.get("parsed")
        checks.append(
            VerificationCheck(
                "artifact_json",
                parsed is not None,
                "JSON parsed" if parsed is not None else "JSON did not parse",
            )
        )
        checks.append(
            VerificationCheck(
                "artifact_hash",
                bool(inspection.get("sha256")),
                "sha256 recorded" if inspection.get("sha256") else "sha256 missing",
                inspection.get("sha256"),
            )
        )
        if parsed is not None and inspection.get("sha256"):
            return VerificationResult(
                status=VerificationStatus.VERIFIED_SUCCESS,
                checks=tuple(checks),
                reason="Artifact parsed and its hash was recorded.",
            )
        return VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            checks=tuple(checks),
            reason="Artifact inspection did not produce verifiable structured data.",
        )

    def _verify_generated(
        self,
        checks: list[VerificationCheck],
        result: SandboxResult,
        *,
        work_dir: Optional[Path],
        artifact_paths: Sequence[str],
        expected_outputs: Sequence[str],
    ) -> VerificationResult:
        payload = result.worker_result if isinstance(result.worker_result, Mapping) else {}
        worker_ok = bool(payload.get("ok"))
        checks.append(
            VerificationCheck("worker_ok", worker_ok, str(payload.get("error") or "ok"))
        )
        structured = result.result_data
        checks.append(
            VerificationCheck(
                "structured_output",
                isinstance(structured, (dict, list)) and bool(structured),
                "structured result.json present"
                if isinstance(structured, (dict, list)) and structured
                else "no structured result.json",
            )
        )
        output_file = None
        if work_dir is not None:
            candidate = Path(work_dir) / "output" / "result.json"
            if candidate.is_file():
                output_file = candidate
        checks.append(
            VerificationCheck(
                "output_artifact",
                bool(output_file and output_file.stat().st_size > 0),
                str(output_file) if output_file else "result.json missing",
            )
        )
        checks.append(
            VerificationCheck(
                "artifact_hashes",
                all(Path(path).is_file() for path in artifact_paths),
                f"{sum(1 for path in artifact_paths if Path(path).is_file())} artifact(s)",
            )
        )
        if expected_outputs:
            serialized = json.dumps(
                {"result": structured, "artifacts": list(artifact_paths)},
                default=str,
            ).lower()
            matched = [
                item for item in expected_outputs if item.lower() in serialized
            ]
            checks.append(
                VerificationCheck(
                    "expected_outputs",
                    bool(matched),
                    f"matched {len(matched)} of {len(expected_outputs)}",
                )
            )
        if (
            worker_ok
            and isinstance(structured, (dict, list))
            and structured
            and output_file is not None
            and output_file.stat().st_size > 0
            and all(Path(path).is_file() for path in artifact_paths)
        ):
            return VerificationResult(
                status=VerificationStatus.VERIFIED_SUCCESS,
                checks=tuple(checks),
                reason="Generated analysis produced structured output and a verified artifact.",
            )
        if result.exit_code not in (0, None):
            status = VerificationStatus.FAILED
            reason = "The generated worker failed."
        else:
            status = VerificationStatus.INCONCLUSIVE
            reason = "The worker ran but did not produce verifiable structured output."
        return VerificationResult(status=status, checks=tuple(checks), reason=reason)

    def _verify_script(
        self,
        checks: list[VerificationCheck],
        action: ActionSpec,
        result: SandboxResult,
        artifact_paths: Sequence[str],
    ) -> VerificationResult:
        checks.append(
            VerificationCheck(
                "script_artifact",
                bool(artifact_paths)
                and all(Path(path).is_file() for path in artifact_paths),
                f"{len(artifact_paths)} artifact(s)",
            )
        )
        text = result.stdout or ""
        if action.action_id == "script:validate-planner-dataset":
            match = re.search(r"OK:\s*(\d+)\s+records", text, re.IGNORECASE)
            checks.append(
                VerificationCheck(
                    "dataset_record_signal",
                    bool(match and int(match.group(1)) > 0),
                    match.group(0) if match else "no OK record count",
                )
            )
            if match and int(match.group(1)) > 0 and result.exit_code == 0:
                return VerificationResult(
                    status=VerificationStatus.VERIFIED_SUCCESS,
                    checks=tuple(checks),
                    reason="Dataset validator emitted a positive record count.",
                )
            return VerificationResult(
                status=VerificationStatus.FAILED
                if result.exit_code not in (0, None)
                else VerificationStatus.INCONCLUSIVE,
                checks=tuple(checks),
                reason="Dataset validation did not produce a positive verified result.",
            )
        checks.append(
            VerificationCheck(
                "script_stdout",
                bool(text.strip()),
                "stdout captured" if text.strip() else "stdout empty",
            )
        )
        if result.exit_code == 0 and text.strip() and artifact_paths:
            return VerificationResult(
                status=VerificationStatus.COMPLETED,
                checks=tuple(checks),
                reason="Script completed and its output was archived; no action-specific verifier exists.",
            )
        return VerificationResult(
            status=VerificationStatus.FAILED
            if result.exit_code not in (0, None)
            else VerificationStatus.INCONCLUSIVE,
            checks=tuple(checks),
            reason="Script did not produce a verifiable result.",
        )

    def _verify_validator(
        self,
        checks: list[VerificationCheck],
        result: SandboxResult,
    ) -> VerificationResult:
        payload = result.worker_result if isinstance(result.worker_result, Mapping) else {}
        status = str(payload.get("status") or "").lower()
        validation = payload.get("validation")
        checks.append(
            VerificationCheck(
                "validator_status",
                status in {"confirmed", "rejected"},
                status or "missing",
            )
        )
        checks.append(
            VerificationCheck(
                "structured_evidence",
                isinstance(validation, Mapping) and bool(validation),
                "validation object present" if validation else "missing",
            )
        )
        if status == "confirmed":
            return VerificationResult(
                status=VerificationStatus.VERIFIED_SUCCESS,
                checks=tuple(checks),
                reason="Registered validator confirmed the finding with structured evidence.",
            )
        if status == "rejected":
            return VerificationResult(
                status=VerificationStatus.COMPLETED,
                checks=tuple(checks),
                reason="Registered validator ran and rejected the hypothesis.",
            )
        return VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            checks=tuple(checks),
            reason="Validator did not produce a confirmed or rejected result.",
        )

    def _verify_technique(
        self,
        checks: list[VerificationCheck],
        result: SandboxResult,
    ) -> VerificationResult:
        payload = result.worker_result if isinstance(result.worker_result, Mapping) else {}
        technique = payload.get("result") if isinstance(payload.get("result"), Mapping) else {}
        status = str(technique.get("status") or "").lower()
        evidence = technique.get("evidence")
        checks.append(
            VerificationCheck("technique_status", bool(status), status or "missing")
        )
        checks.append(
            VerificationCheck(
                "technique_evidence",
                isinstance(evidence, Mapping) and bool(evidence),
                "evidence present" if evidence else "evidence missing",
            )
        )
        if status == "confirmed" and isinstance(evidence, Mapping) and evidence:
            return VerificationResult(
                status=VerificationStatus.VERIFIED_SUCCESS,
                checks=tuple(checks),
                reason="Technique confirmed with structured evidence.",
            )
        if status in {"rejected", "inconclusive", "skipped"}:
            return VerificationResult(
                status=VerificationStatus.COMPLETED,
                checks=tuple(checks),
                reason=f"Technique returned a non-confirmed status: {status}.",
            )
        if status == "blocked":
            return VerificationResult(
                status=VerificationStatus.BLOCKED,
                checks=tuple(checks),
                reason="Technique was blocked by a missing prerequisite or policy.",
            )
        return VerificationResult(
            status=VerificationStatus.FAILED,
            checks=tuple(checks),
            reason="Technique execution did not produce a usable result.",
        )

    def _verify_tool(
        self,
        checks: list[VerificationCheck],
        action: ActionSpec,
        result: SandboxResult,
    ) -> VerificationResult:
        payload = result.worker_result if isinstance(result.worker_result, Mapping) else {}
        output = str(payload.get("output") or result.stdout or "")
        extra = payload.get("extra") if isinstance(payload.get("extra"), Mapping) else {}
        tool_id = action.action_id.split(":", 1)[-1]
        structured: Dict[str, Any] = {}
        verified = False
        completed = bool(payload.get("ok"))
        if tool_id == "sqlmap-exploit":
            databases = extra.get("databases") if isinstance(extra, Mapping) else None
            structured = {"databases": databases or []}
            verified = bool(databases) and "vulnerable" in output.lower()
        elif tool_id == "hydra-brute":
            credentials = extra.get("credentials") if isinstance(extra, Mapping) else None
            structured = {"credential_count": len(credentials or [])}
            completed = bool(credentials)
            # Recovered material is not a verified session by itself.
        elif tool_id == "nmap-vuln-scripts":
            structured = {
                "vulnerability_signal": "VULNERABLE" in output
            }
            verified = bool(structured["vulnerability_signal"])
        elif tool_id in {"lfi-exploit", "xxe-exploit"}:
            structured = {
                "file_marker": any(
                    marker in output
                    for marker in ("root:x:0:0", "daemon:", "bin:")
                )
            }
            verified = bool(structured["file_marker"])
        elif tool_id in {"gobuster-dir", "ffuf-fuzz", "katana-crawl"}:
            key = "urls" if tool_id == "katana-crawl" else "paths"
            items = extra.get(key) if isinstance(extra, Mapping) else None
            structured = {key: list(items or [])[:64]}
            verified = bool(items)
        elif tool_id == "nikto-scan":
            structured = {"finding_marker": "+ " in output}
            completed = structured["finding_marker"]
        elif tool_id.startswith("metasploit-"):
            structured = {"shell_obtained": bool(payload.get("shell_obtained"))}
            verified = bool(payload.get("shell_obtained"))
        checks.append(
            VerificationCheck(
                "structured_tool_signal",
                bool(structured),
                json.dumps(structured, default=str)[:1000],
            )
        )
        if verified:
            return VerificationResult(
                status=VerificationStatus.VERIFIED_SUCCESS,
                checks=tuple(checks),
                reason="Tool output contains an action-specific verified signal.",
            )
        if completed and result.exit_code in (0, None):
            return VerificationResult(
                status=VerificationStatus.COMPLETED,
                checks=tuple(checks),
                reason="Tool ran successfully but did not produce a verified exploit/discovery proof.",
            )
        return VerificationResult(
            status=VerificationStatus.FAILED,
            checks=tuple(checks),
            reason="Tool execution did not produce a usable result.",
        )


def settings_timeout() -> int:
    from app.core.config import settings

    return settings.TASK_AGENT_WORKER_TIMEOUT


__all__ = ["TaskVerifier"]

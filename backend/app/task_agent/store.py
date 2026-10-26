"""Persistence helpers for task-agent runs.

Every method owns a short SQLAlchemy transaction from the supplied session
factory, so the background runner and API can share the same database without
sharing an ORM session across threads.
"""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional
from uuid import uuid4

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import (
    AgentApprovalORM,
    AgentArtifactORM,
    AgentAuditEventORM,
    AgentCodeVersionORM,
    AgentEvidenceORM,
    AgentReportORM,
    AgentTargetSessionORM,
    AgentTaskORM,
    AgentTaskStepORM,
)
from app.task_agent.contracts import TaskContract, TaskStatus


class TaskStoreError(RuntimeError):
    pass


class TaskNotFoundError(TaskStoreError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _json_list(value: Any) -> list:
    return list(value) if isinstance(value, (list, tuple)) else []


def _json_dict(value: Any) -> dict:
    return dict(value) if isinstance(value, Mapping) else {}


class TaskStore:
    def __init__(self, session_factory, *, audit_path: Optional[Path] = None) -> None:
        if session_factory is None:
            raise TypeError("session_factory is required")
        self.session_factory = session_factory
        self.audit_path = Path(
            audit_path or settings.TASK_AGENT_AUDIT_LOG_PATH
        ).expanduser()
        self._audit_lock = threading.Lock()

    @contextmanager
    def _session(self) -> Iterator[Session]:
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------

    def create_task(
        self,
        contract: TaskContract,
        *,
        scope: Optional[Mapping[str, Any]] = None,
        model_name: Optional[str] = None,
        status: str = TaskStatus.CREATED,
    ) -> AgentTaskORM:
        with self._session() as session:
            existing = session.get(AgentTaskORM, contract.task_id)
            if existing is not None:
                raise TaskStoreError(f"task {contract.task_id!r} already exists")
            record = AgentTaskORM(
                id=contract.task_id,
                user_goal=contract.user_goal,
                target=contract.target,
                target_type=contract.target_type,
                allowed_hosts=list(contract.allowed_hosts),
                allowed_ports=list(contract.allowed_ports),
                authorized_lab_scope=contract.authorized_lab_scope,
                input_files=list(contract.input_files),
                expected_outputs=list(contract.expected_outputs),
                permitted_actions=list(contract.permitted_actions),
                maximum_steps=contract.maximum_steps,
                maximum_runtime=contract.maximum_runtime,
                maximum_repair_attempts=contract.maximum_repair_attempts,
                network_policy=contract.network_policy,
                approval_required=contract.approval_required,
                current_status=TaskStatus.normalize(status),
                current_step=0,
                model_name=model_name,
                scope_json=dict(scope or {}),
                created_at=contract.created_at,
                updated_at=contract.updated_at,
            )
            session.add(record)
            session.flush()
            session.expunge(record)
            return record

    def get_task(self, task_id: str) -> Optional[AgentTaskORM]:
        with self._session() as session:
            record = session.get(AgentTaskORM, task_id)
            if record is not None:
                session.expunge(record)
            return record

    def require_task(self, task_id: str) -> AgentTaskORM:
        record = self.get_task(task_id)
        if record is None:
            raise TaskNotFoundError(f"task {task_id!r} was not found")
        return record

    def list_tasks(
        self,
        *,
        limit: int = 50,
        status: Optional[str] = None,
    ) -> List[AgentTaskORM]:
        if not 1 <= int(limit) <= 200:
            raise ValueError("limit must be between 1 and 200")
        with self._session() as session:
            statement = select(AgentTaskORM).order_by(
                desc(AgentTaskORM.created_at), desc(AgentTaskORM.id)
            )
            if status:
                statement = statement.where(
                    AgentTaskORM.current_status == TaskStatus.normalize(status)
                )
            records = list(session.scalars(statement.limit(int(limit))))
            for record in records:
                session.expunge(record)
            return records

    def update_task(
        self,
        task_id: str,
        *,
        status: Optional[str] = None,
        current_step: Optional[int] = None,
        stop_reason: Optional[str] = None,
        model_name: Optional[str] = None,
        report_json_path: Optional[str] = None,
        report_md_path: Optional[str] = None,
    ) -> AgentTaskORM:
        with self._session() as session:
            record = session.get(AgentTaskORM, task_id)
            if record is None:
                raise TaskNotFoundError(f"task {task_id!r} was not found")
            if status is not None:
                record.current_status = TaskStatus.normalize(status)
            if current_step is not None:
                record.current_step = int(current_step)
            if stop_reason is not None:
                record.stop_reason = str(stop_reason)[:2048]
            if model_name is not None:
                record.model_name = str(model_name)[:256]
            if report_json_path is not None:
                record.report_json_path = str(report_json_path)[:2048]
            if report_md_path is not None:
                record.report_md_path = str(report_md_path)[:2048]
            record.updated_at = _now()
            session.flush()
            session.expunge(record)
            return record

    def set_scope(self, task_id: str, scope: Mapping[str, Any]) -> None:
        with self._session() as session:
            record = session.get(AgentTaskORM, task_id)
            if record is None:
                raise TaskNotFoundError(f"task {task_id!r} was not found")
            record.scope_json = dict(scope)
            record.updated_at = _now()
            session.flush()

    # ------------------------------------------------------------------
    # Steps
    # ------------------------------------------------------------------

    def create_step(
        self,
        *,
        task_id: str,
        step_number: int,
        decision: str,
        action_id: str,
        reason: str = "",
        arguments: Optional[Mapping[str, Any]] = None,
        target: str = "",
        expected_result: str = "",
        risk_level: str = "low",
        requires_approval: bool = False,
        policy_allowed: bool = False,
        policy_reason: str = "",
        retrieved_skills: Optional[Iterable[Mapping[str, Any]]] = None,
        model_name: Optional[str] = None,
        request_id: Optional[str] = None,
        response_id: Optional[str] = None,
    ) -> AgentTaskStepORM:
        with self._session() as session:
            if session.get(AgentTaskORM, task_id) is None:
                raise TaskNotFoundError(f"task {task_id!r} was not found")
            record = AgentTaskStepORM(
                id=f"step-{uuid4()}",
                task_id=task_id,
                step_number=int(step_number),
                decision=str(decision)[:64],
                action_id=str(action_id)[:128],
                reason=str(reason or "")[:2048],
                arguments=dict(arguments or {}),
                target=str(target or "")[:4096],
                expected_result=str(expected_result or "")[:2048],
                risk_level=str(risk_level or "low")[:32],
                requires_approval=bool(requires_approval),
                policy_allowed=bool(policy_allowed),
                policy_reason=str(policy_reason or "")[:2048],
                observation={},
                verification={},
                retrieved_skills=[dict(item) for item in (retrieved_skills or [])],
                model_name=(str(model_name)[:256] if model_name else None),
                request_id=(str(request_id)[:256] if request_id else None),
                response_id=(str(response_id)[:256] if response_id else None),
            )
            session.add(record)
            session.flush()
            session.expunge(record)
            return record

    def update_step(
        self,
        step_id: str,
        *,
        observation: Optional[Mapping[str, Any]] = None,
        verification: Optional[Mapping[str, Any]] = None,
        policy_allowed: Optional[bool] = None,
        policy_reason: Optional[str] = None,
        completed: bool = False,
        response_id: Optional[str] = None,
    ) -> AgentTaskStepORM:
        with self._session() as session:
            record = session.get(AgentTaskStepORM, step_id)
            if record is None:
                raise TaskStoreError(f"step {step_id!r} was not found")
            if observation is not None:
                record.observation = dict(observation)
            if verification is not None:
                record.verification = dict(verification)
            if policy_allowed is not None:
                record.policy_allowed = bool(policy_allowed)
            if policy_reason is not None:
                record.policy_reason = str(policy_reason)[:2048]
            if response_id is not None:
                record.response_id = str(response_id)[:256]
            if completed:
                record.completed_at = _now()
            session.flush()
            session.expunge(record)
            return record

    def list_steps(self, task_id: str) -> List[AgentTaskStepORM]:
        with self._session() as session:
            statement = (
                select(AgentTaskStepORM)
                .where(AgentTaskStepORM.task_id == task_id)
                .order_by(AgentTaskStepORM.step_number, AgentTaskStepORM.id)
            )
            records = list(session.scalars(statement))
            for record in records:
                session.expunge(record)
            return records

    # ------------------------------------------------------------------
    # Code versions, artifacts, evidence
    # ------------------------------------------------------------------

    def create_code_version(
        self,
        *,
        task_id: str,
        version: int,
        code: str,
        code_hash: str,
        status: str,
        step_id: Optional[str] = None,
        error: Optional[str] = None,
        explanation: Optional[str] = None,
    ) -> AgentCodeVersionORM:
        with self._session() as session:
            if session.get(AgentTaskORM, task_id) is None:
                raise TaskNotFoundError(f"task {task_id!r} was not found")
            record = AgentCodeVersionORM(
                id=f"code-{uuid4()}",
                task_id=task_id,
                step_id=step_id,
                version=int(version),
                code=code,
                code_hash=code_hash,
                status=str(status)[:64],
                error=(str(error)[:2048] if error else None),
                explanation=(str(explanation)[:8192] if explanation else None),
            )
            session.add(record)
            session.flush()
            session.expunge(record)
            return record

    def list_code_versions(self, task_id: str) -> List[AgentCodeVersionORM]:
        with self._session() as session:
            statement = (
                select(AgentCodeVersionORM)
                .where(AgentCodeVersionORM.task_id == task_id)
                .order_by(AgentCodeVersionORM.version)
            )
            records = list(session.scalars(statement))
            for record in records:
                session.expunge(record)
            return records

    def add_artifact(
        self,
        *,
        task_id: str,
        kind: str,
        path: str,
        sha256: Optional[str] = None,
        size_bytes: Optional[int] = None,
        step_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> AgentArtifactORM:
        with self._session() as session:
            if session.get(AgentTaskORM, task_id) is None:
                raise TaskNotFoundError(f"task {task_id!r} was not found")
            record = AgentArtifactORM(
                id=f"artifact-{uuid4()}",
                task_id=task_id,
                step_id=step_id,
                kind=str(kind)[:64],
                path=str(path)[:2048],
                sha256=sha256,
                size_bytes=(int(size_bytes) if size_bytes is not None else None),
                metadata_json=dict(metadata or {}),
            )
            session.add(record)
            session.flush()
            session.expunge(record)
            return record

    def list_artifacts(self, task_id: str) -> List[AgentArtifactORM]:
        with self._session() as session:
            statement = (
                select(AgentArtifactORM)
                .where(AgentArtifactORM.task_id == task_id)
                .order_by(AgentArtifactORM.created_at, AgentArtifactORM.id)
            )
            records = list(session.scalars(statement))
            for record in records:
                session.expunge(record)
            return records

    def add_evidence(
        self,
        *,
        task_id: str,
        evidence_type: str,
        summary: str,
        payload: Optional[Mapping[str, Any]] = None,
        artifact_path: Optional[str] = None,
        step_id: Optional[str] = None,
    ) -> AgentEvidenceORM:
        with self._session() as session:
            if session.get(AgentTaskORM, task_id) is None:
                raise TaskNotFoundError(f"task {task_id!r} was not found")
            record = AgentEvidenceORM(
                id=f"evidence-{uuid4()}",
                task_id=task_id,
                step_id=step_id,
                evidence_type=str(evidence_type)[:64],
                summary=str(summary)[:2048],
                payload=dict(payload or {}),
                artifact_path=(str(artifact_path)[:2048] if artifact_path else None),
            )
            session.add(record)
            session.flush()
            session.expunge(record)
            return record

    def list_evidence(self, task_id: str) -> List[AgentEvidenceORM]:
        with self._session() as session:
            statement = (
                select(AgentEvidenceORM)
                .where(AgentEvidenceORM.task_id == task_id)
                .order_by(AgentEvidenceORM.created_at, AgentEvidenceORM.id)
            )
            records = list(session.scalars(statement))
            for record in records:
                session.expunge(record)
            return records

    # ------------------------------------------------------------------
    # Target sessions and approvals
    # ------------------------------------------------------------------

    def upsert_target_session(
        self,
        *,
        task_id: str,
        session_key: str,
        kind: str,
        host: str,
        port: Optional[int] = None,
        username: Optional[str] = None,
        target_host: Optional[str] = None,
        status: str = "open",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> AgentTargetSessionORM:
        with self._session() as session:
            statement = select(AgentTargetSessionORM).where(
                AgentTargetSessionORM.task_id == task_id,
                AgentTargetSessionORM.session_key == session_key,
            )
            record = session.scalar(statement)
            if record is None:
                record = AgentTargetSessionORM(
                    id=f"session-{uuid4()}",
                    task_id=task_id,
                    session_key=session_key,
                    kind=kind,
                    host=host,
                    port=port,
                    username=username,
                    target_host=target_host,
                    status=status,
                    metadata_json=dict(metadata or {}),
                )
                session.add(record)
            else:
                record.kind = kind
                record.host = host
                record.port = port
                record.username = username
                record.target_host = target_host
                record.status = status
                record.metadata_json = dict(metadata or {})
                record.updated_at = _now()
            session.flush()
            session.expunge(record)
            return record

    def list_target_sessions(self, task_id: str) -> List[AgentTargetSessionORM]:
        with self._session() as session:
            statement = (
                select(AgentTargetSessionORM)
                .where(AgentTargetSessionORM.task_id == task_id)
                .order_by(AgentTargetSessionORM.created_at, AgentTargetSessionORM.id)
            )
            records = list(session.scalars(statement))
            for record in records:
                session.expunge(record)
            return records

    def create_approval(
        self,
        *,
        task_id: str,
        action_id: str,
        step_id: Optional[str] = None,
        reason: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> AgentApprovalORM:
        with self._session() as session:
            if session.get(AgentTaskORM, task_id) is None:
                raise TaskNotFoundError(f"task {task_id!r} was not found")
            record = AgentApprovalORM(
                id=f"approval-{uuid4()}",
                task_id=task_id,
                step_id=step_id,
                action_id=str(action_id)[:128],
                reason=(str(reason)[:2048] if reason else None),
                risk_level=(str(risk_level)[:32] if risk_level else None),
                status="pending",
            )
            session.add(record)
            session.flush()
            session.expunge(record)
            return record

    def get_approval(self, approval_id: str) -> Optional[AgentApprovalORM]:
        with self._session() as session:
            record = session.get(AgentApprovalORM, approval_id)
            if record is not None:
                session.expunge(record)
            return record

    def list_approvals(self, task_id: str) -> List[AgentApprovalORM]:
        with self._session() as session:
            statement = (
                select(AgentApprovalORM)
                .where(AgentApprovalORM.task_id == task_id)
                .order_by(desc(AgentApprovalORM.requested_at))
            )
            records = list(session.scalars(statement))
            for record in records:
                session.expunge(record)
            return records

    def pending_approval(self, task_id: str) -> Optional[AgentApprovalORM]:
        with self._session() as session:
            statement = (
                select(AgentApprovalORM)
                .where(
                    AgentApprovalORM.task_id == task_id,
                    AgentApprovalORM.status == "pending",
                )
                .order_by(desc(AgentApprovalORM.requested_at))
            )
            record = session.scalar(statement)
            if record is not None:
                session.expunge(record)
            return record

    def decide_approval(
        self,
        approval_id: str,
        *,
        approved: bool,
        decided_by: str = "operator",
    ) -> AgentApprovalORM:
        if not isinstance(approved, bool):
            raise TypeError("approved must be a boolean")
        with self._session() as session:
            record = session.get(AgentApprovalORM, approval_id)
            if record is None:
                raise TaskStoreError(f"approval {approval_id!r} was not found")
            if record.status != "pending":
                raise TaskStoreError("approval has already been decided")
            record.status = "approved" if approved else "denied"
            record.decided_at = _now()
            record.decided_by = str(decided_by)[:256]
            session.flush()
            session.expunge(record)
            return record

    # ------------------------------------------------------------------
    # Reports and audit
    # ------------------------------------------------------------------

    def save_report(
        self,
        *,
        task_id: str,
        report_json: Mapping[str, Any],
        report_md: str,
        json_path: Optional[str] = None,
        md_path: Optional[str] = None,
    ) -> AgentReportORM:
        with self._session() as session:
            if session.get(AgentTaskORM, task_id) is None:
                raise TaskNotFoundError(f"task {task_id!r} was not found")
            record = AgentReportORM(
                id=f"report-{uuid4()}",
                task_id=task_id,
                report_json=dict(report_json),
                report_md=str(report_md),
                json_path=(str(json_path)[:2048] if json_path else None),
                md_path=(str(md_path)[:2048] if md_path else None),
            )
            session.add(record)
            session.flush()
            session.expunge(record)
            return record

    def list_reports(self, task_id: str) -> List[AgentReportORM]:
        with self._session() as session:
            statement = (
                select(AgentReportORM)
                .where(AgentReportORM.task_id == task_id)
                .order_by(desc(AgentReportORM.created_at))
            )
            records = list(session.scalars(statement))
            for record in records:
                session.expunge(record)
            return records

    def add_audit_event(
        self,
        *,
        task_id: Optional[str],
        event_type: str,
        action_id: Optional[str] = None,
        detail: Optional[Mapping[str, Any]] = None,
    ) -> AgentAuditEventORM:
        safe_detail = _safe_audit_detail(detail or {})
        with self._session() as session:
            record = AgentAuditEventORM(
                id=f"audit-{uuid4()}",
                task_id=task_id,
                event_type=str(event_type)[:64],
                action_id=(str(action_id)[:128] if action_id else None),
                detail=safe_detail,
            )
            session.add(record)
            session.flush()
            session.expunge(record)
        self._append_audit_file(
            {
                "task_id": task_id,
                "event_type": event_type,
                "action_id": action_id,
                "detail": safe_detail,
                "created_at": _now().isoformat(),
            }
        )
        return record

    def list_audit_events(self, task_id: Optional[str] = None) -> List[AgentAuditEventORM]:
        with self._session() as session:
            statement = select(AgentAuditEventORM).order_by(
                desc(AgentAuditEventORM.created_at)
            )
            if task_id:
                statement = statement.where(AgentAuditEventORM.task_id == task_id)
            records = list(session.scalars(statement))
            for record in records:
                session.expunge(record)
            return records

    def _append_audit_file(self, payload: Mapping[str, Any]) -> None:
        path = self.audit_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(payload, default=str, sort_keys=True)
            with self._audit_lock:
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
                    handle.flush()
        except OSError:
            # Audit persistence must not take down a task; the DB event remains.
            return


def _safe_audit_detail(detail: Mapping[str, Any]) -> Dict[str, Any]:
    sensitive = {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "cookie",
        "authorization",
        "credential",
        "credentials",
    }
    result: Dict[str, Any] = {}

    def clean(value: Any, depth: int = 0) -> Any:
        if depth > 4:
            return "<truncated>"
        if isinstance(value, Mapping):
            return {
                str(key)[:128]: "<redacted>"
                if str(key).lower() in sensitive
                else clean(item, depth + 1)
                for key, item in list(value.items())[:64]
            }
        if isinstance(value, (list, tuple)):
            return [clean(item, depth + 1) for item in list(value)[:32]]
        if isinstance(value, str):
            return value[:2048]
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        return str(value)[:512]

    for key, value in list(detail.items())[:64]:
        key_text = str(key)[:128]
        result[key_text] = "<redacted>" if key_text.lower() in sensitive else clean(value)
    return result


def task_summary(record: AgentTaskORM) -> Dict[str, Any]:
    return {
        "task_id": record.id,
        "user_goal": record.user_goal,
        "target": record.target,
        "target_type": record.target_type,
        "current_status": record.current_status,
        "current_step": record.current_step,
        "stop_reason": record.stop_reason,
        "model_name": record.model_name,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
    }


def task_detail(
    record: AgentTaskORM,
    *,
    steps: Optional[Iterable[AgentTaskStepORM]] = None,
    artifacts: Optional[Iterable[AgentArtifactORM]] = None,
    evidence: Optional[Iterable[AgentEvidenceORM]] = None,
    approvals: Optional[Iterable[AgentApprovalORM]] = None,
    target_sessions: Optional[Iterable[AgentTargetSessionORM]] = None,
    reports: Optional[Iterable[AgentReportORM]] = None,
) -> Dict[str, Any]:
    data = task_summary(record)
    data.update(
        {
            "allowed_hosts": list(_json_list(record.allowed_hosts)),
            "allowed_ports": list(_json_list(record.allowed_ports)),
            "authorized_lab_scope": bool(record.authorized_lab_scope),
            "input_files": list(_json_list(record.input_files)),
            "expected_outputs": list(_json_list(record.expected_outputs)),
            "permitted_actions": list(_json_list(record.permitted_actions)),
            "maximum_steps": record.maximum_steps,
            "maximum_runtime": record.maximum_runtime,
            "maximum_repair_attempts": record.maximum_repair_attempts,
            "network_policy": record.network_policy,
            "approval_required": bool(record.approval_required),
            "scope": dict(_json_dict(record.scope_json)),
            "report_json_path": record.report_json_path,
            "report_md_path": record.report_md_path,
            "steps": [step_dict(item) for item in (steps or [])],
            "artifacts": [artifact_dict(item) for item in (artifacts or [])],
            "evidence": [evidence_dict(item) for item in (evidence or [])],
            "approvals": [approval_dict(item) for item in (approvals or [])],
            "target_sessions": [
                target_session_dict(item) for item in (target_sessions or [])
            ],
            "reports": [report_dict(item) for item in (reports or [])],
        }
    )
    return data


def step_dict(record: AgentTaskStepORM) -> Dict[str, Any]:
    return {
        "step_id": record.id,
        "task_id": record.task_id,
        "step_number": record.step_number,
        "decision": record.decision,
        "action_id": record.action_id,
        "reason": record.reason,
        "arguments": dict(_json_dict(record.arguments)),
        "target": record.target,
        "expected_result": record.expected_result,
        "risk_level": record.risk_level,
        "requires_approval": bool(record.requires_approval),
        "policy_allowed": bool(record.policy_allowed),
        "policy_reason": record.policy_reason,
        "observation": dict(_json_dict(record.observation)),
        "verification": dict(_json_dict(record.verification)),
        "retrieved_skills": list(_json_list(record.retrieved_skills)),
        "model_name": record.model_name,
        "request_id": record.request_id,
        "response_id": record.response_id,
        "started_at": record.started_at.isoformat() if record.started_at else None,
        "completed_at": record.completed_at.isoformat() if record.completed_at else None,
    }


def artifact_dict(record: AgentArtifactORM) -> Dict[str, Any]:
    return {
        "artifact_id": record.id,
        "task_id": record.task_id,
        "step_id": record.step_id,
        "kind": record.kind,
        "path": record.path,
        "sha256": record.sha256,
        "size_bytes": record.size_bytes,
        "metadata": dict(_json_dict(record.metadata_json)),
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }


def evidence_dict(record: AgentEvidenceORM) -> Dict[str, Any]:
    return {
        "evidence_id": record.id,
        "task_id": record.task_id,
        "step_id": record.step_id,
        "evidence_type": record.evidence_type,
        "summary": record.summary,
        "payload": dict(_json_dict(record.payload)),
        "artifact_path": record.artifact_path,
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }


def approval_dict(record: AgentApprovalORM) -> Dict[str, Any]:
    return {
        "approval_id": record.id,
        "task_id": record.task_id,
        "step_id": record.step_id,
        "action_id": record.action_id,
        "reason": record.reason,
        "risk_level": record.risk_level,
        "status": record.status,
        "requested_at": record.requested_at.isoformat() if record.requested_at else None,
        "decided_at": record.decided_at.isoformat() if record.decided_at else None,
        "decided_by": record.decided_by,
    }


def target_session_dict(record: AgentTargetSessionORM) -> Dict[str, Any]:
    return {
        "session_id": record.id,
        "task_id": record.task_id,
        "session_key": record.session_key,
        "kind": record.kind,
        "host": record.host,
        "port": record.port,
        "username": record.username,
        "target_host": record.target_host,
        "status": record.status,
        "metadata": dict(_json_dict(record.metadata_json)),
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
    }


def report_dict(record: AgentReportORM) -> Dict[str, Any]:
    return {
        "report_id": record.id,
        "task_id": record.task_id,
        "json_path": record.json_path,
        "md_path": record.md_path,
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }


def code_version_dict(record: AgentCodeVersionORM) -> Dict[str, Any]:
    return {
        "code_version_id": record.id,
        "task_id": record.task_id,
        "step_id": record.step_id,
        "version": record.version,
        "code": record.code,
        "code_hash": record.code_hash,
        "status": record.status,
        "error": record.error,
        "explanation": record.explanation,
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }


__all__ = [
    "TaskNotFoundError",
    "TaskStore",
    "TaskStoreError",
    "approval_dict",
    "artifact_dict",
    "code_version_dict",
    "evidence_dict",
    "report_dict",
    "step_dict",
    "target_session_dict",
    "task_detail",
    "task_summary",
]

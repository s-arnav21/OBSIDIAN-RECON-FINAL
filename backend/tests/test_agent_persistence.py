"""Tests for agent-run result persistence (exploit + validation evidence)."""
from __future__ import annotations

import json
import unittest
from dataclasses import replace

from app.agent.models import (
    AgentAction,
    AgentExecutionStatus,
    AgentObservation,
    AgentState,
    AgentStatus,
)
from app.agent.policy import PolicyDecision, PolicyDecisionCode
from app.agent.run_service import AgentRunResult, AgentRunStep
from app.attack_chain.mitre_mapping import enrich_finding_model
from app.agent.executor import _resolve_agent_http_session
from app.db.repository import PersistenceRepository
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult
from app.services.agent_persistence import (
    agent_run_session_name,
    persist_agent_run_results,
)
from app.validation.dispatcher import apply_validation_result
from sqlalchemy import text
from tests.db_utils import make_test_session_factory

ORIGIN = "http://127.0.0.1:8090"
SCAN_ID = "scan-persist-1"
ASSET_ID = "asset-persist-1"
FINDING_ID = "finding-persist-1"


def make_finding(
    status: str = ValidationStatus.MANUAL_REVIEW,
) -> Finding:
    return Finding(
        finding_id=FINDING_ID,
        scan_id=SCAN_ID,
        asset_id=ASSET_ID,
        target=ORIGIN,
        host="127.0.0.1",
        port=8090,
        protocol="http",
        source="agent_test",
        template_id="debug-resource",
        validator_id="generic-http-exposed-resource",
        vulnerability_type="information_disclosure",
        endpoint="/debug/config",
        http_method="GET",
        severity="high",
        validation_status=status,
        validation_confidence=0.5,
    )


def make_action() -> AgentAction:
    return AgentAction(
        action_id="action-1",
        tool_id="validate-exposed-resource",
        scan_id=SCAN_ID,
        asset_id=ASSET_ID,
        finding_id=FINDING_ID,
        target=ORIGIN,
        reason="Validate the normalized candidate using a registered tool.",
    )


def make_policy(action: AgentAction) -> PolicyDecision:
    return PolicyDecision(
        action_id=action.action_id,
        tool_id=action.tool_id,
        finding_id=action.finding_id,
        allowed=True,
        code=PolicyDecisionCode.ALLOWED,
        reason="action permitted",
    )


def make_validation() -> ValidationResult:
    return ValidationResult(
        status=ValidationStatus.CONFIRMED,
        confidence=0.95,
        validator="generic_http_exposed_resource",
        method="fetch resource and classify",
        evidence={
            "response_status": 200,
            "response_content_type": "text/plain",
            "response_size": 42,
            "classification_signals": ["api_key"],
        },
    )


def make_state(maximum_steps: int = 2) -> AgentState:
    return AgentState(
        scan_id=SCAN_ID,
        target=ORIGIN,
        asset_id=ASSET_ID,
        authorized=True,
        findings=(make_finding(),),
        maximum_steps=maximum_steps,
    )


def make_completed_result() -> AgentRunResult:
    action = make_action()
    policy = make_policy(action)
    validation = make_validation()
    updated = enrich_finding_model(apply_validation_result(make_finding(), validation))
    observation = AgentObservation(
        action_id=action.action_id,
        tool_id=action.tool_id,
        finding_id=action.finding_id,
        policy_decision=PolicyDecisionCode.ALLOWED,
        policy_allowed=True,
        execution_status=AgentExecutionStatus.COMPLETED,
        summary="Deterministic validation completed with status confirmed.",
        validation_status=validation.status,
    )
    initial = make_state()
    final = replace(
        initial,
        status=AgentStatus.COMPLETED,
        terminal_reason="planner_completed",
        current_step=1,
        findings=(updated,),
    )
    step = AgentRunStep(
        step_number=1,
        proposed_action=action,
        policy_decision=policy,
        observation=observation,
        validation_result=validation,
        updated_finding=updated,
    )
    return AgentRunResult(
        initial_state=initial,
        final_state=final,
        steps=(step,),
    )


def make_shell_result() -> AgentRunResult:
    action = replace(make_action(), tool_id="metasploit-web-rce")
    policy = make_policy(action)
    observation = AgentObservation(
        action_id=action.action_id,
        tool_id=action.tool_id,
        finding_id=action.finding_id,
        policy_decision=PolicyDecisionCode.ALLOWED,
        policy_allowed=True,
        execution_status=AgentExecutionStatus.COMPLETED,
        summary="Meterpreter session opened",
        shell_obtained=True,
        shell_info={
            "session_id": "7",
            "connection": "10.0.0.5:4444",
            "type": "meterpreter",
            "module": "exploit/multi/http/tomcat_mgr_upload",
        },
    )
    initial = make_state()
    final = replace(
        initial,
        status=AgentStatus.COMPLETED,
        terminal_reason="planner_completed",
        current_step=1,
    )
    step = AgentRunStep(
        step_number=1,
        proposed_action=action,
        policy_decision=policy,
        observation=observation,
    )
    return AgentRunResult(
        initial_state=initial,
        final_state=final,
        steps=(step,),
    )


class AgentPersistenceTests(unittest.TestCase):

    def setUp(self):
        self.engine, factory = make_test_session_factory()
        self.session = factory()
        self.repository = PersistenceRepository(self.session)

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def _seed(self) -> None:
        self.repository.create_scan(
            scan_id=SCAN_ID,
            target_url=ORIGIN,
            authorized=True,
            status="completed",
        )
        self.repository.persist_asset(
            scan_id=SCAN_ID,
            asset_id=ASSET_ID,
            hostname="127.0.0.1",
            base_url=ORIGIN,
        )
        self.repository.persist_finding(make_finding())
        self.session.commit()

    def test_persists_exploit_and_structured_validation_evidence(self):
        self._seed()
        result = make_completed_result()

        summary = persist_agent_run_results(
            self.session,
            scan_id=SCAN_ID,
            result=result,
        )

        self.assertEqual(summary["steps"], 1)
        self.assertEqual(summary["validations"], 1)
        self.assertEqual(summary["findings_updated"], 1)
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(
            summary["session_id"].startswith("agent-"), True,
        )

        session_row = self.repository.get_exploit_session(summary["session_id"])
        self.assertIsNotNone(session_row)
        self.assertEqual(session_row.session_name, agent_run_session_name(SCAN_ID))
        self.assertEqual(session_row.status, "completed")
        exploits = self.repository.list_exploits_for_session(session_row.id)
        self.assertEqual(len(exploits), 1)
        self.assertEqual(exploits[0].outcome, "success")

        validations = self.session.execute(text(
            f"SELECT id, finding_id, validator_id, status, confidence "
            f"FROM validations WHERE finding_id = '{FINDING_ID}'"
        )).fetchall()
        self.assertEqual(len(validations), 1)
        self.assertEqual(validations[0][2], "generic_http_exposed_resource")
        self.assertEqual(validations[0][3], ValidationStatus.CONFIRMED)

        evidence = self.session.execute(text(
            f"SELECT finding_id, evidence_json FROM evidence "
            f"WHERE finding_id = '{FINDING_ID}'"
        )).fetchall()
        self.assertEqual(len(evidence), 1)
        evidence_payload = json.loads(evidence[0][1])
        self.assertEqual(
            evidence_payload["response_status"], 200,
        )

        persisted = self.session.execute(text(
            f"SELECT status FROM findings WHERE id = '{FINDING_ID}'"
        )).fetchone()
        self.assertEqual(persisted[0], ValidationStatus.CONFIRMED)

    def test_completed_run_marks_session_completed_not_failed(self):
        self._seed()
        result = make_completed_result()

        summary = persist_agent_run_results(
            self.session,
            scan_id=SCAN_ID,
            result=result,
        )

        self.assertEqual(summary["status"], "completed")
        session_row = self.repository.get_exploit_session(summary["session_id"])
        self.assertEqual(session_row.status, "completed")

    def test_reuses_existing_run_session_for_repeat_call(self):
        self._seed()
        first = persist_agent_run_results(
            self.session,
            scan_id=SCAN_ID,
            result=make_completed_result(),
        )
        second = persist_agent_run_results(
            self.session,
            scan_id=SCAN_ID,
            result=make_completed_result(),
        )

        self.assertEqual(first["session_id"], second["session_id"])
        sessions = self.repository.list_exploit_sessions(scan_id=SCAN_ID)
        self.assertEqual(len(sessions), 1)

    def test_preexisting_session_id_is_used_instead_of_new(self):
        self._seed()
        reserved = self.repository.create_exploit_session(
            session_id="auto-reserved",
            scan_id=SCAN_ID,
            target_url=ORIGIN,
            session_name="auto-reserved-name",
            tool_used="agent-llm-loop",
            status="running",
        )
        self.session.commit()

        summary = persist_agent_run_results(
            self.session,
            scan_id=SCAN_ID,
            result=make_completed_result(),
            session_id=reserved.id,
            session_name="auto-reserved-name",
            target_url=ORIGIN,
        )

        self.assertEqual(summary["session_id"], "auto-reserved")
        sessions = self.repository.list_exploit_sessions(scan_id=SCAN_ID)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].status, "completed")

    def test_missing_finding_skips_validation_without_failing_run(self):
        self._seed()
        self.session.execute(text(f"DELETE FROM findings WHERE id = '{FINDING_ID}'"))
        self.session.commit()
        result = make_completed_result()

        summary = persist_agent_run_results(
            self.session,
            scan_id=SCAN_ID,
            result=result,
        )

        self.assertEqual(summary["steps"], 1)
        self.assertEqual(summary["validations"], 0)
        self.assertEqual(summary["findings_updated"], 0)
        self.assertEqual(summary["status"], "completed")

    def test_agent_shell_is_persisted_automatically(self):
        self._seed()
        summary = persist_agent_run_results(
            self.session,
            scan_id=SCAN_ID,
            result=make_shell_result(),
        )

        self.assertEqual(summary["shells"], 1)
        session_row = self.repository.get_exploit_session(summary["session_id"])
        shells = self.repository.list_shells_for_session(session_row.id)
        self.assertEqual(len(shells), 1)
        self.assertEqual(shells[0].shell_type, "meterpreter")
        self.assertEqual(shells[0].host, "10.0.0.5")
        self.assertEqual(shells[0].port, 4444)
        self.assertEqual(shells[0].active, True)

    def test_repeated_run_does_not_duplicate_shell_row(self):
        self._seed()
        first = persist_agent_run_results(
            self.session,
            scan_id=SCAN_ID,
            result=make_shell_result(),
        )
        second = persist_agent_run_results(
            self.session,
            scan_id=SCAN_ID,
            result=make_shell_result(),
        )

        self.assertEqual(first["shells"], 1)
        self.assertEqual(second["shells"], 0)
        session_row = self.repository.get_exploit_session(second["session_id"])
        shells = self.repository.list_shells_for_session(session_row.id)
        self.assertEqual(len(shells), 1)

    def test_no_shell_persisted_when_none_obtained(self):
        self._seed()
        summary = persist_agent_run_results(
            self.session,
            scan_id=SCAN_ID,
            result=make_completed_result(),
        )

        self.assertEqual(summary["shells"], 0)
        session_row = self.repository.get_exploit_session(summary["session_id"])
        self.assertEqual(self.repository.list_shells_for_session(session_row.id), [])

    def test_rejected_shell_claim_is_not_persisted(self):
        self._seed()
        action = replace(make_action(), tool_id="metasploit-web-rce")
        policy = PolicyDecision(
            action_id=action.action_id,
            tool_id=action.tool_id,
            finding_id=action.finding_id,
            allowed=False,
            code=PolicyDecisionCode.DENIED_UNAUTHORIZED,
            reason="not permitted",
        )
        observation = AgentObservation(
            action_id=action.action_id,
            tool_id=action.tool_id,
            finding_id=action.finding_id,
            policy_decision=policy.code,
            policy_allowed=False,
            execution_status=AgentExecutionStatus.BLOCKED,
            summary="rejected by policy gate",
            shell_obtained=True,
            shell_info={"type": "meterpreter", "connection": "10.0.0.5:4444"},
        )
        initial = make_state()
        final = replace(
            initial,
            status=AgentStatus.BLOCKED,
            terminal_reason=policy.code,
            current_step=1,
        )
        result = AgentRunResult(
            initial_state=initial,
            final_state=final,
            steps=(
                AgentRunStep(
                    step_number=1,
                    proposed_action=action,
                    policy_decision=policy,
                    observation=observation,
                ),
            ),
        )

        summary = persist_agent_run_results(
            self.session,
            scan_id=SCAN_ID,
            result=result,
        )

        self.assertEqual(summary["shells"], 0)
        session_row = self.repository.get_exploit_session(summary["session_id"])
        self.assertEqual(self.repository.list_shells_for_session(session_row.id), [])


class ExecutorSessionResolutionTests(unittest.TestCase):

    def test_db_session_is_substituted_with_http_session(self):
        engine, factory = make_test_session_factory()
        db_session = factory()

        resolved = _resolve_agent_http_session(db_session)

        self.assertIsNot(resolved, db_session)
        self.assertTrue(callable(getattr(resolved, "request", None)))
        self.assertTrue(callable(getattr(resolved, "get", None)))
        db_session.close()
        engine.dispose()

    def test_http_capable_session_passes_through_unchanged(self):
        class FakeHttpSession:
            def get(self, url, **_kwargs):
                return None

            def request(self, method, url, **_kwargs):
                return None

        http_session = FakeHttpSession()
        resolved = _resolve_agent_http_session(http_session)

        self.assertIs(resolved, http_session)

    def test_none_resolves_to_fresh_http_session(self):
        resolved = _resolve_agent_http_session(None)
        self.assertIsNotNone(resolved)
        self.assertTrue(callable(getattr(resolved, "request", None)))


if __name__ == "__main__":
    unittest.main()
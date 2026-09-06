"""Focused API coverage for the optional controlled-demo agent trace."""

from __future__ import annotations

import json
import unittest

from fastapi.testclient import TestClient

from app.agent.llm_client import LLMClientError
from app.agent.llm_planner import LLMPlanner
from app.agent.run_service import AgentRunService
from app.api.test_harness import get_test_harness_pipeline
from app.db.session import get_db
from app.main import app
from app.services.generic_local_web_validation import GENERIC_LOCAL_WEB_SCENARIO
from app.services.test_harness import TestHarnessPipeline
from tests.db_utils import make_test_session_factory
from tests.integration_apps.vulnerable_web_app import LocalVulnerableAppServer


class _ActionThenCompleteClient:
    def __init__(self) -> None:
        self.calls = 0
        self.raw_provider_body = "provider-secret-must-not-leak"

    def complete(self, messages, *, response_format):
        del response_format
        self.calls += 1
        context = json.loads(messages[1]["content"])
        state = context["state"]
        if state["observations"]:
            return json.dumps({"decision": "complete", "action": None})
        finding = next(
            item
            for item in state["findings"]
            if item["validator_id"] == "generic-http-sqli"
        )
        return json.dumps({
            "decision": "action",
            "action": {
                "action_id": "controlled-demo-action-1",
                "tool_id": "validate-sql-injection",
                "scan_id": state["scan_id"],
                "asset_id": state["asset_id"],
                "finding_id": finding["finding_id"],
                "target": state["target"],
                "reason": "Select the registered deterministic SQLi validator.",
                "expected_capabilities": ["discovered_services"],
            },
        })


class _UnavailableClient:
    def complete(self, messages, *, response_format):
        del messages, response_format
        raise LLMClientError("network_error")


class ControlledDemoAgentApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = LocalVulnerableAppServer()
        cls.origin = cls.server.start()
        cls.engine, cls.factory = make_test_session_factory()
        cls.client = TestClient(app)

        def override_get_db():
            with cls.factory() as session:
                yield session

        app.dependency_overrides[get_db] = override_get_db

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_test_harness_pipeline, None)
        cls.engine.dispose()
        cls.server.stop()

    def tearDown(self):
        app.dependency_overrides.pop(get_test_harness_pipeline, None)

    def _post(self, pipeline, **updates):
        app.dependency_overrides[get_test_harness_pipeline] = lambda: pipeline
        body = {
            "target_url": self.origin,
            "scenario": GENERIC_LOCAL_WEB_SCENARIO,
            "authorized": True,
            "skip_dns_verification": False,
        }
        body.update(updates)
        return self.client.post("/api/test-harness/run", json=body)

    def test_success_attaches_real_sanitized_policy_enforced_agent_run(self):
        provider = _ActionThenCompleteClient()
        pipeline = TestHarnessPipeline(
            mode="fixture",
            allowed_origins=[],
            agent_run_service_factory=lambda: AgentRunService(
                LLMPlanner(provider)
            ),
        )

        response = self._post(pipeline)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["overall_status"], "completed")
        self.assertEqual(len(body["findings"]), 5)
        run = body["agent_run"]
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["stop_reason"], "planner_completed")
        self.assertEqual(run["steps_used"], 1)
        self.assertEqual(len(run["steps"]), 1)
        step = run["steps"][0]
        self.assertEqual(
            step["proposed_action"]["tool_id"],
            "validate-sql-injection",
        )
        self.assertTrue(step["policy_decision"]["allowed"])
        self.assertEqual(step["policy_decision"]["code"], "allowed")
        self.assertEqual(
            step["observation"]["validation_status"],
            "confirmed",
        )
        self.assertIn(
            "application_compromise",
            step["observation"]["capabilities_gained"],
        )
        selected = next(
            item
            for item in run["final_state"]["findings"]
            if item["finding_id"] == step["proposed_action"]["finding_id"]
        )
        self.assertEqual(selected["mitre_technique_id"], "T1190")
        serialized_run = json.dumps(run)
        self.assertNotIn(provider.raw_provider_body, serialized_run)
        self.assertNotIn("detection_methods", serialized_run)
        self.assertNotIn("chain_of_thought", serialized_run)

    def test_provider_failure_does_not_break_deterministic_assessment(self):
        pipeline = TestHarnessPipeline(
            mode="fixture",
            allowed_origins=[],
            agent_run_service_factory=lambda: AgentRunService(
                LLMPlanner(_UnavailableClient())
            ),
        )

        response = self._post(pipeline)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["overall_status"], "completed")
        self.assertEqual(len(body["validations"]), 5)
        self.assertEqual(body["agent_run"]["status"], "failed")
        self.assertEqual(body["agent_run"]["stop_reason"], "planner_error")
        self.assertEqual(body["agent_run"]["steps"], [])

    def test_missing_configuration_returns_bounded_existing_run_shape(self):
        def unavailable_factory():
            raise LLMClientError("configuration_error")

        pipeline = TestHarnessPipeline(
            mode="fixture",
            allowed_origins=[],
            agent_run_service_factory=unavailable_factory,
        )

        response = self._post(pipeline)

        self.assertEqual(response.status_code, 200)
        run = response.json()["agent_run"]
        self.assertEqual(run["status"], "failed")
        self.assertEqual(
            run["stop_reason"],
            "agent_configuration_unavailable",
        )
        self.assertEqual(run["steps_used"], 0)
        self.assertEqual(run["steps"], [])

    def test_browser_cannot_supply_agent_action_or_execution_fields(self):
        pipeline = TestHarnessPipeline(mode="fixture", allowed_origins=[])
        forbidden = {
            "agent_action": {"tool_id": "validate-sql-injection"},
            "tool_id": "validate-sql-injection",
            "payload": "browser-selected-input",
            "action_url": "http://127.0.0.1:8090/items",
        }
        for field, value in forbidden.items():
            with self.subTest(field=field):
                response = self._post(pipeline, **{field: value})
                self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()

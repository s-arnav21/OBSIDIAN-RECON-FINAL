import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.api.readiness import get_optional_readiness_db
from app.main import app
from tests.db_utils import make_test_session_factory


STATIC_DIR = Path(__file__).resolve().parents[1] / "app" / "static"


class ReadinessApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine, cls.factory = make_test_session_factory()

        def override_readiness_db():
            with cls.factory() as session:
                yield session

        app.dependency_overrides[get_optional_readiness_db] = override_readiness_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.pop(get_optional_readiness_db, None)
        cls.engine.dispose()

    def test_readiness_reports_backend_database_and_configured_scanners(self):
        with patch.dict(os.environ, {
            "RECON_NMAP_PATH": "/bin/sh",
            "RECON_NUCLEI_PATH": "/bin/sh",
        }):
            response = self.client.get("/api/readiness")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ready")
        self.assertEqual(set(body["components"]), {
            "backend", "postgresql", "nmap", "nuclei",
        })
        self.assertTrue(all(
            set(component) == {"status"}
            for component in body["components"].values()
        ))

    def test_readiness_reports_missing_scanners_without_leaking_paths(self):
        with patch.dict(os.environ, {
            "RECON_NMAP_PATH": "",
            "RECON_NUCLEI_PATH": "/definitely/not/a/scanner",
        }):
            response = self.client.get("/api/readiness")
        body = response.json()
        self.assertEqual(body["status"], "degraded")
        self.assertEqual(body["components"]["nmap"]["status"], "not_configured")
        self.assertEqual(body["components"]["nuclei"]["status"], "unavailable")
        serialized = response.text
        self.assertNotIn("/definitely/not/a/scanner", serialized)
        self.assertNotIn("DATABASE_URL", serialized)

    def test_existing_health_contract_is_unchanged(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "healthy"})


class PrototypeStaticUiTests(unittest.TestCase):
    @staticmethod
    def _agent_presentation_with_javascript(payload):
        if shutil.which("node") is None:
            raise unittest.SkipTest("Node.js is required for frontend adapter tests")
        javascript = (STATIC_DIR / "app.js").read_text()
        adapter_source = javascript.split("function displayFindingType", 1)[0]
        program = (
            adapter_source
            + "\nprocess.stdout.write(JSON.stringify(agentRunPresentation("
            + json.dumps(payload)
            + ")));"
        )
        result = subprocess.run(
            ["node", "-e", program],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    @staticmethod
    def _extract_pairs_with_javascript(payload):
        if shutil.which("node") is None:
            raise unittest.SkipTest("Node.js is required for frontend adapter tests")
        javascript = (STATIC_DIR / "app.js").read_text()
        adapter_source = javascript.split("function resultChains(data)", 1)[0]
        program = (
            adapter_source
            + "\nprocess.stdout.write(JSON.stringify(findingValidationPairs("
            + json.dumps(payload)
            + ")));"
        )
        result = subprocess.run(
            ["node", "-e", program],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    def test_existing_static_page_contains_real_and_controlled_workflows(self):
        html = (STATIC_DIR / "index.html").read_text()
        self.assertIn('id="scan-form"', html)
        self.assertIn('id="demo-form"', html)
        self.assertIn("START ASSESSMENT", html)
        self.assertIn("Controlled Lab Demonstration", html)
        self.assertIn("Advanced · view raw API response", html)
        self.assertIn("ATTACK PATHS", html)
        self.assertIn("<th>Validator</th>", html)
        self.assertIn("<th>Capabilities gained</th>", html)
        self.assertIn('id="agent-heading">Agent Activity', html)
        self.assertIn("chain-of-thought are never displayed", html)
        self.assertIn('id="scan-target-context"', html)
        self.assertIn('id="demo-target-context"', html)
        self.assertIn('id="verification-panel"', html)
        self.assertIn('id="verify-dns-button"', html)
        self.assertIn('id="verification-name"', html)
        self.assertIn("*.netlify.app", html)
        self.assertIn("sibling subdomains", html)
        self.assertIn('id="dev-dns-bypass-control"', html)
        self.assertIn('id="skip-dns-verification"', html)
        self.assertIn("DEVELOPMENT ONLY", html)
        self.assertIn(
            "DNS OWNERSHIP CHECK BYPASSED — DEVELOPMENT TEST ONLY",
            html,
        )
        bypass_input = html.split('id="skip-dns-verification"', 1)[1]
        self.assertIn("disabled", bypass_input.split(">", 1)[0])
        self.assertNotIn("checked", bypass_input.split(">", 1)[0])

    def test_javascript_wires_real_scan_harness_retrieval_and_summary(self):
        javascript = (STATIC_DIR / "app.js").read_text()
        for contract in (
            'postJson("/api/scans/run"',
            'postJson("/api/test-harness/run"',
            'requestJson("/api/readiness"',
            "function computeSummary(data)",
            "function renderChains(data)",
            "function renderAgentActivity(data)",
            "data.agent_run || data.agent_activity",
            '"Policy Gate"',
            '"APPROVED"',
            '"Deterministic validator"',
            '"MITRE ATT&CK"',
            "run.final_state?.findings",
            "function renderTargetContext(inputSelector, outputSelector)",
            'return "Controlled Command-Execution Simulation"',
            'return "Controlled System Information Discovery Simulation"',
            "VIEW PROOF OF CONCEPT",
            "Business-risk rationale",
            "Controlled request shapes",
            'requestJson(`/api/scans/${encoded}/findings`)',
            'requestJson(`/api/scans/${encoded}/chains`)',
            'postJson("/api/target-verifications"',
            "target_verification_required",
            "function renderTargetVerification(verification)",
            '/api/target-verifications/${encodeURIComponent(activeVerificationId)}/verify',
            'requestJson("/api/test-harness/config")',
            "function setDevelopmentDnsBypassAvailability(enabled)",
            "checkbox.checked = false",
            "checkbox.disabled = !enabled",
            "control.hidden = !enabled",
            'skip_dns_verification: $("#skip-dns-verification").checked',
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, javascript)

    def test_agent_panel_is_trace_only_and_has_a_safe_empty_state(self):
        html = (STATIC_DIR / "index.html").read_text()
        javascript = (STATIC_DIR / "app.js").read_text()
        self.assertIn("proposal, policy decision, registered tool", html)
        self.assertIn("browser cannot choose", html)
        self.assertIn("Server-trusted AgentRunService", html)
        self.assertIn("live LLM endpoint", html)
        self.assertIn("proposed_action", javascript)
        self.assertIn("policy_decision", javascript)
        self.assertIn("observation", javascript)
        self.assertNotIn("/api/agent", javascript)

    def test_policy_denial_is_presented_as_a_safe_policy_stop(self):
        for reason in (
            "denied_not_automatic",
            "denied_duplicate",
            "denied_prerequisite",
        ):
            with self.subTest(reason=reason):
                presentation = self._agent_presentation_with_javascript({
                    "status": "blocked",
                    "stop_reason": reason,
                })

                self.assertEqual(presentation["badgeText"], "POLICY STOPPED")
                self.assertEqual(presentation["statusTone"], "warning")
                self.assertEqual(
                    presentation["emptyMessage"],
                    "Agent stopped safely by policy: "
                    f"{reason.replace('_', ' ')}.",
                )

    def test_non_policy_blocked_run_keeps_existing_presentation(self):
        presentation = self._agent_presentation_with_javascript({
            "status": "blocked",
            "stop_reason": "planner_error",
        })

        self.assertEqual(presentation["badgeText"], "blocked")
        self.assertEqual(presentation["statusTone"], "warning")
        self.assertEqual(
            presentation["emptyMessage"],
            "Agent stopped without an executable action: planner error.",
        )

    def test_nested_attack_flow_presentations_render_as_unique_findings(self):
        sql_presentation = {
            "finding_id": "finding-sqli",
            "vulnerability_type": "sql_injection",
            "location": {
                "target": "http://127.0.0.1:8090",
                "endpoint": "/items",
                "http_method": "GET",
                "parameter_name": "id",
                "parameter_location": "query",
            },
            "validation": {
                "status": "confirmed",
                "confidence": 0.85,
                "validator": "generic_http_sqli",
                "reason": "one_or_more_detection_methods_confirmed",
            },
            "mitre": {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            },
            "provides": ["application_compromise", "possible_database_access"],
            "risk": {"rating": "High"},
        }
        command_presentation = {
            "finding_id": "finding-command",
            "vulnerability_type": "command_execution",
            "location": {
                "target": "http://127.0.0.1:8090",
                "endpoint": "/admin/diagnostics",
                "http_method": "POST",
            },
            "validation": {
                "status": "confirmed",
                "confidence": 0.9,
                "validator": "generic_http_command_execution",
            },
            "mitre": {
                "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Unix Shell",
                "tactic": "Execution",
            },
            "provides": ["command_execution"],
            "risk": {"rating": "Critical"},
        }
        payload = {
            "validations": {},
            "attack_flow": {
                "multi_stage_paths": [{
                    "steps": [
                        {"finding_presentation": sql_presentation},
                        {"finding_presentation": command_presentation},
                    ],
                }],
                "standalone_findings": [{
                    "steps": [{"finding_presentation": sql_presentation}],
                }],
            },
        }

        pairs = self._extract_pairs_with_javascript(payload)

        self.assertEqual(len(pairs), 2)
        by_id = {pair["finding"]["finding_id"]: pair for pair in pairs}
        sql = by_id["finding-sqli"]
        self.assertEqual(sql["finding"]["endpoint"], "/items")
        self.assertEqual(sql["validation"]["status"], "confirmed")
        self.assertEqual(sql["validation"]["confidence"], 0.85)
        self.assertEqual(sql["validation"]["validator"], "generic_http_sqli")
        self.assertEqual(sql["finding"]["mitre_technique_id"], "T1190")
        self.assertEqual(
            sql["finding"]["provides"],
            ["application_compromise", "possible_database_access"],
        )
        self.assertEqual(sql["presentation"]["risk"]["rating"], "High")

    def test_progress_copy_does_not_claim_streaming_events(self):
        html = (STATIC_DIR / "index.html").read_text()
        self.assertIn("Stage-level events are not streamed yet", html)
        for stage in (
            "Target validation",
            "Reconnaissance",
            "Service discovery",
            "Vulnerability discovery",
            "Active validation",
            "MITRE mapping",
            "Attack-path analysis",
            "Persistence",
        ):
            with self.subTest(stage=stage):
                self.assertIn(f'"{stage}"', (STATIC_DIR / "app.js").read_text())


if __name__ == "__main__":
    unittest.main()

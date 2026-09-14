"""Deterministic tests for the real attack execution engine."""

from __future__ import annotations

import unittest

from app.db.models import FindingORM
from app.db.repository import PersistenceRepository
from app.models.finding import Finding
from app.services.attack_execution import execute_planned_attack
from app.services.exploit_planner import ExploitPlan
from tests.db_utils import make_test_session_factory

TARGET = "http://example.test"
_NEXT = 0


def _persist_finding(factory, *, validator_id, endpoint):
    global _NEXT
    _NEXT += 1
    scan_id = f"scan-exec-test-{_NEXT}"
    asset_id = f"asset-exec-test-{_NEXT}"
    finding_id = f"finding-exec-test-{_NEXT}"
    with factory() as session:
        repository = PersistenceRepository(session)
        repository.create_scan(scan_id=scan_id, target_url=TARGET, authorized=True)
        repository.persist_asset(
            scan_id=scan_id,
            asset_id=asset_id,
            hostname="example.test",
            base_url=TARGET,
        )
        session.commit()
        finding = Finding(
            finding_id=finding_id,
            scan_id=scan_id,
            asset_id=asset_id,
            target=TARGET,
            host="example.test",
            source="nuclei",
            vulnerability_type="command_execution",
            validator_id=validator_id,
            template_id="diagnostics",
            endpoint=endpoint,
            http_method="GET",
            severity="critical",
            validation_status="confirmed",
        )
        repository.persist_finding(finding)
        session.commit()
        return session.get(FindingORM, finding_id)


class AttackExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine, cls.factory = make_test_session_factory()

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()

    def _base_plan(self, **extra) -> ExploitPlan:
        kwargs = {
            "technique_id": "T1059.004",
            "technique_name": "Command and Scripting Interpreter: Unix Shell",
            "tactic": "Execution",
            "source": "fallback",
            "summary": "execute test",
            "steps": [],
        }
        kwargs.update(extra)
        return ExploitPlan(**kwargs)

    def test_command_path_runs_and_injects_target_via_environment(self):
        finding = _persist_finding(
            self.factory,
            validator_id=None,
            endpoint="/diagnostics",
        )
        plan = self._base_plan(
            command='printf "PWNED:%s" "$OBSIDIAN_TARGET:$OBSIDIAN_ENDPOINT"'
        )
        attempt = execute_planned_attack(plan, finding)
        self.assertEqual(attempt["status"], "success")
        self.assertEqual(attempt["method"], "command")
        self.assertEqual(attempt["exit_code"], 0)
        self.assertEqual(attempt["stdout"], "PWNED:http://example.test:/diagnostics")

    def test_command_path_reports_nonzero_exit_as_failed(self):
        finding = _persist_finding(self.factory, validator_id=None, endpoint="/x")
        attempt = execute_planned_attack(self._base_plan(command="exit 3"), finding)
        self.assertEqual(attempt["status"], "failed")
        self.assertEqual(attempt["exit_code"], 3)

    def test_command_path_bounds_timeouts(self):
        from app.services import attack_execution

        finding = _persist_finding(self.factory, validator_id=None, endpoint="/x")
        plan = self._base_plan(command="sleep 5")
        previous = attack_execution._EXEC_TIMEOUT_SECONDS
        attack_execution._EXEC_TIMEOUT_SECONDS = 0.3
        try:
            attempt = execute_planned_attack(plan, finding)
        finally:
            attack_execution._EXEC_TIMEOUT_SECONDS = previous
        self.assertEqual(attempt["status"], "error")
        self.assertIn("timed out", attempt["stderr"])

    def test_plan_without_command_and_without_validator_is_planned(self):
        finding = _persist_finding(self.factory, validator_id=None, endpoint="/x")
        attempt = execute_planned_attack(self._base_plan(), finding)
        self.assertEqual(attempt["status"], "planned")


if __name__ == "__main__":
    unittest.main()
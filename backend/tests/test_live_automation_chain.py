"""Live end-to-end test: the automation technique scripts against the fixture.

Complements the validator-level integration test by exercising the actual
technique scripts (T1190 -> T1059.004 -> T1082) through the runner, proving the
unattended web -> shell -> discovery chain end to end on the loopback fixture.
"""

from __future__ import annotations

import unittest

from app.automation.base import TechniqueStatus
from tests.integration_apps.run_automation_chain_demo import run_demo


class LiveAutomationChainTests(unittest.TestCase):
    def test_web_shell_discovery_chain_confirms_end_to_end(self):
        results = run_demo()
        statuses = {result.technique_id: result.status for result in results}
        self.assertEqual(statuses.get("T1190"), TechniqueStatus.CONFIRMED)
        self.assertEqual(statuses.get("T1059.004"), TechniqueStatus.CONFIRMED)
        self.assertEqual(statuses.get("T1082"), TechniqueStatus.CONFIRMED)

    def test_chain_grants_expected_capabilities(self):
        results = run_demo()
        by_id = {result.technique_id: result for result in results}
        self.assertIn(
            "application_compromise", by_id["T1190"].capabilities_gained
        )
        self.assertIn(
            "command_execution", by_id["T1059.004"].capabilities_gained
        )
        self.assertIn(
            "system_information", by_id["T1082"].capabilities_gained
        )


if __name__ == "__main__":
    unittest.main()

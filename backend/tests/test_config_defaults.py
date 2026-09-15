"""Tests for configurable defaults (env-driven Settings, scanner bindings)."""
from __future__ import annotations

import unittest

from app.core.config import settings
from app.agent.models import ABSOLUTE_MAX_AGENT_STEPS


class SettingsDefaultsTests(unittest.TestCase):
    def test_agent_max_steps_default(self):
        self.assertEqual(settings.AGENT_MAX_STEPS, 10)
        self.assertIsInstance(settings.AGENT_MAX_STEPS, int)

    def test_nuclei_concurrency_default(self):
        self.assertEqual(settings.NUCLEI_CONCURRENCY, 20)
        self.assertIsInstance(settings.NUCLEI_CONCURRENCY, int)

    def test_nuclei_rate_limit_default(self):
        self.assertEqual(settings.NUCLEI_RATE_LIMIT, 50)
        self.assertIsInstance(settings.NUCLEI_RATE_LIMIT, int)

    def test_api_auth_token_empty_by_default(self):
        self.assertEqual(settings.API_AUTH_TOKEN, "")


class NucleiScannerBindingsTests(unittest.TestCase):
    def test_nuclei_scanner_constants_bind_to_settings(self):
        from pipeline.scanner.nuclei_scanner import CONCURRENCY, RATE_LIMIT

        self.assertEqual(CONCURRENCY, settings.NUCLEI_CONCURRENCY)
        self.assertEqual(RATE_LIMIT, settings.NUCLEI_RATE_LIMIT)


class AgentStepsBindingsTests(unittest.TestCase):
    def test_absolute_max_agent_steps_backed_by_settings(self):
        self.assertEqual(ABSOLUTE_MAX_AGENT_STEPS, settings.AGENT_MAX_STEPS)


class RetestingModuleExistsTests(unittest.TestCase):
    def test_retesting_endpoints_are_importable(self):
        from app.services.retesting import retest_finding, retest_findings_batch

        self.assertTrue(callable(retest_finding))
        self.assertTrue(callable(retest_findings_batch))


if __name__ == "__main__":
    unittest.main()

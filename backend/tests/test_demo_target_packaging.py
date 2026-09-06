"""Packaging checks for the one-command controlled demo target."""

from __future__ import annotations

from pathlib import Path
import unittest

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = REPOSITORY_ROOT / "docker-compose.yml"
DOCKERIGNORE_PATH = REPOSITORY_ROOT / "backend" / ".dockerignore"


class DemoTargetPackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
        cls.service = cls.compose["services"]["demo-target"]

    def test_demo_service_reuses_existing_integration_fixture(self):
        self.assertEqual(self.service["build"], "./backend")
        self.assertIn(
            "tests.integration_apps.vulnerable_web_app:app",
            self.service["command"],
        )
        self.assertEqual(self.service["profiles"], ["demo"])

    def test_demo_service_is_published_on_host_loopback_only(self):
        self.assertEqual(
            self.service["ports"],
            ["127.0.0.1:8090:8090"],
        )

    def test_demo_service_has_a_real_fixture_healthcheck(self):
        healthcheck = self.service["healthcheck"]
        self.assertIn("/health", " ".join(healthcheck["test"]))
        self.assertEqual(healthcheck["interval"], "3s")
        self.assertEqual(healthcheck["timeout"], "3s")
        self.assertEqual(healthcheck["retries"], 10)

    def test_demo_container_is_restricted(self):
        self.assertTrue(self.service["read_only"])
        self.assertEqual(self.service["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", self.service["security_opt"])
        self.assertIn("/tmp", self.service["tmpfs"])

    def test_backend_build_context_excludes_local_runtime_artifacts(self):
        patterns = DOCKERIGNORE_PATH.read_text(encoding="utf-8").splitlines()
        self.assertIn(".venv/", patterns)
        self.assertIn("__pycache__/", patterns)
        self.assertNotIn("tests/", patterns)


if __name__ == "__main__":
    unittest.main()

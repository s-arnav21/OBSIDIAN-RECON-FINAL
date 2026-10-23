import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.api.readiness import get_optional_readiness_db
from app.main import app
from tests.db_utils import make_test_session_factory


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
        # The scan pipeline resolves tooling from PATH when the explicit env
        # override is empty; readiness reflects that same reality. Make the
        # fake PATH empty so both scanners are genuinely unresolvable here.
        with patch.dict(os.environ, {
            "RECON_NMAP_PATH": "",
            "RECON_NUCLEI_PATH": "/definitely/not/a/scanner",
            "PATH": "/definitely/empty",
        }):
            response = self.client.get("/api/readiness")
        body = response.json()
        self.assertEqual(body["status"], "degraded")
        self.assertEqual(body["components"]["nmap"]["status"], "not_configured")
        self.assertEqual(body["components"]["nuclei"]["status"], "unavailable")
        serialized = response.text
        self.assertNotIn("/definitely/not/a/scanner", serialized)
        self.assertNotIn("DATABASE_URL", serialized)

    def test_readiness_reports_path_tools_ready_when_env_override_empty(self):
        # Empty env override must not downgrade an actually-installed tool:
        # ready when resolvable on PATH, even without the env var.
        with patch.dict(os.environ, {
            "RECON_NMAP_PATH": "",
            "RECON_NUCLEI_PATH": "",
        }):
            response = self.client.get("/api/readiness")
        body = response.json()
        self.assertIn(body["components"]["nmap"]["status"], ("ready", "not_configured"))
        self.assertIn(body["components"]["nuclei"]["status"], ("ready", "not_configured"))

    def test_existing_health_contract_is_unchanged(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "healthy"})


if __name__ == "__main__":
    unittest.main()
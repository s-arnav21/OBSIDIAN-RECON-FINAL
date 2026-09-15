"""Tests for API key authentication (opt-in via API_AUTH_TOKEN).

When API_AUTH_TOKEN is empty every endpoint works as before.
When set, POST/PUT/PATCH/DELETE require ``X-API-Key`` header with the correct
value; missing or wrong keys return 401.  Read-only readiness stays open.
"""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from app.core.config import settings
from app.db.session import get_db
from app.main import app
from tests.db_utils import make_test_session_factory


def _setup_client():
    engine, factory = make_test_session_factory()

    def override_get_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    old_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    return client, engine, factory, old_override


class ApiAuthDisabledTests(unittest.TestCase):
    def test_endpoints_work_without_key_when_not_configured(self):
        original = settings.API_AUTH_TOKEN
        try:
            settings.API_AUTH_TOKEN = ""
            client, engine, factory, _ = _setup_client()
            try:
                response = client.post(
                    "/api/scans",
                    json={
                        "target_url": "http://127.0.0.1:9099",
                        "authorized": True,
                    },
                )
                # Should not be 401 (may be 403 for non-loopback etc)
                self.assertNotEqual(response.status_code, 401)
            finally:
                app.dependency_overrides.pop(get_db, None)
                engine.dispose()
        finally:
            settings.API_AUTH_TOKEN = original


class ApiAuthEnabledTests(unittest.TestCase):
    def setUp(self):
        original = settings.API_AUTH_TOKEN
        self._original = original
        settings.API_AUTH_TOKEN = "test-secret-key-123"
        self.client, self.engine, self.factory, _ = _setup_client()

    def tearDown(self):
        app.dependency_overrides.pop(get_db, None)
        self.engine.dispose()
        settings.API_AUTH_TOKEN = self._original

    def test_mutating_request_without_key_returns_401(self):
        response = self.client.post(
            "/api/scans",
            json={
                "target_url": "http://127.0.0.1:9099",
                "authorized": True,
            },
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn("X-API-Key", response.json()["detail"])

    def test_mutating_request_with_wrong_key_returns_401(self):
        response = self.client.post(
            "/api/scans",
            headers={"X-API-Key": "wrong-key"},
            json={
                "target_url": "http://127.0.0.1:9099",
                "authorized": True,
            },
        )
        self.assertEqual(response.status_code, 401)

    def test_mutating_request_with_correct_key_proceeds(self):
        response = self.client.post(
            "/api/scans",
            headers={"X-API-Key": "test-secret-key-123"},
            json={
                "target_url": "http://127.0.0.1:9099",
                "authorized": True,
            },
        )
        # Should proceed past auth (may be 403/422 for non-loopback, not 401)
        self.assertNotEqual(response.status_code, 401)

    def test_readiness_always_accessible_without_key(self):
        response = self.client.get("/api/readiness")
        self.assertIn(response.status_code, (200, 503))

    def test_health_always_accessible_without_key(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()

"""Reachability-policy tests for local and verified external validation."""

from __future__ import annotations

import unittest
from unittest.mock import patch

import httpx

from app.models.finding import ValidationStatus
from app.models.validation import ValidationResult
from app.scanning.http_discovery import ScopedReconHttpClient
from app.scanning.scope import AuthorizedTarget
from app.services.generic_local_web_validation import (
    LocalTargetConnectionError,
    execute_local_multi_validator_pipeline,
    execute_verified_external_web_validation,
)


EXTERNAL_ORIGIN = "https://verified.example.com"
PUBLIC_ADDRESS = "93.184.216.34"


class _Response:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _LocalReachabilityClient:
    def __init__(self, origin: str, status_code: int) -> None:
        self.approved_origin = origin
        self.status_code = status_code
        self.requested_urls: list[str] = []

    def get(self, url: str, **_kwargs):
        self.requested_urls.append(url)
        return _Response(self.status_code)


def _external_target() -> AuthorizedTarget:
    return AuthorizedTarget(
        origin=EXTERNAL_ORIGIN,
        hostname="verified.example.com",
        port=443,
        scheme="https",
        resolved_addresses=(PUBLIC_ADDRESS,),
    )


def _rejected_validation(_finding, session) -> ValidationResult:
    del session
    return ValidationResult(
        status=ValidationStatus.REJECTED,
        confidence=0.9,
        validator="reachability_test_dispatch",
        method="test-only dispatch observation",
        evidence={},
    )


class ReachabilityPolicyTests(unittest.TestCase):
    def test_local_pipeline_still_requires_successful_health_endpoint(self):
        client = _LocalReachabilityClient(
            "http://127.0.0.1:8090",
            200,
        )

        with patch(
            "app.services.generic_local_web_validation.dispatch",
            side_effect=_rejected_validation,
        ) as mocked_dispatch:
            result = execute_local_multi_validator_pipeline(
                client.approved_origin,
                client,
                scan_id="scan-local-reachability",
            )

        self.assertEqual(
            client.requested_urls,
            ["http://127.0.0.1:8090/health"],
        )
        self.assertEqual(result.reachability.endpoint, "/health")
        self.assertEqual(
            result.reachability.source,
            "local_integration_fixture",
        )
        self.assertEqual(
            result.reachability.template_id,
            "local-fixture-health-check",
        )
        self.assertEqual(result.reachability.evidence, {"health_status": 200})
        self.assertEqual(mocked_dispatch.call_count, 6)
        self.assertIn(
            "controlled-http-system-information-discovery",
            {
                artifact.candidate.validator_id
                for artifact in result.validations
            },
        )

    def test_local_pipeline_health_failure_still_fails_closed(self):
        client = _LocalReachabilityClient(
            "http://127.0.0.1:8090",
            404,
        )

        with patch(
            "app.services.generic_local_web_validation.dispatch"
        ) as mocked_dispatch:
            with self.assertRaisesRegex(
                LocalTargetConnectionError,
                "fixture health check",
            ):
                execute_local_multi_validator_pipeline(
                    client.approved_origin,
                    client,
                )

        self.assertEqual(
            client.requested_urls,
            ["http://127.0.0.1:8090/health"],
        )
        mocked_dispatch.assert_not_called()

    def _run_external(self, handler):
        target = _external_target()
        client = ScopedReconHttpClient(
            target,
            address_resolver=lambda _hostname: (PUBLIC_ADDRESS,),
        )
        client._client.close()
        client._client = httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
            timeout=3.0,
            trust_env=False,
        )

        with (
            patch(
                "app.services.generic_local_web_validation."
                "ScopedReconHttpClient",
                return_value=client,
            ),
            patch(
                "app.services.generic_local_web_validation.dispatch",
                side_effect=_rejected_validation,
            ) as mocked_dispatch,
        ):
            result = execute_verified_external_web_validation(
                target,
                scan_id="scan-external-reachability",
                address_resolver=lambda _hostname: (PUBLIC_ADDRESS,),
            )
        return result, mocked_dispatch

    def test_external_root_200_proceeds_without_health_endpoint(self):
        requested_paths = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested_paths.append(request.url.path)
            return httpx.Response(200, request=request)

        result, mocked_dispatch = self._run_external(handler)

        self.assertEqual(requested_paths, ["/"])
        self.assertNotIn("/health", requested_paths)
        self.assertEqual(mocked_dispatch.call_count, 5)
        self.assertEqual(result.reachability.endpoint, "/")

    def test_external_root_404_still_proves_reachability(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, request=request)

        result, mocked_dispatch = self._run_external(handler)

        self.assertEqual(result.reachability.validation_status, "confirmed")
        self.assertEqual(result.reachability.evidence, {"response_status": 404})
        self.assertEqual(mocked_dispatch.call_count, 5)

    def test_external_network_failure_is_bounded(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("untrusted transport details", request=request)

        with self.assertRaisesRegex(
            LocalTargetConnectionError,
            "authorized external target is unreachable",
        ) as raised:
            self._run_external(handler)

        self.assertNotIn("untrusted transport details", str(raised.exception))

    def test_external_redirect_is_observed_but_not_followed(self):
        requested_urls = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested_urls.append(str(request.url))
            return httpx.Response(
                302,
                headers={"location": "https://off-origin.invalid/escaped"},
                request=request,
            )

        result, mocked_dispatch = self._run_external(handler)

        self.assertEqual(requested_urls, [f"{EXTERNAL_ORIGIN}/"])
        self.assertEqual(result.reachability.evidence, {"response_status": 302})
        self.assertEqual(mocked_dispatch.call_count, 5)

    def test_external_reachability_uses_non_fixture_metadata(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, request=request)

        result, mocked_dispatch = self._run_external(handler)

        self.assertEqual(result.reachability.source, "generic_external_validation")
        self.assertEqual(result.reachability.template_id, "generic-web-reachability")
        self.assertEqual(result.reachability.endpoint, "/")
        self.assertNotIn("health_status", result.reachability.evidence)
        self.assertEqual(
            {
                artifact.candidate.validator_id
                for artifact in result.validations
            },
            {
                "generic-http-sqli",
                "generic-http-reflected-xss",
                "generic-http-ssrf",
                "generic-http-command-execution",
                "generic-http-exposed-resource",
            },
        )
        self.assertEqual(mocked_dispatch.call_count, 5)


if __name__ == "__main__":
    unittest.main()

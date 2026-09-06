"""Tests for the safe, deterministic local test harness."""

import unittest
from contextlib import contextmanager
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.api.test_harness import get_test_harness_pipeline
from app.db.models import TargetVerificationORM
from app.db.session import get_db
from app.integrations.labs.dvwa import (
    DVWALabConfigurationError,
    DVWALabConnectionError,
)
from app.main import app
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult
from app.services.generic_local_web_validation import (
    GENERIC_LOCAL_WEB_SCENARIO,
    GenericLocalWebRun,
    LocalTargetConnectionError,
)
from app.services.test_harness import (
    AuthorizationRequiredError,
    DEV_DNS_BYPASS_ENV,
    InvalidTargetError,
    TargetNotAllowedError,
    TestHarnessPipeline,
)
from app.services.target_verification import TargetVerificationService
from app.validation.dispatcher import dispatch
from tests.integration_apps.vulnerable_web_app import LocalVulnerableAppServer
from tests.db_utils import make_test_session_factory


class FakeResponse:
    def __init__(self, text):
        self.text = text


class FakeValidatorSession:
    def __init__(self, *, confirmed=True):
        baseline_record = (
            '<pre>ID: 1<br />First name: admin<br />Surname: admin</pre>'
        )
        injected_text = (
            "".join(
                f'<pre>ID: {index}<br />First name: user{index}'
                f'<br />Surname: surname{index}</pre>'
                for index in range(1, 6)
            )
            if confirmed
            else baseline_record
        )
        self.responses = iter([
            FakeResponse(
                '<input name="user_token" value="token-one">'
            ),
            FakeResponse(
                baseline_record
                + '<input name="user_token" value="token-two">'
            ),
            FakeResponse(injected_text),
        ])
        self.calls = []

    def get(self, url, params=None):
        self.calls.append((url, params))
        return next(self.responses)


class FakeLabAdapter:
    def __init__(self, session, base_url="http://127.0.0.1:8080"):
        self.base_url = base_url
        self._session = session

    @contextmanager
    def session(self):
        yield self._session


class FailingLabAdapter:
    base_url = "http://127.0.0.1:8080"

    @contextmanager
    def session(self):
        raise DVWALabConnectionError("local lab is unavailable")
        yield


class TestHarnessPipelineTests(unittest.TestCase):

    def setUp(self):
        self.pipeline = TestHarnessPipeline(
            allowed_origins=[],
            mode="fixture",
        )

    def test_authorization_is_required(self):
        with self.assertRaisesRegex(
            AuthorizationRequiredError,
            "authorization",
        ):
            self.pipeline.run(
                target_url="http://localhost",
                scenario="public_app_validation",
                authorized=False,
            )

    def test_malformed_url_is_rejected(self):
        with self.assertRaisesRegex(InvalidTargetError, "http or https"):
            self.pipeline.run(
                target_url="localhost/dvwa",
                scenario="public_app_validation",
                authorized=True,
            )

    def test_non_local_target_is_rejected(self):
        with self.assertRaisesRegex(TargetNotAllowedError, "allowlisted"):
            self.pipeline.run(
                target_url="https://example.com",
                scenario="public_app_validation",
                authorized=True,
            )

    def test_deterministic_fixture_path_uses_existing_pipeline(self):
        result = self.pipeline.run(
            target_url="http://127.0.0.1:8080/dvwa",
            scenario="public_app_validation",
            authorized=True,
        )

        self.assertEqual(result["mode"], "fixture")
        self.assertEqual(
            result["validation_result"]["status"],
            ValidationStatus.CONFIRMED,
        )
        self.assertEqual(result["technique"]["technique_id"], "T1190")
        self.assertEqual(result["chain_result"]["status"], "confirmed")
        self.assertEqual(
            result["chain_result"]["chains"][0]["mitre_techniques"],
            ["T1190"],
        )

    def test_fixture_provider_receives_canonical_finding(self):
        received = []

        def fixture_provider(finding):
            received.append(finding)
            return ValidationResult(
                status=ValidationStatus.MANUAL_REVIEW,
                confidence=0.6,
                validator="injected_test_fixture",
                method="unit_test",
                evidence={"fixture": True},
            )

        pipeline = TestHarnessPipeline(
            fixture_result_provider=fixture_provider,
            allowed_origins=[],
            mode="fixture",
        )
        result = pipeline.run(
            target_url="http://localhost",
            scenario="public_app_validation",
            authorized=True,
        )

        self.assertEqual(len(received), 1)
        self.assertIsInstance(received[0], Finding)
        self.assertEqual(result["chain_result"]["status"], "potential")

    def test_explicit_lab_origin_can_be_allowlisted_without_network_access(self):
        pipeline = TestHarnessPipeline(
            allowed_origins=["http://lab.internal:8080"],
            mode="fixture",
        )
        result = pipeline.run(
            target_url="http://lab.internal:8080/dvwa",
            scenario="public_app_validation",
            authorized=True,
        )
        self.assertEqual(result["target_url"], "http://lab.internal:8080/dvwa")
        self.assertTrue(result["validation_result"]["evidence"]["fixture"])

    def test_missing_local_lab_configuration_is_reported(self):
        def missing_config():
            raise DVWALabConfigurationError(
                "missing local-lab configuration"
            )

        pipeline = TestHarnessPipeline(
            mode="local_lab",
            allowed_origins=[],
            lab_adapter_factory=missing_config,
        )
        with self.assertRaisesRegex(
            DVWALabConfigurationError,
            "missing local-lab configuration",
        ):
            pipeline.run(
                target_url="http://127.0.0.1:8080",
                scenario="public_app_validation",
                authorized=True,
            )

    def test_local_lab_connection_failure_is_reported(self):
        pipeline = TestHarnessPipeline(
            mode="local_lab",
            allowed_origins=[],
            lab_adapter_factory=lambda: FailingLabAdapter(),
        )
        with self.assertRaisesRegex(
            DVWALabConnectionError,
            "unavailable",
        ):
            pipeline.run(
                target_url="http://127.0.0.1:8080",
                scenario="public_app_validation",
                authorized=True,
            )

    def test_local_lab_uses_existing_registered_validator(self):
        session = FakeValidatorSession(confirmed=True)
        pipeline = TestHarnessPipeline(
            mode="local_lab",
            allowed_origins=[],
            lab_adapter_factory=lambda: FakeLabAdapter(session),
        )
        result = pipeline.run(
            target_url="http://127.0.0.1:8080",
            scenario="public_app_validation",
            authorized=True,
        )

        self.assertEqual(result["mode"], "local_lab")
        self.assertEqual(
            result["validation_result"]["validator"],
            "dvwa_sqli_low",
        )
        self.assertEqual(
            result["validation_result"]["status"],
            ValidationStatus.CONFIRMED,
        )
        self.assertEqual(
            result["validation_result"]["evidence"]["baseline_result_count"],
            1,
        )
        self.assertEqual(
            result["validation_result"]["evidence"]["injected_result_count"],
            5,
        )
        self.assertEqual(len(session.calls), 3)
        self.assertEqual(result["technique"]["technique_id"], "T1190")
        self.assertEqual(result["chain_result"]["status"], "confirmed")

    def test_rejected_local_lab_validation_has_no_confirmed_chain(self):
        session = FakeValidatorSession(confirmed=False)
        pipeline = TestHarnessPipeline(
            mode="local_lab",
            allowed_origins=[],
            lab_adapter_factory=lambda: FakeLabAdapter(session),
        )
        result = pipeline.run(
            target_url="http://127.0.0.1:8080",
            scenario="public_app_validation",
            authorized=True,
        )

        self.assertEqual(
            result["validation_result"]["status"],
            ValidationStatus.REJECTED,
        )
        self.assertNotEqual(result["chain_result"]["status"], "confirmed")
        self.assertEqual(result["chain_result"]["chains"], [])

    def test_assessment_identifiers_survive_local_lab_pipeline(self):
        received = []
        session = FakeValidatorSession(confirmed=True)

        def recording_dispatcher(finding, validator_session):
            received.append(finding)
            return dispatch(finding, validator_session)

        pipeline = TestHarnessPipeline(
            mode="local_lab",
            allowed_origins=[],
            dispatcher=recording_dispatcher,
            lab_adapter_factory=lambda: FakeLabAdapter(session),
        )
        result = pipeline.run(
            target_url="http://127.0.0.1:8080",
            scenario="public_app_validation",
            authorized=True,
        )

        self.assertEqual(len(received), 1)
        self.assertIsInstance(received[0], Finding)
        for field_name in ("finding_id", "scan_id", "asset_id"):
            self.assertEqual(
                result["finding"][field_name],
                getattr(received[0], field_name),
            )

    def test_local_lab_target_must_match_backend_configuration(self):
        pipeline = TestHarnessPipeline(
            mode="local_lab",
            allowed_origins=[],
            lab_adapter_factory=lambda: FakeLabAdapter(
                FakeValidatorSession(),
                base_url="http://127.0.0.1:8080",
            ),
        )
        with self.assertRaisesRegex(TargetNotAllowedError, "DVWA_BASE_URL"):
            pipeline.run(
                target_url="http://127.0.0.1:9090",
                scenario="public_app_validation",
                authorized=True,
            )


class HarnessVerificationDns:
    def __init__(self):
        self.txt = {}
        self.addresses = {}

    def resolve_txt(self, name):
        return tuple(self.txt.get(name, ()))

    def resolve_addresses(self, hostname):
        return tuple(self.addresses.get(hostname, ("93.184.216.34",)))


class GenericExternalVerificationTests(unittest.TestCase):
    def setUp(self):
        self.engine, self.factory = make_test_session_factory()
        self.dns = HarnessVerificationDns()
        self.verification = TargetVerificationService(dns_resolver=self.dns)
        self.external_executions = []

    def tearDown(self):
        self.engine.dispose()

    def pipeline(self, **overrides):
        options = {
            "mode": "fixture",
            "allowed_origins": [],
            "target_verification_service": self.verification,
            "verified_external_scenario_executor": self.external_executor,
            "dev_dns_bypass_enabled": False,
        }
        options.update(overrides)
        return TestHarnessPipeline(**options)

    def external_executor(
        self,
        target,
        *,
        scan_id,
        address_resolver,
    ):
        self.external_executions.append(target)
        self.assertEqual(
            address_resolver(target.hostname),
            ("93.184.216.34",),
        )
        asset_id = f"asset-{scan_id[-12:]}"
        reachability = Finding(
            finding_id=f"finding-{scan_id[-12:]}",
            scan_id=scan_id,
            asset_id=asset_id,
            target=target.origin,
            host=target.hostname,
            port=target.port,
            protocol=target.scheme,
            endpoint="/",
            source="verified_external_test",
            vulnerability_type="service_scan",
            validation_status=ValidationStatus.CONFIRMED,
            validation_confidence=1.0,
        )
        return GenericLocalWebRun(
            origin=target.origin,
            scan_id=scan_id,
            asset_id=asset_id,
            reachability=reachability,
            validations=(),
            chains=(),
        )

    def verify(self, session, origin):
        pending = self.verification.create_challenge(
            session,
            target_url=origin,
        )
        self.dns.txt[pending.txt_record_name] = (pending.txt_record_value,)
        verified = self.verification.verify_challenge(session, pending.id)
        self.assertEqual(verified.status, "verified")
        session.commit()

    def test_loopback_generic_target_keeps_existing_runner_path(self):
        received = []
        pipeline = self.pipeline(
            generic_scenario_runner=lambda origin: (
                received.append(origin) or {"target_url": origin}
            ),
        )

        result = pipeline.run(
            target_url="http://127.0.0.1:8090",
            scenario=GENERIC_LOCAL_WEB_SCENARIO,
            authorized=True,
        )

        self.assertEqual(result["target_url"], "http://127.0.0.1:8090")
        self.assertEqual(received, ["http://127.0.0.1:8090"])
        self.assertEqual(self.external_executions, [])
        self.assertFalse(result["development_dns_bypass_used"])

    def test_external_target_without_verification_is_rejected(self):
        with self.factory() as session:
            with self.assertRaisesRegex(
                TargetNotAllowedError,
                "DNS ownership verification",
            ):
                self.pipeline().run(
                    target_url="https://unverified.example.com",
                    scenario=GENERIC_LOCAL_WEB_SCENARIO,
                    authorized=True,
                    persistence_session=session,
                    skip_dns_verification=False,
                )
        self.assertEqual(self.external_executions, [])

    def test_bypass_request_is_rejected_when_server_flag_is_disabled(self):
        with self.factory() as session:
            with self.assertRaisesRegex(TargetNotAllowedError, "disabled"):
                self.pipeline().run(
                    target_url="https://unverified.example.com",
                    scenario=GENERIC_LOCAL_WEB_SCENARIO,
                    authorized=True,
                    persistence_session=session,
                    skip_dns_verification=True,
                )
        self.assertEqual(self.external_executions, [])

    def test_enabled_server_flag_without_request_still_requires_verification(self):
        with self.factory() as session:
            with self.assertRaisesRegex(
                TargetNotAllowedError,
                "DNS ownership verification",
            ):
                self.pipeline(dev_dns_bypass_enabled=True).run(
                    target_url="https://unverified.example.com",
                    scenario=GENERIC_LOCAL_WEB_SCENARIO,
                    authorized=True,
                    persistence_session=session,
                    skip_dns_verification=False,
                )
        self.assertEqual(self.external_executions, [])

    def test_two_part_gate_bypasses_only_persisted_ownership_check(self):
        origin = "https://bypass.example.com"
        with self.factory() as session:
            pending = self.verification.create_challenge(
                session,
                target_url=origin,
            )
            session.commit()

            result = self.pipeline(dev_dns_bypass_enabled=True).run(
                target_url=origin,
                scenario=GENERIC_LOCAL_WEB_SCENARIO,
                authorized=True,
                persistence_session=session,
                skip_dns_verification=True,
            )
            record = session.get(TargetVerificationORM, pending.id)

        self.assertTrue(result["development_dns_bypass_used"])
        self.assertEqual(len(self.external_executions), 1)
        self.assertEqual(record.status, "pending")
        self.assertIsNone(record.verified_at)

    def test_verified_exact_external_origin_is_allowed(self):
        origin = "https://verified.example.com"
        with self.factory() as session:
            self.verify(session, origin)
            result = self.pipeline().run(
                target_url=origin,
                scenario=GENERIC_LOCAL_WEB_SCENARIO,
                authorized=True,
                persistence_session=session,
                skip_dns_verification=False,
            )

        self.assertEqual(result["target_url"], origin)
        self.assertFalse(result["development_dns_bypass_used"])
        self.assertEqual(len(self.external_executions), 1)
        self.assertEqual(self.external_executions[0].origin, origin)
        self.assertEqual(
            self.external_executions[0].resolved_addresses,
            ("93.184.216.34",),
        )

    def test_verified_origin_does_not_authorize_a_different_subdomain(self):
        with self.factory() as session:
            self.verify(session, "https://app.example.com")
            with self.assertRaisesRegex(
                TargetNotAllowedError,
                "exact external target origin",
            ):
                self.pipeline().run(
                    target_url="https://admin.example.com",
                    scenario=GENERIC_LOCAL_WEB_SCENARIO,
                    authorized=True,
                    persistence_session=session,
                )
        self.assertEqual(self.external_executions, [])

    def test_external_http_target_is_rejected(self):
        with self.factory() as session:
            with self.assertRaisesRegex(TargetNotAllowedError, "HTTPS"):
                self.pipeline(dev_dns_bypass_enabled=True).run(
                    target_url="http://external.example.com",
                    scenario=GENERIC_LOCAL_WEB_SCENARIO,
                    authorized=True,
                    persistence_session=session,
                    skip_dns_verification=True,
                )
        self.assertEqual(self.external_executions, [])

    def test_bypass_still_rejects_private_external_resolution(self):
        self.dns.addresses["private.example.com"] = ("10.0.0.8",)
        with self.factory() as session:
            with self.assertRaisesRegex(TargetNotAllowedError, "non-public"):
                self.pipeline(dev_dns_bypass_enabled=True).run(
                    target_url="https://private.example.com",
                    scenario=GENERIC_LOCAL_WEB_SCENARIO,
                    authorized=True,
                    persistence_session=session,
                    skip_dns_verification=True,
                )
        self.assertEqual(self.external_executions, [])

    def test_external_verification_fails_closed_without_persistence_session(self):
        with self.assertRaisesRegex(TargetNotAllowedError, "persistence session"):
            self.pipeline().run(
                target_url="https://verified.example.com",
                scenario=GENERIC_LOCAL_WEB_SCENARIO,
                authorized=True,
            )
        self.assertEqual(self.external_executions, [])

    def test_authorization_and_origin_path_checks_remain_authoritative(self):
        with self.assertRaises(AuthorizationRequiredError):
            self.pipeline(dev_dns_bypass_enabled=True).run(
                target_url="https://verified.example.com",
                scenario=GENERIC_LOCAL_WEB_SCENARIO,
                authorized=False,
                skip_dns_verification=True,
            )
        with self.assertRaisesRegex(InvalidTargetError, "without a path"):
            self.pipeline(dev_dns_bypass_enabled=True).run(
                target_url="https://verified.example.com/items",
                scenario=GENERIC_LOCAL_WEB_SCENARIO,
                authorized=True,
                skip_dns_verification=True,
            )
        self.assertEqual(self.external_executions, [])

    def test_environment_flag_defaults_off_and_requires_exact_true(self):
        with patch.dict(
            "os.environ",
            {DEV_DNS_BYPASS_ENV: "false"},
            clear=False,
        ):
            self.assertFalse(TestHarnessPipeline().dev_dns_bypass_enabled)
        with patch.dict(
            "os.environ",
            {DEV_DNS_BYPASS_ENV: "true"},
            clear=False,
        ):
            self.assertTrue(TestHarnessPipeline().dev_dns_bypass_enabled)


class TestHarnessApiTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine, cls.factory = make_test_session_factory()

        def override_get_db():
            session = cls.factory()
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.pop(get_db, None)
        cls.engine.dispose()

    def post(self, **overrides):
        request = {
            "target_url": "http://localhost/dvwa",
            "scenario": "public_app_validation",
            "authorized": True,
        }
        request.update(overrides)
        return self.client.post("/api/test-harness/run", json=request)

    def test_api_requires_authorization(self):
        response = self.post(authorized=False)
        self.assertEqual(response.status_code, 403)
        self.assertIn("authorization", response.json()["detail"])

    def test_api_rejects_malformed_url(self):
        response = self.post(target_url="not-a-url")
        self.assertEqual(response.status_code, 422)

    def test_api_rejects_non_local_target(self):
        response = self.post(target_url="https://example.com")
        self.assertEqual(response.status_code, 403)
        self.assertIn("allowlisted", response.json()["detail"])

    def test_generic_scenario_requires_authorization(self):
        response = self.post(
            scenario=GENERIC_LOCAL_WEB_SCENARIO,
            target_url="http://127.0.0.1:8090",
            authorized=False,
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("authorization", response.json()["detail"])

    def test_api_exposes_only_the_server_side_bypass_capability(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                pipeline = TestHarnessPipeline(
                    mode="fixture",
                    allowed_origins=[],
                    dev_dns_bypass_enabled=enabled,
                )
                app.dependency_overrides[
                    get_test_harness_pipeline
                ] = lambda pipeline=pipeline: pipeline
                try:
                    response = self.client.get("/api/test-harness/config")
                finally:
                    app.dependency_overrides.pop(
                        get_test_harness_pipeline,
                        None,
                    )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    response.json(),
                    {"development_dns_bypass_enabled": enabled},
                )

    def test_api_rejects_requested_bypass_when_server_flag_is_disabled(self):
        pipeline = TestHarnessPipeline(
            mode="fixture",
            allowed_origins=[],
            dev_dns_bypass_enabled=False,
        )
        app.dependency_overrides[get_test_harness_pipeline] = lambda: pipeline
        try:
            response = self.post(
                scenario=GENERIC_LOCAL_WEB_SCENARIO,
                target_url="https://unverified.example.com",
                skip_dns_verification=True,
            )
        finally:
            app.dependency_overrides.pop(get_test_harness_pipeline, None)

        self.assertEqual(response.status_code, 403)
        self.assertIn("disabled", response.json()["detail"])

    def test_generic_scenario_static_allowlist_does_not_replace_verification(self):
        pipeline = TestHarnessPipeline(
            mode="fixture",
            allowed_origins=["https://lab.internal"],
        )
        app.dependency_overrides[get_test_harness_pipeline] = lambda: pipeline
        try:
            response = self.post(
                scenario=GENERIC_LOCAL_WEB_SCENARIO,
                target_url="https://lab.internal",
            )
        finally:
            app.dependency_overrides.pop(get_test_harness_pipeline, None)

        self.assertEqual(response.status_code, 403)
        self.assertIn("DNS ownership verification", response.json()["detail"])

    def test_generic_scenario_requires_an_origin_without_path(self):
        response = self.post(
            scenario=GENERIC_LOCAL_WEB_SCENARIO,
            target_url="http://127.0.0.1:8090/items",
        )
        self.assertEqual(response.status_code, 422)
        self.assertIn("without a path", response.json()["detail"])

    def test_api_response_schema(self):
        response = self.post()
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(
            set(body),
            {
                "mode",
                "scenario",
                "target_url",
                "scan_id",
                "finding",
                "validation_result",
                "technique",
                "chain_result",
                "evidence_refs",
                "finding_presentations",
                "attack_flow",
                "presentation_mode",
            },
        )
        self.assertTrue({
            "finding_id",
            "scan_id",
            "asset_id",
            "target",
            "validation_status",
        }.issubset(body["finding"]))
        self.assertTrue({
            "status",
            "confidence",
            "validator",
            "method",
            "evidence",
            "evidence_refs",
        }.issubset(body["validation_result"]))
        self.assertTrue({"status", "chains"}.issubset(body["chain_result"]))
        self.assertEqual(
            body["finding_presentations"][0]["poc"]["label"],
            "Evidence Only",
        )
        self.assertEqual(
            body["finding_presentations"][0]["poc"]["requests"],
            [],
        )

    def test_api_rejects_undeclared_payload_fields(self):
        response = self.post(payload="user-controlled-payload")
        self.assertEqual(response.status_code, 422)

    def test_browser_cannot_select_local_lab_mode(self):
        response = self.post(mode="local_lab")
        self.assertEqual(response.status_code, 422)

    def test_api_returns_clean_lab_connection_error(self):
        pipeline = TestHarnessPipeline(
            mode="local_lab",
            allowed_origins=[],
            lab_adapter_factory=lambda: FailingLabAdapter(),
        )
        app.dependency_overrides[get_test_harness_pipeline] = lambda: pipeline
        try:
            response = self.post(target_url="http://127.0.0.1:8080")
        finally:
            app.dependency_overrides.pop(get_test_harness_pipeline, None)

        self.assertEqual(response.status_code, 502)
        self.assertIn("unavailable", response.json()["detail"])

    def test_api_returns_clean_missing_lab_configuration_error(self):
        def missing_config():
            raise DVWALabConfigurationError(
                "missing local-lab configuration"
            )

        pipeline = TestHarnessPipeline(
            mode="local_lab",
            allowed_origins=[],
            lab_adapter_factory=missing_config,
        )
        app.dependency_overrides[get_test_harness_pipeline] = lambda: pipeline
        try:
            response = self.post(target_url="http://127.0.0.1:8080")
        finally:
            app.dependency_overrides.pop(get_test_harness_pipeline, None)

        self.assertEqual(response.status_code, 503)
        self.assertIn("configuration", response.json()["detail"])

    def test_api_returns_clean_generic_local_connection_error(self):
        def unreachable(_origin, *, scan_id):
            raise LocalTargetConnectionError(
                "authorized local target is unreachable"
            )

        pipeline = TestHarnessPipeline(
            mode="fixture",
            allowed_origins=[],
            generic_scenario_executor=unreachable,
        )
        app.dependency_overrides[get_test_harness_pipeline] = lambda: pipeline
        try:
            response = self.post(
                scenario=GENERIC_LOCAL_WEB_SCENARIO,
                target_url="http://127.0.0.1:1",
            )
        finally:
            app.dependency_overrides.pop(get_test_harness_pipeline, None)

        self.assertEqual(response.status_code, 502)
        self.assertEqual(
            response.json()["detail"],
            "authorized local target is unreachable",
        )

    def test_stopped_local_fixture_fails_safely(self):
        server = LocalVulnerableAppServer()
        origin = server.start()
        server.stop()

        pipeline = TestHarnessPipeline(mode="fixture", allowed_origins=[])
        with self.assertRaisesRegex(
            LocalTargetConnectionError,
            "unreachable",
        ):
            pipeline.run(
                target_url=origin,
                scenario=GENERIC_LOCAL_WEB_SCENARIO,
                authorized=True,
            )

    def test_health_remains_available(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "healthy"})

    def test_root_serves_temporary_ui(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("OBSIDIAN RECON", response.text)
        self.assertIn("Controlled Lab Demonstration", response.text)
        self.assertIn("Authorized security assessment", response.text)

    def test_ui_exposes_generic_local_scenario(self):
        response = self.client.get("/static/app.js")
        self.assertEqual(response.status_code, 200)
        self.assertIn(GENERIC_LOCAL_WEB_SCENARIO, response.text)


class GenericLocalWebHarnessApiTests(unittest.TestCase):
    """Exercise UI API wiring against the controlled real-HTTP fixture."""

    @classmethod
    def setUpClass(cls):
        cls.server = LocalVulnerableAppServer()
        cls.origin = cls.server.start()
        cls.addClassCleanup(cls.server.stop)
        cls.engine, cls.factory = make_test_session_factory()

        def override_get_db():
            session = cls.factory()
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)
        pipeline = TestHarnessPipeline(mode="fixture", allowed_origins=[])
        app.dependency_overrides[get_test_harness_pipeline] = lambda: pipeline
        try:
            cls.response = cls.client.post(
                "/api/test-harness/run",
                json={
                    "target_url": cls.origin,
                    "scenario": GENERIC_LOCAL_WEB_SCENARIO,
                    "authorized": True,
                },
            )
        finally:
            app.dependency_overrides.pop(get_test_harness_pipeline, None)
        cls.body = cls.response.json()

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.pop(get_db, None)
        cls.engine.dispose()

    def validation(self, name):
        return self.body["validations"][name]

    def test_scenario_is_accepted_and_returns_six_findings(self):
        self.assertEqual(self.response.status_code, 200)
        self.assertEqual(self.body["scenario"], GENERIC_LOCAL_WEB_SCENARIO)
        self.assertEqual(self.body["mode"], "live_loopback_fixture")
        self.assertEqual(len(self.body["findings"]), 6)
        self.assertEqual(len(self.body["validations"]), 6)

    def test_sqli_is_confirmed_and_mapped_to_t1190(self):
        result = self.validation("sql_injection")
        self.assertEqual(
            result["validation_result"]["status"],
            ValidationStatus.CONFIRMED,
        )
        self.assertEqual(
            result["validation_result"]["validator"],
            "generic_http_sqli",
        )
        self.assertEqual(result["finding"]["mitre_technique_id"], "T1190")

    def test_xss_is_confirmed_without_fabricated_mitre_mapping(self):
        result = self.validation("reflected_xss")
        self.assertEqual(
            result["validation_result"]["status"],
            ValidationStatus.CONFIRMED,
        )
        self.assertEqual(
            result["validation_result"]["validator"],
            "generic_http_reflected_xss",
        )
        self.assertIsNone(result["finding"]["mitre_technique_id"])

    def test_ssrf_is_confirmed_without_fabricated_mitre_or_capability(self):
        result = self.validation("ssrf")

        self.assertEqual(
            result["validation_result"]["status"],
            ValidationStatus.CONFIRMED,
        )
        self.assertEqual(
            result["validation_result"]["validator"],
            "generic_http_ssrf",
        )
        self.assertTrue(
            result["validation_result"]["evidence"]
            ["canary_content_marker_observed"]
        )
        self.assertIsNone(result["finding"]["mitre_technique_id"])
        self.assertEqual(result["finding"]["provides"], [])

    def test_exposure_is_confirmed_with_conservative_capability(self):
        result = self.validation("exposed_resource")
        self.assertEqual(
            result["validation_result"]["status"],
            ValidationStatus.CONFIRMED,
        )
        self.assertEqual(
            result["validation_result"]["validator"],
            "generic_http_exposed_resource",
        )
        self.assertEqual(
            result["finding"]["provides"],
            ["potential_information_exposure"],
        )

    def test_command_execution_is_confirmed_and_mapped(self):
        result = self.validation("command_execution")
        self.assertEqual(
            result["validation_result"]["status"],
            ValidationStatus.CONFIRMED,
        )
        self.assertEqual(
            result["validation_result"]["validator"],
            "generic_http_command_execution",
        )
        self.assertEqual(
            result["finding"]["mitre_technique_id"],
            "T1059.004",
        )

    def test_system_information_is_confirmed_and_mapped(self):
        result = self.validation("system_information_discovery")
        self.assertEqual(
            result["validation_result"]["status"],
            ValidationStatus.CONFIRMED,
        )
        self.assertEqual(
            result["validation_result"]["validator"],
            "controlled_http_system_information_discovery",
        )
        self.assertEqual(result["finding"]["mitre_technique_id"], "T1082")
        self.assertEqual(
            result["finding"]["requires_any"],
            ["command_execution"],
        )
        self.assertEqual(
            result["finding"]["provides"],
            ["system_information"],
        )

    def test_attack_chains_and_steps_are_serialized(self):
        chain_result = self.body["chain_result"]
        self.assertEqual(chain_result["status"], "confirmed")
        self.assertEqual(len(chain_result["chains"]), 4)
        self.assertTrue(all(chain["steps"] for chain in chain_result["chains"]))
        self.assertEqual(chain_result["chains"], self.body["chains"])
        progression = next(
            chain for chain in chain_result["chains"]
            if "T1059.004" in chain["mitre_techniques"]
        )
        self.assertEqual(
            progression["mitre_techniques"],
            ["T1190", "T1059.004", "T1082"],
        )
        self.assertEqual(len(progression["steps"]), 4)

    def test_generic_api_response_schema_is_valid(self):
        self.assertEqual(
            set(self.body),
            {
                "mode",
                "scenario",
                "overall_status",
                "target_url",
                "origin",
                "scan_id",
                "asset_id",
                "findings",
                "validations",
                "chain_result",
                "chains",
                "finding_presentations",
                "attack_flow",
                "presentation_mode",
                "development_dns_bypass_used",
                "agent_run",
            },
        )
        self.assertFalse(self.body["development_dns_bypass_used"])
        self.assertEqual(self.body["overall_status"], "completed")
        self.assertEqual(self.body["presentation_mode"], "controlled_lab")
        self.assertEqual(len(self.body["finding_presentations"]), 6)
        self.assertTrue(self.body["attack_flow"]["multi_stage_paths"])
        self.assertEqual(
            set(self.body["agent_run"]),
            {
                "initial_state",
                "steps",
                "final_state",
                "status",
                "stop_reason",
                "steps_used",
            },
        )
        self.assertEqual(
            self.body["agent_run"]["initial_state"]["scan_id"],
            self.body["scan_id"],
        )
        self.assertEqual(
            self.body["agent_run"]["initial_state"]["asset_id"],
            self.body["asset_id"],
        )
        for result in self.body["validations"].values():
            self.assertTrue({
                "vulnerability_type",
                "template_id",
                "mitre_technique_id",
                "provides",
            }.issubset(result["finding"]))
            self.assertTrue({
                "status",
                "confidence",
                "validator",
            }.issubset(result["validation_result"]))

    def test_generic_api_exposes_controlled_poc_and_cumulative_chain_risk(self):
        presentations = {
            item["vulnerability_type"]: item
            for item in self.body["finding_presentations"]
        }
        self.assertEqual(
            presentations["sql_injection"]["poc"]["label"],
            "Controlled Lab",
        )
        self.assertEqual(
            len(presentations["sql_injection"]["poc"]["requests"]),
            7,
        )
        method_states = {
            method["name"]: method["state"]
            for method in presentations["sql_injection"]["poc"]
            ["detection_methods"]
        }
        self.assertEqual(method_states["Boolean Differential"], "confirmed")
        self.assertEqual(
            presentations["command_execution"]["risk"]["rating"],
            "Critical",
        )
        self.assertEqual(
            presentations["ssrf"]["poc"]["verification_method"],
            "Controlled same-origin canary retrieval",
        )
        self.assertIn(
            "No loopback admin service",
            presentations["ssrf"]["poc"]["safety_note"],
        )
        progression = next(
            path
            for path in self.body["attack_flow"]["multi_stage_paths"]
            if "command_execution" in path["cumulative_capabilities"]
        )
        self.assertEqual(progression["cumulative_risk"], "Critical")
        self.assertTrue(any(
            dependency["capability"] == "application_compromise"
            for dependency in progression["dependencies"]
        ))


if __name__ == "__main__":
    unittest.main()

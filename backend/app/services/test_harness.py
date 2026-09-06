"""Safe, deterministic pipeline for the temporary local developer UI."""

from __future__ import annotations

import hashlib
import ipaddress
import os
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Callable, ContextManager, Dict, Iterable, Optional, Protocol
from urllib.parse import urlparse, urlunparse
from uuid import uuid4

from sqlalchemy.orm import Session

from app.agent.run_service import AgentRunService
from app.attack_chain.engine import build_attack_paths, load_all_findings
from app.attack_chain.mitre_mapping import enrich_finding_model
from app.integrations.labs.dvwa import DVWALabAdapter
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult
from app.services.controlled_demo_agent import (
    AgentRunServiceFactory,
    run_controlled_demo_agent,
)
from app.services.generic_local_web_validation import (
    GENERIC_LOCAL_WEB_SCENARIO,
    GenericLocalWebRun,
    TargetScopeError,
    execute_generic_local_web_validation,
    execute_verified_external_web_validation,
    run_generic_local_web_validation,
)
from app.services.persistence import (
    ServicePersistenceRecord,
    ValidationPersistenceRecord,
    mark_validation_run_failed,
    persist_validation_outputs,
    start_validation_run,
)
from app.scanning.scope import (
    AuthorizedTarget,
    ReconScopeError,
    TargetVerificationRequiredError,
    authorize_target,
    normalize_origin,
)
from app.services.target_verification import TargetVerificationService
from app.validation.dispatcher import apply_validation_result, dispatch


PUBLIC_APP_SCENARIO = "public_app_validation"
# Compatibility name retained for callers of the original single scenario.
SUPPORTED_SCENARIO = PUBLIC_APP_SCENARIO
SUPPORTED_SCENARIOS = frozenset({
    PUBLIC_APP_SCENARIO,
    GENERIC_LOCAL_WEB_SCENARIO,
})
FIXTURE_MODE = "fixture"
LOCAL_LAB_MODE = "local_lab"
SUPPORTED_MODES = frozenset({FIXTURE_MODE, LOCAL_LAB_MODE})
MODE_ENV = "TEST_HARNESS_MODE"
ALLOWED_ORIGINS_ENV = "TEST_HARNESS_ALLOWED_ORIGINS"
DEV_DNS_BYPASS_ENV = "ENABLE_DEV_DNS_BYPASS"


class TestHarnessError(ValueError):
    """Base class for request errors that can be returned safely by the API."""


class AuthorizationRequiredError(TestHarnessError):
    """Raised when the caller has not confirmed authorization."""


class UnsupportedScenarioError(TestHarnessError):
    """Raised when a scenario is not implemented by the fixture harness."""


class InvalidTargetError(TestHarnessError):
    """Raised when a target URL cannot be safely normalized."""


class TargetNotAllowedError(TestHarnessError):
    """Raised when a target is neither local nor explicitly allowlisted."""


class HarnessConfigurationError(TestHarnessError):
    """Raised when backend-only harness mode configuration is invalid."""


@dataclass(frozen=True)
class TargetContext:
    """Normalized, non-secret target metadata used by fixture records."""

    url: str
    origin: str
    host: str
    port: int
    protocol: str
    endpoint: str


FixtureResultProvider = Callable[[Finding], ValidationResult]
Dispatcher = Callable[[Finding, Optional[Any]], ValidationResult]


class LabAdapter(Protocol):
    @property
    def base_url(self) -> str:
        ...

    def session(self) -> ContextManager[Any]:
        ...


LabAdapterFactory = Callable[[], LabAdapter]
GenericScenarioRunner = Callable[[str], Dict[str, Any]]
GenericScenarioExecutor = Callable[..., GenericLocalWebRun]
VerifiedExternalScenarioExecutor = Callable[..., GenericLocalWebRun]


def deterministic_fixture_result(finding: Finding) -> ValidationResult:
    """Adapt the checked-in SQLi fixture; never connect to the target."""
    if not isinstance(finding, Finding):
        raise TypeError("fixture result provider expects a Finding instance")

    fixture = _load_fixture_finding("sql_injection")
    return ValidationResult(
        status=fixture.validation_status,
        confidence=fixture.validation_confidence,
        validator="test_harness_fixture",
        method="deterministic_fixture",
        evidence={
            **fixture.evidence,
            "fixture": True,
            "fixture_source": "backend/data/evidence_store.json",
            "scenario": SUPPORTED_SCENARIO,
            "summary": (
                "Checked-in developer fixture; no request was sent to the target."
            ),
        },
        evidence_refs=[
            "fixture://test-harness/public-app-validation/result"
        ],
    )


def _load_fixture_finding(vulnerability_type: str) -> Finding:
    for fixture in load_all_findings(scan_id="test-harness-fixture-template"):
        if fixture.vulnerability_type == vulnerability_type:
            return fixture
    raise RuntimeError(
        f"checked-in test fixture is missing {vulnerability_type!r}"
    )


def _format_hostname(hostname: str) -> str:
    return f"[{hostname}]" if ":" in hostname else hostname


def _parse_target(target_url: str) -> TargetContext:
    if not isinstance(target_url, str) or not target_url.strip():
        raise InvalidTargetError("target_url must be a non-empty URL")

    try:
        parsed = urlparse(target_url.strip())
        port = parsed.port
    except ValueError as exc:
        raise InvalidTargetError("target_url contains an invalid port") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise InvalidTargetError("target_url must use http or https")
    if not parsed.hostname:
        raise InvalidTargetError("target_url must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise InvalidTargetError("target_url must not include credentials")
    if parsed.query or parsed.fragment:
        raise InvalidTargetError(
            "target_url must not include a query string or fragment"
        )

    protocol = parsed.scheme.lower()
    host = parsed.hostname.lower()
    resolved_port = port or (443 if protocol == "https" else 80)
    display_host = _format_hostname(host)
    default_port = 443 if protocol == "https" else 80
    netloc = (
        display_host
        if resolved_port == default_port
        else f"{display_host}:{resolved_port}"
    )
    origin = f"{protocol}://{netloc}"
    endpoint = parsed.path or "/"
    normalized_url = urlunparse((
        protocol,
        netloc,
        endpoint,
        "",
        "",
        "",
    ))

    return TargetContext(
        url=normalized_url,
        origin=origin,
        host=host,
        port=resolved_port,
        protocol=protocol,
        endpoint=endpoint,
    )


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _normalize_allowed_origins(origins: Iterable[str]) -> frozenset[str]:
    normalized = set()
    for origin in origins:
        if not origin.strip():
            continue
        context = _parse_target(origin)
        if context.endpoint != "/":
            raise InvalidTargetError(
                "allowlisted targets must be origins without a path"
            )
        normalized.add(context.origin)
    return frozenset(normalized)


class TestHarnessPipeline:
    """Coordinate fixture or configured local-lab validation through the core."""

    __test__ = False

    def __init__(
        self,
        *,
        fixture_result_provider: FixtureResultProvider = (
            deterministic_fixture_result
        ),
        allowed_origins: Optional[Iterable[str]] = None,
        mode: Optional[str] = None,
        dispatcher: Dispatcher = dispatch,
        lab_adapter_factory: LabAdapterFactory = DVWALabAdapter.from_environment,
        generic_scenario_runner: GenericScenarioRunner = (
            run_generic_local_web_validation
        ),
        generic_scenario_executor: GenericScenarioExecutor = (
            execute_generic_local_web_validation
        ),
        verified_external_scenario_executor: VerifiedExternalScenarioExecutor = (
            execute_verified_external_web_validation
        ),
        target_verification_service: Optional[TargetVerificationService] = None,
        dev_dns_bypass_enabled: Optional[bool] = None,
        agent_run_service_factory: AgentRunServiceFactory = (
            AgentRunService.from_environment
        ),
    ) -> None:
        if not callable(fixture_result_provider):
            raise TypeError("fixture_result_provider must be callable")
        self._fixture_result_provider = fixture_result_provider
        if not callable(dispatcher):
            raise TypeError("dispatcher must be callable")
        if not callable(lab_adapter_factory):
            raise TypeError("lab_adapter_factory must be callable")
        if not callable(generic_scenario_runner):
            raise TypeError("generic_scenario_runner must be callable")
        if not callable(generic_scenario_executor):
            raise TypeError("generic_scenario_executor must be callable")
        if not callable(verified_external_scenario_executor):
            raise TypeError(
                "verified_external_scenario_executor must be callable"
            )
        self._dispatcher = dispatcher
        self._lab_adapter_factory = lab_adapter_factory
        self._generic_scenario_runner = generic_scenario_runner
        self._generic_scenario_executor = generic_scenario_executor
        self._verified_external_scenario_executor = (
            verified_external_scenario_executor
        )
        self._target_verification_service = (
            target_verification_service or TargetVerificationService()
        )
        if not callable(agent_run_service_factory):
            raise TypeError("agent_run_service_factory must be callable")
        self._agent_run_service_factory = agent_run_service_factory
        if (
            dev_dns_bypass_enabled is not None
            and type(dev_dns_bypass_enabled) is not bool
        ):
            raise TypeError("dev_dns_bypass_enabled must be a boolean")
        self._dev_dns_bypass_enabled = (
            os.getenv(DEV_DNS_BYPASS_ENV, "false").strip().lower() == "true"
            if dev_dns_bypass_enabled is None
            else dev_dns_bypass_enabled
        )
        configured_mode = mode if mode is not None else os.getenv(
            MODE_ENV,
            FIXTURE_MODE,
        )
        self._mode = configured_mode.strip().lower()

        configured_origins = allowed_origins
        if configured_origins is None:
            configured_origins = os.getenv(ALLOWED_ORIGINS_ENV, "").split(",")
        self._allowed_origins = _normalize_allowed_origins(configured_origins)

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def dev_dns_bypass_enabled(self) -> bool:
        return self._dev_dns_bypass_enabled

    def _validate_mode(self) -> None:
        if self._mode not in SUPPORTED_MODES:
            supported = ", ".join(sorted(SUPPORTED_MODES))
            raise HarnessConfigurationError(
                f"unsupported {MODE_ENV} {self._mode!r}; expected: {supported}"
            )

    def _run_local_lab(
        self,
        finding: Finding,
        target: TargetContext,
    ) -> ValidationResult:
        adapter = self._lab_adapter_factory()
        configured_target = _parse_target(adapter.base_url)
        if configured_target.url.rstrip("/") != target.url.rstrip("/"):
            raise TargetNotAllowedError(
                "local_lab target must exactly match the backend-configured "
                "DVWA_BASE_URL"
            )

        with adapter.session() as session:
            return self._dispatcher(finding, session)

    def _authorize_generic_external_target(
        self,
        target: TargetContext,
        persistence_session: Optional[Session],
        *,
        skip_dns_verification: bool,
    ) -> tuple[Optional[AuthorizedTarget], bool]:
        if _is_loopback_host(target.host):
            return None, False
        if persistence_session is None:
            raise TargetNotAllowedError(
                "external generic validation requires a persistence session "
                "for DNS ownership verification"
            )

        try:
            normalized = normalize_origin(target.origin)
            bypass_used = (
                self._dev_dns_bypass_enabled and skip_dns_verification
            )
            ownership_verified = bypass_used
            if not ownership_verified:
                ownership_verified = (
                    self._target_verification_service.is_origin_verified(
                        persistence_session,
                        normalized.origin,
                    )
                )
            authorized_target = authorize_target(
                normalized.origin,
                authorized=True,
                ownership_verified=ownership_verified,
                address_resolver=(
                    self._target_verification_service.resolve_addresses
                ),
            )
            return authorized_target, bypass_used
        except TargetVerificationRequiredError:
            raise TargetNotAllowedError(
                "DNS ownership verification is required for this exact "
                "external target origin"
            ) from None
        except ReconScopeError as exc:
            raise TargetNotAllowedError(str(exc)) from exc

    def run(
        self,
        *,
        target_url: str,
        scenario: str,
        authorized: bool,
        persistence_session: Optional[Session] = None,
        skip_dns_verification: bool = False,
    ) -> Dict[str, object]:
        self._validate_mode()
        if authorized is not True:
            raise AuthorizationRequiredError(
                "explicit authorization confirmation is required"
            )
        if scenario not in SUPPORTED_SCENARIOS:
            supported = ", ".join(sorted(SUPPORTED_SCENARIOS))
            raise UnsupportedScenarioError(
                f"unsupported scenario {scenario!r}; supported: {supported}"
            )
        if type(skip_dns_verification) is not bool:
            raise TargetNotAllowedError(
                "skip_dns_verification must be a boolean"
            )
        if skip_dns_verification and not self._dev_dns_bypass_enabled:
            raise TargetNotAllowedError(
                "development DNS ownership bypass is disabled on this server"
            )
        if (
            skip_dns_verification
            and scenario != GENERIC_LOCAL_WEB_SCENARIO
        ):
            raise TargetNotAllowedError(
                "development DNS ownership bypass is available only for the "
                "generic test-harness scenario"
            )

        target = _parse_target(target_url)
        verified_external_target = None
        development_dns_bypass_used = False
        if scenario == GENERIC_LOCAL_WEB_SCENARIO:
            if target.endpoint != "/":
                raise InvalidTargetError(
                    "generic local web validation requires a target origin "
                    "without a path"
                )
            (
                verified_external_target,
                development_dns_bypass_used,
            ) = self._authorize_generic_external_target(
                target,
                persistence_session,
                skip_dns_verification=skip_dns_verification,
            )
            if verified_external_target is not None:
                target = _parse_target(verified_external_target.origin)
        elif (
            not _is_loopback_host(target.host)
            and target.origin not in self._allowed_origins
        ):
            raise TargetNotAllowedError(
                "target must be localhost, a loopback address, or an explicitly "
                "allowlisted lab origin"
            )

        scan_id = f"scan-{uuid4()}"
        asset_digest = hashlib.sha256(
            f"{scan_id}:{target.origin}".encode("utf-8")
        ).hexdigest()[:16]
        asset_id = f"asset-{asset_digest}"

        scan_started = False
        if persistence_session is not None:
            start_validation_run(
                persistence_session,
                scan_id=scan_id,
                target_url=target.url,
                authorized=authorized,
            )
            scan_started = True

        try:
            if scenario == GENERIC_LOCAL_WEB_SCENARIO:
                if persistence_session is None:
                    result = dict(self._generic_scenario_runner(target.origin))
                    result["development_dns_bypass_used"] = False
                    return result
                if verified_external_target is None:
                    generic_run = self._generic_scenario_executor(
                        target.origin,
                        scan_id=scan_id,
                    )
                else:
                    generic_run = self._verified_external_scenario_executor(
                        verified_external_target,
                        scan_id=scan_id,
                        address_resolver=(
                            self._target_verification_service.resolve_addresses
                        ),
                    )
                persist_validation_outputs(
                    persistence_session,
                    scan_id=scan_id,
                    findings=generic_run.findings,
                    validations=[
                        ValidationPersistenceRecord(
                            candidate=artifact.candidate,
                            validation=artifact.validation,
                            enriched=artifact.enriched,
                        )
                        for artifact in generic_run.validations
                    ],
                    attack_chains=generic_run.chains,
                    services=[ServicePersistenceRecord(
                        asset_id=generic_run.asset_id,
                        port=target.port,
                        protocol="tcp",
                        service_name=target.protocol,
                        state="open",
                        source="local_integration_fixture",
                    )],
                )
                result = generic_run.to_dict()
                agent_run = run_controlled_demo_agent(
                    generic_run,
                    authorized_target=verified_external_target,
                    address_resolver=(
                        self._target_verification_service.resolve_addresses
                        if verified_external_target is not None
                        else None
                    ),
                    run_service_factory=self._agent_run_service_factory,
                )
                result["agent_run"] = agent_run.to_dict()
                result["development_dns_bypass_used"] = (
                    development_dns_bypass_used
                )
                return result

            return self._run_public_app_scenario(
                target=target,
                scenario=scenario,
                scan_id=scan_id,
                asset_id=asset_id,
                persistence_session=persistence_session,
            )
        except TargetScopeError as exc:
            if scan_started:
                self._mark_failed(persistence_session, scan_id, exc)
            raise TargetNotAllowedError(str(exc)) from exc
        except Exception as exc:
            if scan_started:
                self._mark_failed(persistence_session, scan_id, exc)
            raise

    @staticmethod
    def _mark_failed(
        session: Optional[Session],
        scan_id: str,
        error: Exception,
    ) -> None:
        if session is None:
            return
        mark_validation_run_failed(
            session,
            scan_id=scan_id,
            failure_reason=(
                f"{type(error).__name__}: controlled harness run failed"
            ),
        )

    def _run_public_app_scenario(
        self,
        *,
        target: TargetContext,
        scenario: str,
        scan_id: str,
        asset_id: str,
        persistence_session: Optional[Session],
    ) -> Dict[str, object]:

        observed_at = datetime.now(timezone.utc).isoformat()
        reachability_fixture = _load_fixture_finding("nmap_scan")
        reachability = replace(
            reachability_fixture,
            finding_id=f"finding-{uuid4()}",
            scan_id=scan_id,
            asset_id=asset_id,
            target=target.url,
            host=target.host,
            port=target.port,
            protocol=target.protocol,
            endpoint=target.endpoint,
            source="test_harness_fixture",
            observed_at=observed_at,
            evidence={
                **reachability_fixture.evidence,
                "fixture": True,
                "fixture_source": "backend/data/evidence_store.json",
            },
            evidence_refs=[
                "fixture://test-harness/public-app-validation/reachability"
            ],
        )
        finding_fixture = _load_fixture_finding("sql_injection")
        finding = replace(
            finding_fixture,
            finding_id=f"finding-{uuid4()}",
            scan_id=scan_id,
            asset_id=asset_id,
            target=target.url,
            host=target.host,
            port=target.port,
            protocol=target.protocol,
            endpoint=finding_fixture.endpoint,
            source=(
                "test_harness_fixture"
                if self._mode == FIXTURE_MODE
                else "test_harness_local_lab"
            ),
            validation_status=ValidationStatus.DETECTED,
            validation_confidence=0.2,
            observed_at=observed_at,
            evidence={
                "fixture": self._mode == FIXTURE_MODE,
                "scenario": SUPPORTED_SCENARIO,
                "mode": self._mode,
            },
            evidence_refs=(
                ["fixture://test-harness/public-app-validation/finding"]
                if self._mode == FIXTURE_MODE
                else []
            ),
        )

        if self._mode == FIXTURE_MODE:
            validation_result = self._fixture_result_provider(finding)
        else:
            validation_result = self._run_local_lab(finding, target)
        if not isinstance(validation_result, ValidationResult):
            raise TypeError(
                "validation must return a ValidationResult"
            )

        validated_finding = apply_validation_result(
            finding,
            validation_result,
        )
        mapped_finding = enrich_finding_model(validated_finding)
        chains = build_attack_paths([reachability, mapped_finding])

        if persistence_session is not None:
            persist_validation_outputs(
                persistence_session,
                scan_id=scan_id,
                findings=[reachability, finding],
                validations=[ValidationPersistenceRecord(
                    candidate=finding,
                    validation=validation_result,
                    enriched=mapped_finding,
                )],
                attack_chains=chains,
                services=[ServicePersistenceRecord(
                    asset_id=asset_id,
                    port=target.port,
                    protocol="tcp",
                    service_name=target.protocol,
                    state="open",
                    source=reachability.source,
                )],
            )

        serialized_chains = [chain.to_dict() for chain in chains]
        chain_status = (
            serialized_chains[0]["status"] if serialized_chains else "none"
        )
        evidence_refs = list(dict.fromkeys([
            *mapped_finding.evidence_refs,
            *(
                reference
                for chain in chains
                for reference in chain.evidence_refs
            ),
        ]))

        technique = None
        if mapped_finding.mitre_technique_id:
            technique = {
                "technique_id": mapped_finding.mitre_technique_id,
                "technique_name": mapped_finding.mitre_technique_name,
                "tactic": mapped_finding.mitre_tactic,
            }

        return {
            "mode": self._mode,
            "scenario": scenario,
            "target_url": target.url,
            "scan_id": scan_id,
            "finding": mapped_finding.to_dict(),
            "validation_result": validation_result.to_dict(),
            "technique": technique,
            "chain_result": {
                "status": chain_status,
                "chains": serialized_chains,
            },
            "evidence_refs": evidence_refs,
        }

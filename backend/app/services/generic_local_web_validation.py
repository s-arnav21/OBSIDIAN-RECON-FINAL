"""Loopback-only orchestration for the generic local web demo."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlsplit
from uuid import uuid4

import httpx

from app.attack_chain.engine import build_attack_paths
from app.attack_chain.mitre_mapping import enrich_finding_model
from app.models.attack_chain import AttackChain
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult
from app.scanning.http_discovery import ScopedReconHttpClient
from app.scanning.normalizer import (
    ExposedResourceScannerRecord,
    HttpScannerRecord,
    normalize_command_execution_record,
    normalize_exposed_resource_record,
    normalize_http_sqli_record,
    normalize_reflected_xss_record,
    normalize_ssrf_record,
    normalize_system_information_discovery_record,
)
from app.scanning.scope import AuthorizedTarget, ReconScopeError
from app.validation.dispatcher import apply_validation_result, dispatch


GENERIC_LOCAL_WEB_SCENARIO = "generic_local_web_validation"


class TargetScopeError(ValueError):
    """Raised before a request can leave the approved loopback origin."""


class LocalTargetConnectionError(ConnectionError):
    """Raised when the approved local fixture cannot be reached safely."""


@dataclass(frozen=True)
class _ReachabilityPolicy:
    endpoint: str
    source: str
    template_id: str
    evidence_status_key: str
    required_status: Optional[int] = None
    controlled_fixture: bool = False


_LOCAL_FIXTURE_REACHABILITY = _ReachabilityPolicy(
    endpoint="/health",
    source="local_integration_fixture",
    template_id="local-fixture-health-check",
    evidence_status_key="health_status",
    required_status=200,
    controlled_fixture=True,
)

_EXTERNAL_REACHABILITY = _ReachabilityPolicy(
    endpoint="/",
    source="generic_external_validation",
    template_id="generic-web-reachability",
    evidence_status_key="response_status",
)


@dataclass(frozen=True)
class GenericValidationArtifact:
    """Original candidate and its separate deterministic validation views."""

    name: str
    candidate: Finding
    validation: ValidationResult
    enriched: Finding


@dataclass(frozen=True)
class GenericLocalWebRun:
    """Typed artifacts retained until optional persistence is complete."""

    origin: str
    scan_id: str
    asset_id: str
    reachability: Finding
    validations: Tuple[GenericValidationArtifact, ...]
    chains: Tuple[AttackChain, ...]

    @property
    def findings(self) -> Tuple[Finding, ...]:
        return (
            self.reachability,
            *(artifact.candidate for artifact in self.validations),
        )

    def to_dict(self) -> Dict[str, Any]:
        serialized_validations = {
            artifact.name: {
                "finding": artifact.enriched.to_dict(),
                "validation_result": artifact.validation.to_dict(),
            }
            for artifact in self.validations
        }
        serialized_chains = [chain.to_dict() for chain in self.chains]
        chain_status = (
            "confirmed"
            if serialized_chains
            and all(chain["status"] == "confirmed" for chain in serialized_chains)
            else "potential"
            if serialized_chains
            else "none"
        )
        return {
            "mode": "live_loopback_fixture",
            "scenario": GENERIC_LOCAL_WEB_SCENARIO,
            "overall_status": "completed",
            "target_url": self.origin,
            "origin": self.origin,
            "scan_id": self.scan_id,
            "asset_id": self.asset_id,
            "findings": [
                artifact.enriched.to_dict() for artifact in self.validations
            ],
            "validations": serialized_validations,
            "chain_result": {
                "status": chain_status,
                "chains": serialized_chains,
            },
            # Retained for the Step 7 integration contract.
            "chains": serialized_chains,
        }


def _origin_tuple(
    url: str,
    *,
    require_origin: bool = False,
) -> tuple[str, str, int]:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise TargetScopeError("approved origin contains an invalid port") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetScopeError("approved origin must be an HTTP URL")
    if parsed.username is not None or parsed.password is not None:
        raise TargetScopeError("approved origin must not include credentials")
    if require_origin and (
        parsed.query or parsed.fragment or parsed.path not in {"", "/"}
    ):
        raise TargetScopeError("approved origin must not include a path or query")

    resolved_port = port or (443 if scheme == "https" else 80)
    return scheme, parsed.hostname.lower(), resolved_port


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _format_hostname(host: str) -> str:
    return f"[{host}]" if ":" in host else host


class ScopedLoopbackHttpClient:
    """HTTP client that rejects every request outside one loopback origin."""

    def __init__(self, approved_origin: str) -> None:
        scheme, host, port = _origin_tuple(
            approved_origin,
            require_origin=True,
        )
        if not _is_loopback(host):
            raise TargetScopeError("approved origin must be loopback")

        default_port = 443 if scheme == "https" else 80
        display_host = _format_hostname(host)
        netloc = display_host if port == default_port else f"{display_host}:{port}"
        self.approved_origin = f"{scheme}://{netloc}"
        self._approved_origin_tuple = (scheme, host, port)
        self._client = httpx.Client(
            follow_redirects=False,
            timeout=3.0,
            trust_env=False,
        )
        self.requested_urls: list[str] = []
        self.blocked_urls: list[str] = []

    def _scoped_url(self, url: str) -> str:
        resolved = urljoin(f"{self.approved_origin}/", url)
        if _origin_tuple(resolved) != self._approved_origin_tuple:
            self.blocked_urls.append(resolved)
            raise TargetScopeError("request URL is outside the approved origin")
        self.requested_urls.append(resolved)
        return resolved

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        """Send one request after resolving and enforcing the exact origin."""
        return self._client.request(method, self._scoped_url(url), **kwargs)

    def get(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Any:
        return self.request("GET", url, params=params, **kwargs)

    def post(
        self,
        url: str,
        data: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Any:
        return self.request("POST", url, data=data, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Any:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> Any:
        return self.request("PATCH", url, **kwargs)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ScopedLoopbackHttpClient":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def _scanner_records(
    origin: str,
    *,
    scan_id: str,
    asset_id: str,
    observed_at: str,
    include_system_information_discovery: bool,
) -> Dict[str, object]:
    """Create only the trusted candidates exposed by the local fixture."""
    common = {
        "scan_id": scan_id,
        "asset_id": asset_id,
        "target": origin,
        "scanner_name": "local_integration_fixture",
        "observed_at": observed_at,
    }
    records: Dict[str, object] = {
        "sql_injection": HttpScannerRecord(
            record_id=f"finding-{uuid4()}",
            endpoint="/items",
            http_method="GET",
            parameter_name="id",
            parameter_location="query",
            scanner_template_id="local-fixture-sqli-check",
            vulnerability_type="sql_injection",
            severity="high",
            evidence={"fixture_endpoint": True},
            **common,
        ),
        "reflected_xss": HttpScannerRecord(
            record_id=f"finding-{uuid4()}",
            endpoint="/search",
            http_method="GET",
            parameter_name="q",
            parameter_location="query",
            scanner_template_id="local-fixture-reflected-xss-check",
            vulnerability_type="reflected_xss",
            severity="medium",
            evidence={"fixture_endpoint": True},
            **common,
        ),
        "ssrf": HttpScannerRecord(
            record_id=f"finding-{uuid4()}",
            endpoint="/ssrf/fetch",
            http_method="GET",
            parameter_name="url",
            parameter_location="query",
            scanner_template_id="local-fixture-ssrf-check",
            vulnerability_type="ssrf",
            severity="high",
            evidence={"fixture_endpoint": True},
            **common,
        ),
        "command_execution": HttpScannerRecord(
            record_id=f"finding-{uuid4()}",
            endpoint="/admin/diagnostics",
            http_method="POST",
            parameter_name="diagnostic_token",
            parameter_location="form",
            scanner_template_id="local-fixture-command-execution-check",
            vulnerability_type="command_execution",
            severity="critical",
            evidence={"fixture_endpoint": True},
            **common,
        ),
        "exposed_resource": ExposedResourceScannerRecord(
            record_id=f"finding-{uuid4()}",
            endpoint="/debug-config",
            scanner_template_id="local-fixture-exposure-check",
            vulnerability_type="debug_resource_exposure",
            severity="high",
            evidence={"fixture_endpoint": True},
            **common,
        ),
    }
    if include_system_information_discovery:
        records["system_information_discovery"] = HttpScannerRecord(
            record_id=f"finding-{uuid4()}",
            endpoint="/admin/system-information",
            http_method="POST",
            parameter_name="discovery_token",
            parameter_location="form",
            scanner_template_id=(
                "local-fixture-system-information-discovery-check"
            ),
            vulnerability_type="system_information_discovery",
            severity="low",
            evidence={
                "fixture_endpoint": True,
                "synthetic_system_information_only": True,
            },
            **common,
        )
    return records


def execute_local_multi_validator_pipeline(
    origin: str,
    client: ScopedLoopbackHttpClient | ScopedReconHttpClient,
    *,
    scan_id: Optional[str] = None,
    reachability_policy: _ReachabilityPolicy = _LOCAL_FIXTURE_REACHABILITY,
) -> GenericLocalWebRun:
    """Run the existing pipeline and retain typed artifacts for persistence."""
    approved_origin = getattr(client, "approved_origin", None)
    if approved_origin is None:
        approved_origin = getattr(getattr(client, "target", None), "origin", None)
    if approved_origin != origin.rstrip("/"):
        raise TargetScopeError("pipeline origin must match the scoped client")

    reachability_response = client.get(
        f"{origin}{reachability_policy.endpoint}"
    )
    reachability_status = getattr(reachability_response, "status_code", None)
    if isinstance(reachability_status, bool) or not isinstance(
        reachability_status,
        int,
    ):
        raise LocalTargetConnectionError(
            "authorized target returned an invalid HTTP response"
        )
    if (
        reachability_policy.required_status is not None
        and reachability_status != reachability_policy.required_status
    ):
        raise LocalTargetConnectionError(
            "authorized local target failed its fixture health check"
        )

    resolved_scan_id = scan_id or f"scan-{uuid4()}"
    asset_digest = hashlib.sha256(
        f"{resolved_scan_id}:{origin}".encode("utf-8")
    ).hexdigest()[:16]
    asset_id = f"asset-{asset_digest}"
    observed_at = datetime.now(timezone.utc).isoformat()
    records = _scanner_records(
        origin,
        scan_id=resolved_scan_id,
        asset_id=asset_id,
        observed_at=observed_at,
        include_system_information_discovery=(
            reachability_policy.controlled_fixture
        ),
    )
    findings = {
        "sql_injection": normalize_http_sqli_record(records["sql_injection"]),
        "reflected_xss": normalize_reflected_xss_record(records["reflected_xss"]),
        "ssrf": normalize_ssrf_record(records["ssrf"]),
        "command_execution": normalize_command_execution_record(
            records["command_execution"]
        ),
        "exposed_resource": normalize_exposed_resource_record(
            records["exposed_resource"]
        ),
    }
    if "system_information_discovery" in records:
        findings["system_information_discovery"] = (
            normalize_system_information_discovery_record(
                records["system_information_discovery"]
            )
        )

    validations = []
    enriched_findings = []
    for name, finding in findings.items():
        validation_result = dispatch(finding, session=client)
        validated = apply_validation_result(finding, validation_result)
        enriched = enrich_finding_model(validated)
        enriched_findings.append(enriched)
        validations.append(GenericValidationArtifact(
            name=name,
            candidate=finding,
            validation=validation_result,
            enriched=enriched,
        ))

    parsed_origin = urlsplit(origin)
    reachability = Finding(
        finding_id=f"finding-{uuid4()}",
        scan_id=resolved_scan_id,
        asset_id=asset_id,
        target=origin,
        host=parsed_origin.hostname or "127.0.0.1",
        port=parsed_origin.port,
        protocol=parsed_origin.scheme,
        endpoint=reachability_policy.endpoint,
        source=reachability_policy.source,
        template_id=reachability_policy.template_id,
        vulnerability_type="service_scan",
        validation_status=ValidationStatus.CONFIRMED,
        validation_confidence=1.0,
        evidence={
            reachability_policy.evidence_status_key: reachability_status,
        },
    )
    chains = build_attack_paths([reachability, *enriched_findings])
    return GenericLocalWebRun(
        origin=origin,
        scan_id=resolved_scan_id,
        asset_id=asset_id,
        reachability=reachability,
        validations=tuple(validations),
        chains=tuple(chains),
    )


def run_local_multi_validator_pipeline(
    origin: str,
    client: ScopedLoopbackHttpClient,
) -> Dict[str, Any]:
    """Compatibility wrapper returning the existing serialized response."""
    return execute_local_multi_validator_pipeline(origin, client).to_dict()


def execute_generic_local_web_validation(
    origin: str,
    *,
    scan_id: Optional[str] = None,
) -> GenericLocalWebRun:
    """Execute against one exact loopback origin and return typed artifacts."""
    try:
        with ScopedLoopbackHttpClient(origin) as client:
            return execute_local_multi_validator_pipeline(
                origin,
                client,
                scan_id=scan_id,
            )
    except TargetScopeError:
        raise
    except LocalTargetConnectionError:
        raise
    except httpx.RequestError as exc:
        raise LocalTargetConnectionError(
            "authorized local target is unreachable"
        ) from exc


def execute_verified_external_web_validation(
    target: AuthorizedTarget,
    *,
    scan_id: Optional[str] = None,
    address_resolver: Optional[Callable[[str], Sequence[str]]] = None,
) -> GenericLocalWebRun:
    """Execute the fixed generic scenario through the canonical scoped client."""
    if not isinstance(target, AuthorizedTarget):
        raise TypeError("target must be an AuthorizedTarget")
    if target.scheme != "https" or not target.resolved_addresses:
        raise TargetScopeError(
            "external validation requires an authorized HTTPS target"
        )
    try:
        with ScopedReconHttpClient(
            target,
            address_resolver=address_resolver,
        ) as client:
            return execute_local_multi_validator_pipeline(
                target.origin,
                client,
                scan_id=scan_id,
                reachability_policy=_EXTERNAL_REACHABILITY,
            )
    except ReconScopeError as exc:
        raise TargetScopeError(str(exc)) from exc
    except LocalTargetConnectionError:
        raise
    except httpx.RequestError as exc:
        raise LocalTargetConnectionError(
            "authorized external target is unreachable"
        ) from exc


def run_generic_local_web_validation(origin: str) -> Dict[str, Any]:
    """Run the demo against one exact loopback origin with safe failures."""
    return execute_generic_local_web_validation(origin).to_dict()

"""Authorized reconnaissance orchestration into the canonical pipeline."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Sequence, Tuple
from uuid import uuid4

import httpx
from sqlalchemy.orm import Session

from app.attack_chain.engine import build_attack_paths
from app.attack_chain.mitre_mapping import enrich_finding_model
from app.core.config import settings
from app.models.attack_chain import AttackChain
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult
from app.scanning.http_discovery import (
    ScopedReconHttpClient,
    discover_http_service,
)
from app.scanning.models import AssetObservation, ScannerCandidateRecord, ServiceObservation
from app.scanning.normalizer import normalize_scanner_candidate
from app.scanning.scope import (
    AuthorizedTarget,
    ReconScopeError,
    authorize_target,
    is_loopback_host,
    normalize_origin,
    resolve_public_target_addresses,
)
from app.services.persistence import (
    AssetPersistenceRecord,
    ServicePersistenceRecord,
    ValidationPersistenceRecord,
    mark_validation_run_failed,
    persist_validation_outputs,
    start_validation_run,
)
from app.services.target_verification import TargetVerificationService
from app.validation.dispatcher import apply_validation_result, dispatch


@dataclass(frozen=True)
class ReconValidationArtifact:
    candidate: Finding
    validation: ValidationResult
    enriched: Finding


@dataclass(frozen=True)
class ReconRun:
    scan_id: str
    target: AuthorizedTarget
    asset: AssetObservation
    services: Tuple[ServiceObservation, ...]
    reachability: Finding
    validations: Tuple[ReconValidationArtifact, ...]
    chains: Tuple[AttackChain, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "status": "completed",
            "target_url": self.target.origin,
            "asset": {
                "asset_id": self.asset.asset_id,
                "hostname": self.asset.hostname,
                "ip_address": self.asset.ip_address,
                "base_url": self.asset.base_url,
            },
            "services": [service.__dict__ for service in self.services],
            "findings": [
                artifact.enriched.to_dict() for artifact in self.validations
            ],
            "validations": [
                artifact.validation.to_dict() for artifact in self.validations
            ],
            "chains": [chain.to_dict() for chain in self.chains],
        }


def _asset_id(scan_id: str, origin: str) -> str:
    digest = hashlib.sha256(f"{scan_id}:{origin}".encode()).hexdigest()[:16]
    return f"asset-{digest}"


def _literal_ip(hostname: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        return None


def _deduplicate_services(
    services: Sequence[ServiceObservation],
) -> Tuple[ServiceObservation, ...]:
    records: Dict[tuple[Any, ...], ServiceObservation] = {}
    for service in services:
        key = (service.asset_id, service.port, service.protocol, service.service_name)
        existing = records.get(key)
        if existing is None or (existing.source == "http_discovery" and service.source == "nmap"):
            records[key] = service
    return tuple(records.values())


class ReconPipeline:
    """Coordinates discovery while keeping scanner detection non-authoritative."""

    def __init__(
        self,
        *,
        nmap_scanner: Optional[Any] = None,
        nuclei_scanner: Optional[Any] = None,
        http_client_factory: Any = None,
        target_verification_service: Optional[TargetVerificationService] = None,
        address_resolver: Optional[Callable[[str], Sequence[str]]] = None,
    ) -> None:
        self.nmap_scanner = nmap_scanner
        self.nuclei_scanner = nuclei_scanner
        self.target_verification_service = (
            target_verification_service or TargetVerificationService()
        )
        self.address_resolver = (
            address_resolver
            or self.target_verification_service.resolve_addresses
        )
        self.http_client_factory = http_client_factory or (
            lambda target: ScopedReconHttpClient(
                target,
                address_resolver=self.address_resolver,
            )
        )

    def _revalidate_external_resolution(self, target: AuthorizedTarget) -> None:
        if not target.resolved_addresses:
            return
        current = resolve_public_target_addresses(
            target.hostname,
            address_resolver=self.address_resolver,
        )
        if set(current) != set(target.resolved_addresses):
            raise ReconScopeError(
                "verified target DNS resolution changed during the scan"
            )

    def run(
        self,
        *,
        target_url: str,
        authorized: bool,
        session: Session,
    ) -> ReconRun:
        normalized_target = normalize_origin(target_url)
        ownership_verified = True
        if settings.AUTHORIZATION_RESTRICTED:
            ownership_verified = is_loopback_host(normalized_target.hostname)
            if not ownership_verified:
                ownership_verified = self.target_verification_service.is_origin_verified(
                    session,
                    normalized_target.origin,
                )
        target = authorize_target(
            target_url,
            authorized=authorized,
            ownership_verified=ownership_verified,
            address_resolver=self.address_resolver,
        )
        scan_id = f"scan-{uuid4()}"
        asset_id = _asset_id(scan_id, target.origin)
        start_validation_run(
            session,
            scan_id=scan_id,
            target_url=target.origin,
            authorized=True,
        )

        try:
            asset = AssetObservation(
                asset_id=asset_id,
                hostname=target.hostname,
                ip_address=(
                    target.resolved_addresses[0]
                    if target.resolved_addresses
                    else _literal_ip(target.hostname)
                ),
                base_url=target.origin,
            )
            services = []
            candidates: Sequence[ScannerCandidateRecord] = ()
            self._revalidate_external_resolution(target)
            with self.http_client_factory(target) as client:
                http_service, http_evidence = discover_http_service(
                    target,
                    asset_id=asset_id,
                    client=client,
                )
                services.append(http_service)
                if self.nmap_scanner is not None:
                    self._revalidate_external_resolution(target)
                    nmap_result = self.nmap_scanner.scan(
                        target,
                        asset_id=asset_id,
                    )
                    if hasattr(nmap_result, "services"):
                        services.extend(nmap_result.services)
                        discovered_ips = tuple(nmap_result.ip_addresses)
                        if asset.ip_address is None and discovered_ips:
                            asset = AssetObservation(
                                asset_id=asset.asset_id,
                                hostname=asset.hostname,
                                ip_address=discovered_ips[0],
                                base_url=asset.base_url,
                            )
                    else:
                        # Small injected test adapters may return observations.
                        services.extend(nmap_result)
                if self.nuclei_scanner is not None:
                    self._revalidate_external_resolution(target)
                    candidates = self.nuclei_scanner.scan(
                        target,
                        scan_id=scan_id,
                        asset_id=asset_id,
                    )

                reachability = Finding(
                    finding_id=f"finding-{uuid4()}",
                    scan_id=scan_id,
                    asset_id=asset_id,
                    target=target.origin,
                    host=target.hostname,
                    port=target.port,
                    protocol=target.scheme,
                    endpoint="/",
                    source="http_discovery",
                    template_id="http-reachability",
                    vulnerability_type="service_scan",
                    severity="info",
                    validation_status=ValidationStatus.CONFIRMED,
                    validation_confidence=1.0,
                    evidence=http_evidence,
                )

                artifacts = []
                enriched_findings = []
                for scanner_record in candidates:
                    candidate = normalize_scanner_candidate(scanner_record)
                    validation = dispatch(candidate, session=client)
                    enriched = enrich_finding_model(
                        apply_validation_result(candidate, validation)
                    )
                    artifacts.append(ReconValidationArtifact(
                        candidate=candidate,
                        validation=validation,
                        enriched=enriched,
                    ))
                    enriched_findings.append(enriched)

            deduplicated_services = _deduplicate_services(services)
            chains = tuple(build_attack_paths([reachability, *enriched_findings]))
            persist_validation_outputs(
                session,
                scan_id=scan_id,
                findings=[reachability, *(item.candidate for item in artifacts)],
                validations=[ValidationPersistenceRecord(
                    candidate=item.candidate,
                    validation=item.validation,
                    enriched=item.enriched,
                ) for item in artifacts],
                attack_chains=chains,
                assets=[AssetPersistenceRecord(
                    asset_id=asset.asset_id,
                    hostname=asset.hostname,
                    ip_address=asset.ip_address,
                    base_url=asset.base_url,
                )],
                services=[ServicePersistenceRecord(
                    asset_id=service.asset_id,
                    port=service.port,
                    protocol=service.protocol,
                    service_name=service.service_name,
                    product=service.product,
                    version=service.version,
                    state=service.state,
                    source=service.source,
                ) for service in deduplicated_services],
            )
            return ReconRun(
                scan_id=scan_id,
                target=target,
                asset=asset,
                services=deduplicated_services,
                reachability=reachability,
                validations=tuple(artifacts),
                chains=chains,
            )
        except Exception as exc:
            mark_validation_run_failed(
                session,
                scan_id=scan_id,
                failure_reason=f"{type(exc).__name__}: reconnaissance failed",
            )
            if isinstance(exc, httpx.RequestError):
                raise ConnectionError("authorized target is unreachable") from exc
            raise

"""Integration tests for version-CVE resolution, privilege escalation, and retesting."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from app.db.models import (
    FindingORM,
    MitreMappingORM,
    ScanORM,
)
from app.models.finding import Finding, ValidationStatus

# ── Version → CVE Resolver ─────────────────────────────────────────────


class TestVersionCVEMatchLocal:
    def test_local_lookup_nginx_vulnerable(self):
        from app.services.version_cve_resolver import resolve_version_to_cves

        result = resolve_version_to_cves(
            "nginx", "1.20.0", use_nvd_api=False,
        )
        assert result.total_cves > 0
        assert result.highest_cvss > 0
        assert result.resolution_method == "local_database"

    def test_no_versions_vulnerable(self):
        from app.services.version_cve_resolver import resolve_version_to_cves

        result = resolve_version_to_cves(
            "nginx", "2.0.0", use_nvd_api=False,
        )
        assert result.total_cves == 0
        assert result.highest_cvss == 0

    def test_batch_resolve(self):
        from app.services.version_cve_resolver import batch_resolve_versions

        results = batch_resolve_versions(
            [
                {"product": "nginx", "version": "1.20.0"},
                {"product": "apache", "version": "2.4.50"},
            ],
            use_nvd_api=False,
        )
        assert len(results) == 2
        assert any(r.total_cves > 0 for r in results)


# ── Privilege Escalation ───────────────────────────────────────────────

def _make_finding_orm(
    finding_id: str,
    *,
    scan_id: str = "scan-1",
    asset_id: str = "asset-1",
    vuln_type: str = "sqli",
    status: str = "confirmed",
    technique_id: str = "T1190",
    technique_name: str = "Exploit Public-Facing Application",
    tactic: str = "Initial Access",
) -> FindingORM:
    finding = FindingORM(
        id=finding_id,
        scan_id=scan_id,
        asset_id=asset_id,
        source="test",
        scanner_template_id="generic-http-sqli",
        validator_id="generic-http-sqli",
        vulnerability_type=vuln_type,
        severity="high",
        target="http://127.0.0.1:8000",
        endpoint=f"/vuln/{finding_id}",
        http_method="GET",
        parameter_name="id",
        parameter_location="query",
        status=status,
    )
    finding.mitre_mappings = [
        MitreMappingORM(
            id=f"mapping-{finding_id}",
            finding_id=finding_id,
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            mapping_confidence=1.0,
        )
    ]
    return finding


class TestPrivilegeEscalationMapper:
    def test_build_escalation_map_with_chain(self):
        from app.services.privilege_escalation import (
            build_privilege_escalation_map,
        )

        # A chain: SQLi (initial access) → RCE (command execution)
        findings = [
            _make_finding_orm(
                "find-1", vuln_type="sqli", technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
                tactic="Initial Access",
            ),
            _make_finding_orm(
                "find-2", vuln_type="rce", technique_id="T1059.004",
                technique_name="Command and Scripting Interpreter: Unix Shell",
                tactic="Execution",
            ),
            _make_finding_orm(
                "find-3", vuln_type="system_information_discovery",
                technique_id="T1082",
                technique_name="System Information Discovery",
                tactic="Discovery",
            ),
        ]

        result = build_privilege_escalation_map(
            scan_id="scan-1",
            asset_id="asset-1",
            findings=findings,
        )
        assert result.scan_id == "scan-1"
        assert result.deepest_path is not None
        assert result.deepest_path.total_depth >= 1

    def test_build_escalation_map_no_chain(self):
        from app.services.privilege_escalation import (
            build_privilege_escalation_map,
        )

        findings = [
            _make_finding_orm(
                "find-1", vuln_type="sqli", technique_id="T1190",
            ),
        ]
        result = build_privilege_escalation_map(
            scan_id="scan-1",
            asset_id="asset-1",
            findings=findings,
        )
        assert result.deepest_path is None
        assert result.paths == []
        assert result.highest_risk_score == 0


# ── Retesting ──────────────────────────────────────────────────────────

class TestRetesting:
    def test_retest_error_without_validator(self):
        from app.services.retesting import RetestError, retest_finding

        session = Mock()

        # Finding without validator
        finding_orm = _make_finding_orm(
            "find-novalidator", vuln_type="idor", status="confirmed",
        )
        finding_orm.validator_id = None

        repo = Mock()
        repo.list_findings_for_scan.return_value = [finding_orm]

        with patch(
            "app.services.retesting.PersistenceRepository",
            return_value=repo,
        ):
            with pytest.raises(RetestError):
                retest_finding(
                    session,
                    scan_id="scan-1",
                    finding_id="find-novalidator",
                )

    def test_retest_finding_uses_dispatcher(self):
        from app.services.retesting import retest_finding

        session = Mock()

        finding_orm = _make_finding_orm(
            "find-retest", vuln_type="sqli", status="confirmed",
        )

        repo = Mock()
        repo.list_findings_for_scan.return_value = [finding_orm]
        repo.persist_validation.return_value = Mock(id="validation-1")
        repo.persist_evidence.return_value = Mock(id="evidence-1")

        result_orm = Mock(
            id="result-1",
            finding_id="find-retest",
            validator_id="generic_http_sqli",
            method="test",
            status=ValidationStatus.REJECTED,
            confidence=0.9,
            evidence={"reason": "rejected"},
            evidence_refs=[],
            timestamp="2024-01-01T00:00:00Z",
            error=None,
        )

        with (
            patch(
                "app.services.retesting.PersistenceRepository",
                return_value=repo,
            ),
            patch(
                "app.services.retesting.dispatch",
                return_value=result_orm,
            ),
        ):
            result = retest_finding(
                session,
                scan_id="scan-1",
                finding_id="find-retest",
            )

        assert result.previous_status == "confirmed"
        assert result.retest_confirmed is True
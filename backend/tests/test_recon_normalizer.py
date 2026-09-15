import unittest

from app.models.finding import ValidationStatus
from app.scanning.models import ScannerCandidateRecord
from app.scanning.normalizer import (
    GENERIC_AUTH_BYPASS_VALIDATOR_ID,
    GENERIC_IDOR_VALIDATOR_ID,
    GENERIC_LFI_VALIDATOR_ID,
    GENERIC_SSTI_VALIDATOR_ID,
    GENERIC_SQLI_VALIDATOR_ID,
    GENERIC_XXE_VALIDATOR_ID,
    RECON_MANUAL_REVIEW_VALIDATOR_ID,
    normalize_scanner_candidate,
)


def candidate(**overrides):
    values = {
        "record_id": "candidate-1",
        "scan_id": "scan-1",
        "asset_id": "asset-1",
        "target": "http://127.0.0.1:8090",
        "scanner_name": "nuclei",
        "scanner_template_id": "candidate-template",
        "vulnerability_type": "sql_injection",
        "severity": "high",
        "endpoint": "/items",
        "http_method": "get",
        "parameter_name": "id",
        "parameter_location": "query",
        "evidence": {"scanner": "nuclei"},
    }
    values.update(overrides)
    return ScannerCandidateRecord(**values)


class ReconCandidateNormalizerTests(unittest.TestCase):
    def test_explicit_complete_sqli_context_routes_generic_validator(self):
        finding = normalize_scanner_candidate(candidate())
        self.assertEqual(finding.validator_id, GENERIC_SQLI_VALIDATOR_ID)
        self.assertEqual(finding.http_method, "GET")
        self.assertEqual(finding.validation_status, ValidationStatus.DETECTED)
        self.assertEqual(finding.evidence, {"scanner": "nuclei"})

    def test_incomplete_context_is_preserved_for_manual_review(self):
        finding = normalize_scanner_candidate(candidate(parameter_name=None))
        self.assertEqual(finding.validator_id, RECON_MANUAL_REVIEW_VALIDATOR_ID)
        self.assertEqual(finding.template_id, "candidate-template")
        self.assertEqual(finding.vulnerability_type, "sql_injection")

    def test_command_candidate_never_routes_active_validator(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="command_execution",
            scanner_template_id="generic-http-command-execution",
            http_method="POST",
            parameter_name="command",
            parameter_location="form",
        ))
        self.assertEqual(finding.validator_id, RECON_MANUAL_REVIEW_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "command_execution")

    def test_unknown_candidate_is_not_promoted(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="nuclei_candidate",
            endpoint="/status",
            http_method=None,
            parameter_name=None,
            parameter_location=None,
        ))
        self.assertEqual(finding.validator_id, RECON_MANUAL_REVIEW_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "nuclei_candidate")


class NewVulnerabilityClassNormalizerTests(unittest.TestCase):
    def test_lfi_complete_context_routes_lfi_validator(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="path_traversal",
            http_method="POST",
            parameter_name="file",
            parameter_location="form",
        ))
        self.assertEqual(finding.validator_id, GENERIC_LFI_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "local_file_inclusion")
        self.assertEqual(finding.http_method, "POST")
        self.assertEqual(finding.validation_status, ValidationStatus.DETECTED)

    def test_lfi_incomplete_context_is_manual_review(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="lfi",
            http_method="GET",
            parameter_name=None,
            parameter_location=None,
        ))
        self.assertEqual(finding.validator_id, RECON_MANUAL_REVIEW_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "local_file_inclusion")

    def test_xxe_complete_context_routes_xxe_validator(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="xml_external_entity",
            http_method="POST",
            parameter_name="data",
            parameter_location="json",
        ))
        self.assertEqual(finding.validator_id, GENERIC_XXE_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "xml_external_entity")
        self.assertEqual(finding.http_method, "POST")

    def test_xxe_get_request_not_routable(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="xxe",
            http_method="GET",
            parameter_name="id",
            parameter_location="query",
        ))
        # GET not in XXE_REQUEST_SHAPES
        self.assertEqual(finding.validator_id, RECON_MANUAL_REVIEW_VALIDATOR_ID)

    def test_idor_complete_context_routes_idor_validator(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="insecure_direct_object_reference",
            http_method="DELETE",
            parameter_name="id",
            parameter_location="path",
        ))
        self.assertEqual(finding.validator_id, GENERIC_IDOR_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "insecure_direct_object_reference")
        self.assertEqual(finding.http_method, "DELETE")

    def test_idor_incomplete_context_is_manual_review(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="idor",
            http_method="GET",
            parameter_name=None,
            parameter_location=None,
        ))
        self.assertEqual(finding.validator_id, RECON_MANUAL_REVIEW_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "insecure_direct_object_reference")

    def test_ssti_complete_context_routes_ssti_validator(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="template_injection",
            http_method="POST",
            parameter_name="name",
            parameter_location="json",
        ))
        self.assertEqual(finding.validator_id, GENERIC_SSTI_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "server_side_template_injection")
        self.assertEqual(finding.http_method, "POST")

    def test_ssti_incomplete_context_is_manual_review(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="ssti",
            http_method="GET",
            parameter_name=None,
            parameter_location=None,
        ))
        self.assertEqual(finding.validator_id, RECON_MANUAL_REVIEW_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "server_side_template_injection")

    def test_auth_bypass_with_endpoint_routes_auth_bypass_validator(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="unauthenticated_access",
            http_method="GET",
            endpoint="/admin/dashboard",
            parameter_name=None,
            parameter_location=None,
        ))
        self.assertEqual(finding.validator_id, GENERIC_AUTH_BYPASS_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "authentication_bypass")
        self.assertEqual(finding.http_method, "GET")
        self.assertEqual(finding.validation_status, ValidationStatus.DETECTED)

    def test_auth_bypass_without_method_is_manual_review(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="authentication_bypass",
            http_method=None,
            parameter_name=None,
            parameter_location=None,
        ))
        self.assertEqual(finding.validator_id, RECON_MANUAL_REVIEW_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "authentication_bypass")

    def test_auth_bypass_without_endpoint_is_manual_review(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="auth_bypass",
            http_method="GET",
            endpoint=None,
            parameter_name=None,
            parameter_location=None,
        ))
        self.assertEqual(finding.validator_id, RECON_MANUAL_REVIEW_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "authentication_bypass")


if __name__ == "__main__":
    unittest.main()

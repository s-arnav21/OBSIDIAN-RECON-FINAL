"""Tests for the new validation handlers: LFI, XXE, IDOR, SSTI, file upload, auth bypass, deserialization, session fixation."""

from __future__ import annotations

import hashlib
import json
from unittest.mock import Mock

import pytest

from app.db.models import FindingORM
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult
from app.validation.dispatcher import HANDLERS, dispatch
from app.validation.auth_bypass import (
    VALIDATOR_NAME as AUTH_BYPASS_NAME,
)
from app.validation.deserialization import (
    VALIDATOR_NAME as DESERIALIZATION_NAME,
)
from app.validation.file_upload import (
    VALIDATOR_NAME as FILE_UPLOAD_NAME,
)
from app.validation.idor import (
    VALIDATOR_NAME as IDOR_NAME,
)
from app.validation.lfi import (
    VALIDATOR_NAME as LFI_NAME,
)
from app.validation.session_security import (
    VALIDATOR_NAME as SESSION_SECURITY_NAME,
)
from app.validation.ssti import (
    VALIDATOR_NAME as SSTI_NAME,
)
from app.validation.xxe import (
    VALIDATOR_NAME as XXE_NAME,
)


def _find_payload(
    vulnerability_type: str,
    *,
    endpoint: str = "/vuln",
    http_method: str = "GET",
    parameter_name: str = "id",
    parameter_location: str = "query",
    target: str = "http://127.0.0.1:8000",
    http_request_context: dict | None = None,
) -> Finding:
    return Finding(
        finding_id="find-test-1",
        scan_id="scan-test-1",
        asset_id="asset-test-1",
        target=target,
        host="127.0.0.1",
        source="test-source",
        vulnerability_type=vulnerability_type,
        endpoint=endpoint,
        http_method=http_method,
        parameter_name=parameter_name,
        parameter_location=parameter_location,
        template_id="generic-http-lfi",
        validator_id=(
            "generic-http-lfi"
            if "lfi" in vulnerability_type or "path" in vulnerability_type or "travers" in vulnerability_type or "file_incl" in vulnerability_type
            else (
                "generic-http-xxe"
                if "xxe" in vulnerability_type or "xml" in vulnerability_type
                else (
                    "generic-http-idor"
                    if "idor" in vulnerability_type or "access_control" in vulnerability_type or "authorization" in vulnerability_type
                    else (
                        "generic-http-ssti"
                        if "ssti" in vulnerability_type or "template" in vulnerability_type
                        else (
                            "generic-http-file-upload"
                            if "upload" in vulnerability_type
                            else (
                                "generic-http-auth-bypass"
                                if "auth" in vulnerability_type or "authentication" in vulnerability_type or "unauthenticated" in vulnerability_type
                                else (
                                    "generic-http-deserialization"
                                    if "deserialization" in vulnerability_type
                                    else "generic-http-session-fixation"
                                )
                            )
                        )
                    )
                )
            )
        ),
        http_request_context=http_request_context or {"query": {"id": "1"}},
    )


class TestDispatcherRegistration:
    def test_all_new_validators_registered(self):
        for template_id in (
            "generic-http-lfi",
            "generic-http-xxe",
            "generic-http-idor",
            "generic-http-ssti",
            "generic-http-file-upload",
            "generic-http-auth-bypass",
            "generic-http-deserialization",
            "generic-http-session-fixation",
        ):
            assert template_id in HANDLERS, f"{template_id} not registered"


class TestLFIValidator:
    def test_vulnerability_type_validation(self):
        finding = _find_payload("sql_injection")
        session = Mock()
        result = dispatch(finding, session)
        assert result.status == ValidationStatus.MANUAL_REVIEW
        assert result.evidence["reason"] == "unexpected_vulnerability_type"

    def test_missing_session(self):
        finding = _find_payload("lfi")
        result = dispatch(finding, None)
        assert result.status == ValidationStatus.MANUAL_REVIEW

    def test_confirmed_lfi_passwd_content(self):
        finding = _find_payload("lfi", http_method="GET")
        session = Mock()

        class Response:
            status_code = 200
            text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"

        session.request = Mock(return_value=Response())
        result = dispatch(finding, session)
        assert result.status == ValidationStatus.CONFIRMED
        assert result.evidence["sensitive_file_detected"] is True


class TestXXEValidator:
    def test_confirmed_xxe_error_signal(self):
        finding = _find_payload(
            "xxe",
            http_method="POST",
            parameter_location="form",
            http_request_context={"form": {"data": "test"}},
        )
        session = Mock()

        class SafeResponse:
            status_code = 200
            headers = {}
            text = "ok"

            @property
            def content_type(self):
                return "text/html"

        class ErrorResponse:
            status_code = 500
            headers = {}
            text = "XML parsing error at line 1: no element found"

            @property
            def content_type(self):
                return "text/html"

        session.request = Mock(side_effect=[SafeResponse(), ErrorResponse(), ErrorResponse(), ErrorResponse()])
        result = dispatch(finding, session)
        assert result.status == ValidationStatus.CONFIRMED


class TestIDORValidator:
    def test_confirmed_different_id_accessible(self):
        import copy
        finding = _find_payload("idor")
        session = Mock()

        class AuthResponse:
            status_code = 200
            text = "authorized data"

        session.request = Mock(return_value=AuthResponse())
        result = dispatch(finding, session)
        assert result.status == ValidationStatus.CONFIRMED


class TestSSTIValidator:
    def test_confirmed_math_evaluation(self):
        finding = _find_payload("ssti")
        session = Mock()

        class Response:
            status_code = 200
            text = "The result is 49"

        session.request = Mock(return_value=Response())
        result = dispatch(finding, session)
        assert result.status == ValidationStatus.CONFIRMED


class TestFileUploadValidator:
    def test_confirmed_uploads_accepted(self):
        finding = _find_payload(
            "file_upload", http_method="POST", parameter_name="file",
        )
        session = Mock()

        class Response:
            status_code = 200
            headers = {"content-type": "text/html"}
            text = "file uploaded successfully"

        session.request = Mock(return_value=Response())
        result = dispatch(finding, session)
        assert result.status == ValidationStatus.CONFIRMED


class TestAuthBypassValidator:
    def test_confirmed_access_without_auth(self):
        finding = _find_payload("auth_bypass")
        session = Mock()

        class Response:
            status_code = 200
            text = "admin dashboard content"

        session.request = Mock(return_value=Response())
        result = dispatch(finding, session)
        assert result.status == ValidationStatus.CONFIRMED


class TestDeserializationValidator:
    def test_confirmed_deserialization_signal(self):
        finding = _find_payload(
            "deserialization", http_method="POST",
            parameter_location="json",
            http_request_context={"json": {"data": "test"}},
        )
        session = Mock()

        class Response:
            status_code = 200
            text = "Uncaught Exception: InvalidClassException in deserialization"

        session.request = Mock(return_value=Response())
        result = dispatch(finding, session)
        assert result.status == ValidationStatus.CONFIRMED


class TestSessionSecurityValidator:
    def test_confirmed_session_fixation(self):
        finding = _find_payload("session_fixation")
        session = Mock()

        class Response:
            status_code = 200
            headers = {
                "set-cookie": "session=abc123; Path=/"
            }
            text = ""

        session.request = Mock(return_value=Response())
        result = dispatch(finding, session)
        assert result.status == ValidationStatus.CONFIRMED


class TestVersionCVEMatch:
    def test_services_imports(self):
        from app.services.version_cve_resolver import (
            CVEDetail,
            VersionCVEMatch,
            resolve_version_to_cves,
        )
        assert CVEDetail is not None
        assert VersionCVEMatch is not None
        assert resolve_version_to_cves is not None


class TestPrivilegeEscalationImports:
    def test_module_imports(self):
        from app.services.privilege_escalation import (
            EscalationPath,
            EscalationPathNode,
            PrivilegeEscalationMap,
            build_privilege_escalation_map,
        )
        assert EscalationPath is not None
        assert EscalationPathNode is not None
        assert PrivilegeEscalationMap is not None
        assert build_privilege_escalation_map is not None


class TestRetestingImports:
    def test_module_imports(self):
        from app.services.retesting import (
            RetestError,
            RetestResult,
            retest_finding,
            retest_findings_batch,
        )
        assert RetestError is not None
        assert RetestResult is not None
        assert retest_finding is not None
        assert retest_findings_batch is not None
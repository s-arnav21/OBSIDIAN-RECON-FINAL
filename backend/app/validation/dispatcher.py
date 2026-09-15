"""
Route canonical findings to registered validation handlers.

The dispatcher is deliberately storage-agnostic: it returns structured
ValidationResult objects and never writes evidence or review queues directly.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable, Dict, Optional

from app.models.finding import Finding, STATUS_WEIGHT, ValidationStatus
from app.models.validation import ValidationResult
from app.validation.auth_bypass import validate_generic_http_auth_bypass
from app.validation.command_execution import (
    validate_generic_http_command_execution,
)
from app.validation.deserialization import validate_generic_http_deserialization
from app.validation.exposure import validate_generic_exposed_resource
from app.validation.file_upload import validate_generic_http_file_upload
from app.validation.idor import validate_generic_http_idor
from app.validation.lfi import validate_generic_http_lfi
from app.validation.session_security import validate_generic_http_session_fixation
from app.validation.ssti import validate_generic_http_ssti
from app.validation.sql_injection import validate_generic_http_sqli
from app.validation.ssrf import validate_generic_http_ssrf
from app.validation.system_information import (
    validate_controlled_system_information_discovery,
)
from app.validation.xss import validate_generic_reflected_xss
from app.validation.xxe import validate_generic_http_xxe


ValidationHandler = Callable[[Finding, Any], ValidationResult]
HANDLERS: Dict[str, ValidationHandler] = {}


def register(template_id: str) -> Callable[[ValidationHandler], ValidationHandler]:
    """Register a handler for a validator or legacy scanner template key."""
    if not isinstance(template_id, str) or not template_id:
        raise ValueError("template_id must be a non-empty string")

    def wrapper(fn: ValidationHandler) -> ValidationHandler:
        HANDLERS[template_id] = fn
        return fn

    return wrapper


register("generic-http-sqli")(validate_generic_http_sqli)
register("generic-http-reflected-xss")(validate_generic_reflected_xss)
register("generic-http-ssrf")(validate_generic_http_ssrf)
register("generic-http-exposed-resource")(validate_generic_exposed_resource)
register("generic-http-command-execution")(
    validate_generic_http_command_execution
)
register("controlled-http-system-information-discovery")(
    validate_controlled_system_information_discovery
)
register("generic-http-lfi")(validate_generic_http_lfi)
register("generic-http-xxe")(validate_generic_http_xxe)
register("generic-http-idor")(validate_generic_http_idor)
register("generic-http-ssti")(validate_generic_http_ssti)
register("generic-http-file-upload")(validate_generic_http_file_upload)
register("generic-http-auth-bypass")(validate_generic_http_auth_bypass)
register("generic-http-deserialization")(validate_generic_http_deserialization)
register("generic-http-session-fixation")(validate_generic_http_session_fixation)


# Lab-specific handler retained without expanding its validation behavior.
@register("dvwa-sqli-low")
def handle_dvwa_sqli(finding: Finding, session: Any) -> ValidationResult:
    if session is None:
        raise ValueError("DVWA SQLi validation requires an authenticated session")

    base = finding.target.rstrip("/")
    url = f"{base}/vulnerabilities/sqli/"

    # Get the page first to extract CSRF token.
    page = session.get(url)

    # Extract user_token from the SQLi form.
    from html.parser import HTMLParser

    class TokenParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.token = None

        def handle_starttag(self, tag, attrs):
            if tag == "input":
                attributes = dict(attrs)
                if attributes.get("name") == "user_token":
                    self.token = attributes.get("value")

    token_parser = TokenParser()
    token_parser.feed(page.text)
    token = token_parser.token

    # Build params with token if present.
    baseline_params = {"id": "1", "Submit": "Submit"}
    injected_params = {"id": "1' OR '1'='1", "Submit": "Submit"}
    if token:
        baseline_params["user_token"] = token
        injected_params["user_token"] = token

    baseline = session.get(url, params=baseline_params)

    # Get a fresh token for the second request.
    second_token_parser = TokenParser()
    second_token_parser.feed(baseline.text)
    second_token = second_token_parser.token
    if second_token:
        injected_params["user_token"] = second_token

    injected = session.get(url, params=injected_params)

    baseline_result_count = baseline.text.count("First name:")
    injected_result_count = injected.text.count("First name:")

    confirmed = (
        baseline_result_count > 0
        and injected_result_count > baseline_result_count
    )
    status = (
        ValidationStatus.CONFIRMED
        if confirmed
        else ValidationStatus.REJECTED
    )

    return ValidationResult(
        status=status,
        confidence=1.0,
        validator="dvwa_sqli_low",
        method="boolean-based SQLi, id parameter",
        evidence={
            "baseline_length": len(baseline.text),
            "injected_length": len(injected.text),
            "baseline_result_count": baseline_result_count,
            "injected_result_count": injected_result_count,
        },
    )


def dispatch(
    finding: Finding,
    session: Optional[Any] = None,
) -> ValidationResult:
    """Route a finding to a handler or return a structured manual-review result."""
    if not isinstance(finding, Finding):
        raise TypeError("dispatch expects a Finding instance")

    handler_key = finding.validator_id or finding.template_id
    handler = HANDLERS.get(handler_key or "")
    if handler is None:
        return ValidationResult(
            status=ValidationStatus.MANUAL_REVIEW,
            confidence=STATUS_WEIGHT[ValidationStatus.MANUAL_REVIEW],
            validator="dispatcher_manual_review",
            method="unsupported_template",
            evidence={
                "reason": "no_registered_handler",
                "template_id": finding.template_id,
            },
        )

    result = handler(finding, session)
    if not isinstance(result, ValidationResult):
        raise TypeError(
            f"handler for {handler_key!r} must return ValidationResult"
        )
    return result


def apply_validation_result(
    finding: Finding,
    result: ValidationResult,
) -> Finding:
    """Return a new finding with validation fields and evidence attached."""
    if not isinstance(finding, Finding):
        raise TypeError("finding must be a Finding instance")
    if not isinstance(result, ValidationResult):
        raise TypeError("result must be a ValidationResult instance")

    evidence = {**finding.evidence, **result.evidence}
    evidence_refs = list(dict.fromkeys(
        [*finding.evidence_refs, *result.evidence_refs]
    ))

    return replace(
        finding,
        validation_status=result.status,
        validation_confidence=result.confidence,
        evidence=evidence,
        evidence_refs=evidence_refs,
    )


def dispatch_and_apply(
    finding: Finding,
    session: Optional[Any] = None,
) -> Finding:
    """Dispatch a finding and apply the returned validation result."""
    return apply_validation_result(finding, dispatch(finding, session))

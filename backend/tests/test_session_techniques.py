"""Session-aware technique execution and the T1078 credential/session split.

Pins the honesty rules the integration work must preserve:

* A command/discovery claim made through a session is attributed to the target
  session identity, not to the Obsidian host.
* T1078 grants ``credential_access`` when credentials are recovered, but only
  grants ``authenticated_session`` when a session is actually established.
"""
from __future__ import annotations

import unittest
from unittest import mock

from app.automation import adapters, get_technique
from app.automation.base import AutomationContext
from app.automation.session import SessionCommand, SessionInfo
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult

ORIGIN = "http://127.0.0.1:8090"


class _FakeSession:
    def __init__(self, *, stdout: str = "", rc: int = 0, host: str = "10.0.0.5") -> None:
        self.info = SessionInfo("ssh", host, 22, "root")
        self._stdout = stdout
        self._rc = rc
        self.closed = False
        self.commands = []

    def run(self, command: str, *, timeout: int = 60) -> SessionCommand:
        self.commands.append(command)
        return SessionCommand(rc=self._rc, stdout=self._stdout, stderr="")

    def close(self) -> None:
        self.closed = True


class _ToolResult:
    def __init__(self, *, success=True, output="", raw="", extra=None) -> None:
        self.success = success
        self.output = output
        self.raw = raw
        self.extra = extra or {}


def _finding(vulnerability_type: str = "command_execution") -> Finding:
    return Finding(
        finding_id="finding-command",
        scan_id="scan-automation",
        asset_id="asset-automation",
        target=ORIGIN,
        host="127.0.0.1",
        source="controlled_fixture",
        vulnerability_type=vulnerability_type,
        validator_id="generic-http-command-execution",
        endpoint="/admin/diagnostics",
        http_method="POST",
        parameter_name="cmd",
        parameter_location="form",
        severity="critical",
        validation_status=ValidationStatus.CONFIRMED,
        validation_confidence=0.9,
    )


def _ctx(*, session=None, options=None, vulnerability_type="command_execution") -> AutomationContext:
    return AutomationContext(
        target=ORIGIN,
        authorized=True,
        finding=_finding(vulnerability_type),
        options=dict(options or {}),
        capabilities=("application_compromise",),
        session=session,
    )


class UnixShellSessionTests(unittest.TestCase):
    def test_marker_through_session_confirms_and_names_target(self):
        target = _FakeSession(stdout="obsidian-cmdexec-ok\n0\n")
        result = get_technique("T1059.004").execute(_ctx(session=target))
        self.assertEqual(result.status, "confirmed")
        self.assertIn("command_execution", result.provides)
        self.assertEqual(result.evidence["path"], "session")
        self.assertEqual(result.evidence["session"]["host"], "10.0.0.5")
        self.assertTrue(result.evidence["marker_found"])

    def test_absent_marker_is_rejected(self):
        target = _FakeSession(stdout="no marker here")
        result = get_technique("T1059.004").execute(_ctx(session=target))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.provides, ())

    def test_validator_path_still_used_without_a_session(self):
        validation = ValidationResult(
            status=ValidationStatus.CONFIRMED,
            confidence=0.9,
            validator="generic_http",
            method="deterministic probe",
            evidence={"decision": "confirmed"},
        )
        with mock.patch.object(adapters, "run_validator", return_value=validation):
            result = get_technique("T1059.004").execute(_ctx())
        self.assertEqual(result.status, "confirmed")
        self.assertEqual(result.evidence["path"], "http-validator")


class SystemInfoSessionTests(unittest.TestCase):
    def test_target_facts_confirm(self):
        target = _FakeSession(stdout="Linux host 6.1.0 #1 SMP x86_64 GNU/Linux\nuid=0(root) gid=0(root)")
        result = get_technique("T1082").execute(_ctx(session=target))
        self.assertEqual(result.status, "confirmed")
        self.assertIn("system_information", result.provides)
        self.assertEqual(result.evidence["path"], "session")
        self.assertTrue(result.evidence["kernel_identified"])

    def test_unparseable_output_is_inconclusive(self):
        target = _FakeSession(stdout="garbage output")
        result = get_technique("T1082").execute(_ctx(session=target))
        self.assertEqual(result.status, "inconclusive")


class ValidAccountsSplitTests(unittest.TestCase):
    def _run(self, *, service, try_open_result, session=None):
        options = {"endpoint": "/", "service": service}
        ctx = AutomationContext(
            target=ORIGIN,
            authorized=True,
            finding=_finding("default-credentials"),
            options=options,
            capabilities=("reachable_login_service",),
            session=session,
        )
        tool_result = _ToolResult(
            success=True,
            output="Hydra completed.\nCredentials found: [('root', 'toor')]",
            raw="[22][ssh] host: 127.0.0.1   login: root   password: toor",
            extra={"credentials": [("root", "toor")]},
        )
        with mock.patch.object(adapters, "tool_available", return_value=True), \
             mock.patch.object(adapters, "run_real_tool", return_value=tool_result), \
             mock.patch(
                 "app.automation.session.try_open_ssh_session",
                 return_value=try_open_result,
             ):
            return get_technique("T1078").execute(ctx)

    def test_validated_session_grants_authenticated_session(self):
        session = _FakeSession()
        result = self._run(service="ssh", try_open_result=(session, None))
        self.assertEqual(result.status, "confirmed")
        self.assertIn("credential_access", result.provides)
        self.assertIn("authenticated_session", result.provides)
        self.assertTrue(result.evidence["session_validated"])
        self.assertTrue(session.closed)  # validation-only session is closed

    def test_unvalidated_credentials_grant_only_credential_access(self):
        result = self._run(
            service="ssh",
            try_open_result=(None, "SSH connect failed: AuthenticationException"),
        )
        self.assertEqual(result.status, "confirmed")
        self.assertEqual(tuple(result.provides), ("credential_access",))
        self.assertFalse(result.evidence["session_validated"])
        self.assertNotIn("authenticated_session", result.provides)

    def test_non_ssh_service_cannot_claim_a_session(self):
        result = self._run(service="http-post-form", try_open_result=(None, None))
        self.assertEqual(tuple(result.provides), ("credential_access",))
        self.assertEqual(result.evidence["session_reason"], "unvalidated_service")

    def test_missing_hydra_is_blocked(self):
        ctx = AutomationContext(target=ORIGIN, authorized=True, finding=_finding("default-credentials"))
        with mock.patch.object(adapters, "tool_available", return_value=False):
            result = get_technique("T1078").execute(ctx)
        self.assertEqual(result.status, "blocked")


class ElevationSessionTests(unittest.TestCase):
    SUID = (
        "== SUID ==\n/usr/bin/passwd\n== SGID ==\n== SUDO ==\n"
        "== CAPS ==\n== WRITABLE ==\n"
    )

    def test_session_transport_confirms_vectors(self):
        result = get_technique("T1548").execute(_ctx(session=_FakeSession(stdout=self.SUID)))
        self.assertEqual(result.status, "confirmed")
        self.assertEqual(result.evidence["transport"], "session")
        self.assertEqual(result.evidence["vector_count"], 1)


class PrivescSessionTests(unittest.TestCase):
    def test_session_root_only_on_uid0(self):
        session = _FakeSession(stdout="uid=0(root) gid=0(root) groups=0(root)")
        result = get_technique("T1068").execute(_ctx(session=session))
        self.assertEqual(result.status, "confirmed")
        self.assertEqual(result.evidence["transport"], "session")
        self.assertIn("root_access", result.provides)

    def test_session_enumeration_without_root_is_inconclusive(self):
        session = _FakeSession(stdout="== SUID ==\n/usr/bin/passwd")
        result = get_technique("T1068").execute(_ctx(session=session))
        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.provides, ())


if __name__ == "__main__":
    unittest.main()

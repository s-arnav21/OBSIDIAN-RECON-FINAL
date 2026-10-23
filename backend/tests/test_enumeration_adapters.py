"""Target-side enumeration adapters (LinPEAS/LSE/pspy) and their honesty rules."""
from __future__ import annotations

import unittest
from unittest import mock

from app.automation import enumeration
from app.automation.base import AutomationContext
from app.automation.session import SessionCommand, SessionInfo
from app.models.finding import Finding, ValidationStatus

ORIGIN = "http://127.0.0.1:8090"

SUID_OUTPUT = (
    "== SUID ==\n/usr/bin/passwd\n/usr/bin/sudo\n"
    "== SGID ==\n== SUDO ==\n== CAPS ==\n== WRITABLE ==\n"
)
ROOT_OUTPUT = "uid=0(root) gid=0(root) groups=0(root)\n"


class _FakeSession:
    def __init__(self, *, stdout: str = "", rc: int = 0, supports_sftp: bool = False):
        self.info = SessionInfo("ssh", "10.0.0.9", 22, "user")
        self._stdout = stdout
        self._rc = rc
        self.commands = []
        self.uploaded = []
        if supports_sftp:
            self.put_file = self._put_file

    def _put_file(self, local, remote, *, timeout=30):
        self.uploaded.append((local, remote))
        return True

    def run(self, command, *, timeout=60):
        self.commands.append(command)
        return SessionCommand(self._rc, self._stdout, "")

    def close(self):
        pass


def _ctx(*, session=None) -> AutomationContext:
    return AutomationContext(
        target=ORIGIN,
        authorized=True,
        finding=Finding(
            finding_id="f", scan_id="s", asset_id="a", target=ORIGIN, host="127.0.0.1",
            source="test", vulnerability_type="command-execution",
            endpoint="/diag", http_method="POST", parameter_name="cmd",
            severity="critical", validation_status=ValidationStatus.CONFIRMED,
            validation_confidence=0.9,
        ),
        capabilities=("command_execution",),
        session=session,
    )


class EnumerationSessionTests(unittest.TestCase):
    def test_session_run_parses_vectors_and_does_not_claim_root(self):
        outcome = enumeration.run_enumeration(_ctx(session=_FakeSession(stdout=SUID_OUTPUT)), "lse")
        self.assertTrue(outcome.ran)
        self.assertEqual(outcome.transport, "session")
        self.assertEqual(outcome.session["host"], "10.0.0.9")
        self.assertEqual(outcome.vector_count, 2)
        self.assertFalse(outcome.root_confirmed)  # enumeration never proves root

    def test_uid_zero_is_the_only_root_proof(self):
        outcome = enumeration.run_enumeration(_ctx(session=_FakeSession(stdout=ROOT_OUTPUT)), "lse")
        self.assertTrue(outcome.root_confirmed)

    def test_sftp_upload_path_used_when_available(self):
        session = _FakeSession(stdout=SUID_OUTPUT, supports_sftp=True)
        with mock.patch.object(
            enumeration, "resolve_enumerator", return_value="/tmp/lse.sh"
        ):
            outcome = enumeration.run_enumeration(_ctx(session=session), "lse")
        self.assertEqual(outcome.transport, "session")
        self.assertTrue(session.uploaded)  # uploaded then executed on target


class EnumerationRceTests(unittest.TestCase):
    def test_rce_fallback_without_a_session(self):
        with mock.patch.object(
            enumeration, "deliver_rce_command", return_value=(0, SUID_OUTPUT, "")
        ):
            outcome = enumeration.run_enumeration(_ctx(), "lse")
        self.assertEqual(outcome.transport, "rce")
        self.assertEqual(outcome.vector_count, 2)

    def test_unknown_enumerator_without_session_is_unavailable(self):
        outcome = enumeration.run_enumeration(_ctx(), "does-not-exist")
        self.assertFalse(outcome.ran)
        self.assertEqual(outcome.transport, "unavailable")

    def test_session_exception_is_fail_soft(self):
        class _Boom(_FakeSession):
            def run(self, command, *, timeout=60):
                raise OSError("channel closed")

        outcome = enumeration.run_enumeration(_ctx(session=_Boom()), "lse")
        self.assertFalse(outcome.ran)
        self.assertIn("OSError", outcome.error)


class ResolutionTests(unittest.TestCase):
    def test_named_enumerators_have_remote_urls(self):
        for name in ("linpeas", "winpeas", "lse", "pspy"):
            self.assertTrue(enumeration.remote_url_for(name))

    def test_resolve_absent_enumerator_is_none(self):
        self.assertIsNone(enumeration.resolve_enumerator("lse"))


if __name__ == "__main__":
    unittest.main()

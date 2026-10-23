"""Target-session adapters: SSH (Paramiko) and HTTP-RCE sessions.

These pin the "local controller execution must never count as target execution"
rule: a session always carries an identity, and commands are attributed to it.
"""
from __future__ import annotations

import unittest
from unittest import mock

from app.automation import session


class _FakeChannel:
    def __init__(self, data: bytes, rc: int) -> None:
        self._data = data
        self._rc = rc
        self._sent = False

    def settimeout(self, _timeout) -> None:  # noqa: D401
        return None

    def recv(self, _size: int) -> bytes:
        if self._sent:
            return b""
        self._sent = True
        return self._data

    def recv_exit_status(self) -> int:
        return self._rc


class _FakeStream:
    def __init__(self, channel: _FakeChannel) -> None:
        self.channel = channel


class _FakeStdin:
    def close(self) -> None:
        return None


class _FakeSSHClient:
    def __init__(self, *, stdout: bytes = b"", rc: int = 0, fail: bool = False) -> None:
        self._stdout = stdout
        self._rc = rc
        self._fail = fail
        self.connect_kwargs = None
        self.commands = []
        self.closed = False

    def set_missing_host_key_policy(self, _policy) -> None:
        return None

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs
        if self._fail:
            raise RuntimeError("auth failed")

    def get_transport(self):
        return object()

    def exec_command(self, command, timeout=None):  # noqa: D401
        self.commands.append((command, timeout))
        channel = _FakeChannel(self._stdout, self._rc)
        return _FakeStdin(), _FakeStream(channel), _FakeStream(_FakeChannel(b"", 0))

    def close(self) -> None:
        self.closed = True


def _credential(**overrides):
    data = dict(host="10.0.0.5", username="root", password="toor", port=22)
    data.update(overrides)
    return session.SSHCredential(**data)


class SSHSessionTests(unittest.TestCase):
    def test_connect_records_identity_and_disables_agent(self):
        fake = _FakeSSHClient()
        target = session.SSHSession.connect(_credential(), client_factory=lambda: fake)
        self.assertEqual(target.info.kind, "ssh")
        self.assertEqual(target.info.host, "10.0.0.5")
        self.assertEqual(target.info.username, "root")
        # Key material is used when present; otherwise the password is passed.
        self.assertEqual(fake.connect_kwargs["password"], "toor")
        self.assertFalse(fake.connect_kwargs["allow_agent"])
        self.assertFalse(fake.connect_kwargs["look_for_keys"])

    def test_connect_prefers_key_over_password(self):
        fake = _FakeSSHClient()
        session.SSHSession.connect(
            _credential(password=None, key_filename="/tmp/id_rsa"),
            client_factory=lambda: fake,
        )
        self.assertEqual(fake.connect_kwargs["key_filename"], "/tmp/id_rsa")
        self.assertNotIn("password", fake.connect_kwargs)

    def test_connect_failure_raises_session_error_and_closes(self):
        fake = _FakeSSHClient(fail=True)
        with self.assertRaises(session.SessionError):
            session.SSHSession.connect(_credential(), client_factory=lambda: fake)
        self.assertTrue(fake.closed)

    def test_run_returns_bounded_command_result(self):
        fake = _FakeSSHClient(stdout=b"obsidian-cmdexec-ok\n0\n", rc=0)
        target = session.SSHSession.connect(_credential(), client_factory=lambda: fake)
        result = target.run("echo obsidian-cmdexec-ok")
        self.assertTrue(result.ok)
        self.assertIn("obsidian-cmdexec-ok", result.stdout)
        self.assertEqual(fake.commands[0][0], "echo obsidian-cmdexec-ok")

    def test_run_never_raises_on_transport_error(self):
        fake = _FakeSSHClient()
        target = session.SSHSession.connect(_credential(), client_factory=lambda: fake)
        fake.exec_command = mock.Mock(side_effect=OSError("broken pipe"))
        result = target.run("id")
        self.assertEqual(result.rc, -1)
        self.assertIn("OSError", result.stderr)

    def test_run_rejects_empty_command(self):
        fake = _FakeSSHClient()
        target = session.SSHSession.connect(_credential(), client_factory=lambda: fake)
        result = target.run("   ")
        self.assertEqual(result.rc, -1)


class CredentialParsingTests(unittest.TestCase):
    def test_ssh_credential_from_options(self):
        cred = session.ssh_credential_from_options(
            {"ssh_host": "h", "ssh_user": "u", "ssh_password": "p", "ssh_port": "2222"}
        )
        self.assertIsNotNone(cred)
        self.assertEqual((cred.host, cred.username, cred.port), ("h", "u", 2222))

    def test_missing_material_returns_none(self):
        self.assertIsNone(session.ssh_credential_from_options({"ssh_host": "h"}))
        self.assertIsNone(session.ssh_credential_from_options({}))

    def test_try_open_ssh_session_reports_missing_credentials(self):
        target, reason = session.try_open_ssh_session({})
        self.assertIsNone(target)
        self.assertEqual(reason, "no_credentials")

    def test_try_open_ssh_session_reports_auth_failure(self):
        fake = _FakeSSHClient(fail=True)
        target, reason = session.try_open_ssh_session(
            {"ssh_host": "h", "ssh_user": "u", "ssh_password": "p"},
            client_factory=lambda: fake,
        )
        self.assertIsNone(target)
        self.assertIn("SSH connect failed", reason)


class HttpRceSessionTests(unittest.TestCase):
    def test_run_invokes_bounded_curl(self):
        seen = {}

        def _fake_run_command(cmd, timeout):
            seen["cmd"] = cmd
            seen["timeout"] = timeout
            return 0, "obsidian-cmdexec-ok", ""

        target = session.HttpRceSession(
            session.SessionInfo("http-rce", "h", 80, origin="http://h"), "/diag", "cmd"
        )
        with mock.patch.object(session, "run_command", _fake_run_command):
            result = target.run("id")
        self.assertTrue(result.ok)
        self.assertEqual(seen["cmd"][0], "curl")
        self.assertIn("cmd=id", seen["cmd"][-1])


class OpenContextSessionTests(unittest.TestCase):
    def test_returns_ready_session(self):
        class _Ctx:
            session = object()
            options = {}
            credentials = {}

        self.assertIs(session.open_context_session(_Ctx()), _Ctx.session)

    def test_returns_none_without_credentials(self):
        class _Ctx:
            session = None
            options = {}
            credentials = {}

        self.assertIsNone(session.open_context_session(_Ctx()))

    def test_derives_merged_options_from_context(self):
        class _Ctx:
            session = None
            options = {}
            credentials = {"ssh_password": "p"}

            def merged_options(self):
                return {"ssh_host": "h", "ssh_user": "u"}

        merged = session.context_options(_Ctx())
        self.assertEqual(merged["ssh_host"], "h")
        self.assertEqual(merged["ssh_user"], "u")
        self.assertEqual(merged["ssh_password"], "p")


if __name__ == "__main__":
    unittest.main()

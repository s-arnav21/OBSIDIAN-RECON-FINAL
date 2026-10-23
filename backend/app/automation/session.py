"""Authenticated *target* sessions for the MITRE technique scripts.

A **target session** is a transport that runs commands ON the authorized target
and never on the Obsidian host. It exists so a technique that claims Execution
(T1059.004), Discovery (T1082) or Privilege Escalation (T1548/T1068) proves the
work happened on the target: the session records the target host and the
credential identity, and every command's output is attributed to that session.

Two session kinds are supported:

* :class:`SSHSession` — a Paramiko-backed authenticated shell on a UNIX/Linux
  target. This is the "real authenticated Linux session adapter": techniques use
  it once ``authenticated_session`` capability (valid credentials) is held. The
  credential *material* and the reusable *session* are separate results, so a
  technique only reports ``authenticated_session`` after a session actually
  connects.
* :class:`HttpRceSession` — a session over an already-established web
  command-execution endpoint, so techniques can run target commands even without
  a shell.

Design rules (mirroring the rest of the automation layer): bounded timeouts and
output caps, deterministic commands (never planner-authored), fail-soft results,
and evidence that identifies the target and the session kind. Local controller
execution is **never** represented as a target session.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Protocol, Tuple

from app.automation.proc import run_command

_MAX_OUTPUT = 200_000

try:  # Paramiko is a declared dependency but must never break import.
    import paramiko  # type: ignore

    _PARAMIKO_ERROR: Optional[str] = None
except Exception as exc:  # noqa: BLE001
    paramiko = None  # type: ignore
    _PARAMIKO_ERROR = f"{type(exc).__name__}: {exc}"


def paramiko_available() -> bool:
    return paramiko is not None


def paramiko_error() -> Optional[str]:
    return _PARAMIKO_ERROR


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionCommand:
    """Result of one command executed on the target."""

    rc: int
    stdout: str
    stderr: str
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.rc == 0


@dataclass(frozen=True)
class SessionInfo:
    """Identity of a target session — attributed to every observation."""

    kind: str                 # "ssh" | "http-rce"
    host: str
    port: int
    username: Optional[str] = None
    origin: Optional[str] = None

    def describe(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "origin": self.origin,
        }


class TargetSession(Protocol):
    info: SessionInfo

    def run(self, command: str, *, timeout: int = 60) -> SessionCommand: ...
    def close(self) -> None: ...


# ---------------------------------------------------------------------------
# SSH session (Paramiko)
# ---------------------------------------------------------------------------


@dataclass
class SSHCredential:
    """Credential material used to open an SSH session (never logged raw)."""

    host: str
    username: str
    password: Optional[str] = None
    key_filename: Optional[str] = None
    port: int = 22
    origin: Optional[str] = None


class SSHSession:
    """Paramiko-backed authenticated session. Commands run on the target."""

    kind = "ssh"

    def __init__(
        self,
        info: SessionInfo,
        client: Any,
        *,
        transport: Any = None,
    ) -> None:
        self.info = info
        self._client = client
        self._transport = transport

    # -- construction --------------------------------------------------------
    @classmethod
    def connect(
        cls,
        credential: SSHCredential,
        *,
        connect_timeout: int = 15,
        client_factory: Optional[Callable[[], Any]] = None,
    ) -> "SSHSession":
        """Open an authenticated SSH session or raise ``SessionError``."""
        if paramiko is None:
            raise SessionError(f"paramiko unavailable ({_PARAMIKO_ERROR})")
        factory = client_factory or (lambda: paramiko.SSHClient())
        client = factory()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs: Dict[str, Any] = {
            "hostname": credential.host,
            "port": credential.port,
            "username": credential.username,
            "timeout": connect_timeout,
            "banner_timeout": connect_timeout,
            "auth_timeout": connect_timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if credential.key_filename:
            connect_kwargs["key_filename"] = credential.key_filename
        else:
            connect_kwargs["password"] = credential.password
        try:
            client.connect(**connect_kwargs)
        except Exception as exc:  # noqa: BLE001 — auth/network failure, bounded
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
            raise SessionError(f"SSH connect failed: {type(exc).__name__}") from None
        info = SessionInfo(
            kind="ssh",
            host=credential.host,
            port=credential.port,
            username=credential.username,
            origin=credential.origin,
        )
        transport = client.get_transport()
        return cls(info, client, transport=transport)

    # -- command execution ---------------------------------------------------
    def run(self, command: str, *, timeout: int = 60) -> SessionCommand:
        """Run one command on the target; never raises."""
        started = time.monotonic()
        if not isinstance(command, str) or not command.strip():
            return SessionCommand(rc=-1, stdout="", stderr="empty command")
        try:
            stdin, stdout, _stderr = self._client.exec_command(
                command, timeout=timeout
            )
            try:
                stdin.close()
            except Exception:  # noqa: BLE001
                pass
            channel = stdout.channel
            channel.settimeout(timeout)
            out = bytearray()
            while True:
                try:
                    chunk = channel.recv(4096)
                except Exception:  # noqa: BLE001 — socket timeout etc.
                    break
                if not chunk:
                    break
                if len(out) + len(chunk) > _MAX_OUTPUT:
                    out.extend(chunk[: _MAX_OUTPUT - len(out)])
                    break
                out.extend(chunk)
            rc = channel.recv_exit_status()
            text = out.decode("utf-8", "replace")
            return SessionCommand(
                rc=rc,
                stdout=text,
                stderr="",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        except Exception as exc:  # noqa: BLE001 — fail-soft
            return SessionCommand(
                rc=-1,
                stdout="",
                stderr=f"{type(exc).__name__}: {exc}"[:512],
                duration_ms=int((time.monotonic() - started) * 1000),
            )

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001
            pass

    def put_file(self, local_path: str, remote_path: str, *, timeout: int = 30) -> bool:
        """Upload a local file to the target via SFTP. Returns True on success."""
        if paramiko is None:
            return False
        try:
            sftp = self._client.open_sftp()
        except Exception:  # noqa: BLE001 — no SFTP subsystem
            return False
        try:
            sftp.put(local_path, remote_path)
            return True
        except Exception:  # noqa: BLE001
            return False
        finally:
            try:
                sftp.close()
            except Exception:  # noqa: BLE001
                pass

    def __enter__(self) -> "SSHSession":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# HTTP RCE session (no shell required)
# ---------------------------------------------------------------------------


class HttpRceSession:
    """Run target commands through an established web command-execution endpoint.

    The endpoint/parameter come from the finding context and cannot be redirected
    by the planner. This is still genuine *target* execution — the target runs
    the command and returns its output — but it requires no interactive shell.
    """

    kind = "http-rce"

    def __init__(
        self,
        info: SessionInfo,
        endpoint: str,
        parameter: str,
        *,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.info = info
        self._endpoint = endpoint
        self._parameter = parameter
        self._headers = dict(headers or {})

    def run(self, command: str, *, timeout: int = 60) -> SessionCommand:
        from urllib.parse import urlencode

        separator = "&" if "?" in self._endpoint else "?"
        url = f"{self._endpoint}{separator}{urlencode({self._parameter: command})}"
        argv = ["curl", "-sk", "--max-time", str(timeout)]
        for key, value in self._headers.items():
            argv += ["-H", f"{key}: {value}"]
        argv.append(url)
        rc, stdout, stderr = run_command(argv, timeout=timeout + 15)
        return SessionCommand(rc=rc, stdout=stdout, stderr=stderr)

    def close(self) -> None:  # stateless
        return None


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


class SessionError(RuntimeError):
    """A bounded, safe error raised only while *opening* a session."""


def session_from_credential(
    credential: SSHCredential,
    *,
    connect_timeout: int = 15,
    client_factory: Optional[Callable[[], Any]] = None,
) -> SSHSession:
    return SSHSession.connect(
        credential,
        connect_timeout=connect_timeout,
        client_factory=client_factory,
    )


def ssh_credential_from_options(options: Dict[str, Any]) -> Optional[SSHCredential]:
    """Build an SSH credential from bounded option/evidence values.

    Returns None when the required material (host, username and a password or
    key) is not present, so callers degrade instead of guessing.
    """
    if not isinstance(options, dict):
        return None
    host = str(options.get("ssh_host") or options.get("host") or "").strip()
    username = str(options.get("ssh_user") or options.get("username") or "").strip()
    password = options.get("ssh_password") or options.get("password")
    key = options.get("ssh_key") or options.get("key_filename")
    if not host or not username or not (password or key):
        return None
    try:
        port = int(options.get("ssh_port") or options.get("port") or 22)
    except (TypeError, ValueError):
        port = 22
    return SSHCredential(
        host=host,
        username=username,
        password=str(password) if password else None,
        key_filename=str(key) if key else None,
        port=port,
        origin=options.get("origin"),
    )


def context_options(ctx: Any) -> Dict[str, Any]:
    """Merge option/credential material a technique can use to open a session."""
    options: Dict[str, Any] = {}
    merged = getattr(ctx, "merged_options", None)
    if callable(merged):
        try:
            options.update(dict(merged() or {}))
        except Exception:  # noqa: BLE001
            pass
    else:
        options.update(dict(getattr(ctx, "options", {}) or {}))
    options.update(dict(getattr(ctx, "credentials", {}) or {}))
    return options


def try_open_ssh_session(
    options: Dict[str, Any],
    *,
    connect_timeout: int = 15,
    client_factory: Optional[Callable[[], Any]] = None,
) -> Tuple[Optional["SSHSession"], Optional[str]]:
    """Attempt to open an SSH session; return ``(session, reason)``.

    ``reason`` is ``None`` on success, ``"no_credentials"`` when material is
    missing, or a bounded ``SessionError`` message when the target refused the
    credentials/connection. This lets a technique distinguish "we never had
    credentials" from "the credentials were rejected".
    """
    credential = ssh_credential_from_options(options)
    if credential is None:
        return None, "no_credentials"
    try:
        session = session_from_credential(
            credential,
            connect_timeout=connect_timeout,
            client_factory=client_factory,
        )
    except SessionError as exc:
        return None, str(exc)
    return session, None


def open_context_session(ctx: Any) -> Optional[TargetSession]:
    """Return the context's ready session, else one opened from its credentials.

    Returns None when no session is available. Never raises.
    """
    ready = getattr(ctx, "session", None)
    if ready is not None:
        return ready
    session, _reason = try_open_ssh_session(context_options(ctx))
    return session


__all__ = [
    "SessionCommand",
    "SessionInfo",
    "SessionError",
    "TargetSession",
    "SSHCredential",
    "SSHSession",
    "HttpRceSession",
    "session_from_credential",
    "ssh_credential_from_options",
    "context_options",
    "try_open_ssh_session",
    "open_context_session",
    "paramiko_available",
    "paramiko_error",
]

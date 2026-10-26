"""Task authorization scope and target normalization.

The model may propose a target, but only this module decides whether that target
is inside the operator's configured lab scope.  It never expands a task's scope.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit

from app.core.config import settings
from app.task_agent.contracts import TaskContract


class TaskScopeError(ValueError):
    """Raised when a task or proposed action leaves the authorized lab scope."""


@dataclass(frozen=True)
class AuthorizedTaskScope:
    task_id: str
    target: str
    target_type: str
    target_host: Optional[str]
    target_port: Optional[int]
    target_url: Optional[str]
    resolved_addresses: tuple[str, ...] = ()
    container: Optional[str] = None
    network_policy: str = "none"
    allowed_hosts: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = ()
    input_paths: tuple[str, ...] = ()
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "target": self.target,
            "target_type": self.target_type,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "target_url": self.target_url,
            "resolved_addresses": list(self.resolved_addresses),
            "container": self.container,
            "network_policy": self.network_policy,
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_ports": list(self.allowed_ports),
            "input_paths": list(self.input_paths),
            "metadata": self.metadata,
        }


def _canonical_host(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TaskScopeError("target host must be a non-empty string")
    host = value.strip().lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if len(host) > 253 or any(
        not label or len(label) > 63
        for label in host.split(".")
    ):
        raise TaskScopeError("target host contains an invalid hostname")
    return host


def _allowed_networks() -> tuple[ipaddress._BaseNetwork, ...]:
    networks = []
    for value in settings.TASK_AGENT_ALLOWED_NETWORKS:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def _is_allowed_address(
    address: str,
    networks: Sequence[ipaddress._BaseNetwork],
) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if settings.TASK_AGENT_DENY_PUBLIC and (
        parsed.is_global
        or parsed.is_multicast
        or parsed.is_unspecified
        or parsed.is_reserved
    ):
        return False
    return any(parsed in network for network in networks)


def _resolve_host(host: str) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise TaskScopeError(f"target hostname {host!r} could not be resolved") from exc
    addresses = []
    for info in infos:
        address = info[4][0]
        try:
            normalized = str(ipaddress.ip_address(address))
        except ValueError:
            continue
        if normalized not in addresses:
            addresses.append(normalized)
    if not addresses:
        raise TaskScopeError(f"target hostname {host!r} has no usable address")
    return tuple(addresses)


def _port_allowed(port: int, task: TaskContract) -> bool:
    configured = set(settings.TASK_AGENT_ALLOWED_PORTS)
    requested = set(task.allowed_ports)
    if requested and port not in requested:
        return False
    if configured and port not in configured:
        return False
    return 1 <= port <= 65535


def _resolve_input_path(value: str) -> Path:
    root = Path(settings.TASK_AGENT_INPUT_ROOT).expanduser().resolve()
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise TaskScopeError(
            f"input file {value!r} is outside the configured task input root"
        ) from exc
    if candidate.exists() and candidate.is_symlink():
        raise TaskScopeError(f"input file {value!r} must not be a symlink")
    return candidate


def _parse_url_target(value: str) -> tuple[str, int, str]:
    try:
        parsed = urlsplit(value.strip())
    except ValueError as exc:
        raise TaskScopeError("target URL is invalid") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise TaskScopeError("target URL must be an http(s) URL with a host")
    if parsed.username is not None or parsed.password is not None:
        raise TaskScopeError("target URL must not contain credentials")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise TaskScopeError("target URL contains an invalid port") from exc
    host = _canonical_host(parsed.hostname)
    origin = urlunsplit((parsed.scheme.lower(), parsed.netloc, "", "", ""))
    return host, port, origin


def validate_task_scope(
    task: TaskContract,
    *,
    resolver: Optional[Callable[[str], Sequence[str]]] = None,
) -> AuthorizedTaskScope:
    """Validate a task and return the immutable scope used by the runner."""

    if task.authorized_lab_scope is not True:
        raise TaskScopeError(
            "task requires authorized_lab_scope=true from the operator"
        )
    if not task.permitted_actions:
        raise TaskScopeError("task must declare at least one permitted action")
    if not settings.TASK_AGENT_ENABLED:
        raise TaskScopeError("the task agent is disabled by configuration")

    input_paths = tuple(str(_resolve_input_path(path)) for path in task.input_files)
    target = task.target.strip()
    target_host: Optional[str] = None
    target_port: Optional[int] = None
    target_url: Optional[str] = None
    resolved: tuple[str, ...] = ()
    container: Optional[str] = None

    if task.target_type == "local_file":
        path = _resolve_input_path(target)
        if not path.exists() or not path.is_file():
            raise TaskScopeError("local_file target does not exist")
        target_host = None
        target_url = None
    elif task.target_type == "local_script":
        # The target is an action id/name, not a script path.  The action
        # catalog performs the final registration check.
        if "/" in target or "\\" in target:
            raise TaskScopeError("local_script target must be a registered action id")
    elif task.target_type == "docker_lab":
        candidate = target.lower()
        allowed = {item.lower() for item in settings.TASK_AGENT_ALLOWED_CONTAINERS}
        if candidate not in allowed:
            raise TaskScopeError(
                "docker_lab target is not in TASK_AGENT_ALLOWED_CONTAINERS"
            )
        container = target
    elif task.target_type == "private_ip":
        try:
            address = ipaddress.ip_address(target)
        except ValueError as exc:
            raise TaskScopeError("private_ip target must be an IP address") from exc
        if address.is_global or address.is_loopback is False and address.is_private is False:
            raise TaskScopeError("private_ip target must be a private lab address")
        networks = _allowed_networks()
        if not _is_allowed_address(str(address), networks):
            raise TaskScopeError("private_ip target is outside the allowed networks")
        target_host = str(address)
        resolved = (target_host,)
    elif task.target_type in {"hostname", "test_application"}:
        if task.target_type == "test_application" or "://" in target:
            host, port, origin = _parse_url_target(target)
            if not _port_allowed(port, task):
                raise TaskScopeError("target port is not in the allowed task ports")
            target_host, target_port, target_url = host, port, origin
        else:
            host = _canonical_host(target)
            target_host = host
            target_port = None
        allowed_hosts = {
            item.lower().rstrip(".")
            for item in (*settings.TASK_AGENT_ALLOWED_HOSTS, *task.allowed_hosts)
        }
        if target_host not in allowed_hosts:
            raise TaskScopeError(
                "target hostname is not in the configured or task allowlist"
            )
        if target_host in {"localhost", "127.0.0.1", "::1"}:
            resolved = _resolve_host(target_host) if resolver is None else tuple(
                resolver(target_host)
            )
        else:
            resolved = _resolve_host(target_host) if resolver is None else tuple(
                resolver(target_host)
            )
        networks = _allowed_networks()
        if not resolved or any(
            not _is_allowed_address(address, networks) for address in resolved
        ):
            raise TaskScopeError(
                "target resolves outside the explicitly allowed lab networks"
            )
    else:
        raise TaskScopeError(f"unsupported target type {task.target_type!r}")

    if task.network_policy not in {"none", "lab", "allowlisted"}:
        raise TaskScopeError("unsupported network policy")
    if task.network_policy == "none" and target_host and target_type_is_network(task):
        # "none" is valid for local scripts but a network tool cannot reach a
        # target with networking disabled.  The planner gets a clear error.
        pass

    return AuthorizedTaskScope(
        task_id=task.task_id,
        target=target,
        target_type=task.target_type,
        target_host=target_host,
        target_port=target_port,
        target_url=target_url,
        resolved_addresses=resolved,
        container=container,
        network_policy=task.network_policy,
        allowed_hosts=tuple(task.allowed_hosts or settings.TASK_AGENT_ALLOWED_HOSTS),
        allowed_ports=tuple(task.allowed_ports or settings.TASK_AGENT_ALLOWED_PORTS),
        input_paths=input_paths,
        metadata={"deny_public": settings.TASK_AGENT_DENY_PUBLIC},
    )


def target_type_is_network(task: TaskContract) -> bool:
    return task.target_type in {"private_ip", "hostname", "test_application", "docker_lab"}


def target_in_scope(value: str, scope: AuthorizedTaskScope) -> bool:
    """Check a planner-supplied target against the already validated scope."""

    if not isinstance(value, str) or not value.strip():
        return False
    candidate = value.strip()
    if candidate in {scope.target, scope.target_url, scope.target_host}:
        return True
    if scope.container and candidate.lower() == scope.container.lower():
        return True
    if scope.target_type in {"local_file", "local_script"}:
        try:
            _resolve_input_path(candidate)
            return True
        except TaskScopeError:
            return candidate == scope.target
    try:
        host, port, _origin = _parse_url_target(candidate)
    except TaskScopeError:
        try:
            host = _canonical_host(candidate)
            port = None
        except TaskScopeError:
            return False
    allowed_hosts = {item.lower().rstrip(".") for item in scope.allowed_hosts}
    if host not in allowed_hosts:
        return False
    if port is not None and scope.allowed_ports and port not in scope.allowed_ports:
        return False
    if scope.resolved_addresses:
        networks = _allowed_networks()
        if not all(_is_allowed_address(address, networks) for address in scope.resolved_addresses):
            return False
    return True


def assert_target_in_scope(value: str, scope: AuthorizedTaskScope) -> None:
    if not target_in_scope(value, scope):
        raise TaskScopeError("proposed target is outside the task's authorized scope")


def normalize_tool_target(value: str, *, kind: str = "web") -> str:
    """Normalize a target for a tool that expects a URL, host, or host:port."""

    if not isinstance(value, str) or not value.strip():
        raise TaskScopeError("tool target is empty")
    value = value.strip()
    if kind == "host":
        if "://" in value:
            parsed = urlsplit(value)
            if not parsed.hostname:
                raise TaskScopeError("tool target has no hostname")
            return _canonical_host(parsed.hostname)
        if value.startswith("[") and "]" in value:
            return value[1:value.index("]")]
        return _canonical_host(value.split("/", 1)[0].split(":", 1)[0])
    if kind == "hostport":
        if "://" in value:
            parsed = urlsplit(value)
            if not parsed.hostname:
                raise TaskScopeError("tool target has no hostname")
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            return f"{_canonical_host(parsed.hostname)}:{port}"
        return value
    if "://" not in value:
        raise TaskScopeError("web tool target must be an http(s) URL")
    host, port, origin = _parse_url_target(value)
    return origin


__all__ = [
    "AuthorizedTaskScope",
    "TaskScopeError",
    "assert_target_in_scope",
    "normalize_tool_target",
    "target_in_scope",
    "validate_task_scope",
]

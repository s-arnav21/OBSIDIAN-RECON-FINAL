"""Bounded real external-tool confirmation for canonical validators.

The differential validators prove injection behaviour with controlled HTTP
probes. Where a canonical external exploitation tool exists for the same
vulnerability and is installed on the host, that tool is run (bounded, batch,
non-interactive) so a ``CONFIRMED`` verdict is corroborated by genuine
exploitation output instead of heuristics alone.

Every function here is storage- and session-agnostic: sqlmap performs its own
network requests against the persisted in-scope endpoint. When the tool is
absent the validator's own probes remain the sole evidence and keep their
current conservative behaviour.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from app.models.finding import Finding

_SQLMAP_BINARY = "sqlmap"

_DEFAULT_TOOL_TIMEOUT_SECONDS = float(os.getenv("REAL_TOOL_TIMEOUT", "180"))
_DEFAULT_OUTPUT_CAP = int(os.getenv("REAL_TOOL_OUTPUT_CAP", "200000"))
_SNIPPET_LIMIT = 6000
_PRUNING_AGE_SECONDS = 6 * 3600

_SQLMAP_POSITIVE_PATTERNS = (
    re.compile(r"is vulnerable", re.I),
    re.compile(r"available databases", re.I),
    re.compile(r"\[\*\]\s+dbms[:\s]", re.I),
    re.compile(r"the back-?end dbms", re.I),
    re.compile(r"parameter[^\n]*is vulnerable", re.I),
    re.compile(r"bin contains[^\n]*\(sqlmap\)", re.I),
    re.compile(r"getting current (database|user|host):?\s+\S+", re.I),
    re.compile(r"fetched data logged", re.I),
)

_SQLMAP_NEGATIVE_PATTERNS = (
    re.compile(r"doe?s? not appear to be injectable", re.I),
    re.compile(r"all tested parameters[^\n]*not[^\n]*injectable", re.I),
    re.compile(r"could not have been tested[^\n]*no[^\n]*injection", re.I),
    re.compile(r"no parameter\b[^\n]*\binjectable", re.I),
)

_SQLMAP_DBMS_PATTERNS = (
    re.compile(r"\bback-?end dbms:\s*([^\n]+)", re.I),
    re.compile(r"\bthe back-?end dbms is ([^\(\n]+)", re.I),
)

_SQLMAP_DB_BLOCK_RE = re.compile(
    r"available databases \[\d+\]:\n(.*?)(?:\n\n|\Z)",
    re.I | re.S,
)
_SQLMAP_DB_ENTRY_RE = re.compile(r"^\[\*\]\s+(\S.*)$", re.M)
_SQLMAP_ERROR_PATTERNS = (
    re.compile(r"^\[critical\][^\n]*(?:could not connect|connection refused|failed to connect)", re.I | re.M),
    re.compile(r"could not connect", re.I),
    re.compile(r"connection refused", re.I),
    re.compile(r"failed to connect", re.I),
)

_SQLMAP_UNSUPPORTED_METHODS = frozenset({"HEAD", "DELETE", "OPTIONS", "TRACE"})


@dataclass(frozen=True)
class ToolConfirmation:
    """Structured real-tool verdict consumed by validators and callers."""

    tool: str
    available: bool
    ran: bool
    timed_out: bool
    error: Optional[str]
    confirmed: bool
    not_vulnerable: bool
    dbms: Optional[str]
    databases: List[str]
    command: str
    duration_seconds: Optional[float]
    output_snippet: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        """True when the tool ran and produced a decision, not a failure."""
        return self.ran and not self.timed_out and not self.error


def binary_available(name: str) -> bool:
    return shutil.which(name) is not None


def _resolve_absolute_url(finding: Finding) -> Optional[str]:
    """Resolve the persisted endpoint against the target when it is relative."""
    endpoint = (finding.endpoint or "").strip()
    if not endpoint:
        return None
    parts = urlsplit(endpoint)
    if parts.scheme or parts.netloc:
        return endpoint
    target = (finding.target or "").strip()
    if not target:
        return None
    return urljoin(f"{target.rstrip('/')}/", endpoint.lstrip("/"))


def _sqlmap_url(finding: Finding, location: str) -> Optional[str]:
    """Absolute URL for sqlmap, merging the persisted query context."""
    url = _resolve_absolute_url(finding)
    if not url:
        return None
    context = (finding.http_request_context or {}).get("query", {})
    if location != "query" or not context:
        return url
    parts = urlsplit(url)
    merged = dict(context)
    parameter = finding.parameter_name or ""
    if parameter and parameter not in merged:
        merged[parameter] = "1"
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(merged), "")
    )


def _sqlmap_options(finding: Finding) -> Tuple[List[str], Optional[str]]:
    """Build a bounded sqlmap invocation for the finding.

    Returns ``(argv, error)`` where ``error`` is set when sqlmap cannot test
    the parameter location accurately.
    """
    method = (finding.http_method or "GET").upper()
    if method in _SQLMAP_UNSUPPORTED_METHODS:
        return [], "unsupported_http_method_for_sqlmap"
    location = finding.parameter_location or ""
    context = (finding.http_request_context or {}).get(location, {})
    parameter = finding.parameter_name or ""

    if location == "header":
        return [], "header_parameter_location_unsupported_by_sqlmap"
    if location not in {"query", "form", "json", "cookie"}:
        return [], f"unsupported_parameter_location_for_sqlmap:{location}"

    url = _sqlmap_url(finding, location)
    if not url:
        return [], "missing_endpoint"

    extra: List[str] = []
    if method in {"POST", "PUT", "PATCH"}:
        extra += ["--method", method]
        if location == "form":
            extra += ["--data", urlencode(context)]
        elif location == "json":
            extra += [
                "--data",
                json.dumps(context),
                "--headers",
                "Content-Type: application/json",
            ]
    if location == "cookie" and context:
        cookie = "; ".join(
            f"{name}={value}" for name, value in context.items()
        )
        extra += ["--cookie", cookie]

    command = [
        _SQLMAP_BINARY,
        "-u", url,
        "--batch",
        "--level", "1",
        "--risk", "1",
        "--threads", "1",
        "--timeout", "15",
        "--retries", "1",
        "--disable-coloring",
        "--flush-session",
        "--verbose", "0",
        "--output-dir", _output_dir(finding.finding_id),
    ]
    if parameter:
        command += ["-p", parameter]
    command += extra
    command += [
        "--dbs",
        "--current-db",
    ]
    return command, None


def _output_dir(finding_id: Optional[str] = None) -> str:
    label = re.sub(r"[^A-Za-z0-9._-]+", "_", finding_id or "finding")
    return f"/tmp/obsidian_sqlmap/{label}"


def _prune_output_dirs() -> None:
    root = "/tmp/obsidian_sqlmap"
    try:
        entries = os.listdir(root)
    except OSError:
        return
    now = time.time()
    for entry in entries:
        path = os.path.join(root, entry)
        try:
            if now - os.path.getmtime(path) > _PRUNING_AGE_SECONDS:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            continue


def _run_sqlmap(command: Sequence[str], timeout: float) -> Tuple[int, str, str, bool]:
    try:
        proc = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/tmp",
            start_new_session=True,
        )
    except subprocess.TimeoutExpired:
        return -1, "", f"sqlmap timed out after {timeout:g}s", True
    except OSError as exc:
        return -1, "", f"failed to launch sqlmap: {str(exc)[:300]}", False
    if proc.returncode != 0 and proc.stderr:
        return proc.returncode, proc.stdout, proc.stderr[:2000], False
    return proc.returncode, proc.stdout, proc.stderr, False


def sqlmap_confirmation(
    finding: Finding,
    *,
    timeout: Optional[float] = None,
) -> ToolConfirmation:
    """Run a bounded sqlmap scan against the finding and parse the verdict.

    Returns a structured :class:`ToolConfirmation`. The tool is best-effort:
    when sqlmap is missing, the endpoint cannot be reconstructed, or the run
    fails, the result carries ``ran=False`` (or an explicit failure) and the
    caller's heuristic evidence remains authoritative.
    """
    if not binary_available(_SQLMAP_BINARY):
        return ToolConfirmation(
            tool=_SQLMAP_BINARY,
            available=False,
            ran=False,
            timed_out=False,
            error="sqlmap not installed",
            confirmed=False,
            not_vulnerable=False,
            dbms=None,
            databases=[],
            command="",
            duration_seconds=None,
            output_snippet="",
        )

    command, build_error = _sqlmap_options(finding)
    if build_error is not None:
        return ToolConfirmation(
            tool=_SQLMAP_BINARY,
            available=True,
            ran=False,
            timed_out=False,
            error=build_error,
            confirmed=False,
            not_vulnerable=False,
            dbms=None,
            databases=[],
            command="",
            duration_seconds=None,
            output_snippet="",
        )

    _prune_output_dirs()
    started = time.monotonic()
    use_timeout = (
        float(timeout)
        if timeout is not None and isinstance(timeout, (int, float))
        else _DEFAULT_TOOL_TIMEOUT_SECONDS
    )
    returncode, stdout, stderr, timed_out = _run_sqlmap(command, use_timeout)
    duration = round(time.monotonic() - started, 3)

    output = stdout + "\n" + stderr
    capped = output[: _DEFAULT_OUTPUT_CAP]
    snippet = capped[-_SNIPPET_LIMIT:]
    confirmed = any(
        pattern.search(capped) for pattern in _SQLMAP_POSITIVE_PATTERNS
    )
    not_vulnerable = any(
        pattern.search(capped) for pattern in _SQLMAP_NEGATIVE_PATTERNS
    ) and not confirmed

    dbms = _extract_dbms(capped)
    databases = _extract_databases(capped)
    error = (
        None
        if timed_out or not_vulnerable
        else (_failure_message(capped) or None)
    )

    evidence = {
        "returncode": returncode,
        "timed_out": timed_out,
        "parameter_name": finding.parameter_name,
        "parameter_location": finding.parameter_location,
        "http_method": finding.http_method,
    }

    return ToolConfirmation(
        tool=_SQLMAP_BINARY,
        available=True,
        ran=True,
        timed_out=timed_out,
        error=error,
        confirmed=confirmed,
        not_vulnerable=not_vulnerable,
        dbms=dbms,
        databases=databases,
        command=" ".join(command),
        duration_seconds=duration,
        output_snippet=snippet,
        evidence=evidence,
    )


def _extract_dbms(text: str) -> Optional[str]:
    bounded = text[: _DEFAULT_OUTPUT_CAP]
    for pattern in _SQLMAP_DBMS_PATTERNS:
        match = pattern.search(bounded)
        if match:
            value = re.sub(r"\s+", " ", match.group(1)).strip(" .,:;")
            if value and not value.lower().startswith(("like", "considering")):
                return value[:120]
    return None


def _extract_databases(text: str) -> List[str]:
    bounded = text[: _DEFAULT_OUTPUT_CAP]
    block = _SQLMAP_DB_BLOCK_RE.search(bounded)
    if not block:
        return []
    names = _SQLMAP_DB_ENTRY_RE.findall(block.group(1))
    if not names:
        return []
    return list(dict.fromkeys(name.strip() for name in names))


def _failure_message(text: str) -> Optional[str]:
    bounded = text[: _DEFAULT_OUTPUT_CAP]
    if any(pattern.search(bounded) for pattern in _SQLMAP_ERROR_PATTERNS):
        return "sqlmap reported a runtime error"
    return None


__all__ = [
    "ToolConfirmation",
    "binary_available",
    "sqlmap_confirmation",
]
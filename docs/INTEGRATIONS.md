# Tooling & integration map

This document records what Obsidian actually integrates today, how each piece
maps onto the eight technique scripts, and what remains staged. It exists so a
claim like “we run LinPEAS” or “Metasploit is wired in” can be checked against
code rather than assumed.

> Scope rule used throughout: **detection ≠ exploitation**, **local controller
> execution ≠ target execution**, and **enumeration ≠ proven abuse**. Every
> integration below is written to preserve those distinctions.

## 1. Implemented in the automation layer

| Module | Adapted from | What it gives the agent |
|---|---|---|
| `backend/app/automation/session.py` | Paramiko | `SSHSession` (real authenticated Linux session) and `HttpRceSession` (session over an an established web RCE endpoint). Every session carries a `SessionInfo` identity so results name the target they ran against. Local controller execution is never represented as a session. |
| `backend/app/automation/evidence.py` | VulnClaw `traffic/store.py` + `traffic/replay.py` | Bounded `EvidenceStore` that captures request/response exchanges and replays them with explicit overrides for reproducibility, with JSON persistence. |
| `backend/app/automation/dispatch.py` | VulnClaw `tool_call_manager.py` | `ToolDispatcher` that runs tool calls, records every success *and* failure, and supports bounded parallel execution. |
| `backend/app/automation/enumeration.py` | PEASS/LSE/pspy family | `run_enumeration` runs a cached enumerator **on the target** (SFTP upload via the session, or through the RCE endpoint) and classifies output. `root_confirmed` comes only from definitive `uid=0` evidence. |
| `backend/app/automation/zap_client.py` | OWASP ZAP REST API | Fail-soft `ZapClient` (spider / active scan / alerts) for a *running* ZAP instance. Gated on `ZAP_BASE_URL`. |
| `backend/app/automation/mitm_capture.py` | mitmproxy addons | Converts captured flows into `EvidenceEntry` objects; `EvidenceCaptureAddon` records responses into an `EvidenceStore`. |
| `backend/app/automation/metasploit_rpc.py` | pymetasploit3 | Drives an existing `msfrpcd` (modules, jobs, sessions); the `metasploit-*` tools now prefer RPC when it is enabled+available, falling back to `msfconsole`. |

Context plumbing: `AutomationContext` carries an optional ready `session` and a
bounded `credentials` map; `runner.build_context(..., target_session=,
credentials=)` threads them, and `session.open_context_session(ctx)` returns the
ready session or opens one from recovered credentials.

### Technique-script changes

| Technique | Change |
|---|---|
| **T1059.004** (Unix shell) | Prefers a target session: runs a fixed marker command *through the session* and confirms from the target's own output, recording session identity. Falls back to the deterministic HTTP validator when no session is available. |
| **T1082** (System info) | Same session-first behaviour; collects OS/kernel/identity facts through the session and attributes them to the session host. |
| **T1078** (Valid accounts) | Splits capabilities honestly: `credential_access` when hydra recovers accepted credentials, `authenticated_session` **only** when a session is actually established (a ready session, or an SSH session opened with the recovered credentials). Unvalidated credentials can no longer claim a session. |
| **T1548** (Elevation-control abuse) | Prefers a target session (runs the fixed SUID/SGID/sudo/caps enumeration through it); falls back to the RCE endpoint. Records the transport and session identity; echoed section headers are still never evidence. |
| **T1068** (Priv-esc exploitation) | When a session is available, runs LSE/LinPEAS through `enumeration.run_enumeration`; otherwise keeps the cached/remote LinPEAS/WinPEAS tool path. `root_access` still requires definitive `uid=0` evidence. |

### Discovery tools added to the registry

`ffuf-fuzz` and `katana-crawl` join `nuclei`/`gobuster`/`nikto`/`sqlmap`/`hydra`
as real tools the planner can select. `scripts/install_tools.sh --user` installs
them as static release binaries. They supply *candidates* (paths, endpoints) to
the validators; they do not by themselves prove compromise.

## 2. Eight-technique mapping

| Technique | Tools integrated / available | Required distinction (enforced) |
|---|---|---|
| **T1595** Active scanning | nmap, httpx (Python), nuclei, ffuf, katana | Service discovery supplies candidates for further checks. |
| **T1190** Public app exploitation | nuclei, deterministic validators, sqlmap, Metasploit tools | Detection and demonstrated exploitation carry separate statuses. |
| **T1078** Valid accounts | hydra, SSH session validation | Accepted credentials (`credential_access`) and a reusable session (`authenticated_session`) are separate results. |
| **T1059.004** Unix shell | SSH session (Paramiko) or HTTP RCE session | Local controller execution never counts as target execution. |
| **T1082** System information | SSH session; deterministic validator | Evidence identifies the target/session it came from. |
| **T1548** Elevation-control abuse | fixed SUID/SGID/sudo/caps enumeration; session or RCE delivery | Enumeration identifies opportunities; it does not prove abuse (echoed section headers are never evidence). |
| **T1068** Priv-esc exploitation | LinPEAS/WinPEAS (cached or fetched); session or RCE delivery | Suggestions are candidates; `root_access` requires definitive uid-0 evidence. |
| **T1213** Repository data | sqlmap database path | Database names, retrieved records, and credential material are distinct capabilities. |

## 3. Status of every requested tool/repository

Legend: **done** = code exists and is tested · **adapter-ready** = the session/
dispatch/evidence primitives are in place, only a thin adapter is missing ·
**staged** = not started, rationale noted.

| Repository / tool | Status | Notes |
|---|---|---|
| Paramiko | **done** | `session.SSHSession`; used by T1059.004/T1082/T1078/T1548/T1068, incl. SFTP upload of enumerators. |
| Nuclei + templates | **done** | Existing scanner + agent tool. |
| httpx | **done** | Python dependency + discovery fallback. |
| feroxbuster | **done** | Already resolved by the scanner. |
| ffuf, Katana | **done** | Registry tools + installer + dispatch. |
| ZAP (Python API / REST) | **done** | `zap_client.py` (spider/ascan/alerts); enable with `ZAP_BASE_URL`. |
| mitmproxy | **done** | `mitm_capture.py` converts flows -> `EvidenceStore` for replay. |
| pymetasploit3 / Metasploit RPC | **done** | `metasploit_rpc.py`; `metasploit-*` tools prefer `msfrpcd` when `MSF_RPC_ENABLED` + the package is present. |
| PEASS-ng (LinPEAS/WinPEAS) | **done** | Cached in `delivery.py`; T1068 requires uid-0 evidence. |
| Linux Smart Enumeration (LSE) | **done** | `delivery.resolve_enumerator("lse")`; run via `enumeration.run_enumeration`. |
| pspy | **done** | `delivery.resolve_enumerator("pspy")`; observations are enumeration only. |
| GTFOBins / LOLBAS | staged | Reference data, not execution; expose as a lookup used while interpreting T1548/T1068 output. |
| AutoRecon | staged | Task orchestration; the existing scanner + `dispatch.py` cover most of the need. |
| VulnClaw evidence/dispatch patterns | **done** | `evidence.py` + `dispatch.py` keep the `TechniqueScript` interface. |

### Configuration keys added

`ZAP_BASE_URL`, `ZAP_API_KEY`, `ZAP_TIMEOUT` (ZAP) and `MSF_RPC_ENABLED`,
`MSF_RPC_HOST`, `MSF_RPC_PORT`, `MSF_RPC_USER`, `MSF_RPC_PASSWORD`,
`MSF_RPC_SSL` (Metasploit RPC). Enumerators are resolved from the existing
`delivery._SCRIPT_CACHE_DIRS` (`/root/.local/share/recon`, …).

## 4. Adding a new adapter

1. Implement a small, bounded function/adapter (timeout + output cap, fail-soft).
2. If it runs *on the target*, return a `SessionInfo`-carrying `TargetSession`
   (or use `session.open_context_session`).
3. Register a real tool in `backend/app/agent/tools.py` (`TOOL_REGISTRY`,
   executor, dispatcher map, `VULN_TO_TOOL_PRIORITY`) so the planner can select it.
4. Add the binary to `scripts/install_tools.sh` and the README §1.2 table.
5. Add tests proving catalog exposure, policy-allow, and honest evidence.

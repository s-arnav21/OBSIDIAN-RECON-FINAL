# Obsidian Recon — Working Task List & Knowledge Base Backlog

Status: `[ ]` pending · `[x]` done · `[~]` in progress

## 0. Dashboard & Pipeline Fixes (reported by operator)

- [x] `nuclei` runs on the target — removed `nuclei` / `nuclei-targeted` from vm & ctf profile skip lists (`backend/app/core/profiles.py`); nuclei v3.11.1 resolves via PATH (verified).
- [x] Subdomain enumeration no longer `(excluded)` — `subdomains` scanner removed from vm/ctf skip lists (pure-Python httpx, produces live-subdomain findings).
- [x] Progress bar reflects ONLY executed steps — `ScanJob.snapshot().done` = DONE+FAILED only; skipped/pending excluded (`backend/app/core/progress.py`).
- [x] Journal ticks off steps as they actually run — skipped steps stay `·`/pending `○`; nothing pre-marks as done.
- [x] Manifest (62 items) seeded in real execution order — recon → recon skills → network → web → exploit → scanners (subdomains→http probe→nmap→nuclei→nmap tls→content→waf detect) → subdomain chain → origin hunt → triage·validation·normalization (`seed_manifest` + `_SKILL_PHASE_ORDER`).
- [x] Journal renders in run order — steps sorted by run `seq` (stamped when each goes live) in `renderJournal`/`sortBySeq` (`backend/app/static/recon.js`).
- [x] Severity Summary headers use human labels — `vulnLabel()` map in `recon.js` + `label` field from KB in `remediation_plan.py`; `reconnaissance`/`misconfiguration` render as proper titles.
- [x] Recon is robust for websites AND VMs — tools auto-resolved (nuclei/nmap/httpx/subfinder verified), subdomain scanner is pure-Python httpx, nuclei tolerates non-zero exits when JSONL output exists.
- [x] Scans never hang forever — `--host-timeout 120s` + `--max-retries 2` added to nmap discovery (skill + scanner); `settings.NMAP_HOST_TIMEOUT`; port plan is profile-aware: full `-p-` for vm/ctf, fast `--top-ports 1000` for webapp/stealth (`ScanProfile.nmap_full_port` → `SkillContext.profile` + `NmapScanner.start_plan`).

## 1. Knowledge Base — Scoring Method

- [x] `calculate_severity()` in `pipeline/triage.py`: `FINAL = CVSS_BASE + OWASP_MODIFIER(+0.5) + CONTEXT_MODIFIER(±)` capped 0.1–10.0; context: +1.0 creds, +1.0 RCE, +0.5 auth bypass, −0.5 local, −1.0 physical.
- [x] Severity thresholds: CRITICAL 9.0+, HIGH 7.0+, MEDIUM 4.0+, LOW 0.1+, INFO 0 (`cvss_severity`).
- [x] Wired into normalization — `severity_for_type()` in `pipeline/normalize.py` picks the more severe of (tool rating, KB baseline) for every canonical `Finding`.

## 2. Knowledge Base — Injection Attacks (A)

- [x] SQL Injection — `sql-injection`, CWE-89, A03, T1190, CVSS 9.8 (aliases: sqli, sqli-error/blind/time/boolean/union/stacked)
- [x] Command / OS Injection — `command-execution`, CWE-78, A03, T1059, 9.8 (aliases: rce, command-injection, webshell)
- [x] XSS — `xss`, CWE-79, A03, T1189, 6.1 (reflected/stored/DOM aliases)
- [x] LFI / Path Traversal — `lfi`, CWE-22, A01, T1083, 8.6
- [x] XXE — `xxe`, CWE-611, A05, T1190, 8.8
- [x] SSRF — `ssrf`, CWE-918, A10, T1190, 9.1 (+creds → 10.0)
- [x] SSTI — `ssti`, CWE-1336, A03, T1059, 9.8
- [x] CSRF, IDOR, Open Redirect, File Upload — all canonicalized with KB entries

## 3. Knowledge Base — Broken Authentication (B)

- [x] Default/Weak Credentials — `default-credentials` CWE-284 A07 T1078 9.8 · `weak-credentials` CWE-307 A07 T1110 7.5 (aliases: default-login, brute-force)
- [~] Session/Cookie flags — `cookie-missing-secure` CWE-614 · `cookie-missing-httponly` CWE-1004 (in KB; session-fixation checks TBD)

## 4. Knowledge Base — Cross-Site Attacks (C)

- [x] XSS family — see section 2
- [x] Clickjacking — `clickjacking` CWE-1021 A04 T1204 4.3 (alias x-frame-options-missing)

## 5. Knowledge Base — Access Control (D)

- [x] IDOR — CWE-639 A01 T1530 6.5
- [x] LFI / Path Traversal — CWE-22 A01 T1083 8.6
- [x] Exposed admin panel — `exposed-admin-panel` CWE-284 A07 T1190 6.5
- [~] Privilege escalation depth-map — advisories exist; per-CVE escalation scoring TBD

## 6. Knowledge Base — Security Misconfiguration (E)

- [x] Exposed admin/debug/backup/.env/.git/archive paths — KB entries with CVSS (env-exposed 9.1 critical, git-exposed 7.5, backup 7.5)
- [x] Missing Security Headers — `missing-security-header` CWE-693 A05 3.7; clickjacking/CSP/mime-sniffing entries
- [x] Information disclosure — `information-disclosure` CWE-200 T1592 5.3 (+ `leaked-san`, `info-leak` aliases)

## 7. Knowledge Base — Network Attacks (F)

- [x] TLS weaknesses — `weak-tls-cipher` CWE-295 A02 T1573 7.4 · `expired-tls` CWE-299 6.5 (POODLE/BEAST/CRIME/LOGJAM/DROWN remediation in weak-cipher entry)
- [x] Open ports & services — `open-service-exposure` CWE-284 T1046 5.6 (aliases open-port, port-open, service-detected → merged triage family)
- [x] SSRF — section 2

## 8. Knowledge Base — Host Header Attacks (G)

- [x] Host header injection — `host-header-injection` CWE-290 A07 T1190 6.1 (reset/cache-poisoning/SSRF-via-Host remediation)

## 9. Knowledge Base — Cryptographic Failures (H)

- [x] Weak hashing — `weak-hashing` CWE-327 A02 T1555 7.5 (Argon2id/bcrypt before MD5/SHA1)

## 10. Knowledge Base — CVE Mapping

- [x] Generic `cve` type → CWE-1035 A06 T1190 9.8 (nuclei **-id/name mapping feeds this) + per-CVE advisories in CVE table below
- [~] Version→CVE+CVSS resolver (currently generic-cve with evidence; per-CVE detail table in KB next)

## 11. Knowledge Base — MITRE ATT&CK Mapping

- [x] Recon methodology: T1590/T1591/T1592/T1593 mapped on osint-* + reconnaissance
- [x] Initial access: T1190/T1078/T1133; Execution T1059/T1203/T1059.007; Credential access T1110/T1555/T1539; Discovery T1046/T1082/T1083/T1518
- [x] `mitre` field on every KB entry; exposed via `enrich()`

## 12. Feeding KB into Code (normalize.py / triage.py)

- [x] `_KB` in `pipeline/normalize.py` extended (label, cwe, owasp, mitre, cvss, severity, remediation) — 45+ canonical types
- [x] Alias map extended (~80 slug variants → canonical) + underscore/dash normalisation
- [x] `pipeline/triage.py` — `calculate_severity()` + `cvss_severity()`
- [x] `severity_for_type()` wired into `normalize_all`; `enrich()` returns label/mitre; `label_for()` exported
- [x] Report/summary labels use KB `label` — fixes `reconnaissance`/`misconfiguration` headers

## 13. Verification

- [x] Backend test suite passes — `735 passed, 260 subtests` (run from `backend/`)
- [x] Nuclei/nmap/httpx/subfinder all resolve via `_resolve_executable`
- [x] Live run on `https://mukeshpatel.mylineupx.com/` — vm profile: recon ~25s → port-scan bounded 121s (degrades to top-ports on CDN) → subdomain scanner ~15-43s (89 live-subdomain findings) → http_probe → nmap scanner bounded 121s → nuclei → tls-audit ≤130s → finalize.
- [x] webapp profile: fast path uses `--top-ports 1000` (port-scan ~73s incl. banner pass on 80/443).
- [~] Note: a real scan takes several minutes by design; the `triage · validation · normalization 0.1s` you see is only THAT final step's duration, not the whole scan.

---

## Skill / step inventory (the "62")

The UI pre-seeds the whole tick list before anything runs. With the default
**webapp** profile (nuclei + subdomain scanners enabled, exploit phase off)
the count is **~62** steps:

- **1 job-level phase** — `recon (passive OSINT + DNS)`
- **51 registered skills**, phase-ordered recon → network → web → exploit(gated) → post → report:
  - **recon (12):** cert-transparency, dns-zone-transfer, email-security, origin-hunt, port-scan, reverse-ip, subdomain-enum, takeover-check, tech-fingerprint, tls-audit, wayback-harvest, whois-analysis
  - **network (14):** bind-version-probe, bindshell-probe, distcc-rce-probe, ftp-probe, http-service-fp, irc-backdoor, java-rmi-probe, mysql-probe, nfs-probe, smb-probe, smtp-probe, snmp-probe, ssh-audit, vnc-probe
  - **web (16):** security_headers, api_version_enum, waf_detect, open_redirect, method_tamper, spring_actuator, ssrf_probe, default_creds, graphql_probe, host_header, content_discovery, wordpress_scan, cookie_audit, js_harvest, cors_probe, asp_error_harvest
  - **exploit (4, phase-gated):** lfi-probe, rce-probe, sqli-error, xxe-probe
  - **post (2):** correlate, nuclei-targeted
  - **report (3):** remediation-plan, executive-summary, markdown-report
- **7 scanner steps** (run order): subdomains → http probe → nmap → nuclei → nmap tls → content discovery → waf detect
- **3 chain/finalize steps:** subdomain chained deep-scan, origin hunt (behind WAF), triage · validation · normalization

Skill/profiling detail: `backend/skills/` (registry + runner + selector),
scanner order: `backend/pipeline/scanner/__init__.py`.
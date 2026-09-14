"""HTTP service fingerprint on non-standard ports.

Gated on any of the classic admin/alt web ports being open. A single GET to
each open non-standard port classifies the service by response headers and
body markers — Tomcat (incl. manager), Jenkins, Grafana, Kibana, RabbitMQ
management, Kubernetes API, Solr, Spring Boot, plus generics (nginx, Express,
Apache).

Findings: `admin-interface-exposed` (HIGH) for developer/admin consoles,
`http-service-fingerprint` (INFO) for every identified service. Each port is
recorded on osint.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

ALT_PORTS = (8080, 8443, 8888, 9090, 4848, 7001)
CONNECT_TIMEOUT = 12
_USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
               "educational security platform)")

# (backend, is_admin, [header regexes], [body regexes])
_MARKERS: List[tuple] = [
    ("tomcat", True, [r"^.*(?:Apache-?Coyote|Catalina)", r"Tomcat"],
     [r"Apache Tomcat", r"Catalina"]),
    ("jenkins", True, [r"Jenkins", r"X-Jenkins"],
     [r"Jenkins", r"\/login\?from", r"Dashboard \[Jenkins\]"]),
    ("grafana", True, [r"grafana", r"X-Grafana"],
     [r"Grafana", r"grafana"]),
    ("kibana", True, [r"kibana"], [r"kibana", r"Kibana"]),
    ("rabbitmq-mgmt", True, [r"rabbitmq", r"RabbitMQ"],
     [r"RabbitMQ", r"RabbitMQ Management"]),
    ("kubernetes-api", True, [], [r"kubernetes/", r"Kubernetes", r"\"kind\":", r"kube-apiserver"]),
    ("solr", True, [], [r"Apache Solr", r"solr\.js,", r"Solr Admin"]),
    ("spring-boot", False, [r"Spring Boot"], [r"Whitelabel Error Page", r"ErrorPageFilter", r"Spring Boot"]),
    ("express", False, [r"Express"], []),
    ("nginx", False, [r"nginx"], []),
    ("apache", False, [r"Apache"], [r"It works!"]),
]


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _probe(host: str, port: int) -> Optional[dict]:
    url = f"http://{host}:{port}/"
    try:
        with httpx.Client(verify=False, timeout=CONNECT_TIMEOUT,
                          follow_redirects=False) as client:
            r = client.get(url, headers={"User-Agent": _USER_AGENT,
                                         "Accept": "*/*"}, auth=None)
        return {
            "url": url,
            "status": r.status_code,
            "server": (r.headers.get("server") or "").strip(),
            "powered_by": (r.headers.get("x-powered-by") or "").strip(),
            "title": _extract_title(r.text),
            "location": (r.headers.get("location") or ""),
            "body_headers": dict(r.headers),
        }
    except Exception:  # noqa: BLE001
        return None


def _extract_title(body: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "",
                  re.I | re.S)
    return m.group(1).strip()[:120] if m else None


def _classify(probe: Optional[dict]) -> Optional[dict]:
    if probe is None:
        return None
    server = probe.get("server") or ""
    powered = probe.get("powered_by") or ""
    title = probe.get("title") or ""
    headers = " ".join((server, powered)).strip().lower()
    body = " ".join((title, probe.get("location") or "")).lower()
    for backend, is_admin, header_re, body_re in _MARKERS:
        if any(re.search(p, headers, re.I) for p in header_re) or any(
                re.search(p, body, re.I) for p in body_re):
            return {"backend": backend, "is_admin": is_admin,
                    "title": title, "server": server,
                    "confidence": 0.9 if (header_re and body_re) else 0.7}
    return {"backend": "unknown", "is_admin": False,
            "title": title, "server": server, "confidence": 0.3}


@register
class HttpServiceFpSkill(Skill):
    """Fingerprint HTTP services listening on non-standard ports."""

    name = "http-service-fp"
    display_name = "HTTP Service Fingerprint (alt ports)"
    category = SkillCategory.NETWORK
    version = "1.0"

    requires_any: list[str] = [f"port_{p}_open" for p in ALT_PORTS]

    timeout_seconds = 60
    max_requests = len(ALT_PORTS)

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_extract_host(ctx)) and any(
            p in ctx.open_ports for p in ALT_PORTS)

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        if not host:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"alt_services": "no-target"}})
        ports = [p for p in ALT_PORTS if p in ctx.open_ports]
        if not ports:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"alt_services": "none-open"}})

        findings: list[RawFinding] = []
        services: List[dict] = []
        for port in ports:
            probe = _probe(host, port)
            if not probe:
                continue
            meta = _classify(probe)
            if meta["backend"] == "unknown":
                continue
            services.append({"port": port, **meta})

        for svc in services:
            url = f"http://{host}:{svc['port']}/"
            raw = {"port": svc["port"], "backend": svc["backend"],
                   "server": svc["server"], "title": svc["title"],
                   "confidence": svc["confidence"]}
            if svc["is_admin"]:
                findings.append(RawFinding(
                    scanner="skill:" + self.name,
                    scanner_template_id="admin-interface-exposed",
                    vulnerability_type="exposed_interface",
                    target=f"{host}:{svc['port']}", host=host,
                    severity="high",
                    url=url,
                    description=(
                        f"{svc['backend']} management/admin interface exposed "
                        f"on non-standard port {svc['port']}"),
                    raw=raw,
                ))
            findings.append(RawFinding(
                scanner="skill:" + self.name,
                scanner_template_id="http-service-fingerprint",
                vulnerability_type="reconnaissance",
                target=f"{host}:{svc['port']}", host=host,
                severity="info",
                url=url,
                description=(f"Non-standard HTTP port {svc['port']} runs "
                             f"{svc['backend']}"),
                raw=raw,
            ))

        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"alt_services": "clean"}})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "alt_services": [{"port": s["port"], "backend": s["backend"]}
                                 for s in services]}})
"""Reconnaissance pipeline — orchestrates DNS, live host check, and fingerprinting."""
from __future__ import annotations

from typing import Optional

from app.models.recon import Asset, ReconResult
from pipeline.recon.dns import resolve
from pipeline.recon.fingerprint import fingerprint
from pipeline.recon.live_hosts import check_live, extract_host, normalize_url
from pipeline.recon.osint import run_osint

DOMAIN_SEPARATORS = ("://", "/")


def domain_of(target: str) -> str:
    """Extract bare domain from a URL."""
    t = target.strip()
    for sep in DOMAIN_SEPARATORS:
        if sep in t:
            t = t.split(sep, 1)[1] if sep == "://" else t
    return t.split("/")[0].split(":")[0]


def _classify_asset(hostname: str, techs: list[str]) -> str:
    """Assign a coarse role to a host based on naming and technologies."""
    h = hostname.lower()
    if any(h.startswith(p) for p in ("api", "graphql")):
        return "api"
    if "db" in h or "mysql" in h or "postgres" in h or "redis" in h:
        return "database"
    if "mail" in h or "smtp" in h or "pop" in h:
        return "mail"
    if any(t in techs for t in ("wordpress", "django", "laravel", "nextjs", "express", "fastapi")):
        return "web"
    if any(h.startswith(p) for p in ("dev", "staging", "test")):
        return "dev"
    return "web"


def run_recon(target: str, persist: bool = False, db: Optional[object] = None) -> ReconResult:
    """Run the full reconnaissance pipeline for a target.

    Steps:
        1. Normalize URL and extract domain
        2. Live-host check (HTTP reachability + response metadata)
        3. Technology fingerprinting (from live check response)
        4. DNS resolution
        5. OSINT enrichment (WHOIS, CT, reverse-IP, historical URLs);
           results are attached to the primary Asset. Highly tolerant:
           any OSINT source failure never blocks recon.

    Args:
        target: URL or hostname to recon.
        persist: If True, save results to data/recon/recon.json.
        db: optional SQLAlchemy session. If provided, the recon result is
            persisted to the shared PostgreSQL database.

    Returns:
        ReconResult with all reconnaissance data.
    """
    url = normalize_url(target)
    host = extract_host(url)

    # 1. Live host check
    live = check_live(url)

    # 2. Fingerprint from live response
    fp = fingerprint(live.headers, live.body_sample)

    # 3. DNS resolution
    dns = resolve(host)

    # 4. OSINT enrichment (attached to primary asset)
    osint_result, _osint_findings = run_osint(host if host else target)

    # 5. Build primary asset
    primary = Asset(
        url=live.url,
        host=host,
        ip=dns.primary_ip,
        status_code=live.status_code,
        technologies=fp.technologies,
        https_supported=live.https_supported,
        role=_classify_asset(host, fp.technologies),
        is_primary=True,
        osint=osint_result.to_dict() if osint_result.sources or osint_result.errors else None,
    )

    result = ReconResult(
        target=target,
        dns=dns,
        live=live,
        fingerprint=fp,
        assets=[primary],
        primary_asset=primary,
        osint_findings=[f.to_dict() for f in _osint_findings],
        total_assets=1,
    )

    if persist:
        from app.core import storage
        storage.save("recon", result.to_dict())

    if db is not None:
        from app.db.persist import persist_recon
        try:
            persist_recon(db, result)
        except Exception:
            # DB write failure must not break the pipeline result.
            pass

    return result

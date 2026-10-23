"""T1213 — Data from Information Repositories.

With database access (or a confirmed application compromise) confirmed, this
technique enumerates the backend repository using the bounded ``sqlmap`` tool
(``--dbs``). Confirmation grants ``repository_data_access``; the
``credential_material`` capability is added only when the tool actually
recovered credentials.
"""
from __future__ import annotations

import time
from typing import Dict

from app.automation import register
from app.automation import adapters
from app.automation.base import AutomationContext, TechniqueResult, TechniqueScript, TechniqueStatus


def _tool_options(ctx: AutomationContext) -> Dict[str, str]:
    merged = ctx.merged_options()
    endpoint = str(merged.get("endpoint") or ctx.target)
    if not endpoint.startswith(("http://", "https://")):
        endpoint = ctx.target.rstrip("/") + "/" + endpoint.lstrip("/")
    options: Dict[str, str] = {
        "target": endpoint,
        "method": str(merged.get("http_method") or "GET").upper(),
    }
    if merged.get("parameter_name"):
        options["parameter"] = str(merged["parameter_name"])
    return options


@register
class RepositoryDataAccess(TechniqueScript):
    """Access data held in an information repository (MITRE T1213)."""

    technique_id = "T1213"
    name = "Data from Information Repositories"
    tactic = "Collection"
    description = (
        "Enumerate the backend database via sqlmap once database access is "
        "established, collecting repository data access evidence."
    )
    requires_any = ("possible_database_access", "application_compromise", "authenticated_session")
    # ``credential_material`` is granted dynamically only when the tool actually
    # returned credential rows; database enumeration alone does not imply it.
    provides = ("repository_data_access",)
    vuln_types = ("sql-injection", "sqli", "database_repository_access", "information-disclosure")
    allowed_options = ("endpoint", "http_method", "parameter_name")
    automatic_allowed = True

    def execute(self, ctx: AutomationContext) -> TechniqueResult:
        started = time.time()
        if not adapters.tool_available("sqlmap-exploit"):
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.BLOCKED,
                summary="sqlmap is not installed; repository access is unavailable.",
                error="missing_binary:sqlmap",
                duration_ms=int((time.time() - started) * 1000),
            )

        result = adapters.run_real_tool("sqlmap-exploit", _tool_options(ctx))
        artifact = adapters.write_artifact(
            ctx, "t1213_sqlmap.txt", getattr(result, "raw", "") or result.output
        )
        extra = getattr(result, "extra", {}) or {}
        databases = extra.get("databases", [])
        credentials = extra.get("credentials", [])
        provides = ("repository_data_access",)
        if credentials:
            provides = ("repository_data_access", "credential_material")
        evidence = {
            "tool": "sqlmap-exploit",
            "success": bool(result.success),
            "databases": databases,
            "credentials_recovered": len(credentials) if credentials else 0,
            "output": (result.output or "")[:2000],
        }
        artifacts = (artifact,) if artifact else ()
        if result.success and databases:
            return TechniqueResult(
                technique_id=self.technique_id,
                status=TechniqueStatus.CONFIRMED,
                summary=f"enumerated {len(databases)} database(s).",
                provides=provides,
                evidence=evidence,
                artifacts=artifacts,
                duration_ms=int((time.time() - started) * 1000),
            )
        return TechniqueResult(
            technique_id=self.technique_id,
            status=TechniqueStatus.INCONCLUSIVE,
            summary="repository data could not be enumerated.",
            evidence=evidence,
            artifacts=artifacts,
            duration_ms=int((time.time() - started) * 1000),
        )

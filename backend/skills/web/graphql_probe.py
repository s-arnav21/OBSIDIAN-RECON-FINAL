"""GraphQL Probe — introspection, batch bypass, and sensitive-field detection.

Runs when the recon/content stages indicate a GraphQL or API endpoint exists
(selector requires `graphql_found` or `api_found`). For each candidate
endpoint it:

  1. Introspection: posts the standard __schema introspection query. If the
     endpoint answers with a schema, an enabled-introspection HIGH finding is
     emitted (the single most common GraphQL misconfiguration).
  2. Batch bypass: posts an array payload `[{q}, {q}]`. Endpoints that accept
     batched queries bypass the single-query rate limits/AWScopes that protect
     many deployments, so this is surfaced INFO.
  3. Sensitive fields: when the schema is returned, walk its types/fields and
     flag names that look sensitive (password, token, secret, credit card,
     personal data) as INFO findings.

Candidates come from `discovered_paths` / `js_endpoints` that mention graphql,
plus common fallback mount points under the origin. Bounded: candidate count,
per-request timeout, and a cap on emitted sensitive-field findings.
Tools: nothing external (httpx).
"""
from __future__ import annotations

from typing import List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

MAX_CANDIDATES = 12
MAX_SENSITIVE_FIELDS = 25
PROBE_TIMEOUT = 10

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")

_INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { queryType { name } "
    "mutationType { name } subscriptionType { name } "
    "types { name kind fields { name } } } }"
)
_TRIVIAL_QUERY = "{ __typename }"

_FALLBACK_PATHS = ("/graphql", "/graphiql", "/api/graphql",
                   "/api/v1/graphql", "/v1/graphql", "/graphql.php")

_SENSITIVE_FIELD_HINTS = (
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "private_key", "access_key", "auth", "credential", "email",
    "phone", "ssn", "credit", "card", "iban", "swift", "grant",
    "client_secret", "authorization", "bearer", "cookie",
)


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _base(ctx: SkillContext) -> Optional[str]:
    host = _extract_host(ctx)
    if not host:
        return None
    scheme = (ctx.scheme or "https").lower()
    port = ctx.port or 0
    if port in (443, 8443):
        scheme = "https"
    elif port in (80, 8080):
        scheme = "http"
    for p in (443, 8443, 80, 8080):
        if p in ctx.open_ports:
            port = p
            scheme = "https" if p in (443, 8443) else "http"
            break
    netloc = host
    if port and not ((scheme == "http" and port == 80)
                     or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    return f"{scheme}://{netloc}"


def _client() -> httpx.Client:
    return httpx.Client(timeout=PROBE_TIMEOUT, follow_redirects=True,
                        headers={"User-Agent": USER_AGENT}, verify=False)


def _candidate_urls(ctx: SkillContext, base: str) -> list[str]:
    """Collect GraphQL candidate URLs (deduped, source order)."""
    cands: list[str] = []
    seen: set[str] = set()
    hint = False

    def add(url: str) -> None:
        if url and url not in seen:
            seen.add(url)
            cands.append(url)

    for p in (list(ctx.discovered_paths) + list(ctx.js_endpoints)):
        p = (p or "").strip()
        if not p:
            continue
        url = p if p.startswith(("http://", "https://")) else urljoin(base, p)
        low = url.lower()
        if "graphql" in low or "graphiql" in low:
            hint = True
            add(url.split("#")[0])
            # a discovered /graphiql page usually sits next to /graphql
            if "graphiql" in low:
                add(url.lower().replace("graphiql", "graphql").split("?")[0])
        elif "api" in low:
            hint = True

    # Fallback mount points are only probed when recon hinted at a GraphQL/API
    # surface (the selector's requires_any gates on exactly those tokens).
    if hint:
        for path in _FALLBACK_PATHS:
            add(urljoin(base, path))
    return cands[:MAX_CANDIDATES]


def _post(client: httpx.Client, url: str,
          payload) -> Optional[tuple[int, Optional[dict]]]:
    """POST a GraphQL payload (dict or list) to a candidate endpoint."""
    try:
        resp = client.post(url, json=payload, timeout=PROBE_TIMEOUT)
        try:
            data = resp.json()
        except Exception:  # noqa: BLE001 - non-JSON response
            data = None
        return resp.status_code, data
    except Exception:  # noqa: BLE001 - timeout/conn error
        return None


def _has_schema(data: Optional[dict]) -> bool:
    if not isinstance(data, dict):
        return False
    schema = data.get("data", {}).get("__schema")
    return isinstance(schema, dict) and bool(schema.get("types"))


def _batch_allowed(data: Optional[dict]) -> bool:
    """True when the endpoints answered a `[{q},{q}]` array with two results."""
    if not isinstance(data, list) or len(data) < 2:
        return False
    return sum(1 for it in data
               if isinstance(it, dict) and isinstance(it.get("data"), dict)) >= 2


def _sensitive_schema_fields(schema: dict) -> list[tuple[str, str]]:
    """[(type_name, field_name)] for schema fields whose names look sensitive."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for t in schema.get("types") or []:
        tname = t.get("name") or ""
        if tname.startswith("__") or tname.lower().startswith(("query", "mutation", "subscription")):
            continue
        for f in t.get("fields") or []:
            fname = f.get("name") or ""
            low = fname.lower()
            if any(hint in low for hint in _SENSITIVE_FIELD_HINTS):
                pair = (tname, fname)
                if pair not in seen:
                    seen.add(pair)
                    out.append(pair)
    return out[:MAX_SENSITIVE_FIELDS]


@register
class GraphqlProbeSkill(Skill):
    """Probe GraphQL endpoints for introspection/batch/sensitive fields."""

    name = "graphql-probe"
    display_name = "GraphQL Probe"
    category = SkillCategory.WEB
    version = "1.0"

    requires_any: list[str] = ["graphql_found", "api_found"]

    timeout_seconds = 60
    max_requests = 40

    def should_run(self, ctx: SkillContext) -> bool:
        base = _base(ctx)
        return bool(base) and bool(_candidate_urls(ctx, base))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"graphql_probe_skipped": True}})

        urls = _candidate_urls(ctx, base)
        findings: list[RawFinding] = []
        live_graphql: list[str] = []

        with _client() as client:
            for url in urls:
                result = _post(client, url, {"query": _INTROSPECTION_QUERY})
                if result is None:
                    continue
                status, data = result
                if _has_schema(data):
                    schema = data["data"]["__schema"]
                    live_graphql.append(url)
                    sensitive = _sensitive_schema_fields(schema)
                    raw = {
                        "endpoint": url,
                        "status": status,
                        "schema_types": len(schema.get("types") or []),
                        "sensitive_fields": sensitive,
                        "query_type": (schema.get("queryType") or {}).get("name"),
                        "mutation_type": (schema.get("mutationType") or {}).get("name"),
                    }
                    desc = (f"GraphQL introspection enabled at {url} "
                            f"({len(schema.get('types') or [])} types"
                            + (f", {len(sensitive)} sensitive field(s)" if sensitive else "")
                            + ")")
                    findings.append(RawFinding(
                        scanner="skill:" + self.name,
                        scanner_template_id="graphql-introspection-enabled",
                        vulnerability_type="misconfiguration",
                        target=base, host=base,
                        severity="high",
                        url=url,
                        description=desc,
                        raw=raw,
                    ))
                    for tname, fname in sensitive:
                        findings.append(RawFinding(
                            scanner="skill:" + self.name,
                            scanner_template_id="graphql-sensitive-field",
                            vulnerability_type="information_disclosure",
                            target=base, host=base,
                            severity="info",
                            url=url,
                            description=(
                                f"sensitive GraphQL field {tname}.{fname} exposed "
                                f"via introspection at {url}"),
                            raw={"type": tname, "field": fname,
                                 "endpoint": url},
                        ))
                else:
                    # introspection blocked -> try the batched-query bypass
                    batch = _post(client, url,
                                  [{"query": _TRIVIAL_QUERY},
                                   {"query": _TRIVIAL_QUERY}])
                    if batch is not None and _batch_allowed(batch[1]):
                        live_graphql.append(url)
                        findings.append(RawFinding(
                            scanner="skill:" + self.name,
                            scanner_template_id="graphql-batch-allowed",
                            vulnerability_type="misconfiguration",
                            target=base, host=base,
                            severity="info",
                            url=url,
                            description=(
                                f"GraphQL endpoint {url} accepts batched queries "
                                "(rate-limit/rate-limit bypass surface)"),
                            raw={"endpoint": url,
                                 "status": batch[0]},
                        ))

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "graphql_endpoints": live_graphql,
                "graphql_probed": urls,
            }})
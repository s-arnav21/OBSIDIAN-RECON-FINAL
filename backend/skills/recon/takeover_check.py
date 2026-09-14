"""Subdomain Takeover Check — dangling CNAME detection across cloud services.

A subdomain is *takeoverable* when it points via CNAME to a third-party
service (GitHub pages, S3 bucket, Heroku app, Azure, etc.) whose record no
longer exists — the provider releases the name, and an attacker can claim it
and serve content from the target's trusted subdomain.

This skill resolves each known subdomain's CNAME chain and:
  * flags any CNAME whose target hostname matches a known takeover-prone
    service fingerprint AND does not resolve (dangling = claimable),
  * flags CNAMEs pointing into one of those provider domains even if the
    fingerprint is not an exact release page (best effort — the follow-up
    content probing confirms the live claim).

The 20+ signatures below cover the most commonly abused providers.

Findings:
  - SUBDOMAIN_TAKEOVER_POSSIBLE (HIGH) — dangling CNAME to a cloud service
Tools: dnspython
"""
from __future__ import annotations

import socket
from urllib.parse import urlparse

from app.models.scanner import RawFinding
from skills.base import Skill, SkillCategory, SkillContext, SkillResult
from skills import register

TIMEOUT_SECONDS = 8

# Provider hostname signatures that are takeover-prone when dangling.
# (substring match against the CNAME target)
TAKEOVER_SIGNATURES = (
    "github.io",                # GitHub Pages
    "herokuapp.com",            # Heroku
    "herokussl.com",
    "s3.amazonaws.com",         # AWS S3 bucket
    "s3-website",               # AWS S3 website endpoint
    "amazonaws.com",
    "cloudapp.net",             # Azure CloudApp / classic
    "azurewebsites.net",        # Azure App Service
    "cloudfront.net",           # CloudFront (misconfigured)
    "fastly.net",               # Fastly
    "bitbucket.io",             # Bitbucket Pages
    "surge.sh",                 # Surge
    "netlify.app",              # Netlify
    "zendesk.com",              # Zendesk
    "helpjuice.com",
    "readme.io",                # Readme.io
    "gitlab.io",                # GitLab Pages
    "pantheon.io",              # Pantheon
    "tumblr.com",               # Tumblr
    "wordpress.com",            # WordPress.com
    "ghost.io",                 # Ghost
    "shopify.com",              # Shopify
    "shopifycdn.com",
    "strikingly.com",           # Strikingly
    "smugmug.com",
    "fly.dev",                  # Fly.io
    "vercel.app",               # Vercel
    "function.app",             # Azure Functions
    "trafficmanager.net",       # Azure Traffic Manager
    "static.app",               # static.app
    "launchrock.com",           # LaunchRock
    "myfreesites.net",          # free hosting (dangling-prone)
    "bytesuite.online",
    "servd.app",
    "weebly.com",               # Weebly
)


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except OSError:
            return False


def _extract_host(ctx: SkillContext) -> str:
    host = (ctx.host or "").strip().lower().rstrip(".")
    if host:
        return host
    parsed = urlparse(ctx.target_url)
    return (parsed.hostname or "").strip("[]").lower().rstrip(".")


def _cname_target(subdomain: str) -> str | None:
    """Return the CNAME target for a subdomain (None if none/failure)."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(subdomain, "CNAME", lifetime=TIMEOUT_SECONDS)
        return str(answers[0].target).rstrip(".").lower()
    except Exception:  # noqa: BLE001 - no CNAME / NXDOMAIN / resolution failure
        return None


def _resolves(host: str) -> bool:
    """True if a hostname resolves to at least one IP (dangling check)."""
    try:
        socket.getaddrinfo(host, None, socket.AF_INET)
        return True
    except OSError:
        return False


def _matches_signature(cname: str) -> str | None:
    """Return the first matching takeover signature, or None."""
    low = cname.lower()
    for sig in TAKEOVER_SIGNATURES:
        if sig in low:
            return sig
    return None


@register
class TakeoverCheckSkill(Skill):
    """Detect dangling CNAMEs that allow subdomain takeover."""

    name = "takeover-check"
    display_name = "Subdomain Takeover Check"
    category = SkillCategory.RECON
    version = "1.0"

    requires_all: list[str] = []
    requires_any: list[str] = ["subdomain_found"]

    timeout_seconds = 90
    max_requests = 32

    def should_run(self, ctx: SkillContext) -> bool:
        if not _extract_host(ctx):
            return False
        return bool(ctx.subdomains)

    def run(self, ctx: SkillContext) -> SkillResult:
        host = _extract_host(ctx)
        findings: list[RawFinding] = []
        checked: list[dict] = []

        for subdomain in ctx.subdomains:
            if not subdomain:
                continue
            cname = _cname_target(subdomain)
            if not cname:
                continue
            sig = _matches_signature(cname)
            checked.append({"subdomain": subdomain, "cname": cname,
                            "signature": sig})
            if sig and not _resolves(cname):
                findings.append(self._takeover(host, subdomain, cname, sig))
                break  # one confirmed high is enough per scan

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "takeover_checked": len(checked),
                "takeover_cnames": checked,
            }})

    def _takeover(self, host: str, subdomain: str,
                  cname: str, signature: str) -> RawFinding:
        return RawFinding(
            scanner="skill:" + self.name,
            scanner_template_id="subdomain-takeover-possible",
            vulnerability_type="subdomain-takeover",
            target=host, host=subdomain,
            severity="high",
            description=(
                f"Subdomain {subdomain} CNAMEs to {cname} "
                f"({signature}) which does not resolve — the third-party "
                f"service was released/expired and {subdomain} may be "
                f"claimable by an attacker"
            ),
            raw={
                "host": host,
                "subdomain": subdomain,
                "cname": cname,
                "signature": signature,
            },
        )
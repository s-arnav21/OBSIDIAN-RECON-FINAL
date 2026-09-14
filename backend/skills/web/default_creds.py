"""Default Credentials — try a curated set of well-known default username/
password pairs against login forms.

Huge swaths of exposed admin panels (Django, Adminer, Tomcat, WordPress,
routers, printers, …) ship with unchanged default credentials. This skill:

  1. Gathers login candidates — admin-ish paths already discovered plus a
     handful of conventional admin URLs (/admin, /login, /wp-login.php, …).
  2. GETs each candidate and only proceeds when it is actually a login form
     (a `<input type=password>` present), avoiding blind POST spam.
  3. POSTs each of ~22 default credential pairs using the form's real field
     names, and flags a pair as VALID when the reply reveals a successful
     authentication: a redirect (302/301/303/307), an issued session cookie,
     or a material page change with no login-error text.

A confirmed pair is a CRITICAL `default-credentials-valid` finding and the
successful pair is recorded on `osint` for immediate take-over/cleanup advice.

Only runs when an admin path was discovered or existing recon found a login
form (`requires_any: ["admin_path_found", "login_form_found"]`). httpx only.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from app.models.scanner import RawFinding
from skills import register
from skills.base import Skill, SkillCategory, SkillContext, SkillResult

PROBE_TIMEOUT = 10
_BODY_CAP = 8000
MAX_CANDIDATES = 6

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")

# (username, password) — common default/blankish admin pairs.
_DEFAULT_PAIRS: Tuple[Tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "admin1234"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "12345678"),
    ("admin", "1234"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("test", "test"),
    ("test", "password"),
    ("test", "test123"),
    ("guest", "guest"),
    ("user", "user"),
    ("user", "password"),
    ("tomcat", "tomcat"),
    ("admin", "admin@123"),
    ("admin", "welcome"),
)

_WP_PAIRS = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("administrator", "password"),
)

# Extra default pairs per detected technology.
_TECH_PAIRS = {
    "wordpress": _WP_PAIRS,
    "tomcat": (("admin", "admin"), ("tomcat", "tomcat"), ("manager", "s3cret")),
}

# Conventional admin endpoint paths probed when discovery found nothing.
_DEFAULT_ADMIN_PATHS = (
    "/admin", "/admin/login", "/administrator", "/manager",
    "/login", "/login.php", "/wp-login.php", "/user/login",
)

_LOGINISH_KEYWORDS = ("login", "signin", "sign-in", "auth", "admin",
                      "administrator", "wp-login", "user")

_PASSWORD_FIELD_RE = re.compile(
    r"""<input\b[^>]*?type\s*=\s*["']?password["']?[^>]*>""", re.I)
_INPUT_NAME_RE = re.compile(
    r"""<input\b[^>]*?\bname\s*=\s*["']([^"']+)["'][^>]*>""", re.I)
_FORM_TAG_RE = re.compile(r"""<form\b[^>]*>""", re.I)
_FORM_ACTION_RE = re.compile(r"""\baction\s*=\s*["']([^"']*)["']""", re.I)

_ERROR_RE = re.compile(
    r"(invalid|incorrect|wrong\s+(password|username|credentials)|"
    r"authentication failed|login failed|access denied|"
    r"invalidcredentials|try again|not recognized|no such user|"
    r"account (locked|disabled)|failed login|unrecognized|"
    r"username[^<>]{0,40}password|password[^<>]{0,40}invalid)", re.I)

_SESSION_COOKIE_BLACKLIST = {"cf_clearance"}


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


def _candidate_paths(base: str, ctx: SkillContext) -> List[str]:
    candidates: List[str] = []
    for p in ctx.discovered_paths:
        low = p.lower()
        if any(k in low for k in _LOGINISH_KEYWORDS):
            candidates.append(p)
    for p in _DEFAULT_ADMIN_PATHS:
        if p not in candidates:
            candidates.append(p)
    return candidates[:MAX_CANDIDATES]


def _login_url(base: str, path: str) -> str:
    if path.startswith(("http://", "https://")):
        return path
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _form_info(html: str) -> Optional[dict]:
    """Return form action/method and input names when HTML holds a password
    field; None otherwise."""
    if not _PASSWORD_FIELD_RE.search(html):
        return None
    names = [m.group(1) for m in _INPUT_NAME_RE.finditer(html)]
    if not names:
        return None
    m = _FORM_TAG_RE.search(html)
    action = ""
    if m:
        am = _FORM_ACTION_RE.search(m.group(0))
        if am:
            action = am.group(1)
    method = "POST"
    if m:
        mm = re.search(r"""method\s*=\s*["']([a-zA-Z]+)["']""", m.group(0),
                       re.I)
        if mm and mm.group(1).upper() == "GET":
            method = "GET"
    csrf = [n for n in names if re.search(r"csrf", n, re.I)]
    return {
        "action": action.strip(),
        "method": method,
        "names": names,
        "csrf_field": csrf[0] if csrf else None,
    }


def _pick_fields(form: dict) -> Tuple[str, str, Optional[str]]:
    """Pick username/password (and optional csrf) field names from the form."""
    names = form["names"]
    pwd = next((n for n in names
                if "pass" in n.lower() or "pwd" in n.lower() or "psw" in n.lower()),
               None)
    if pwd is None:
        pwd = names[-1] if names else "password"
    others = [n for n in names if n != pwd]
    user = next((n for n in others
                 if any(k in n.lower() for k in ("user", "login", "email",
                                                 "name", "id"))),
                others[0] if others else "username")
    return user, pwd, form["csrf_field"]


def _has_error(body: str) -> bool:
    return bool(_ERROR_RE.search(body))


def _session_cookie_issued(resp: httpx.Response) -> bool:
    for name in resp.cookies.keys():
        if name.lower() in _SESSION_COOKIE_BLACKLIST:
            continue
        return True
    return False


def _attempt(client: httpx.Client, url: str, form: dict,
             user: str, pwd: str, baseline: str) -> Tuple[bool, str]:
    """POST a credential pair. Returns (valid, signal)."""
    names = form["names"]
    u_field, p_field, csrf = _pick_fields(form)
    data = dict.fromkeys(names, "")
    data[u_field] = user
    data[p_field] = pwd
    if csrf and csrf in data:
        data[csrf] = "1"

    target = urljoin(url + "/", form["action"]) if form["action"] else url
    try:
        if form["method"] == "GET":
            resp = client.get(target, params=data, timeout=PROBE_TIMEOUT)
        else:
            resp = client.post(target, data=data, timeout=PROBE_TIMEOUT)
    except Exception:  # noqa: BLE001
        return False, ""

    body = (resp.text or "")[: _BODY_CAP]
    if resp.status_code in (301, 302, 303, 307, 308):
        return True, "redirect"
    if _session_cookie_issued(resp):
        if not _has_error(body):
            return True, "session-cookie"
        if len(body) - len(baseline) > 400:
            return True, "session-cookie+content-change"
    if _has_error(body):
        return False, "error"
    if len(body) > 50 and abs(len(body) - len(baseline)) > 400:
        return True, "content-change"
    return False, "no-change"


@register
class DefaultCredsSkill(Skill):
    """Try ~22 default credential pairs against discovered login forms."""

    name = "default-creds"
    display_name = "Default Credentials"
    category = SkillCategory.WEB
    version = "1.0"

    requires_any: list[str] = ["admin_path_found", "login_form_found"]

    timeout_seconds = 120
    max_requests = 160

    def should_run(self, ctx: SkillContext) -> bool:
        return bool(_base(ctx))

    def run(self, ctx: SkillContext) -> SkillResult:
        base = _base(ctx)
        if not base:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {"default_creds_scan": "no-target"}})

        techs = [t.lower() for t in (ctx.technologies or [])]
        pairs = list(_DEFAULT_PAIRS)
        for tech, extra in _TECH_PAIRS.items():
            if any(tech in t for t in techs):
                for p in extra:
                    if p not in pairs:
                        pairs.append(p)

        findings: list[RawFinding] = []
        valid_creds: list[dict] = []

        with _client() as client:
            for path in _candidate_paths(base, ctx):
                url = _login_url(base, path)
                try:
                    resp = client.get(url, timeout=PROBE_TIMEOUT)
                    baseline = (resp.text or "")
                except Exception:  # noqa: BLE001
                    continue
                form = _form_info(baseline)
                if form is None:
                    continue
                for user, pwd in pairs:
                    ok, signal = _attempt(client, url, form, user, pwd,
                                          baseline)
                    if not ok:
                        continue
                    valid_creds.append({
                        "url": url, "username": user, "password": pwd,
                        "signal": signal, "form_action": form["action"],
                    })
                    findings.append(RawFinding(
                        scanner="skill:" + self.name,
                        scanner_template_id="default-credentials-valid",
                        vulnerability_type="weak_credentials",
                        target=base, host=base,
                        severity="critical",
                        url=url,
                        description=(
                            f"valid default credentials on {url}: "
                            f"{user} / {pwd} (signal: {signal})"),
                        raw={
                            "username": user, "password": pwd,
                            "url": url, "signal": signal,
                            "form_action": form["action"],
                        },
                    ))
                    break  # one valid pair per login form is enough

        if not findings:
            return SkillResult(
                skill_name=self.name, success=True, findings=[],
                context_updates={"osint": {
                    "default_creds_valid": False,
                    "default_creds_scan": "clear"}})

        return SkillResult(
            skill_name=self.name, success=True, findings=findings,
            context_updates={"osint": {
                "default_creds_valid": True,
                "default_cred_pairs": valid_creds,
                "default_creds_scan": "valid-credentials"}})
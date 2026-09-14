"""Technology fingerprinting from HTTP headers and HTML body."""
import re

from app.models.recon import FingerprintResult

TECH_SIGNATURES = [
    (re.compile(r"\bnginx\b", re.I), "nginx", "server"),
    (re.compile(r"\bapache\b", re.I), "apache", "server"),
    (re.compile(r"cloudflare", re.I), "cloudflare", "server"),
    (re.compile(r"\biis\b", re.I), "iis", "server"),
    (re.compile(r"wp-content|wordpress", re.I), "wordpress", "cms"),
    (re.compile(r"laravel", re.I), "laravel", "framework"),
    (re.compile(r"\bdjango\b", re.I), "django", "framework"),
    (re.compile(r"express", re.I), "express", "framework"),
    (re.compile(r"\breact\b", re.I), "react", "frontend"),
    (re.compile(r"next\.js|__next", re.I), "nextjs", "frontend"),
    (re.compile(r"phpsessid|\bphp\b", re.I), "php", "language"),
    (re.compile(r"asp\.net|aspx", re.I), "asp.net", "framework"),
    (re.compile(r"java|jsessionid", re.I), "java", "language"),
    (re.compile(r"rails|ruby", re.I), "rails", "framework"),
    (re.compile(r"nuxt", re.I), "nuxt", "frontend"),
    (re.compile(r"fastapi", re.I), "fastapi", "framework"),
    (re.compile(r"uvicorn", re.I), "uvicorn", "server"),
]


def fingerprint(headers: dict, body: str = "") -> FingerprintResult:
    """Detect technologies from HTTP response headers and body content."""
    raw = " ".join([
        headers.get("server", ""),
        headers.get("x-powered-by", ""),
        headers.get("via", ""),
        body or "",
    ])

    detected = []
    categories = {}
    raw_matches = []

    for pattern, tech, category in TECH_SIGNATURES:
        if pattern.search(raw) and tech not in detected:
            detected.append(tech)
            categories[tech] = category
            raw_matches.append({"pattern": pattern.pattern, "tech": tech, "category": category})

    return FingerprintResult(
        technologies=sorted(detected),
        categories=categories,
        raw_matches=raw_matches,
    )

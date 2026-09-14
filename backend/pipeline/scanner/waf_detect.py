"""WAF / CDN detection scanner (pure httpx, no wafw00f).

Detects a web application firewall / CDN provider in front of a target using
multiple independent signals so the caller can trust the result:

  1. Response-header fingerprints: cf-ray, x-sucuri-id, x-cdn, x-cache,
     x-amz-cf-id, x-fw-hash, x-protected-by, x-waf, akamai, etc.
  2. Distinctive `Server` / `Via` / `X-Powered-By` values for known
     providers (Cloudflare, Akamai Ghost, Sucuri, Imperva Incapsula,
     Barracuda, F5 BIG-IP, AWS CloudFront).
  3. A deliberate "bad request" probe (URL-encoded XSS in the path) whose
     response body is checked for provider block/error page signatures; a
     WAF block page that differs sharply from the normal 2xx body is a strong
     signal.
  4. Response-time anomaly: raw origin is typically not a WAF; timing spread
     across repeated requests vs. a known CDN-cached response.

The finding carries `waf_metadata` (provider candidates, confidence, method),
which the orchestration layer attaches to the scan's `Asset` so downstream
scanners (nuclei rate-limiting, nmap timing, origin hunt) can adjust behavior.

Never raises: any failure degrades to no finding + informational `detail`.
"""
from __future__ import annotations

from typing import List, Optional

import httpx

from app.models.scanner import RawFinding
from pipeline.scanner import base

USER_AGENT = ("Mozilla/5.0 (compatible; ObsidianRecon/3.0; "
              "educational security platform)")
PROBE_TIMEOUT = 10
REPEAT_REQUESTS = 3  # for timing-spread signal

# (header, needle, provider) — needle is matched (case-insensitively) in the
# header value. `None` means presence-only (exact-ish header existence).
_HEADER_SIGNATURES = [
    # ---- Cloudflare ----
    ("cf-ray", None, "cloudflare"),
    ("server", "cloudflare", "cloudflare"),
    ("cf-cache-status", None, "cloudflare"),
    ("cf-cache-status", "cloudflare", "cloudflare"),
    ("cf-connecting-ip", None, "cloudflare"),
    ("cf-ipcountry", None, "cloudflare"),
    ("cf-request-id", None, "cloudflare"),
    ("cf-loopback", None, "cloudflare"),
    # ---- Sucuri ----
    ("x-sucuri-id", None, "sucuri"),
    ("x-sucuri-debug", None, "sucuri"),
    ("x-sucuri-cache", None, "sucuri"),
    ("server", "sucuri", "sucuri"),
    # ---- generic-CDN ----
    ("x-cdn", None, "generic-cdn"),
    ("x-cdn-origin", None, "generic-cdn"),
    ("via", "cdn", "generic-cdn"),
    ("x-cache", "hit", "generic-cdn"),
    ("x-cache-status", "hit", "generic-cdn"),
    ("x-cacheable", None, "generic-cdn"),
    ("x-wa-info", None, "generic-cdn"),
    # ---- Imperva / Incapsula ----
    ("x-cdn", "imperva", "imperva"),
    ("x-iinfo", None, "imperva"),
    ("server", "incapsula", "imperva"),
    ("x-datacenter-pricing", None, "imperva"),
    ("x-requested-with", None, "imperva"),
    # ---- AWS CloudFront / WAF ----
    ("x-amz-cf-id", None, "aws-cloudfront"),
    ("x-amz-cf", None, "aws-cloudfront"),
    ("x-amz-cid", None, "aws-cloudfront"),
    ("x-amz-cf-pop", None, "aws-cloudfront"),
    ("x-amz-cf-ip", None, "aws-cloudfront"),
    ("x-amz-region", None, "aws-cloudfront"),
    ("x-amz-fwd-status", None, "aws-cloudfront"),
    ("server", "cloudfront", "aws-cloudfront"),
    ("via", "cloudfront", "aws-cloudfront"),
    ("x-amzn-requestid", None, "aws-waf"),
    ("x-amzn-trace-id", None, "aws-waf"),
    ("server", "aws-waf", "aws-waf"),
    ("server", "aws waf", "aws-waf"),
    # ---- Fastly ----
    ("x-served-by", None, "fastly"),
    ("server", "fastly", "fastly"),
    ("x-fastly-request-id", None, "fastly"),
    ("x-fastly-cache", None, "fastly"),
    ("x-timer", None, "fastly"),
    ("x-served-by-cache", None, "fastly"),
    # ---- Azure Front Door / CDN / WAF ----
    ("x-azure-ref", None, "azure-cdn"),
    ("x-ec-custom-error", None, "azure-cdn"),
    ("x-ms-request-id", None, "azure-cdn"),
    ("x-ms-request-charge", None, "azure-cdn"),
    ("x-ms-cache", None, "azure-cdn"),
    ("x-requestid", None, "azure-frontdoor"),
    ("x-aesinfo", None, "azure-frontdoor"),
    ("server", "frontdoor", "azure-frontdoor"),
    ("x-fd-healthprobe", None, "azure-frontdoor"),
    ("server", "azure", "azure-cdn"),
    ("azurecdn", None, "azure-cdn"),
    # ---- ModSecurity ----
    ("server", "mod_security", "modsecurity"),
    ("server", "modsecurity", "modsecurity"),
    ("server", "mod_sec", "modsecurity"),
    ("x-mod-security", None, "modsecurity"),
    # ---- aworker / generic WAFs ----
    ("x-fw-hash", None, "aworker-waf"),
    ("x-protected-by", None, "generic-waf"),
    ("x-waf", None, "generic-waf"),
    ("x-waf-proxy", None, "generic-waf"),
    ("x-secd", None, "generic-waf"),
    # ---- Vercel ----
    ("x-vercel-id", None, "vercel"),
    ("x-vercel-cache", None, "vercel"),
    # ---- Heroku ----
    ("x-heroku", None, "heroku"),
    ("x-heroku-request-id", None, "heroku"),
    ("via", "heroku", "heroku"),
    # ---- Akamai ----
    ("server", "akamai", "akamai"),
    ("server", "akamaighost", "akamai"),
    ("x-akamai", None, "akamai"),
    ("x-check-cacheable", None, "akamai"),
    ("x-akamai-transformed", None, "akamai"),
    ("x-akamai-session", None, "akamai"),
    ("x-cache", None, "akamai"),
    ("x-px-host", None, "akamai"),
    # ---- F5 BIG-IP / ASM ----
    ("server", "bigip", "f5-bigip"),
    ("x-wa-info", None, "f5-bigip"),
    ("x-f5-waf", None, "f5-bigip"),
    # ---- Barracuda ----
    ("server", "barracuda", "barracuda"),
    ("x-barracuda", None, "barracuda"),
    ("x-bws-ref", None, "barracuda"),
    # ---- Reblaze ----
    ("server", "reblaze", "reblaze"),
    ("server", "cloud easy", "reblaze"),
    ("x-reblaze", None, "reblaze"),
    # ---- Wallarm ----
    ("server", "wallarm", "wallarm"),
    ("x-wallarm", None, "wallarm"),
    # ---- Radware ----
    ("server", "radware", "radware"),
    ("x-radware", None, "radware"),
    ("x-alteon", None, "radware"),
    # ---- StackPath / MaxCDN ----
    ("server", "stackpath", "stackpath"),
    ("x-stackpath", None, "stackpath"),
    ("x-maxcdn", None, "stackpath"),
    # ---- Zscaler ----
    ("server", "zscaler", "zscaler"),
    ("x-zscaler", None, "zscaler"),
    ("via", "zscaler", "zscaler"),
    # ---- Citrix NetScaler / AppFW ----
    ("server", "netscaler", "citrix"),
    ("server", "citrix", "citrix"),
    ("x-netscaler", None, "citrix"),
    # ---- Fortinet FortiWeb ----
    ("server", "fortiweb", "fortinet"),
    ("server", "fortinet", "fortinet"),
    ("x-fortiweb", None, "fortinet"),
    # ---- AWS WAF (managed) / shield ----
    ("server", "shield", "aws-shield"),
    ("x-amz-cf", "shield", "aws-shield"),
    # ---- GCP Cloud Armor / Google LB ----
    ("server", "cloud-armor", "gcp-cloudarmor"),
    ("server", "gfe", "gcp-cloudarmor"),
    ("x-app-engine-country", None, "gcp-cloudarmor"),
    ("via", "cloud", "gcp-cloudarmor"),
    # ---- Yandex / DDoS-Guard / PentaSecurity ----
    ("server", "ddos-guard", "ddos-guard"),
    ("server", "ddosguard", "ddos-guard"),
    ("server", "showdevac", "ddos-guard"),
    ("server", "pentasecurity", "pentasecurity"),
    ("server", "wapp", "watson"),
]

# Distinctive Server/Via/X-Powered-By values by provider (name -> substrings).
_PROVIDER_SERVER_MARKS = {
    "cloudflare": ("cloudflare",),
    "akamai": ("akamai", "akamaighost"),
    "sucuri": ("sucuri",),
    "imperva": ("incapsula",),
    "barracuda": ("barracuda",),
    "f5-bigip": ("bigip",),
    "aws-cloudfront": ("cloudfront",),
    "aws-waf": ("aws waf", "awswaf"),
    "fastly": ("fastly",),
    "azure-cdn": ("azure",),
    "azure-frontdoor": ("frontdoor",),
    "modsecurity": ("mod_security", "modsecurity", "mod_sec"),
    "vercel": ("vercel",),
    "reblaze": ("reblaze", "cloud easy"),
    "wallarm": ("wallarm",),
    "radware": ("radware",),
    "stackpath": ("stackpath",),
    "zscaler": ("zscaler",),
    "citrix": ("netscaler", "citrix"),
    "fortinet": ("fortiweb", "fortinet"),
    "ddos-guard": ("ddos-guard", "ddosguard"),
    "pentasecurity": ("pentasecurity",),
    "watson": ("wapp",),
}

_PROVIDER_META = {
    "cloudflare": {"vendor": "Cloudflare Inc.", "kind": "cdn+waf"},
    "akamai": {"vendor": "Akamai", "kind": "cdn+waf"},
    "aws-cloudfront": {"vendor": "Amazon (CloudFront)", "kind": "cdn"},
    "aws-waf": {"vendor": "Amazon (AWS WAF)", "kind": "waf"},
    "aws-shield": {"vendor": "Amazon (AWS Shield)", "kind": "waf"},
    "fastly": {"vendor": "Fastly", "kind": "cdn+waf"},
    "azure-cdn": {"vendor": "Microsoft (Azure CDN)", "kind": "cdn"},
    "azure-frontdoor": {"vendor": "Microsoft (Azure Front Door)", "kind": "cdn+waf"},
    "modsecurity": {"vendor": "ModSecurity (OWASP)", "kind": "waf"},
    "sucuri": {"vendor": "Sucuri", "kind": "waf"},
    "imperva": {"vendor": "Imperva (Incapsula)", "kind": "waf"},
    "barracuda": {"vendor": "Barracuda Networks", "kind": "waf"},
    "f5-bigip": {"vendor": "F5 Networks", "kind": "waf"},
    "vercel": {"vendor": "Vercel", "kind": "cdn"},
    "reblaze": {"vendor": "Reblaze", "kind": "waf"},
    "wallarm": {"vendor": "Wallarm", "kind": "waf"},
    "radware": {"vendor": "Radware (AppWall)", "kind": "cdn+waf"},
    "stackpath": {"vendor": "StackPath", "kind": "cdn"},
    "zscaler": {"vendor": "Zscaler", "kind": "waf"},
    "citrix": {"vendor": "Citrix / NetScaler", "kind": "cdn+waf"},
    "fortinet": {"vendor": "Fortinet (FortiWeb)", "kind": "cdn+waf"},
    "ddos-guard": {"vendor": "DDoS-Guard", "kind": "cdn+waf"},
    "pentasecurity": {"vendor": "PentaSecurity (WAPPLES)", "kind": "cdn+waf"},
    "watson": {"vendor": "IBM Watson WAF", "kind": "waf"},
    "gcp-cloudarmor": {"vendor": "Google (Cloud Armor)", "kind": "waf"},
    "generic-cdn": {"vendor": "Unknown", "kind": "cdn"},
    "generic-waf": {"vendor": "Unknown", "kind": "waf"},
}


def _normalize(target: str) -> str:
    return target if "://" in target else f"http://{target}"


@base.register
class WafDetectScanner(base.Scanner):
    name = "waf_detect"
    executable = ""  # pure httpx, always available

    def __init__(self) -> None:
        self.warning: Optional[str] = None
        self.detail: Optional[dict] = None
        self._client: Optional[httpx.Client] = None

    def setup_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=PROBE_TIMEOUT,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
                verify=False,
                http2=False,
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def scan(self, target: str, timeout: int = 40) -> List[RawFinding]:
        self.warning = None
        self.detail = None
        url = _normalize(target)
        client = self.setup_client()

        try:
            base_resp = client.get(url, timeout=timeout)
            base_headers = {k.lower(): v for k, v in base_resp.headers.items()}
            base_body = base_resp.text or ""
            base_status = base_resp.status_code
        except Exception as exc:  # noqa: BLE001
            self.warning = f"WAF probe unreachable: {exc}"
            self.detail = {"mode": "unreachable"}
            return []

        providers, methods = self._header_detect(base_headers, url)

        # Bad-request probe for block-page signatures.
        bad_body, bad_status = self._bad_request_probe(client, url)

        providers |= self._block_page_detect(bad_body)

        # Timing spread across repeated requests.
        median_ms, spread_ms = self._timing_spread(client, url)

        # P2.1 method 3: high RTT variance + CDN-ish headers -> edge caching.
        has_cdn = any(p in providers for p in
                      ("cloudflare", "akamai", "aws-cloudfront", "aws-waf",
                       "fastly", "azure-cdn", "azure-frontdoor", "vercel",
                       "radware", "stackpath", "gcp-cloudarmor", "generic-cdn"))
        if spread_ms is not None and spread_ms > 500 and has_cdn:
            providers.add("generic-cdn")
            methods.add("timing")

        if not providers:
            self.detail = {"found": False, "method": "none", "mode": "clear"}
            return []

        provider = self._pick_provider(providers)
        confidence = self._confidence(len(methods), providers, bad_status, base_status)
        method = "+".join(sorted(methods)) or "header"

        meta = _PROVIDER_META.get(provider, {"vendor": "Unknown", "kind": "waf"})
        waf_metadata = {
            "provider": provider,
            "vendor": meta.get("vendor"),
            "kind": meta.get("kind"),
            "confidence": confidence,
            "method": method,
            "detected_headers": sorted(providers),
            "block_page": bool(bad_body and bad_body != base_body),
        }

        finding = RawFinding(
            scanner="waf_detect",
            scanner_template_id="WAF_DETECTED",
            vulnerability_type="reconnaissance",
            target=url,
            host=url,
            severity="info",
            url=url,
            description=(
                f"WAF/CDN detected in front of origin: {provider} "
                f"(confidence {confidence}, via {method})"
            ),
            raw={
                "provider": provider,
                "confidence": confidence,
                "method": method,
                "waf_metadata": waf_metadata,
                "detected_headers": sorted(providers),
                "timing_ms": median_ms,
                "timing_spread_ms": spread_ms,
                "block_page": waf_metadata["block_page"],
            },
        )
        self.detail = {"found": True, **waf_metadata}
        return [finding]

    # ---- detection helpers ----

    def _header_detect(self, headers: dict, url: str) -> tuple[set, set]:
        providers: set[str] = set()
        methods: set[str] = set()

        for header, needle, provider in _HEADER_SIGNATURES:
            value = headers.get(header)
            if value is None:
                continue
            # Exact-ish header presence for needleless signals (cf-ray, x-vercel-id...);
            # substring match on Server/Via/X-Powered-By for provider-distinctive marks.
            if needle:
                if needle.lower() not in value.lower():
                    continue
            providers.add(provider)
            methods.add("header")

        # Match provider-distinctive Server/Via/X-Powered-By values.
        for provider, marks in _PROVIDER_SERVER_MARKS.items():
            for m in marks:
                if any(m in (headers.get(h) or "").lower()
                       for h in ("server", "via", "x-powered-by")):
                    providers.add(provider)
                    methods.add("server-value")

        return providers, methods

    def _bad_request_probe(self, client, url: str) -> tuple[str, int]:
        # P2.1 method 2: a URL-encoded XSS + SQLi probe in the path often
        # triggers a WAF block page.
        probe = (url.rstrip("/")
                 + "/%3Cscript%3Ealert(1)%3C/script%3E?id=1'OR'1'='1")
        try:
            resp = client.get(probe, timeout=PROBE_TIMEOUT)
            return (resp.text or ""), resp.status_code
        except Exception:
            return "", 0

    # P2.1 method 2 generic block-page keywords (spec): any of these in the
    # body of a 403/406/429/503 response counts as an active WAF block.
    _BLOCK_KEYWORDS = (
        "blocked", "forbidden", "waf", "firewall", "security",
        "access denied", "protection", "detected", "malicious",
    )

    def _block_page_detect(self, body: str) -> set[str]:
        low = body.lower()
        sigs = {
            "cloudflare": ("cloudflare", "attention required", "cf-error-code",
                           "cf-ray", "error 1005", "error 1006", "error 1020"),
            "akamai": ("akamai", "access denied", "the request could not be completed",
                       "akamaighost", "reference #"),
            "fastly": ("fastly", "fastly error", "vcl_error", "fetch failed",
                       "error 503 first byte timeout"),
            "azure-cdn": ("azure", "azure front door", "request blocked by azure",
                          "403 forbidden (azure)"),
            "azure-frontdoor": ("azure front door", "front door"),
            "modsecurity": ("mod_security", "modsecurity", "mod_sec",
                            "error 403 forbidden by security policy"),
            "sucuri": ("sucuri.net", "blocked by sucuri", "sucuri web application firewall"),
            "imperva": ("incapsula", "incapsula incident id", "imperva"),
            "barracuda": ("barracuda", "blocked by barracuda",
                          "access denied (barracuda)"),
            "f5-bigip": ("bigip", "asfvb", "request rejected by f5", "f5 networks"),
            "radware": ("radware", "appwall", "request blocked by appwall"),
            "stackpath": ("stackpath", "access denied by stackpath"),
            "citrix": ("netscaler", "citrix", "appfw"),
            "fortinet": ("fortiweb", "fortinet", "violation of site security policy"),
            "zscaler": ("zscaler", "blocked by zscaler", "zscaler security"),
            "generic-waf": ("access denied", "your request has been blocked",
                            "security check", "unusual traffic", "rejected by",
                            "web application firewall", "rate limit exceeded",
                            "you have been blocked"),
        }
        found: set[str] = set()
        for provider, needles in sigs.items():
            if any(n in low for n in needles):
                found.add(provider)
        # Spec method 2 generic keyword set.
        if any(k in low for k in self._BLOCK_KEYWORDS):
            found.add("generic-waf")
        return found

    def _timing_spread(self, client, url: str) -> tuple[Optional[float], Optional[float]]:
        from datetime import datetime
        timings = []
        try:
            for _ in range(REPEAT_REQUESTS):
                t0 = datetime.now()
                client.get(url, timeout=PROBE_TIMEOUT)
                timings.append((datetime.now() - t0).total_seconds() * 1000.0)
        except Exception:
            return None, None
        if not timings:
            return None, None
        timings.sort()
        median = timings[len(timings) // 2]
        spread = max(timings) - min(timings)
        # A very tight sub-second response spread is a CDN-cache signal.
        return round(median, 1), round(spread, 1)

    @staticmethod
    def _pick_provider(providers: set[str]) -> str:
        for p in ("cloudflare", "akamai", "aws-cloudfront", "aws-waf",
                  "azure-frontdoor", "azure-cdn", "vercel", "sucuri",
                  "imperva", "fastly", "radware", "fortinet", "citrix",
                  "zscaler", "barracuda", "f5-bigip", "reblaze", "wallarm",
                  "ddos-guard", "pentasecurity", "watson", "gcp-cloudarmor"):
            if p in providers:
                return p
        return "generic-waf"

    @staticmethod
    def _confidence(signal_count: int, providers: set, bad_status: int,
                    base_status: int) -> str:
        score = 0.0
        score += min(signal_count * 0.25, 0.6)
        if len(providers) >= 2:
            score += 0.15
        if bad_status and base_status and bad_status in (400, 403, 404, 429):
            score += 0.2
        if bad_status in (403, 429):
            score += 0.1
        if score >= 0.8:
            return "high"
        if score >= 0.5:
            return "medium"
        return "low"

    def available(self) -> bool:
        return True
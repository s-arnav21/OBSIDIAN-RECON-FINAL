"""Live host detection — probe target over HTTP(S) to confirm reachability."""
import time
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3

from app.models.recon import LiveHostResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def normalize_url(target: str) -> str:
    """Ensure target is a full http(s) URL. Bare domains get https://."""
    if isinstance(target, str) and "://" not in target:
        return f"https://{target}"
    return target


def extract_host(url: str) -> str:
    """Extract hostname from a URL."""
    return urlparse(url).hostname or url


def check_live(target: str, timeout: int = 10) -> LiveHostResult:
    """Probe a URL for liveness and return a normalized LiveHostResult."""
    url = normalize_url(target)
    host = extract_host(url)
    start = time.monotonic()

    try:
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return LiveHostResult(
            url=url,
            host=host,
            status_code=resp.status_code,
            headers=headers,
            body_sample=resp.text[:20000],
            https_supported=True,
            response_time_ms=elapsed_ms,
            server=headers.get("server"),
            x_powered_by=headers.get("x-powered-by"),
            reachable=True,
        )
    except requests.exceptions.SSLError:
        http_url = url.replace("https://", "http://", 1)
        try:
            start = time.monotonic()
            resp = requests.get(http_url, timeout=timeout, allow_redirects=True)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return LiveHostResult(
                url=http_url,
                host=host,
                status_code=resp.status_code,
                headers=headers,
                body_sample=resp.text[:20000],
                https_supported=False,
                response_time_ms=elapsed_ms,
                server=headers.get("server"),
                x_powered_by=headers.get("x-powered-by"),
                reachable=True,
            )
        except requests.RequestException:
            pass
    except requests.RequestException:
        pass

    elapsed_ms = int((time.monotonic() - start) * 1000)
    return LiveHostResult(
        url=url,
        host=host,
        https_supported=False,
        response_time_ms=elapsed_ms,
        reachable=False,
    )

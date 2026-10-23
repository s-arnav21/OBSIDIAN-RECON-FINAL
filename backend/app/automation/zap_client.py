"""OWASP ZAP REST adapter.

A thin, fail-soft client for a *running* ZAP instance, controlled through its
JSON API (no extra dependency — plain HTTP). It gives the agent a programmable
web-testing backend: spider, active scan, and alert retrieval. Like every other
integration here it only *reports* what the scanner observed; ZAP alerts are
candidates, not proof of exploitation.

A ZAP client is created only when a base URL is configured (``ZAP_BASE_URL``).
Everything is bounded by a request timeout and never raises to the caller for
transport errors — callers get an empty/structured result instead.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

_DEFAULT_TIMEOUT = 15


class ZapError(RuntimeError):
    """Raised only for programmer errors (e.g. malformed call)."""


def _settings():
    try:
        from app.core.config import settings

        return settings
    except Exception:  # noqa: BLE001
        return None


def configured(settings: Any = None) -> bool:
    """Return True when a ZAP base URL is configured."""
    settings = settings or _settings()
    return bool(getattr(settings, "ZAP_BASE_URL", ""))


def from_settings(settings: Any = None) -> Optional["ZapClient"]:
    """Build a client from settings, or None when ZAP is not configured."""
    settings = settings or _settings()
    if not settings or not getattr(settings, "ZAP_BASE_URL", ""):
        return None
    return ZapClient(
        settings.ZAP_BASE_URL,
        api_key=getattr(settings, "ZAP_API_KEY", "") or None,
        timeout=int(getattr(settings, "ZAP_TIMEOUT", _DEFAULT_TIMEOUT) or _DEFAULT_TIMEOUT),
    )


class ZapClient:
    def __init__(
        self,
        base_url: str,
        *,
        api_key: Optional[str] = None,
        http_session: Any = None,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = str(base_url).rstrip("/")
        self._api_key = api_key
        self._session = http_session
        self._timeout = max(1, int(timeout))

    # -- plumbing ------------------------------------------------------------
    def _http(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session

    def _get(self, component: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        query = dict(params or {})
        if self._api_key:
            query["apikey"] = self._api_key
        url = f"{self.base_url}/JSON/{component}/"
        try:
            response = self._http().get(url, params=query, timeout=self._timeout)
            return response.json()
        except Exception:  # noqa: BLE001 — fail-soft
            return {}

    # -- read ----------------------------------------------------------------
    def version(self) -> Optional[str]:
        data = self._get("core/view/version")
        return data.get("version") if isinstance(data, dict) else None

    def alerts(self, base_url: str) -> List[Dict[str, Any]]:
        data = self._get("core/view/alerts", {"baseurl": base_url})
        alerts = data.get("alerts") if isinstance(data, dict) else None
        return list(alerts or [])

    # -- scan control --------------------------------------------------------
    def spider(self, url: str) -> Optional[int]:
        data = self._get("spider/action/scan", {"url": url})
        scan_id = data.get("scan") if isinstance(data, dict) else None
        try:
            return int(scan_id)
        except (TypeError, ValueError):
            return None

    def spider_status(self, scan_id: int) -> Optional[int]:
        data = self._get("spider/view/status", {"scanId": scan_id})
        return _as_int(data.get("status") if isinstance(data, dict) else None)

    def active_scan(self, url: str) -> Optional[int]:
        data = self._get("ascan/action/scan", {"url": url})
        scan_id = data.get("scan") if isinstance(data, dict) else None
        try:
            return int(scan_id)
        except (TypeError, ValueError):
            return None

    def active_scan_status(self, scan_id: int) -> Optional[int]:
        data = self._get("ascan/view/status", {"scanId": scan_id})
        return _as_int(data.get("status") if isinstance(data, dict) else None)

    def wait(self, status_fn, scan_id: int, *, timeout: int = 300, interval: int = 2) -> bool:
        """Poll a status function until it reports 100 or the budget expires."""
        import time

        deadline = time.monotonic() + max(1, timeout)
        while time.monotonic() < deadline:
            percent = status_fn(scan_id)
            if percent is not None and percent >= 100:
                return True
            time.sleep(max(1, interval))
        return False


def _as_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


__all__ = ["ZapClient", "ZapError", "configured", "from_settings"]

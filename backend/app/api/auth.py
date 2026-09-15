"""API key authentication for the API routers.

Authentication is opt-in: when ``API_AUTH_TOKEN`` is empty (default) every API
route works as before so local development stays frictionless. When an operator
sets ``API_AUTH_TOKEN`` in .env, every router it is applied to requires
``X-API-Key: <token>`` and returns 401 otherwise. Comparisons are constant-time
to avoid leaking the token through timing.
"""
from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

from app.core.config import settings


def require_api_key(request: Request) -> None:
    """Reject anonymous requests once an API key is configured."""
    expected = settings.API_AUTH_TOKEN.strip()
    if not expected:
        return
    candidate = request.headers.get("x-api-key", "").strip()
    if not candidate or not hmac.compare_digest(candidate, expected):
        raise HTTPException(
            status_code=401,
            detail="a valid X-API-Key header is required for this endpoint",
        )
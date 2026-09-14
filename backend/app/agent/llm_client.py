"""Bounded OpenAI-compatible chat client for the agent planner."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from typing import Any, Dict, Mapping, Optional, Sequence
from urllib.parse import urlsplit

import httpx


AGENT_LLM_BASE_URL_ENV = "AGENT_LLM_BASE_URL"
AGENT_LLM_API_KEY_ENV = "AGENT_LLM_API_KEY"
AGENT_LLM_MODEL_ENV = "AGENT_LLM_MODEL"
AGENT_LLM_TIMEOUT_ENV = "AGENT_LLM_TIMEOUT"

DEFAULT_LLM_TIMEOUT_SECONDS = 15.0
MAX_LLM_TIMEOUT_SECONDS = 600.0
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024
ABSOLUTE_MAX_RESPONSE_BYTES = 256 * 1024


class LLMClientError(RuntimeError):
    """A bounded provider failure that never includes provider response data."""

    _MESSAGES = {
        "configuration_error": "Agent LLM configuration is invalid.",
        "network_error": "The agent LLM provider could not be reached.",
        "timeout": "The agent LLM provider request timed out.",
        "provider_http_error": "The agent LLM provider rejected the request.",
        "response_too_large": "The agent LLM provider response exceeded its limit.",
        "invalid_provider_response": "The agent LLM provider returned an invalid response.",
    }

    def __init__(self, category: str) -> None:
        if category not in self._MESSAGES:
            category = "invalid_provider_response"
        self.category = category
        super().__init__(self._MESSAGES[category])

    def __repr__(self) -> str:
        return f"{type(self).__name__}(category={self.category!r})"


def _required_setting(value: Any, name: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LLMClientError("configuration_error")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise LLMClientError("configuration_error")
    return normalized


@dataclass(frozen=True, repr=False)
class LLMClientConfig:
    """Replaceable provider configuration loaded independently of app logic."""

    base_url: str
    api_key: str = field(repr=False)
    model: str
    timeout_seconds: float = DEFAULT_LLM_TIMEOUT_SECONDS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        base_url = _required_setting(self.base_url, "base_url", maximum=2048)
        api_key = _required_setting(self.api_key, "api_key", maximum=4096)
        model = _required_setting(self.model, "model", maximum=256)

        parts = urlsplit(base_url)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise LLMClientError("configuration_error")
        if isinstance(self.timeout_seconds, bool) or not isinstance(
            self.timeout_seconds,
            (int, float),
        ):
            raise LLMClientError("configuration_error")
        timeout = float(self.timeout_seconds)
        if not 0 < timeout <= MAX_LLM_TIMEOUT_SECONDS:
            raise LLMClientError("configuration_error")
        if isinstance(self.max_response_bytes, bool) or not isinstance(
            self.max_response_bytes,
            int,
        ):
            raise LLMClientError("configuration_error")
        if not 1024 <= self.max_response_bytes <= ABSOLUTE_MAX_RESPONSE_BYTES:
            raise LLMClientError("configuration_error")

        object.__setattr__(self, "base_url", base_url.rstrip("/"))
        object.__setattr__(self, "api_key", api_key)
        object.__setattr__(self, "model", model)
        object.__setattr__(self, "timeout_seconds", timeout)

    def __repr__(self) -> str:
        return (
            "LLMClientConfig("
            f"base_url={self.base_url!r}, "
            "api_key=<redacted>, "
            f"model={self.model!r}, "
            f"timeout_seconds={self.timeout_seconds!r}, "
            f"max_response_bytes={self.max_response_bytes!r})"
        )

    @classmethod
    def from_environment(
        cls,
        environment: Optional[Mapping[str, str]] = None,
    ) -> "LLMClientConfig":
        source = os.environ if environment is None else environment
        timeout_text = source.get(AGENT_LLM_TIMEOUT_ENV, "").strip()
        try:
            timeout = (
                float(timeout_text)
                if timeout_text
                else DEFAULT_LLM_TIMEOUT_SECONDS
            )
        except (TypeError, ValueError):
            raise LLMClientError("configuration_error") from None
        return cls(
            base_url=source.get(AGENT_LLM_BASE_URL_ENV, ""),
            api_key=source.get(AGENT_LLM_API_KEY_ENV, ""),
            model=source.get(AGENT_LLM_MODEL_ENV, ""),
            timeout_seconds=timeout,
        )


class OpenAICompatibleClient:
    """Call only the standard chat-completions surface with strict bounds."""

    def __init__(
        self,
        config: LLMClientConfig,
        *,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        if not isinstance(config, LLMClientConfig):
            raise TypeError("config must be an LLMClientConfig")
        self.config = config
        self._transport = transport

    def complete(
        self,
        messages: Sequence[Dict[str, str]],
        *,
        response_format: Dict[str, Any],
    ) -> str:
        request_body = {
            "model": self.config.model,
            "messages": list(messages),
            "temperature": 0,
            "stream": False,
            "think": False,
            "response_format": response_format,
        }
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            with httpx.Client(
                timeout=self.config.timeout_seconds,
                follow_redirects=False,
                transport=self._transport,
            ) as client:
                with client.stream(
                    "POST",
                    f"{self.config.base_url}/chat/completions",
                    headers=headers,
                    json=request_body,
                ) as response:
                    if not 200 <= response.status_code < 300:
                        raise LLMClientError("provider_http_error")
                    content_length = response.headers.get("content-length")
                    if content_length and content_length.isdigit():
                        if int(content_length) > self.config.max_response_bytes:
                            raise LLMClientError("response_too_large")
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        if (
                            len(body) + len(chunk)
                            > self.config.max_response_bytes
                        ):
                            raise LLMClientError("response_too_large")
                        body.extend(chunk)
        except LLMClientError:
            raise
        except (httpx.TimeoutException, TimeoutError):
            raise LLMClientError("timeout") from None
        except (httpx.RequestError, OSError):
            raise LLMClientError("network_error") from None

        try:
            payload = json.loads(bytes(body).decode("utf-8"))
            choices = payload["choices"]
            message = choices[0]["message"]
            content = message.get("content") or message.get("reasoning") or ""
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            IndexError,
            TypeError,
        ):
            raise LLMClientError("invalid_provider_response") from None
        if not isinstance(content, str) or not content.strip():
            raise LLMClientError("invalid_provider_response")
        return content

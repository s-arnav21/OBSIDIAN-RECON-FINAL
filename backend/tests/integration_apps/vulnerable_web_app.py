"""Deliberately vulnerable loopback-only application for integration tests."""

from __future__ import annotations

import html
import json
import re
import socket
import threading
import time
from typing import Optional
from urllib.parse import parse_qs, urlsplit

import uvicorn
import httpx
from fastapi import FastAPI, Query, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
)

from app.validation.command_execution import (
    BASELINE_DIAGNOSTIC_TOKEN,
    CONTROL_PROBE_TOKEN,
    EXECUTION_MARKER,
    EXECUTION_PROBE_TOKEN,
)
from app.validation.ssrf import (
    CONTROLLED_CANARY_PATH,
    CONTROLLED_CONTROL_PATH,
    controlled_content_marker,
)
from app.validation.system_information import (
    BASELINE_DISCOVERY_TOKEN,
    CONTROL_DISCOVERY_TOKEN,
    DISCOVERY_PROBE_TOKEN,
    SYSTEM_INFORMATION_MARKER,
)


app = FastAPI(title="Obsidian Recon Local Integration Fixture")
MANUAL_HOST = "127.0.0.1"
MANUAL_PORT = 8090
MANUAL_TARGET_URL = f"http://{MANUAL_HOST}:{MANUAL_PORT}"

_SQLI_BASELINE_BODY = (
    "<html><body>synthetic item available "
    + ("A" * 500)
    + "</body></html>"
)
_SQLI_FALSE_BODY = (
    "<html><body>synthetic item denied "
    + ("Z" * 500)
    + "</body></html>"
)
SYNTHETIC_EXPOSURE_BODY = (
    "APP_MODE=synthetic-integration-test\n"
    "SERVICE_TOKEN=FAKE-NOT-A-REAL-SECRET\n"
)
SYNTHETIC_SYSTEM_INFORMATION_BODY = (
    f"{SYSTEM_INFORMATION_MARKER}\n"
    "hostname=obsidian-demo-host\n"
    "operating_system=Obsidian Demo OS\n"
    "architecture=synthetic-x86_64\n"
)
_SSRF_IDENTIFIER_RE = re.compile(
    r"^or-ssrf-(?:baseline|canary|negative)-[0-9a-f]{20}$"
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ready"}


@app.get("/items", response_class=HTMLResponse)
def items(item_id: str = Query(alias="id")) -> HTMLResponse:
    """Simulate deterministic boolean-response SQL injection behavior."""
    if item_id in {
        "1",
        "1 AND 1=1",
        "1 AND 'x'='x'",
        "0 OR 1=1 AND 1=1",
    }:
        return HTMLResponse(_SQLI_BASELINE_BODY)
    if item_id in {
        "1 AND 1=2",
        "1 AND 'x'='y'",
        "0 OR 1=1 AND 1=2",
    }:
        return HTMLResponse(_SQLI_FALSE_BODY)
    return HTMLResponse("<html><body>synthetic item lookup</body></html>")


@app.get("/search", response_class=HTMLResponse)
def search(q: str) -> HTMLResponse:
    """Deliberately reflect only the supplied test value without encoding."""
    return HTMLResponse(f"<html><body>{q}</body></html>")


@app.get("/xss/text", response_class=HTMLResponse)
def xss_text(q: str) -> HTMLResponse:
    """Reflect text after removing HTML/JS syntax characters."""
    sanitized = re.sub(r"[<>'\"/*;=]", "", q)
    return HTMLResponse(f"<html><body><p>{sanitized}</p></body></html>")


@app.get("/xss/escaped", response_class=HTMLResponse)
def xss_escaped(q: str) -> HTMLResponse:
    """Reflect a safely HTML-escaped value in a text node."""
    return HTMLResponse(
        f"<html><body><p>{html.escape(q, quote=True)}</p></body></html>"
    )


@app.get("/xss/attribute", response_class=HTMLResponse)
def xss_attribute(q: str) -> HTMLResponse:
    """Deliberately place unescaped input in a quoted inert attribute."""
    return HTMLResponse(f'<html><body><div data-value="{q}"></div></body></html>')


@app.get("/xss/comment", response_class=HTMLResponse)
def xss_comment(q: str) -> HTMLResponse:
    """Deliberately place unescaped input in an HTML comment."""
    return HTMLResponse(f"<html><body><!--{q}--></body></html>")


@app.get("/xss/script", response_class=HTMLResponse)
def xss_script(q: str) -> HTMLResponse:
    """Deliberately place unescaped input in a JavaScript string."""
    return HTMLResponse(
        f'<html><body><script>const term = "{q}";</script></body></html>'
    )


@app.get("/xss/script-safe", response_class=HTMLResponse)
def xss_script_safe(q: str) -> HTMLResponse:
    """Serialize reflected input as a safely quoted JavaScript string."""
    serialized = json.dumps(q)
    return HTMLResponse(
        f"<html><body><script>const term = {serialized};</script></body></html>"
    )


@app.get("/xss/style", response_class=HTMLResponse)
def xss_style(q: str) -> HTMLResponse:
    """Reflect input only within a style block for conservative review."""
    return HTMLResponse(
        f"<html><body><style>.sample::after{{content:'{q}'}}</style></body></html>"
    )


@app.get("/xss/json", response_class=JSONResponse)
def xss_json(q: str) -> JSONResponse:
    """Reflect input in JSON, which is not an HTML execution context."""
    return JSONResponse({"query": q})


@app.get("/xss/filter", response_class=HTMLResponse)
def xss_filter(q: str) -> HTMLResponse:
    """Simulate a filter blocking syntax-bearing probes only."""
    if any(token in q for token in ('<', '>', '"', "'", "/*", "-->")):
        return HTMLResponse("request blocked by security policy", status_code=403)
    return HTMLResponse(f"<html><body>{q}</body></html>")


def _origin_tuple(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").lower(),
        parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
    )


def _controlled_ssrf_destination(request: Request, destination: str) -> bool:
    try:
        parsed = urlsplit(destination)
        destination_origin = _origin_tuple(destination)
    except ValueError:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    if parsed.fragment or destination_origin != _origin_tuple(str(request.base_url)):
        return False
    if parsed.path not in {CONTROLLED_CANARY_PATH, CONTROLLED_CONTROL_PATH}:
        return False
    values = parse_qs(parsed.query, keep_blank_values=True)
    if set(values) != {"id"} or len(values["id"]) != 1:
        return False
    identifier = values["id"][0]
    if not _SSRF_IDENTIFIER_RE.fullmatch(identifier):
        return False
    if parsed.path == CONTROLLED_CANARY_PATH:
        return identifier.startswith("or-ssrf-canary-")
    return identifier.startswith(("or-ssrf-baseline-", "or-ssrf-negative-"))


async def _retrieve_controlled_ssrf_destination(
    request: Request,
    destination: str,
) -> PlainTextResponse:
    if not _controlled_ssrf_destination(request, destination):
        return PlainTextResponse("controlled destination rejected", status_code=400)
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=1.0,
        trust_env=False,
    ) as client:
        response = await client.get(destination)
    if response.status_code != 200:
        return PlainTextResponse("controlled retrieval failed", status_code=502)
    return PlainTextResponse(response.text)


@app.get(CONTROLLED_CANARY_PATH, response_class=PlainTextResponse)
def ssrf_canary(id: str) -> PlainTextResponse:
    """Return content derived from, but different from, the canary URL ID."""
    if not _SSRF_IDENTIFIER_RE.fullmatch(id) or not id.startswith(
        "or-ssrf-canary-"
    ):
        return PlainTextResponse("invalid controlled canary", status_code=400)
    return PlainTextResponse(controlled_content_marker("canary", id))


@app.get(CONTROLLED_CONTROL_PATH, response_class=PlainTextResponse)
def ssrf_control(id: str) -> PlainTextResponse:
    """Return a distinct marker for a safe negative/control destination."""
    if not _SSRF_IDENTIFIER_RE.fullmatch(id) or not id.startswith(
        ("or-ssrf-baseline-", "or-ssrf-negative-")
    ):
        return PlainTextResponse("invalid controlled control", status_code=400)
    return PlainTextResponse(controlled_content_marker("control", id))


@app.get("/ssrf/fetch", response_class=PlainTextResponse)
async def ssrf_fetch(request: Request, url: str) -> PlainTextResponse:
    """Fetch only a recognized same-origin controlled canary destination."""
    return await _retrieve_controlled_ssrf_destination(request, url)


@app.post("/ssrf/fetch-json", response_class=PlainTextResponse)
async def ssrf_fetch_json(request: Request) -> PlainTextResponse:
    """JSON-context variant using the same strict destination policy."""
    body = await request.json()
    destination = body.get("url") if isinstance(body, dict) else None
    if not isinstance(destination, str):
        return PlainTextResponse("missing controlled destination", status_code=400)
    return await _retrieve_controlled_ssrf_destination(request, destination)


@app.get("/ssrf/reflect", response_class=PlainTextResponse)
def ssrf_reflect(url: str) -> PlainTextResponse:
    """Reflect a URL without performing a server-side retrieval."""
    return PlainTextResponse(f"submitted URL: {url}")


@app.get("/ssrf/no-fetch", response_class=PlainTextResponse)
def ssrf_no_fetch(url: str) -> PlainTextResponse:
    """Accept a URL-shaped parameter without reflecting or retrieving it."""
    return PlainTextResponse("request accepted without retrieval")


@app.get("/ssrf/sanitized", response_class=PlainTextResponse)
def ssrf_sanitized(url: str) -> PlainTextResponse:
    """Return only a bounded scheme classification, never the destination."""
    scheme = urlsplit(url).scheme.lower()
    return PlainTextResponse(f"URL scheme accepted: {scheme or 'none'}")


@app.get("/ssrf/collision", response_class=PlainTextResponse)
def ssrf_collision(url: str) -> PlainTextResponse:
    """Simulate a canary marker already present in baseline output."""
    identifier = parse_qs(urlsplit(url).query).get("id", [""])[0]
    root = identifier.rsplit("-", 1)[-1]
    canary_identifier = f"or-ssrf-canary-{root}"
    return PlainTextResponse(
        controlled_content_marker("canary", canary_identifier)
    )


@app.get("/ssrf/filter", response_class=PlainTextResponse)
def ssrf_filter(url: str) -> PlainTextResponse:
    """Simulate a request filter rejecting controlled URL probes."""
    return PlainTextResponse("request blocked by security policy", status_code=403)


@app.get("/ssrf/redirect")
def ssrf_redirect(url: str) -> RedirectResponse:
    """Return a redirect that the scoped validation transport must not follow."""
    return RedirectResponse(url=url, status_code=307)


@app.get("/debug-config", response_class=PlainTextResponse)
def debug_config() -> PlainTextResponse:
    """Return static synthetic classifier data; never read host environment."""
    return PlainTextResponse(SYNTHETIC_EXPOSURE_BODY)


@app.post("/admin/diagnostics", response_class=PlainTextResponse)
async def admin_diagnostics(request: Request) -> PlainTextResponse:
    """Interpret fixed synthetic tokens without invoking an operating system."""
    body = (await request.body()).decode("utf-8", errors="replace")
    diagnostic_token = parse_qs(body).get("diagnostic_token", [""])[0]
    if diagnostic_token == EXECUTION_PROBE_TOKEN:
        return PlainTextResponse(f"synthetic result: {EXECUTION_MARKER}")
    if diagnostic_token == BASELINE_DIAGNOSTIC_TOKEN:
        return PlainTextResponse("synthetic diagnostics ready")
    if diagnostic_token == CONTROL_PROBE_TOKEN:
        return PlainTextResponse("synthetic diagnostic control rejected")
    return PlainTextResponse("unsupported synthetic diagnostic token")


@app.post("/admin/system-information", response_class=PlainTextResponse)
async def admin_system_information(request: Request) -> PlainTextResponse:
    """Return fixed demo metadata without inspecting the host system."""
    body = (await request.body()).decode("utf-8", errors="replace")
    discovery_token = parse_qs(body).get("discovery_token", [""])[0]
    if discovery_token == DISCOVERY_PROBE_TOKEN:
        return PlainTextResponse(SYNTHETIC_SYSTEM_INFORMATION_BODY)
    if discovery_token == BASELINE_DISCOVERY_TOKEN:
        return PlainTextResponse("synthetic system-information baseline")
    if discovery_token == CONTROL_DISCOVERY_TOKEN:
        return PlainTextResponse("synthetic system-information control rejected")
    return PlainTextResponse("unsupported synthetic discovery token")


class LocalVulnerableAppServer:
    """Start and stop the fixture on a pre-bound ephemeral loopback socket."""

    def __init__(self) -> None:
        self._socket: Optional[socket.socket] = None
        self._server: Optional[uvicorn.Server] = None
        self._thread: Optional[threading.Thread] = None
        self.origin: Optional[str] = None

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> str:
        if self.is_running:
            raise RuntimeError("local vulnerable app is already running")

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(("127.0.0.1", 0))
            server_socket.listen(128)
        except Exception:
            server_socket.close()
            raise
        port = server_socket.getsockname()[1]

        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="error",
            access_log=False,
            lifespan="off",
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(
            target=server.run,
            kwargs={"sockets": [server_socket]},
            name="obsidian-local-vulnerable-app",
            daemon=True,
        )

        self._socket = server_socket
        self._server = server
        self._thread = thread
        self.origin = f"http://127.0.0.1:{port}"
        thread.start()

        deadline = time.monotonic() + 5.0
        while not server.started:
            if not thread.is_alive():
                self.stop()
                raise RuntimeError("local vulnerable app failed to start")
            if time.monotonic() >= deadline:
                self.stop()
                raise TimeoutError("local vulnerable app startup timed out")
            time.sleep(0.01)
        return self.origin

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            if self._thread.is_alive() and self._server is not None:
                self._server.force_exit = True
                self._thread.join(timeout=1.0)
        if self._socket is not None:
            self._socket.close()

        self._socket = None
        self._server = None
        self._thread = None
        self.origin = None

    def __enter__(self) -> "LocalVulnerableAppServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.stop()


def run_manual_server() -> None:
    """Run the fixed developer fixture until interrupted with Ctrl+C."""
    print(f"Obsidian Recon local fixture target: {MANUAL_TARGET_URL}", flush=True)
    uvicorn.run(
        app,
        host=MANUAL_HOST,
        port=MANUAL_PORT,
        log_level="info",
        access_log=False,
        lifespan="off",
    )


if __name__ == "__main__":
    run_manual_server()

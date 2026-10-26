"""Core configuration for Obsidian Recon. Loads environment variables from .env."""
import os
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[2]
ENV_PATH = BACKEND_DIR.parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)


def _get_bool(key: str, default: bool = False) -> bool:
    value = os.getenv(key)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _get_int(key: str, default: int) -> int:
    value = os.getenv(key)
    if value is None or not value.strip():
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def _get_csv(key: str, default: tuple = ()) -> tuple:
    value = os.getenv(key)
    if value is None:
        return tuple(default)
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _get_ports(key: str, default: tuple = ()) -> tuple:
    ports = []
    for item in _get_csv(key, default):
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return tuple(ports)


class Settings:
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    DATA_DIR: Path = BACKEND_DIR / "data"

    AUTHORIZATION_RESTRICTED: bool = _get_bool("AUTHORIZATION_RESTRICTED", True)
    ALLOWED_PRIVATE_RANGES: tuple = (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    )
    AUTHORIZATION_ALLOW_HOSTS: tuple = tuple(
        h.strip()
        for h in os.getenv("AUTHORIZATION_ALLOW_HOSTS", "").split(",")
        if h.strip()
    )

    CORS_ORIGINS: tuple = tuple(
        o.strip()
        for o in os.getenv("CORS_ORIGINS", "*").split(",")
        if o.strip()
    )

    RISK_CRITICAL: int = int(os.getenv("RISK_CRITICAL", "70"))
    RISK_HIGH: int = int(os.getenv("RISK_HIGH", "40"))

    ALLOW_EXPLOIT_SKILLS: bool = _get_bool("ALLOW_EXPLOIT_SKILLS", False)
    MAX_SKILL_TIMEOUT: int = int(os.getenv("MAX_SKILL_TIMEOUT", "300"))

    # Agent: maximum bounded steps per run (configurable via .env).
    AGENT_MAX_STEPS: int = int(os.getenv("AGENT_MAX_STEPS", "10"))

    # Automation (MITRE technique scripts): per-script wall-clock budget, the
    # directory bounded tool output is written to, whether destructive
    # non-automatic techniques may run without an explicit operator opt-in, and
    # whether post-exploitation helpers (LinPEAS/WinPEAS) may be fetched from
    # the internet (default False: use the baked-in cache only).
    AUTOMATION_TIMEOUT: int = int(os.getenv("AUTOMATION_TIMEOUT", "180"))
    AUTOMATION_ARTIFACT_DIR: str = os.getenv("AUTOMATION_ARTIFACT_DIR", "")
    AUTOMATION_ALLOW_NON_AUTOMATIC: bool = _get_bool(
        "AUTOMATION_ALLOW_NON_AUTOMATIC", False
    )
    AUTOMATION_ALLOW_REMOTE_FETCH: bool = _get_bool(
        "AUTOMATION_ALLOW_REMOTE_FETCH", False
    )

    # OWASP ZAP REST API (optional web-testing backend). Empty base URL means
    # "no ZAP" — the adapter reports unavailable instead of guessing a host.
    ZAP_BASE_URL: str = os.getenv("ZAP_BASE_URL", "")
    ZAP_API_KEY: str = os.getenv("ZAP_API_KEY", "")
    ZAP_TIMEOUT: int = int(os.getenv("ZAP_TIMEOUT", "15"))

    # Metasploit RPC (msfrpcd via pymetasploit3). Disabled unless explicitly
    # enabled AND the optional dependency is importable.
    MSF_RPC_ENABLED: bool = _get_bool("MSF_RPC_ENABLED", False)
    MSF_RPC_HOST: str = os.getenv("MSF_RPC_HOST", "127.0.0.1")
    MSF_RPC_PORT: int = int(os.getenv("MSF_RPC_PORT", "55552"))
    MSF_RPC_USER: str = os.getenv("MSF_RPC_USER", "msf")
    MSF_RPC_PASSWORD: str = os.getenv("MSF_RPC_PASSWORD", "")
    MSF_RPC_SSL: bool = _get_bool("MSF_RPC_SSL", False)

    NMAP_SCAN_TIMEOUT: int = int(os.getenv("NMAP_SCAN_TIMEOUT", "900"))
    NMAP_MIN_RATE: int = int(os.getenv("NMAP_MIN_RATE", "500"))
    # Per-host cap for the Phase-1 open-port sweep; a value + firewall that
    # never answers fails fast and degrades to --top-ports instead of stalling.
    NMAP_HOST_TIMEOUT: str = os.getenv("NMAP_HOST_TIMEOUT", "120s")

    # Nuclei scanner tuning (lower defaults to avoid rate-limiting on real targets).
    NUCLEI_CONCURRENCY: int = int(os.getenv("NUCLEI_CONCURRENCY", "20"))
    NUCLEI_RATE_LIMIT: int = int(os.getenv("NUCLEI_RATE_LIMIT", "50"))

    # API authentication.  When set, all mutating (POST/PUT/PATCH/DELETE)
    # endpoints require ``X-API-Key: <token>``.  Read-only GETs remain open
    # so status/readiness checks work without credentials.
    API_AUTH_TOKEN: str = os.getenv("API_AUTH_TOKEN", "")

    # ------------------------------------------------------------------
    # Task agent (bounded, task-centric LLM automation)
    # ------------------------------------------------------------------
    TASK_AGENT_ENABLED: bool = _get_bool("TASK_AGENT_ENABLED", True)
    TASK_AGENT_MAX_STEPS: int = _get_int("TASK_AGENT_MAX_STEPS", 12)
    TASK_AGENT_MAX_RUNTIME: int = _get_int("TASK_AGENT_MAX_RUNTIME", 900)
    TASK_AGENT_MAX_REPAIR_ATTEMPTS: int = _get_int(
        "TASK_AGENT_MAX_REPAIR_ATTEMPTS", 3
    )
    TASK_AGENT_MAX_OUTPUT_BYTES: int = _get_int(
        "TASK_AGENT_MAX_OUTPUT_BYTES", 64 * 1024
    )
    TASK_AGENT_INPUT_ROOT: Path = Path(
        os.getenv("TASK_AGENT_INPUT_ROOT", str(BACKEND_DIR / "runtime" / "task_inputs"))
    ).expanduser()
    TASK_AGENT_ARTIFACT_DIR: Path = Path(
        os.getenv(
            "TASK_AGENT_ARTIFACT_DIR",
            str(BACKEND_DIR / "runtime" / "task_artifacts"),
        )
    ).expanduser()
    TASK_AGENT_REPORT_DIR: Path = Path(
        os.getenv(
            "TASK_AGENT_REPORT_DIR",
            str(BACKEND_DIR / "runtime" / "task_reports"),
        )
    ).expanduser()
    TASK_AGENT_AUDIT_LOG_PATH: Path = Path(
        os.getenv(
            "TASK_AGENT_AUDIT_LOG_PATH",
            str(BACKEND_DIR / "runtime" / "task_audit.jsonl"),
        )
    ).expanduser()
    TASK_AGENT_ALLOWED_HOSTS: tuple = _get_csv(
        "TASK_AGENT_ALLOWED_HOSTS",
        ("localhost", "127.0.0.1", "::1"),
    )
    TASK_AGENT_ALLOWED_NETWORKS: tuple = _get_csv(
        "TASK_AGENT_ALLOWED_NETWORKS",
        ("127.0.0.0/8", "::1/128"),
    )
    TASK_AGENT_ALLOWED_PORTS: tuple = _get_ports(
        "TASK_AGENT_ALLOWED_PORTS",
        (80, 443, 3000, 5000, 8000, 8001, 8080, 8081, 8443, 9000, 9090),
    )
    TASK_AGENT_ALLOWED_CONTAINERS: tuple = _get_csv(
        "TASK_AGENT_ALLOWED_CONTAINERS", ()
    )
    TASK_AGENT_DENY_PUBLIC: bool = _get_bool("TASK_AGENT_DENY_PUBLIC", True)
    TASK_AGENT_DEFAULT_NETWORK_POLICY: str = os.getenv(
        "TASK_AGENT_DEFAULT_NETWORK_POLICY", "none"
    ).strip().lower()
    TASK_AGENT_APPROVAL_MODE: str = os.getenv(
        "TASK_AGENT_APPROVAL_MODE", "high_risk"
    ).strip().lower()
    TASK_AGENT_MAX_ARTIFACT_BYTES: int = _get_int(
        "TASK_AGENT_MAX_ARTIFACT_BYTES", 8 * 1024 * 1024
    )

    # Isolated worker configuration.  Generated code defaults to no network.
    TASK_AGENT_SANDBOX_BACKEND: str = os.getenv(
        "TASK_AGENT_SANDBOX_BACKEND", "docker"
    ).strip().lower()
    TASK_AGENT_WORKER_IMAGE: str = os.getenv(
        "TASK_AGENT_WORKER_IMAGE", "obsidian-worker:latest"
    ).strip()
    TASK_AGENT_TOOL_WORKER_IMAGE: str = os.getenv(
        "TASK_AGENT_TOOL_WORKER_IMAGE", "obsidian-tool-worker:latest"
    ).strip()
    TASK_AGENT_WORKER_TIMEOUT: int = _get_int("TASK_AGENT_WORKER_TIMEOUT", 120)
    TASK_AGENT_WORKER_MEMORY: str = os.getenv(
        "TASK_AGENT_WORKER_MEMORY", "256m"
    ).strip()
    TASK_AGENT_WORKER_CPUS: str = os.getenv("TASK_AGENT_WORKER_CPUS", "0.50").strip()
    TASK_AGENT_WORKER_PIDS: int = _get_int("TASK_AGENT_WORKER_PIDS", 64)
    TASK_AGENT_WORKER_NETWORK: str = os.getenv(
        "TASK_AGENT_WORKER_NETWORK", "none"
    ).strip()
    TASK_AGENT_LAB_NETWORK: str = os.getenv(
        "TASK_AGENT_LAB_NETWORK", "obsidian-lab"
    ).strip()
    # Deliberately false by default.  It exists only for offline CI/demo hosts
    # where Docker is unavailable; production execution must use Docker.
    TASK_AGENT_ALLOW_LOCAL_SANDBOX: bool = _get_bool(
        "TASK_AGENT_ALLOW_LOCAL_SANDBOX", False
    )
    TASK_AGENT_LOCAL_SANDBOX_TIMEOUT: int = _get_int(
        "TASK_AGENT_LOCAL_SANDBOX_TIMEOUT", 60
    )

    # Claude-Red methodology index/retrieval.
    CLAUDE_RED_SKILLS_PATH: Path = Path(
        os.getenv(
            "CLAUDE_RED_SKILLS_PATH",
            str(BACKEND_DIR / "knowledge" / "claude-red" / "Skills"),
        )
    ).expanduser()
    CLAUDE_RED_INDEX_PATH: Path = Path(
        os.getenv(
            "CLAUDE_RED_INDEX_PATH",
            str(BACKEND_DIR / "runtime" / "claude_red_index.json"),
        )
    ).expanduser()
    CLAUDE_RED_RETRIEVAL_METHOD: str = os.getenv(
        "CLAUDE_RED_RETRIEVAL_METHOD", "hybrid"
    ).strip().lower()
    CLAUDE_RED_TOP_K: int = _get_int("CLAUDE_RED_TOP_K", 5)
    CLAUDE_RED_CONTEXT_TOKENS: int = _get_int("CLAUDE_RED_CONTEXT_TOKENS", 2500)
    CLAUDE_RED_EMBEDDING_DIMENSIONS: int = _get_int(
        "CLAUDE_RED_EMBEDDING_DIMENSIONS", 512
    )


settings = Settings()


def data_file(*parts: str) -> str:
    return str(settings.DATA_DIR.joinpath(*parts))

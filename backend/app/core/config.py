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


settings = Settings()


def data_file(*parts: str) -> str:
    return str(settings.DATA_DIR.joinpath(*parts))

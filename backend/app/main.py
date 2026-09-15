from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.agent import router as agent_router
from app.api.attacks import router as attacks_router
from app.api.exploit import router as exploit_router
from app.api.jobs import router as jobs_router
from app.api.readiness import router as readiness_router
from app.api.recon import router as recon_router
from app.api.scans import router as scans_router
from app.api.security import router as security_router
from app.api.target_verifications import router as target_verifications_router


def _static_dir() -> Path:
    # Website assets now live in the repo-root FRONTEND/ folder.
    repo_frontend = Path(__file__).resolve().parents[2] / "FRONTEND"
    if repo_frontend.is_dir():
        return repo_frontend
    # Container layout: FRONTEND/ is bind-mounted at /app/frontend.
    container_frontend = Path(__file__).resolve().parents[1] / "frontend"
    if container_frontend.is_dir():
        return container_frontend
    return Path(__file__).resolve().parent / "static"


STATIC_DIR = _static_dir()

app = FastAPI(title="Obsidian Recon API")
app.include_router(readiness_router)
app.include_router(recon_router)
app.include_router(jobs_router)
app.include_router(scans_router)
app.include_router(target_verifications_router)
app.include_router(exploit_router)
app.include_router(agent_router)
app.include_router(attacks_router)
app.include_router(security_router)
app.mount("/static", StaticFiles(directory=STATIC_DIR, html=True), name="static")
app.mount("/console", StaticFiles(directory=STATIC_DIR, html=True), name="console")


@app.get("/")
def read_root() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/exploit")
def read_exploit() -> FileResponse:
    return FileResponse(STATIC_DIR / "exploit.html")


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "healthy"}

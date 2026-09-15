# Obsidian Recon — Setup Guide

AI-Powered Automated Penetration Testing Platform

Obsidian Recon runs a reconnaissance → detection → validated-findings pipeline:
passive OSINT + 51 skills, a 7-step scanner chain (subdomains, HTTP probe, nmap,
nuclei, TLS audit, content discovery, WAF detect), triage / validation /
normalization into a unified Postgres store, and an optional LLM-driven exploit
planner/agent that produces proof-of-concept based plans for findings surfaced
to the Attacks UI.

**Current scope boundary.** Live exploitation probes are profile-gated — the
default `webapp` profile runs reconnaissance and validation with *no* active
exploit skills; the `vm` and `ctf` profiles enable the exploit phase for
isolated lab VMs. Reverse-shell catch, an interactive shell channel, and full
post-exploitation are planned extensions, not current scope. The platform's
deliverable is validated findings plus PoC plans, not compromised hosts.

---

## 1. Prerequisites (install BEFORE cloning)

### 1.1 Base tooling (everyone)

| Tool | Why it is required | Where to get it |
|---|---|---|
| **Docker** (with Compose v2) | Runs Postgres, Redis, backend, Adminer, and the demo target | [docker.com](https://www.docker.com/) — for Windows use Docker Desktop (WSL 2 engine) |
| **Git** | Clone / update the repository | [git-scm.com](https://git-scm.com/) or `sudo apt install -y git` |
| **Python 3.10+** | Backend runs a venv (`uvicorn`, FastAPI, SQLAlchemy) | [python.org](https://www.python.org/downloads/) or `sudo apt install -y python3 python3-venv` |

> The Compose images (`postgres:16`, `redis:7-alpine`) are pulled automatically
> by `docker compose up`. You do not need to install Postgres or Redis directly.

### 1.2 Security toolchain (system binaries)

Obsidian auto-resolves these binaries at scan time via PATH (then
`<venv>/bin`, `/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`, `/snap/bin`,
`~/go/bin`). If a binary is missing, the corresponding scanner simply reports
`unavailable` — but for a full scan you want all of these installed:

| Tool | Version | Used by | Install (Ubuntu/Debian) |
|---|---|---|---|
| **nmap** | 7.90+ (latest preferred) | port scanning, service/OS detection, TLS audit (`nmap --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed`) | `sudo apt install -y nmap` |
| **nuclei** | v3.x (>=3.1 recommended) | template-based vulnerability scanning (`nuclei -u <target> -jsonl -silent`); a dedicated `nuclei-targeted` post skill re-scans discovered paths | Download release from [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei/releases) and put the binary on `PATH` |
| **subfinder + dnsx** *(optional)* | latest | fast subdomain enumeration. Obsidian ships a pure-Python httpx fallback, so these are optional but recommended for coverage | Go tools: `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| **feroxbuster** *(optional)* | latest | content discovery. A pure-Python httpx wordlist prober is used by default; feroxbuster is a fallback | Release from [epi052/feroxbuster](https://github.com/epi052/feroxbuster/releases) |

Go tools are picked up automatically from `~/go/bin`. For a governed machine,
install nmap + nuclei at minimum — they cover the most value.

### 1.3 Per-OS quick start

#### Windows users
1. Install WSL2 + Ubuntu: open PowerShell as Administrator, run `wsl --install`, restart your PC
2. Install Docker Desktop for Windows — during/after setup, enable "Use WSL 2 based engine" in Settings > General, and enable WSL Integration for Ubuntu in Settings > Resources > WSL Integration
3. Do all following steps INSIDE the Ubuntu terminal app, not PowerShell/CMD
4. Inside Ubuntu: `sudo apt install -y nmap git python3 python3-venv` and install nuclei per §1.2

#### Mac users
1. Install Homebrew (if not already installed):
   `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
2. `brew install --cask docker`, then launch it once from Applications
3. `brew install git nmap`
4. Install nuclei/feroxbuster per §1.2

#### Linux users
1. Install Docker: `sudo apt install -y docker.io docker-compose-plugin` (Ubuntu/Debian) or your distro's equivalent
2. Add yourself to the docker group: `sudo usermod -aG docker $USER`, then log out and back in
3. `sudo apt install -y git nmap python3 python3-venv`
4. Install nuclei per §1.2

---

## 2. Required LLM (trained agent model)

The exploitation layer is driven by an OpenAI-compatible LLM served on a local
endpoint. The **required trained model for Obsidian Recon will be published
here once training completes** — this section will then point to the exact
model ID / weights / host and the version to download. Until then:

- The platform runs fully without an LLM: the exploit planner falls back to a
  deterministic MITRE-ATT&CK-driven plan (`TECHNIQUE_DEFINITIONS`), and the
  agent planner reports `503` until configured.
- When the trained model is released, download the weights and serve them on a
  compatible server (e.g. vLLM / OpenAI-compatible gateway) on a local port
  (default `http://127.0.0.1:3001/v1`), then set the variables below.

### 2.1 Configure the endpoint (`.env`)

```dotenv
AGENT_LLM_BASE_URL=http://127.0.0.1:3001/v1
AGENT_LLM_API_KEY=<your key, or leave empty for a local server>
AGENT_LLM_MODEL=<model id — set to the released trained version>
AGENT_LLM_TIMEOUT=15
```

| Variable | Default | Meaning |
|---|---|---|
| `AGENT_LLM_BASE_URL` | `http://127.0.0.1:3001/v1` | OpenAI-compatible `/v1` endpoint hosting the model |
| `AGENT_LLM_API_KEY` | (empty) | Provider key; many local servers ignore this |
| `AGENT_LLM_MODEL` | `gpt-oss-120b` | The model name to request — **replace with the published trained version** |
| `AGENT_LLM_TIMEOUT` | `15` | Request timeout in seconds |

> The exact download URL, model ID, minimum supported version, and required
> serving setup for the trained model will be added to this README (and the
> `AGENT_LLM_MODEL` default) in the release that follows training. Watch this
> section for the update.

---

## 3. Setup Steps (same for everyone, once prerequisites are done)

1. Clone the repository:
   ```bash
   git clone https://github.com/s-arnav21/OBSIDIAN-RECON-FINAL.git
   cd OBSIDIAN-RECON-FINAL
   ```
2. Configure environment:
   ```bash
   cp .env.example .env
   # edit .env — set DATABASE_URL, AGENT_LLM_* (see §2), and any scan options
   ```
3. Create the Python env and the database schema:
   ```bash
   cd backend
   python3 -m venv ../venv && source ../venv/bin/activate
   pip install -r requirements.txt
   alembic upgrade head   # apply migrations 0001→0004
   cd ..
   ```
4. Start the stack:
   ```bash
   docker compose up -d postgres redis backend adminer
   ```
   The API is served at `http://127.0.0.1:8000`, Adminer at
   `http://127.0.0.1:8080`, and the exploit UI at
   `http://127.0.0.1:8000/exploit`.

---

## 4. Running the suite

```bash
cd backend && source ../venv/bin/activate
pytest -q        # full backend suite (861 passed, 264 subtests)
```

Scan flow: submit a target in the Recon UI → job manifest (~62 steps) runs
recon → skills → scanners → chain → finalize → persists findings to Postgres →
exploitable findings (`confirmed`/`manual_review`) feed the Attacks UI / LLM
agent for proof-of-concept planning. Live exploit skills run only when the
profile enables the exploit phase (`vm`/`ctf`); the default `webapp` profile
evaluates authorization but runs no exploit skills.
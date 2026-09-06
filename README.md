# Obsidian Recon — Setup Guide

AI-Powered Automated Penetration Testing Platform

## Prerequisites (install BEFORE cloning)

### Windows users
1. Install WSL2 + Ubuntu: open PowerShell as Administrator, run `wsl --install`, restart your PC
2. Install Docker Desktop for Windows — during/after setup, enable "Use WSL 2 based engine" in Settings > General, and enable WSL Integration for Ubuntu in Settings > Resources > WSL Integration
3. Do all following steps INSIDE the Ubuntu terminal app, not PowerShell/CMD

### Mac users
1. Install Homebrew (if not already installed):
   `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
2. Install Docker Desktop for Mac: `brew install --cask docker`, then launch it once from Applications
3. Install Git: `brew install git`

### Linux users
1. Install Docker: `sudo apt install -y docker.io docker-compose-plugin` (Ubuntu/Debian) or your distro's equivalent
2. Add yourself to the docker group: `sudo usermod -aG docker $USER`, then log out and back in
3. Install Git: `sudo apt install -y git`

## Setup Steps (same for everyone, once prerequisites are done)

1. Clone the repo:

## Controlled validation demo target

The repository includes a deliberately vulnerable synthetic web application
used by the automated integration suite. It contains no production database,
real credentials, shell execution, unrestricted proxying, or arbitrary SSRF.
Docker Compose publishes it only on the host loopback interface.

Start the target from the repository root:

```bash
docker compose up -d demo-target
```

Wait for the service to become healthy, then verify it:

```bash
docker compose ps demo-target
curl --fail http://127.0.0.1:8090/health
```

Run Obsidian's `generic_local_web_validation` scenario against this exact
authorized target origin:

```text
http://127.0.0.1:8090
```

The controlled fixture exercises deterministic SQL injection, reflected XSS,
same-origin SSRF canary retrieval, synthetic information exposure, and fixed
command-execution simulation contracts. The command route recognizes only
project-defined synthetic tokens and never invokes an operating-system shell.

Stop the target without stopping the other Compose services:

```bash
docker compose stop demo-target
```

To remove its stopped container as well:

```bash
docker compose rm -f demo-target
```

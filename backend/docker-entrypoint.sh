#!/usr/bin/env bash
# Container entrypoint: first-start tooling.
#   1. SecLists common.txt  -> content discovery wordlist. Baked into the image
#      at build time; this is a network-free fallback if the file is missing.
#   2. nuclei-templates      -> optional default template set. nuclei auto-downloads
#      its own templates on first run, so this is a best-effort add-on only.
# Every step is timeout-guarded so a slow network can never wedge the API.
set -uo pipefail

WL="/root/.local/share/recon/common.txt"
if [ ! -s "$WL" ]; then
  echo ">> fetching content-discovery wordlist (SecLists common.txt) ..."
  mkdir -p "$(dirname "$WL")"
  timeout 60 curl -fsSL \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    -o "$WL" \
    && echo "   wordlist ready ($(wc -l < "$WL") entries)" \
    || echo "!! wordlist fetch failed; content crawler will report unavailable"
else
  echo "   wordlist already present ($(wc -l < "$WL") entries)"
fi

NT="/root/nuclei-templates"
if [ ! -d "$NT" ] || [ ! -f "$NT/README.md" ]; then
  echo ">> downloading nuclei-templates (best-effort) ..."
  if command -v git >/dev/null 2>&1; then
    timeout 300 git clone --depth 1 "https://github.com/projectdiscovery/nuclei-templates.git" "$NT" \
      && echo "   nuclei-templates ready" \
      || echo "!! nuclei-templates fetch failed; nuclei will rely on its own defaults"
  else
    echo "!! git not found; skip nuclei-templates download"
  fi
fi

exec "$@"
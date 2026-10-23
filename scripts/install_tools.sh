#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Obsidian Recon — security toolchain installer ("connect the tools").
#
# Obsidian resolves external binaries at scan time (see
# backend/pipeline/scanner/base.py::_resolve_executable and
# backend/app/agent/tools.py::_binary_available). This script makes every tool
# the project references actually resolve on the host.
#
# It is idempotent and works in two modes:
#
#   1. ROOT / passwordless-sudo mode  -> installs the distro packages with apt
#      (sqlmap hydra nikto gobuster nfs-common, plus Go/PD tooling if missing).
#
#   2. USER-SPACE mode (no root)      -> installs everything into the user's
#      home so no sudo is required:
#        * sqlmap        -> pip into the project venv (or --user)
#        * gobuster      -> upstream static release binary -> ~/.local/bin
#        * nikto         -> git clone + local Perl modules -> ~/.local/bin
#        * hydra         -> apt .deb + uninstalled libs extracted to a prefix
#        * showmount     -> nfs-common .deb extracted (same prefix)
#      The .deb tools are wrapped so their private libs are found via
#      LD_LIBRARY_PATH; nothing is written outside $HOME.
#
# Usage:
#   scripts/install_tools.sh              # auto-detect mode
#   scripts/install_tools.sh --user       # force user-space mode
#   scripts/install_tools.sh --apt        # force apt mode (needs root/sudo)
#   scripts/install_tools.sh --verify     # only report resolution status
#
# NOTE: only run scans against systems you are authorized to test.
# ---------------------------------------------------------------------------
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_BIN="${HOME}/.local/bin"
PREFIX="${HOME}/.local/opt/obsidian-tools"     # extracted .deb prefix
STAMP_DIR="${PREFIX}/.stamps"
VENV_PIP="${REPO_ROOT}/venv/bin/pip"

GOBUSTER_VER="${GOBUSTER_VER:-3.8.2}"
FFUF_VER="${FFUF_VER:-2.1.0}"
KATANA_VER="${KATANA_VER:-1.1.2}"

#: Bump when the extracted-deb wrapper template below changes.
WRAPPER_VERSION="2"

# Binaries the project shells out to. nmap/nuclei/subfinder/dnsx/httpx/
# feroxbuster/openssl are assumed present; these are the ones historically
# missing on a bare Ubuntu host.
CORE_DEB_PKGS=(sqlmap hydra nikto gobuster nfs-common)
USER_DEB_TOOLS=("hydra:hydra" "showmount:nfs-common")

log()  { printf '  %s\n' "$*"; }
head() { printf '\n== %s ==\n' "$*"; }

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
verify() {
  head "Tool resolution"
  local t path status
  for t in nmap nuclei subfinder dnsx httpx feroxbuster katana ffuf openssl \
           sqlmap nikto hydra gobuster showmount msfconsole; do
    path="$(command -v "$t" 2>/dev/null || true)"
    if [ -n "$path" ]; then status="OK      ${path}"; else status="MISSING"; fi
    printf '  %-13s %s\n' "$t" "$status"
  done
}

# ---------------------------------------------------------------------------
# Root mode
# ---------------------------------------------------------------------------
install_apt() {
  head "Installing via apt (root)"
  local SUDO=""
  if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi
  $SUDO apt-get update -y
  $SUDO apt-get install -y --no-install-recommends \
    "${CORE_DEB_PKGS[@]}" unzip
  log "apt install complete"
}

# ---------------------------------------------------------------------------
# User-space mode
# ---------------------------------------------------------------------------
ensure_local_bin() { mkdir -p "$LOCAL_BIN" "$PREFIX" "$STAMP_DIR"; }

install_sqlmap_user() {
  if command -v sqlmap >/dev/null 2>&1; then log "sqlmap already present"; return; fi
  head "sqlmap (pip)"
  if [ -x "$VENV_PIP" ]; then
    "$VENV_PIP" install --quiet --upgrade sqlmap
    # Expose the venv console script on PATH so shutil.which() finds it even
    # when the venv is not activated (agent tools / validators use that).
    ln -sf "${REPO_ROOT}/venv/bin/sqlmap" "${LOCAL_BIN}/sqlmap"
  else
    python3 -m pip install --quiet --user sqlmap
  fi
  log "sqlmap installed"
}

install_gobuster_user() {
  if command -v gobuster >/dev/null 2>&1; then log "gobuster already present"; return; fi
  head "gobuster (static release v${GOBUSTER_VER})"
  local tmp; tmp="$(mktemp -d)"
  curl -fsSL \
    "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VER}/gobuster_Linux_x86_64.tar.gz" \
    -o "${tmp}/gobuster.tgz"
  tar -xzf "${tmp}/gobuster.tgz" -C "$tmp" gobuster
  install -m 0755 "${tmp}/gobuster" "${LOCAL_BIN}/gobuster"
  rm -rf "$tmp"
  log "gobuster installed"
}

install_ffuf_user() {
  if command -v ffuf >/dev/null 2>&1; then log "ffuf already present"; return; fi
  head "ffuf (static release v${FFUF_VER})"
  local tmp; tmp="$(mktemp -d)"
  curl -fsSL \
    "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_amd64.tar.gz" \
    -o "${tmp}/ffuf.tgz" \
    && tar -xzf "${tmp}/ffuf.tgz" -C "$tmp" ffuf \
    && install -m 0755 "${tmp}/ffuf" "${LOCAL_BIN}/ffuf" \
    && log "ffuf installed" || log "!! ffuf install failed"
  rm -rf "$tmp"
}

install_katana_user() {
  if command -v katana >/dev/null 2>&1; then log "katana already present"; return; fi
  head "katana (static release v${KATANA_VER})"
  local tmp; tmp="$(mktemp -d)"
  curl -fsSL \
    "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VER}/katana_${KATANA_VER}_linux_amd64.zip" \
    -o "${tmp}/katana.zip" \
    && python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extract('katana', sys.argv[2])" "${tmp}/katana.zip" "$tmp" \
    && install -m 0755 "${tmp}/katana" "${LOCAL_BIN}/katana" \
    && log "katana installed" || log "!! katana install failed"
  rm -rf "$tmp"
}

# Optional: the Metasploit RPC client used by app/automation/metasploit_rpc.py
# and the metasploit-* agent tools (falls back to msfconsole when absent).
install_python_extras_user() {
  [ -x "$VENV_PIP" ] || return 0
  if "$VENV_PIP" show pymetasploit3 >/dev/null 2>&1; then
    log "pymetasploit3 already present"; return 0
  fi
  head "pymetasploit3 (optional Metasploit RPC client)"
  "$VENV_PIP" install --quiet pymetasploit3 \
    && log "pymetasploit3 installed" \
    || log "!! pymetasploit3 install failed (optional)"
}

install_nikto_user() {
  if command -v nikto >/dev/null 2>&1; then log "nikto already present"; return; fi
  head "nikto (git clone + local Perl modules)"
  rm -rf "${HOME}/.local/share/nikto"
  git clone --depth 1 https://github.com/sullo/nikto.git \
    "${HOME}/.local/share/nikto" >/dev/null 2>&1 || {
      log "!! nikto clone failed"; return 1; }
  # nikto requires XML::Writer at startup; install it under $HOME, not system.
  if ! PERL5LIB="${HOME}/.local/share/perl5/lib/perl5" \
       perl -MXML::Writer -e 1 >/dev/null 2>&1; then
    PERL_MM_USE_DEFAULT=1 PERL_MM_OPT="INSTALL_BASE=${HOME}/.local/share/perl5" \
      timeout 300 cpan XML::Writer >/dev/null 2>&1 || log "!! XML::Writer install failed"
  fi
  cat > "${LOCAL_BIN}/nikto" <<'WRAP'
#!/usr/bin/env bash
# User-space nikto wrapper (git clone + $HOME Perl libs).
export PERL5LIB="$HOME/.local/share/perl5/lib/perl5${PERL5LIB:+:$PERL5LIB}"
exec perl "$HOME/.local/share/nikto/program/nikto.pl" "$@"
WRAP
  chmod +x "${LOCAL_BIN}/nikto"
  log "nikto installed"
}

# Compute the recursive set of *not-installed* package dependencies for a pkg.
missing_closure() {
  local pkg="$1"
  local seen=" " out=""
  local queue="${pkg} "
  local p d
  while [ -n "${queue// /}" ]; do
    p="${queue%% *}"; queue="${queue#* }"
    case "$seen" in *" $p "*) continue;; esac
    seen="${seen}${p} "
    dpkg -s "$p" >/dev/null 2>&1 && continue
    out="${out}${p} "
    while read -r d; do
      [ -n "$d" ] && queue="${queue}${d} "
    done < <(apt-cache depends --recurse --no-recommends --no-suggests \
               --no-conflicts --no-breaks --no-replaces --no-enhances "$p" \
               2>/dev/null \
             | sed -n 's/^[[:space:]]*\(Depends\|PreDepends\):[[:space:]]*\(.*\)$/\2/p' \
             | grep -v '^<' | sort -u)
  done
  echo "$out"
}

# Extract a package (+ its missing lib closure) into $PREFIX and wrap its binary.
install_deb_user() {
  local binary="$1" package="$2"
  # A genuine system install (not our wrapper) short-circuits.
  local existing; existing="$(command -v "$binary" 2>/dev/null || true)"
  case "$existing" in "${LOCAL_BIN}/"*) existing="" ;; esac
  if [ -n "$existing" ] && [ ! -e "${STAMP_DIR}/${binary}" ]; then
    log "$binary already present (${existing})"; return
  fi
  # Our own install: skip when the wrapper template is current and the wrapped
  # target still exists. Bump WRAPPER_VERSION whenever the template changes so
  # existing installs are re-wrapped automatically.
  if [ -e "${STAMP_DIR}/${binary}" ]; then
    read -r stamp_version relative < "${STAMP_DIR}/${binary}"
    if [ "$stamp_version" = "$WRAPPER_VERSION" ] && [ -x "${PREFIX}/${relative}" ]; then
      log "$binary already installed"; return
    fi
  fi
  head "$binary (deb extract: ${package})"

  local pkgs tmp
  pkgs="$(missing_closure "$package")"
  tmp="$(mktemp -d)"
  ( cd "$tmp" && apt-get download $pkgs >/dev/null 2>&1 )
  local count=0 deb
  for deb in "$tmp"/*.deb; do
    [ -e "$deb" ] || continue
    dpkg-deb -x "$deb" "$PREFIX" >/dev/null 2>&1 && count=$((count+1))
  done
  rm -rf "$tmp"

  local target=""
  local candidate
  for candidate in \
      "${PREFIX}/usr/bin/${binary}" \
      "${PREFIX}/usr/sbin/${binary}" \
      "${PREFIX}/sbin/${binary}" \
      "${PREFIX}/bin/${binary}"; do
    if [ -x "$candidate" ]; then target="$candidate"; break; fi
  done
  if [ -z "$target" ]; then
    log "!! ${binary} binary not found after extracting ${package}"
    return 1
  fi
  # Path of the binary relative to the prefix, for the wrapper to exec.
  local relative="${target#"${PREFIX}/"}"
  cat > "${LOCAL_BIN}/${binary}" <<WRAP
#!/usr/bin/env bash
# User-space wrapper: private libs extracted from .deb packages. The samba
# sub-directory is needed for tools (hydra) whose SMB backend links private
# samba libraries that live outside the standard lib dir.
PREFIX="\${HOME}/.local/opt/obsidian-tools"
export LD_LIBRARY_PATH="\$PREFIX/usr/lib/x86_64-linux-gnu:\$PREFIX/usr/lib/x86_64-linux-gnu/samba:\$PREFIX/lib/x86_64-linux-gnu:\$PREFIX/usr/lib:\$PREFIX/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
exec "\$PREFIX/${relative}" "\$@"
WRAP
  chmod +x "${LOCAL_BIN}/${binary}"
  printf '%s %s' "$WRAPPER_VERSION" "$relative" > "${STAMP_DIR}/${binary}"
  log "${binary} installed (${count} packages extracted)"
}

install_user() {
  head "User-space install (no root required)"
  ensure_local_bin
  install_sqlmap_user
  install_gobuster_user
  install_ffuf_user
  install_katana_user
  install_nikto_user
  install_python_extras_user
  local entry
  for entry in "${USER_DEB_TOOLS[@]}"; do
    install_deb_user "${entry%%:*}" "${entry##*:}"
  done
}

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
MODE="auto"
case "${1:-}" in
  --verify) verify; exit 0;;
  --user)   MODE="user";;
  --apt)    MODE="apt";;
  --help|-h)
    sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0;;
  "") ;;
  *) echo "unknown option: $1" >&2; exit 2;;
esac

if [ "$MODE" = "auto" ]; then
  if [ "$(id -u)" -eq 0 ] || sudo -n true 2>/dev/null; then MODE="apt"; else MODE="user"; fi
fi

if [ "$MODE" = "apt" ]; then
  install_apt || { log "apt path failed — falling back to user-space"; install_user; }
else
  install_user
fi

verify

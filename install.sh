#!/usr/bin/env bash
#
# install.sh — installs recon-pipeline dependencies on Debian/Kali systems.
#
# Usage:
#   ./install.sh          # full install (apt + go fallback)
#   ./install.sh --check  # verify-only, performs no installs
#
set -euo pipefail

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else
    echo "[ERROR] Run this script as root or with sudo." >&2; exit 1
  fi
fi

check_distro() {
  if [ ! -f /etc/os-release ]; then
    echo "[ERROR] /etc/os-release not found — unsupported system." >&2; exit 1
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${ID_LIKE:-}" in
    *debian*|*kali*) : ;;
    *) echo "[ERROR] Unsupported distro: ${PRETTY_NAME:-unknown} (Debian/Kali only)." >&2; exit 1 ;;
  esac
  echo "[+] Distro OK: ${PRETTY_NAME:-unknown}"
}

ensure_python() {
  if command -v python3 >/dev/null 2>&1; then
    echo "[+] python3: $(python3 --version)"
  else
    echo "[*] Installing python3..."
    $SUDO apt-get install -y python3 python3-pip python3-venv
  fi
}

ensure_go() {
  if command -v go >/dev/null 2>&1; then
    echo "[+] go: $(go version)"
  else
    echo "[*] Installing golang-go..."
    $SUDO apt-get install -y golang-go
  fi
  export PATH="$(go env GOPATH)/bin:$PATH"
  echo "[+] Go binary dir: $(go env GOPATH)/bin"
}

install_apt() {
  echo "[*] apt: installing $1 ..."
  $SUDO apt-get install -y "$1"
}

install_go_tool() {
  local name="$1" module="$2"
  echo "[*] go install: $name ..."
  go install -v "${module}@latest"
  if [ -x "$(go env GOPATH)/bin/$name" ]; then
    echo "[+] $name installed via go."
  else
    echo "[ERROR] $name failed to install via go install." >&2
    return 1
  fi
}

ensure_tool() {
  # ensure_tool NAME GO_MODULE [APT_PACKAGE ...]
  local name="$1" module="$2"; shift 2
  if command -v "$name" >/dev/null 2>&1; then
    echo "[+] $name: $(command -v "$name")"
    return 0
  fi
  local pkg
  for pkg in "$@"; do
    if install_apt "$pkg" && command -v "$name" >/dev/null 2>&1; then
      echo "[+] $name installed from apt."
      return 0
    fi
  done
  install_go_tool "$name" "$module"
  command -v "$name" >/dev/null 2>&1
}

ensure_httpx() {
  # Kali ships the PD httpx binary as "httpx-toolkit"; upstream go-install
  # produces "httpx". Accept either.
  if command -v httpx-toolkit >/dev/null 2>&1; then
    echo "[+] httpx-toolkit: $(command -v httpx-toolkit)"; return 0
  fi
  if command -v httpx >/dev/null 2>&1; then
    echo "[+] httpx (upstream): $(command -v httpx)"; return 0
  fi
  if install_apt httpx-toolkit && command -v httpx-toolkit >/dev/null 2>&1; then
    echo "[+] httpx-toolkit installed from apt."; return 0
  fi
  install_go_tool httpx "github.com/projectdiscovery/httpx/cmd/httpx"
  command -v httpx >/dev/null 2>&1
}

verify_all() {
  echo ""
  echo "========================================"
  echo " Installed versions"
  echo "========================================"
  for t in subfinder httpx-toolkit httpx dnsx katana; do
    if command -v "$t" >/dev/null 2>&1; then
      echo "[+] $t: $("$t" -version 2>&1 | head -n1 || true)"
    fi
  done
  echo ""
  echo "[INFO] Tools installed via 'go install' live in \$(go env GOPATH)/bin."
  echo "       Add it to PATH permanently:"
  echo "       echo 'export PATH=\"\$(go env GOPATH)/bin:\$PATH\"' >> ~/.bashrc"
}

main() {
  check_distro
  if [ "${1:-}" = "--check" ]; then
    bash scripts/check_dependencies.sh
    exit $?
  fi
  $SUDO apt-get update
  ensure_python
  ensure_go
  ensure_tool subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" subfinder
  ensure_httpx
  ensure_tool dnsx "github.com/projectdiscovery/dnsx/cmd/dnsx" dnsx
  ensure_tool katana "github.com/projectdiscovery/katana/cmd/katana@latest" katana
#   ensure_tool mantra "github.com/Brosck/mantra"
  verify_all
}

main "$@"
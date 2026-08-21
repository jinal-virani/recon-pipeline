#!/usr/bin/env bash
#
# check_dependencies.sh — verify every required tool is present.
# Used by install.sh --check and by recon.py's dependency check.
#
set -u

REQUIRED_CMDS=(python3 go subfinder dnsx katana)
# httpx-toolkit OR httpx (either satisfies the httpx requirement)
REQUIRED_HTTPX=(httpx-toolkit httpx)

fail=0

echo "[*] Checking dependencies..."

for cmd in "${REQUIRED_CMDS[@]}"; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "[+] $cmd: $(command -v "$cmd")"
  else
    echo "[ERROR] $cmd is not installed."
    fail=1
  fi
done

httpx_ok=0
for cmd in "${REQUIRED_HTTPX[@]}"; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "[+] $cmd: $(command -v "$cmd")"
    httpx_ok=1
    break
  fi
done
if [ "$httpx_ok" -eq 0 ]; then
  echo "[ERROR] Neither httpx-toolkit nor httpx is installed."
  echo "[INFO]  Run ./install.sh"
  fail=1
fi

if [ "$fail" -eq 1 ]; then
  echo ""
  echo "[INFO] Missing tools can be installed with: ./install.sh"
  exit 1
fi

echo ""
echo "[+] All dependencies present."
exit 0
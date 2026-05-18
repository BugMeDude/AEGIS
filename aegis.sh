#!/usr/bin/env bash
# AEGIS convenience launcher — runs without installing.
#   ./aegis.sh doctor
#   ./aegis.sh autopilot "http://127.0.0.1:8799/api" --goal baseline
#   ./aegis.sh gui
set -euo pipefail
cd "$(dirname "$0")"
exec python3 -m aegis "$@"

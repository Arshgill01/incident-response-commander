#!/usr/bin/env bash
# ============================================================
# reset-demo.sh — Full environment reset for clean demo runs
#
# Clears all simulated events and metrics, recreates indices,
# and seeds baseline data. Run this between demo sessions.
#
# Usage: bash demo/reset-demo.sh [--hard]
#   --hard : also delete and recreate the Elasticsearch indices
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m';  YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m';      RESET='\033[0m'

info()    { echo -e "${CYAN}[reset]${RESET} $*"; }
success() { echo -e "${GREEN}[reset]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[warn]${RESET} $*"; }
error()   { echo -e "${RED}[error]${RESET} $*" >&2; }

HARD_RESET=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --hard) HARD_RESET=true; shift ;;
    -h|--help)
      echo "Usage: $0 [--hard]"
      echo "  --hard  Delete and recreate indices (removes ALL data)"
      exit 0 ;;
    *) error "Unknown argument: $1"; exit 1 ;;
  esac
done

# ── Pre-flight ────────────────────────────────────────────────
if [[ ! -f "$ROOT_DIR/.env" ]]; then
  error ".env not found. Copy .env.example → .env first."
  exit 1
fi

echo ""
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${YELLOW}  Incident Response Commander — Demo Reset${RESET}"
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════${RESET}"
echo ""

if [[ "$HARD_RESET" == "true" ]]; then
  warn "HARD RESET: All data in security-simulated-events,"
  warn "            incident-response-log and incident-metrics"
  warn "            will be DELETED and recreated."
  echo ""
  read -p "Are you sure? (y/N) " CONFIRM
  [[ "${CONFIRM,,}" == "y" ]] || { info "Aborted."; exit 0; }
fi

# ── Reset indices ─────────────────────────────────────────────
if [[ "$HARD_RESET" == "true" ]]; then
  info "Deleting and recreating indices..."
  python3 "$SCRIPT_DIR/setup-indices.py" --reset
  success "Indices recreated."
else
  info "Verifying indices exist (soft reset)..."
  python3 "$SCRIPT_DIR/setup-indices.py" --verify || {
    warn "Indices missing — running setup..."
    python3 "$SCRIPT_DIR/setup-indices.py"
  }
fi

# ── Seed baseline metrics ─────────────────────────────────────
info "Seeding baseline metrics data..."
python3 "$SCRIPT_DIR/setup-indices.py" --seed
success "Baseline metrics seeded."

# ── Verify connection ─────────────────────────────────────────
info "Running connection test..."
python3 "$SCRIPT_DIR/test-connection.py" && success "Connection verified." || {
  error "Connection test failed. Check your .env credentials."
  exit 1
}

echo ""
echo -e "${GREEN}${BOLD}Reset complete!${RESET}"
echo ""
echo "You can now run a fresh demo:"
echo "  bash demo/run-demo.sh                     # full APT kill-chain"
echo "  bash demo/run-demo.sh --type brute_force  # targeted attack"
echo "  bash demo/run-demo.sh --dry-run           # no data injected"
echo ""

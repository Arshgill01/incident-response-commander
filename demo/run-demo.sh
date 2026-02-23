#!/usr/bin/env bash
# ============================================================
# run-demo.sh — Incident Response Commander full end-to-end demo
# Usage: bash demo/run-demo.sh [--type <attack_type>] [--no-watch] [--dry-run]
#
# Attack types: brute_force | exfiltration | privilege_escalation
#               lateral_movement | apt_attack  (default: apt_attack)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DEMO_DIR="$SCRIPT_DIR"

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m';  YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m';      RESET='\033[0m'

info()    { echo -e "${CYAN}[demo]${RESET} $*"; }
success() { echo -e "${GREEN}[demo]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[warn]${RESET} $*"; }
error()   { echo -e "${RED}[error]${RESET} $*" >&2; }
banner()  { echo -e "\n${BOLD}${CYAN}$*${RESET}\n"; }

# ── Defaults ──────────────────────────────────────────────────
ATTACK_TYPE="apt_attack"
DRY_RUN=false
SKIP_SETUP=false

# ── Argument parsing ──────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --type)       ATTACK_TYPE="$2"; shift 2 ;;
    --dry-run)    DRY_RUN=true;     shift ;;
    --skip-setup) SKIP_SETUP=true;  shift ;;
    -h|--help)
      echo "Usage: $0 [--type <attack_type>] [--dry-run] [--skip-setup]"
      echo ""
      echo "Attack types:"
      echo "  brute_force          Classic credential stuffing attack"
      echo "  exfiltration         Large outbound data transfer"
      echo "  privilege_escalation Sudo / root escalation"
      echo "  lateral_movement     Multi-host SSH pivot (T1021)"
      echo "  apt_attack           Full 6-stage APT kill-chain (default)"
      exit 0
      ;;
    *) error "Unknown argument: $1"; exit 1 ;;
  esac
done

# ── Validate attack type ──────────────────────────────────────
VALID_TYPES=("brute_force" "exfiltration" "privilege_escalation" "lateral_movement" "apt_attack")
VALID=false
for t in "${VALID_TYPES[@]}"; do [[ "$t" == "$ATTACK_TYPE" ]] && VALID=true; done
if [[ "$VALID" == "false" ]]; then
  error "Invalid attack type: '$ATTACK_TYPE'"
  echo "Valid types: ${VALID_TYPES[*]}"
  exit 1
fi

# ── Pre-flight: .env ──────────────────────────────────────────
if [[ ! -f "$ROOT_DIR/.env" ]]; then
  error ".env file not found at $ROOT_DIR/.env"
  echo "Copy .env.example → .env and fill in your credentials."
  exit 1
fi
# shellcheck disable=SC1090
source "$ROOT_DIR/.env"

if [[ -z "${ELASTIC_CLOUD_ID:-}" ]]; then
  error "ELASTIC_CLOUD_ID not set in .env"
  exit 1
fi

# ── Pre-flight: Python ────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  error "python3 not found. Install Python 3.9+."
  exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" 2>/dev/null; then
  success "Python $PYTHON_VERSION OK"
else
  error "Python 3.9+ required (found $PYTHON_VERSION)"
  exit 1
fi

# ── Pre-flight: dependencies ──────────────────────────────────
info "Checking Python dependencies..."
python3 -c "import elasticsearch, dotenv, requests" 2>/dev/null || {
  warn "Some dependencies missing. Installing..."
  pip3 install -q -r "$ROOT_DIR/requirements.txt"
}

# ── HEADER ────────────────────────────────────────────────────
clear
echo -e "${BOLD}${CYAN}"
cat <<'EOF'
  ___            _     _         _     ___
 |_ _|_ __   ___(_) __| | ___ _ | |_  | _ \ ___ ___ _ __   ___  _ _  ___ ___
  | || '_ \ / __| |/ _` |/ _ \ || __|  |   // -_|_-<| '_ \ / _ \| ' \(_-</ -_)
 |___|_| |_|\___| |\__,_|\___/ \__|   |_|_\\___/__/_| .__/ \___/|_||_/__/\___|
           |__/                               |_|
            C O M M A N D E R
EOF
echo -e "${RESET}"
echo -e "${BOLD}Elastic Agent Builder Hackathon — Autonomous Incident Response${RESET}"
echo "Attack simulation: ${BOLD}${ATTACK_TYPE}${RESET}"
echo "Dry run:           ${DRY_RUN}"
echo ""
echo "──────────────────────────────────────────────────────────"

# ── STEP 1: Setup indices ─────────────────────────────────────
if [[ "$SKIP_SETUP" == "false" ]]; then
  banner "STEP 1/4 — Setting up Elasticsearch indices"
  python3 "$DEMO_DIR/setup-indices.py" --verify || {
    info "Indices not found or need creation. Running setup..."
    python3 "$DEMO_DIR/setup-indices.py"
  }
  success "Indices ready."
else
  info "Skipping index setup (--skip-setup)"
fi

# ── STEP 2: Simulate attack ───────────────────────────────────
banner "STEP 2/4 — Simulating ${ATTACK_TYPE} attack"
if [[ "$DRY_RUN" == "true" ]]; then
  warn "[DRY RUN] Skipping event injection."
else
  python3 "$DEMO_DIR/incident-simulator.py" "$ATTACK_TYPE"
  success "Attack events injected into Elasticsearch."
fi

# ── STEP 3: Run orchestrator ──────────────────────────────────
banner "STEP 3/4 — Orchestrator: Detection → Investigation → Response"

ORCH_FLAGS=""
[[ "$DRY_RUN" == "true" ]] && ORCH_FLAGS="--dry-run"

python3 "$DEMO_DIR/orchestrator.py" $ORCH_FLAGS

# ── STEP 4: Print scorecard ───────────────────────────────────
banner "STEP 4/4 — MTTD / MTTR Scorecard"
python3 "$DEMO_DIR/orchestrator.py" --report

echo ""
echo "══════════════════════════════════════════════════════════"
success "Demo complete!"
echo ""
echo "What just happened:"
echo "  1. Index setup confirmed  ✅"
echo "  2. ${ATTACK_TYPE} events injected  ✅"
echo "  3. Orchestrator ran full 3-phase pipeline  ✅"
echo "     Detection → Investigation → Response (autonomous)"
echo "  4. MTTD/MTTR scorecard printed  ✅"
echo ""
echo "Next: Open Kibana → Agent Builder to see the agents."
echo "══════════════════════════════════════════════════════════"

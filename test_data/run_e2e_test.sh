#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run_e2e_test.sh — End-to-end test for ByobScanner batch pipeline
#
# Runs against Cortex XDR using synthetic mock data (no real scanner needed).
#
# Usage:
#   bash test_data/run_e2e_test.sh                          # uses test_data/.env
#   bash test_data/run_e2e_test.sh --cortex-fqdn <fqdn> \
#     --cortex-api-key <key> --cortex-auth-id <id>          # inline creds
#   bash test_data/run_e2e_test.sh --resource-type ecr      # ECR only
#   bash test_data/run_e2e_test.sh --dry-run                # no POST to Cortex
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CACHE_FILE="${SCRIPT_DIR}/mock_findings_cache.json.gz"
ENV_FILE="${SCRIPT_DIR}/.env"

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[e2e]${NC} $*"; }
success() { echo -e "${GREEN}[e2e] ✓${NC} $*"; }
warn()    { echo -e "${YELLOW}[e2e] ⚠${NC}  $*"; }
error()   { echo -e "${RED}[e2e] ✗${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DRY_RUN=false
RESOURCE_TYPE=""
EXTRA_FLAGS=()
CORTEX_FQDN_ARG=""
CORTEX_API_KEY_ARG=""
CORTEX_AUTH_ID_ARG=""

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)          DRY_RUN=true; shift ;;
    --resource-type)    RESOURCE_TYPE="$2"; shift 2 ;;
    --cortex-fqdn)      CORTEX_FQDN_ARG="$2"; shift 2 ;;
    --cortex-api-key)   CORTEX_API_KEY_ARG="$2"; shift 2 ;;
    --cortex-auth-id)   CORTEX_AUTH_ID_ARG="$2"; shift 2 ;;
    --seed)             SEED="$2"; shift 2 ;;
  --batch-dir)        EXTRA_FLAGS+=(--batch-dir "$2"); shift 2 ;;
    --help|-h)
      grep '^#' "$0" | sed 's/^# \{0,2\}//' | tail -n +2
      exit 0
      ;;
    *) error "Unknown argument: $1"; exit 1 ;;
  esac
done

SEED="${SEED:-42}"

# ---------------------------------------------------------------------------
# Step 0 — Load .env if present and creds not already in environment
# ---------------------------------------------------------------------------
echo ""
info "============================================================"
info "  ByobScanner End-to-End Test"
info "============================================================"
echo ""

if [[ -z "${CORTEX_API_KEY:-}" && -f "$ENV_FILE" ]]; then
  info "Loading credentials from ${ENV_FILE} ..."
  # shellcheck disable=SC1090
  set -o allexport
  source "$ENV_FILE"
  set +o allexport
fi

# CLI flags override env vars
[[ -n "$CORTEX_FQDN_ARG"    ]] && export CORTEX_FQDN="$CORTEX_FQDN_ARG"
[[ -n "$CORTEX_API_KEY_ARG" ]] && export CORTEX_API_KEY="$CORTEX_API_KEY_ARG"
[[ -n "$CORTEX_AUTH_ID_ARG" ]] && export CORTEX_AUTH_ID="$CORTEX_AUTH_ID_ARG"

# ---------------------------------------------------------------------------
# Step 1 — Validate environment
# ---------------------------------------------------------------------------
info "Step 1/5 — Validating environment ..."

MISSING=()
[[ -z "${CORTEX_FQDN:-}"    ]] && MISSING+=(CORTEX_FQDN)
[[ -z "${CORTEX_API_KEY:-}" ]] && MISSING+=(CORTEX_API_KEY)
[[ -z "${CORTEX_AUTH_ID:-}" ]] && MISSING+=(CORTEX_AUTH_ID)

if [[ ${#MISSING[@]} -gt 0 && "$DRY_RUN" == false ]]; then
  error "Missing required credentials: ${MISSING[*]}"
  echo ""
  echo "  Set them in test_data/.env:"
  echo "    cp test_data/.env.example test_data/.env"
  echo "    # then edit test_data/.env"
  echo ""
  echo "  Or pass them as flags:"
  echo "    bash test_data/run_e2e_test.sh \\"
  echo "      --cortex-fqdn   api-<tenant>.xdr.us.paloaltonetworks.com \\"
  echo "      --cortex-api-key <key> \\"
  echo "      --cortex-auth-id <id>"
  echo ""
  exit 1
fi

if $DRY_RUN; then
  warn "DRY RUN mode — no data will be posted to Cortex XDR"
fi

# Check Python is available
PYTHON="${REPO_ROOT}/.venv/bin/python3"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="$(command -v python3 2>/dev/null || true)"
fi
if [[ -z "$PYTHON" ]]; then
  error "python3 not found. Install Python 3.12+ and run: pip install -e '.[dev]'"
  exit 1
fi

# Check byob_core is importable
if ! "$PYTHON" -c "import byob_core" 2>/dev/null; then
  error "byob_core not installed. Run: pip install -e '.[dev]'"
  exit 1
fi

success "Environment OK  (python: $($PYTHON --version 2>&1))"

# ---------------------------------------------------------------------------
# Step 2 — Generate mock cache if missing
# ---------------------------------------------------------------------------
info "Step 2/5 — Checking mock cache file ..."

if [[ ! -f "$CACHE_FILE" ]]; then
  warn "Cache file not found — generating now ..."
  "$PYTHON" "${SCRIPT_DIR}/generate_mock_data.py" --seed "$SEED"
else
  CACHE_SIZE=$(du -sh "$CACHE_FILE" | cut -f1)
  success "Cache file found: ${CACHE_FILE}  (${CACHE_SIZE})"
fi

# ---------------------------------------------------------------------------
# Step 3 — Print summary
# ---------------------------------------------------------------------------
info "Step 3/5 — Cache summary ..."
SUMMARY_ARGS=(--cache-file "$CACHE_FILE")
[[ -n "$RESOURCE_TYPE" ]] && SUMMARY_ARGS+=(--resource-type "$RESOURCE_TYPE")
"$PYTHON" "${REPO_ROOT}/scripts/cache_summary.py" "${SUMMARY_ARGS[@]}" || true

# ---------------------------------------------------------------------------
# Step 4 — Build batch files
# ---------------------------------------------------------------------------
info "Step 4/5 — Building batch files from mock cache ..."

BATCH_ARGS=(
  --source aws
  --from-cache
  --cache-file "$CACHE_FILE"
  --download-only
  --yes
)
[[ -n "$RESOURCE_TYPE" ]] && BATCH_ARGS+=(--resource-type "$RESOURCE_TYPE")
[[ ${#EXTRA_FLAGS[@]} -gt 0 ]] && BATCH_ARGS+=("${EXTRA_FLAGS[@]}")

cd "$REPO_ROOT"
"$PYTHON" scripts/batch_push.py "${BATCH_ARGS[@]}"

BATCH_COUNT=$(ls .byob-batches/batch_*.json 2>/dev/null | wc -l | tr -d ' ')
success "Created ${BATCH_COUNT} batch files in .byob-batches/"

# ---------------------------------------------------------------------------
# Step 5 — Push to Cortex (or dry-run)
# ---------------------------------------------------------------------------
info "Step 5/5 — ${DRY_RUN:+[DRY RUN] }Pushing ${BATCH_COUNT} batch(es) to Cortex XDR ..."

if $DRY_RUN; then
  warn "Dry run — skipping Cortex push. Batch files are in .byob-batches/"
  echo ""
  info "To push for real, run without --dry-run:"
  echo "  bash test_data/run_e2e_test.sh"
  echo ""
  info "Or push the existing batch files directly:"
  echo "  python3 scripts/batch_push.py --push-only --yes"
  exit 0
fi

PUSH_ARGS=(
  --push-only
  --yes
  --cortex-fqdn   "${CORTEX_FQDN}"
  --cortex-api-key "${CORTEX_API_KEY}"
  --cortex-auth-id "${CORTEX_AUTH_ID}"
)
[[ ${#EXTRA_FLAGS[@]} -gt 0 ]] && PUSH_ARGS+=("${EXTRA_FLAGS[@]}")

"$PYTHON" scripts/batch_push.py "${PUSH_ARGS[@]}"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
success "============================================================"
success "  End-to-end test complete!"
success "============================================================"
echo ""
info "Verify in Cortex XDR → Vulnerability Management → Assets:"
echo "  • Filter by tag  cloud:aws             → 4,600 assets total"
echo "  • Filter by tag  resource_type:ec2_instance          → 2,000"
echo "  • Filter by tag  resource_type:ecr_container_image   → 1,500"
echo "  • Filter by tag  resource_type:lambda_function       → 1,100"
echo ""
info "To clean up test assets after verification:"
echo "  python3 scripts/expire_findings.py \\"
echo "    --cache-file test_data/mock_findings_cache.json.gz"
echo ""

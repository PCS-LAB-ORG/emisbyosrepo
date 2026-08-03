#!/usr/bin/env bash
# deploy.sh — interactive deployment for ByobScanner
#
# Usage:
#   ./scripts/deploy.sh aws
#   ./scripts/deploy.sh azure
#   ./scripts/deploy.sh both
#   ./scripts/deploy.sh aws    --delete
#   ./scripts/deploy.sh azure  --delete
#   ./scripts/deploy.sh both   --delete
#
# Multi-region: when prompted for a region, enter a single value or a
# comma-separated list — e.g.  us-east-1,us-west-2,eu-west-1
# Each region is deployed (or destroyed) as its own Terraform workspace.
#
# Deployment values are saved to .byob-state after each successful deploy
# so that --delete can auto-fill defaults without re-prompting.

set -euo pipefail

# ── colours ──────────────────────────────────────────────────────────────────
BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
RESET='\033[0m'

header()  { echo -e "\n${CYAN}${BOLD}━━  $*  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }
step()    { echo -e "\n${BOLD}[$*]${RESET}"; }
success() { echo -e "${GREEN}  ✓  $*${RESET}"; }
warn()    { echo -e "${YELLOW}  !  $*${RESET}"; }
die()     { echo -e "${RED}  ✗  $*${RESET}" >&2; exit 1; }

# ---------------------------------------------------------------------------
# ask VAR_NAME "Label" "description" ["default"]
# Uses %s (not %q) so commas in defaults are displayed as-is.
# ---------------------------------------------------------------------------
ask() {
  local _var="$1" _label="$2" _desc="$3" _default="${4:-}"
  echo -e "\n  ${BOLD}${_label}${RESET}"
  [[ -n "$_desc" ]] && echo -e "  ${DIM}${_desc}${RESET}"
  if [[ -n "$_default" ]]; then
    printf "  Enter value (leave blank for \"%s\"): " "$_default" >/dev/tty
  else
    printf "  Enter value: " >/dev/tty
  fi
  read -r _input </dev/tty
  printf -v "$_var" '%s' "${_input:-$_default}"
}

# ask_secret VAR_NAME "Label" "description"  — input is hidden
ask_secret() {
  local _var="$1" _label="$2" _desc="$3"
  echo -e "\n  ${BOLD}${_label}${RESET}"
  [[ -n "$_desc" ]] && echo -e "  ${DIM}${_desc}${RESET}"
  printf "  Enter value (hidden): " >/dev/tty
  read -rs _input </dev/tty; echo >/dev/tty
  printf -v "$_var" '%s' "$_input"
}

# ---------------------------------------------------------------------------
# split_regions INPUT_STR  →  sets global array REGIONS
# ---------------------------------------------------------------------------
split_regions() {
  local raw="${1//[[:space:]]/}"
  IFS=',' read -ra REGIONS <<< "$raw"
  if [[ ${#REGIONS[@]} -eq 0 ]]; then
    die "No regions provided."
  fi
}

# ---------------------------------------------------------------------------
# tf_workspace_select TF_DIR WORKSPACE_NAME
# ---------------------------------------------------------------------------
tf_workspace_select() {
  local dir="$1" ws="$2"
  if terraform -chdir="$dir" workspace list 2>/dev/null | grep -qE "(^|\s)${ws}(\s|$)"; then
    terraform -chdir="$dir" workspace select "$ws" >/dev/null
  else
    terraform -chdir="$dir" workspace new "$ws" >/dev/null
  fi
}

# ---------------------------------------------------------------------------
# State file — saves deploy values so --delete can auto-fill defaults.
# Format: KEY=VALUE lines (no secrets — no API keys or credentials).
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
STATE_FILE="${REPO_ROOT}/.byob-state"

state_set() {
  local key="$1" value="$2"
  # Remove any existing line for this key, then append the new one.
  if [[ -f "$STATE_FILE" ]]; then
    grep -v "^${key}=" "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE" || true
  fi
  printf '%s=%s\n' "$key" "$value" >> "$STATE_FILE"
}

state_get() {
  local key="$1" default="${2:-}"
  if [[ -f "$STATE_FILE" ]]; then
    local val
    val=$(grep "^${key}=" "$STATE_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)
    echo "${val:-$default}"
  else
    echo "$default"
  fi
}

# ---------------------------------------------------------------------------
# gen_suffix — 5 lowercase hex characters, e.g. "a3c7f"
# Uses openssl (no infinite-stream pipe) so it is safe under set -euo pipefail.
# Appended to secret names at deploy time to keep each deployment unique
# and avoid Secrets Manager / Key Vault name-reuse conflicts.
# ---------------------------------------------------------------------------
gen_suffix() {
  openssl rand -hex 3 | cut -c1-5
}

# ── argument ─────────────────────────────────────────────────────────────────
TARGET="${1:-}"
if [[ "$TARGET" != "aws" && "$TARGET" != "azure" && "$TARGET" != "both" ]]; then
  echo -e "\nUsage: ${BOLD}$0 aws | azure | both${RESET} [--delete]\n"
  exit 1
fi

DELETE=false
[[ "${2:-}" == "--delete" ]] && DELETE=true

DO_AWS=false
DO_AZURE=false
[[ "$TARGET" == "aws"   || "$TARGET" == "both" ]] && DO_AWS=true
[[ "$TARGET" == "azure" || "$TARGET" == "both" ]] && DO_AZURE=true

# ── prerequisite checks ───────────────────────────────────────────────────────
header "Checking prerequisites"

check_cmd() {
  if command -v "$1" &>/dev/null; then
    success "$1  →  $(command -v "$1")"
  else
    die "$1 is required but not installed.  $2"
  fi
}

check_cmd terraform  "https://developer.hashicorp.com/terraform/install"

if $DO_AWS;   then check_cmd aws "https://aws.amazon.com/cli/"; fi
if $DO_AZURE; then check_cmd az  "https://learn.microsoft.com/cli/azure/install-azure-cli"; fi

# =============================================================================
# DELETE (terraform destroy) — reads saved state for defaults
# =============================================================================
delete_aws() {
  header "AWS — removing all resources"
  echo -e "  ${DIM}Defaults are loaded from the last deployment (.byob-state).${RESET}"

  ask AWS_REGIONS_RAW \
    "AWS region(s) to remove" \
    "Single region or comma-separated list  (e.g.  us-east-1,us-west-2)" \
    "$(state_get aws_regions "us-east-1")"

  ask SECRET_NAME \
    "Secrets Manager secret name" \
    "Name of the secret that was stored at deploy time" \
    "$(state_get aws_secret_name "byob/cortex")"

  split_regions "$AWS_REGIONS_RAW"

  warn "This will permanently destroy all regional resources (Lambda, EventBridge, Secrets Manager)"
  warn "in: ${REGIONS[*]}"
  warn "and the shared IAM role (byob-scanner-lambda-role)."
  printf "\n  ${RED}${BOLD}Type 'yes' to confirm destruction: ${RESET}" >/dev/tty
  read -r _confirm </dev/tty
  [[ "$_confirm" != "yes" ]] && die "Aborted."

  TF_REGIONAL="${REPO_ROOT}/terraform/aws/regional"
  TF_GLOBAL="${REPO_ROOT}/terraform/aws/global"
  DIST_DIR="${REPO_ROOT}/dist"
  ZIP_PATH="${DIST_DIR}/byob_lambda.zip"
  [[ ! -f "$ZIP_PATH" ]] && ZIP_PATH="/dev/null"

  # Load filter values saved at deploy time (only needed to satisfy Terraform vars)
  SAVED_LOOKBACK="$(state_get aws_inspector2_lookback_hours "6")"

  terraform -chdir="$TF_REGIONAL" init -upgrade -input=false >/dev/null
  terraform -chdir="$TF_GLOBAL"   init -upgrade -input=false >/dev/null
  LAMBDA_ROLE_ARN=$(terraform -chdir="$TF_GLOBAL" output -raw lambda_role_arn 2>/dev/null \
    || echo "arn:aws:iam::000000000000:role/byob-scanner-lambda-role")

  for region in "${REGIONS[@]}"; do
    header "AWS [$region] — destroying regional resources"
    tf_workspace_select "$TF_REGIONAL" "$region"
    terraform -chdir="$TF_REGIONAL" destroy -auto-approve -input=false \
      -var="aws_region=${region}" \
      -var="lambda_zip_path=${ZIP_PATH}" \
      -var="cortex_secret_name=${SECRET_NAME}" \
      -var="lambda_role_arn=${LAMBDA_ROLE_ARN}" \
      -var="inspector2_lookback_hours=${SAVED_LOOKBACK}"
    success "Regional resources destroyed in $region"
  done

  header "AWS — destroying global IAM resources"
  terraform -chdir="$TF_GLOBAL" destroy -auto-approve -input=false \
    -var="cortex_secret_name=${SECRET_NAME}"
  success "Global IAM resources destroyed"

  # Clear saved AWS state
  if [[ -f "$STATE_FILE" ]]; then
    grep -v "^aws_" "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE" || true
  fi
  success "Saved AWS state cleared from .byob-state"

  header "AWS teardown complete  (${#REGIONS[@]} region(s))"
}

delete_azure() {
  header "Azure — removing all resources"
  echo -e "  ${DIM}Defaults are loaded from the last deployment (.byob-state).${RESET}"

  local DEFAULT_SUB=""
  if az account show &>/dev/null 2>&1; then
    DEFAULT_SUB=$(az account show --query id -o tsv 2>/dev/null || true)
  fi

  ask SUBSCRIPTION_ID \
    "Subscription ID" \
    "Azure subscription the resources are in" \
    "$(state_get azure_subscription_id "$DEFAULT_SUB")"

  ask LOCATIONS_RAW \
    "Azure region(s) to remove" \
    "Single region or comma-separated list  (e.g.  eastus,westeurope)" \
    "$(state_get azure_regions "eastus")"

  ask RG_BASE \
    "Resource group base name" \
    "Base used at deploy time — region suffix appended automatically" \
    "$(state_get azure_rg_base "byob-scanner-rg")"

  ask FUNC_BASE \
    "Function App base name" \
    "Base used at deploy time — region suffix appended automatically" \
    "$(state_get azure_func_base "byob-scanner-func")"

  ask KV_BASE \
    "Key Vault base name" \
    "Base used at deploy time — region suffix appended automatically" \
    "$(state_get azure_kv_base "byobscannerkv")"

  ask STORAGE_BASE \
    "Storage account base name" \
    "Base used at deploy time — region suffix appended automatically" \
    "$(state_get azure_storage_base "byobstorage")"

  ask SECRET_NAME \
    "Key Vault secret name" \
    "Name of the secret" \
    "$(state_get azure_secret_name "cortex-credentials")"

  split_regions "$LOCATIONS_RAW"

  warn "This will permanently destroy the Function App, Key Vault, Storage account,"
  warn "App Service plan, Event Grid topic, and resource group in: ${REGIONS[*]}"
  printf "\n  ${RED}${BOLD}Type 'yes' to confirm destruction: ${RESET}" >/dev/tty
  read -r _confirm </dev/tty
  [[ "$_confirm" != "yes" ]] && die "Aborted."

  TF_AZURE="${REPO_ROOT}/terraform/azure"
  terraform -chdir="$TF_AZURE" init -upgrade -input=false >/dev/null

  for loc in "${REGIONS[@]}"; do
    local safe="${loc//-/}"
    local rg="${RG_BASE}-${loc}"
    local func="${FUNC_BASE}-${loc}"
    local kv="${KV_BASE}${safe}"; kv="${kv:0:24}"
    local sa="${STORAGE_BASE}${safe}"; sa="${sa:0:24}"

    header "Azure [$loc] — destroying"
    tf_workspace_select "$TF_AZURE" "$loc"
    terraform -chdir="$TF_AZURE" destroy -auto-approve -input=false \
      -var="subscription_id=${SUBSCRIPTION_ID}" \
      -var="storage_account_name=${sa}" \
      -var="location=${loc}" \
      -var="resource_group_name=${rg}" \
      -var="function_app_name=${func}" \
      -var="key_vault_name=${kv}" \
      -var="cortex_secret_name=${SECRET_NAME}"
    success "Resources destroyed in $loc"
  done

  # Clear saved Azure state
  if [[ -f "$STATE_FILE" ]]; then
    grep -v "^azure_" "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE" || true
  fi
  success "Saved Azure state cleared from .byob-state"

  header "Azure teardown complete  (${#REGIONS[@]} region(s))"
}

# =============================================================================
# DELETE path
# =============================================================================
if $DELETE; then
  if $DO_AWS;   then delete_aws;   fi
  if $DO_AZURE; then delete_azure; fi
  echo
  echo -e "${GREEN}${BOLD}Teardown complete.${RESET}"
  echo
  exit 0
fi

# =============================================================================
# DEPLOY path
# =============================================================================
check_cmd python3    "Install Python 3.12+"
check_cmd zip        "brew install zip  /  apt install zip"

header "Cortex XDR credentials"
echo -e "  ${DIM}Settings → Configurations → API Keys in your Cortex XDR tenant."
echo -e "  Create a Standard key with the Vulnerability Management (Exposure Management) scope.${RESET}"

ask_secret CORTEX_API_KEY \
  "API key" \
  "Paste the API key value (characters will not be shown)"

ask CORTEX_AUTH_ID \
  "API key ID" \
  "Numeric ID listed next to the key in the XDR console"

ask CORTEX_FQDN \
  "Cortex API URL" \
  "Shown in Settings → API Keys — e.g.  https://api-tenant.xdr.us.paloaltonetworks.com"

CORTEX_JSON=$(printf '{"cortex_api_key":"%s","cortex_auth_id":"%s","cortex_fqdn":"%s"}' \
  "$CORTEX_API_KEY" "$CORTEX_AUTH_ID" "$CORTEX_FQDN")

success "Credentials collected (not written to disk)"

# =============================================================================
# AWS — deploy one workspace per region
# =============================================================================
deploy_aws() {
  header "AWS — configuration"
  echo -e "  ${DIM}Press Enter on any prompt to keep the default value shown.${RESET}"

  ask AWS_REGIONS_RAW \
    "AWS region(s)" \
    "Single region or comma-separated list  (e.g.  us-east-1,us-west-2,eu-west-1)" \
    "$(state_get aws_regions "us-east-1")"

  ask SECRET_NAME \
    "Secrets Manager secret name" \
    "Path where the Cortex credentials JSON will be stored" \
    "$(state_get aws_secret_name "byob/cortex")"

  # Append a random 5-char suffix so each deployment gets a unique secret name
  # and avoids Secrets Manager recovery-window conflicts on redeploy.
  SECRET_NAME="${SECRET_NAME}-$(gen_suffix)"
  echo -e "  ${DIM}Secret name with suffix:  ${BOLD}${SECRET_NAME}${RESET}"

  split_regions "$AWS_REGIONS_RAW"

  # ── save state (no secrets) ───────────────────────────────────────────────
  state_set aws_regions                   "$AWS_REGIONS_RAW"
  state_set aws_secret_name               "$SECRET_NAME"
  success "Configuration saved to .byob-state"

  # ── step 1: build Lambda zip ──────────────────────────────────────────────
  step "1/4  Building Lambda package"

  DIST_DIR="${REPO_ROOT}/dist"
  PKG_DIR="${DIST_DIR}/lambda_pkg"
  ZIP_PATH="${DIST_DIR}/byob_lambda.zip"

  rm -rf "$PKG_DIR" && mkdir -p "$PKG_DIR"

  python3 -m pip install "${REPO_ROOT}" \
    --target "$PKG_DIR" \
    --platform manylinux2014_x86_64 \
    --python-version 3.12 \
    --only-binary=:all: \
    --no-cache-dir \
    --upgrade \
    --quiet

  cp "${REPO_ROOT}/aws_lambda/handler.py" "$PKG_DIR/"
  (cd "$PKG_DIR" && zip -r "$ZIP_PATH" . -x "*.pyc" -x "__pycache__/*" -x "*.dist-info/*" >/dev/null)
  success "Lambda zip → $ZIP_PATH"

  # ── step 2: global IAM ────────────────────────────────────────────────────
  step "2/4  Applying global Terraform resources (IAM)"

  TF_GLOBAL="${REPO_ROOT}/terraform/aws/global"
  terraform -chdir="$TF_GLOBAL" init -upgrade -input=false >/dev/null
  terraform -chdir="$TF_GLOBAL" apply -auto-approve -input=false \
    -var="cortex_secret_name=${SECRET_NAME}"
  LAMBDA_ROLE_ARN=$(terraform -chdir="$TF_GLOBAL" output -raw lambda_role_arn)
  success "IAM role ready  →  $LAMBDA_ROLE_ARN"

  # ── steps 3 & 4: regional resources + secret ─────────────────────────────
  TF_REGIONAL="${REPO_ROOT}/terraform/aws/regional"
  terraform -chdir="$TF_REGIONAL" init -upgrade -input=false >/dev/null

  for region in "${REGIONS[@]}"; do
    step "3/4  Applying regional Terraform (AWS / $region)"
    tf_workspace_select "$TF_REGIONAL" "$region"
    terraform -chdir="$TF_REGIONAL" apply -auto-approve -input=false \
      -var="aws_region=${region}" \
      -var="lambda_zip_path=${ZIP_PATH}" \
      -var="cortex_secret_name=${SECRET_NAME}" \
      -var="lambda_role_arn=${LAMBDA_ROLE_ARN}" \
      -var="inspector2_lookback_hours=6"
    success "Terraform apply complete  [$region]"

    step "4/4  Storing credentials in Secrets Manager ($region)"
    aws secretsmanager put-secret-value \
      --region    "$region" \
      --secret-id "$SECRET_NAME" \
      --secret-string "$CORTEX_JSON"
    success "Secret stored  →  $region / $SECRET_NAME"
  done

  header "AWS deployment complete  (${#REGIONS[@]} region(s))"
  for region in "${REGIONS[@]}"; do
    echo -e "\n  ${DIM}Outputs — $region${RESET}"
    tf_workspace_select "$TF_REGIONAL" "$region" 2>/dev/null
    terraform -chdir="$TF_REGIONAL" output
  done
}

# =============================================================================
# AZURE — deploy one workspace per region
# =============================================================================
deploy_azure() {
  header "Azure — configuration"
  echo -e "  ${DIM}Press Enter on any prompt to keep the default value shown.${RESET}"

  local DEFAULT_SUB=""
  if az account show &>/dev/null 2>&1; then
    DEFAULT_SUB=$(az account show --query id -o tsv 2>/dev/null || true)
  fi

  ask SUBSCRIPTION_ID \
    "Subscription ID" \
    "Azure subscription to deploy into  (run: az account show --query id -o tsv)" \
    "$(state_get azure_subscription_id "$DEFAULT_SUB")"

  ask LOCATIONS_RAW \
    "Azure region(s)" \
    "Single region or comma-separated list  (e.g.  eastus,westeurope,australiaeast)" \
    "$(state_get azure_regions "eastus")"

  ask RG_BASE \
    "Resource group base name" \
    "The region name is appended automatically  →  byob-scanner-rg-eastus" \
    "$(state_get azure_rg_base "byob-scanner-rg")"

  ask FUNC_BASE \
    "Function App base name" \
    "The region name is appended automatically  →  byob-scanner-func-eastus" \
    "$(state_get azure_func_base "byob-scanner-func")"

  ask KV_BASE \
    "Key Vault base name" \
    "Hyphens stripped, region appended  →  byobscannerkv<region>  (max 24 chars)" \
    "$(state_get azure_kv_base "byobscannerkv")"

  ask STORAGE_BASE \
    "Storage account base name" \
    "Hyphens stripped, region appended  →  byobstorage<region>  (max 24 chars)" \
    "$(state_get azure_storage_base "byobstorage")"

  ask SECRET_NAME \
    "Key Vault secret name" \
    "Name of the secret that will hold the Cortex credentials JSON" \
    "$(state_get azure_secret_name "cortex-credentials")"

  # Append a random 5-char suffix so each deployment gets a unique secret name.
  SECRET_NAME="${SECRET_NAME}-$(gen_suffix)"
  echo -e "  ${DIM}Secret name with suffix:  ${BOLD}${SECRET_NAME}${RESET}"

  split_regions "$LOCATIONS_RAW"

  # ── save state ────────────────────────────────────────────────────────────
  state_set azure_subscription_id "$SUBSCRIPTION_ID"
  state_set azure_regions         "$LOCATIONS_RAW"
  state_set azure_rg_base         "$RG_BASE"
  state_set azure_func_base       "$FUNC_BASE"
  state_set azure_kv_base         "$KV_BASE"
  state_set azure_storage_base    "$STORAGE_BASE"
  state_set azure_secret_name     "$SECRET_NAME"
  success "Configuration saved to .byob-state"

  # ── build the Azure Function zip once ────────────────────────────────────
  mkdir -p "${REPO_ROOT}/dist"
  AZ_ZIP="${REPO_ROOT}/dist/byob_azure.zip"
  (cd "${REPO_ROOT}/azure_function" && zip -r "$AZ_ZIP" . -x "*.pyc" -x "__pycache__/*" >/dev/null)
  success "Azure Function zip → $AZ_ZIP"

  TF_AZURE="${REPO_ROOT}/terraform/azure"
  terraform -chdir="$TF_AZURE" init -upgrade -input=false >/dev/null

  for loc in "${REGIONS[@]}"; do
    local safe="${loc//-/}"
    local rg="${RG_BASE}-${loc}"
    local func="${FUNC_BASE}-${loc}"
    local kv="${KV_BASE}${safe}"; kv="${kv:0:24}"
    local sa="${STORAGE_BASE}${safe}"; sa="${sa:0:24}"

    step "1/3  Applying Terraform (Azure / $loc)"
    tf_workspace_select "$TF_AZURE" "$loc"
    terraform -chdir="$TF_AZURE" apply -auto-approve -input=false \
      -var="subscription_id=${SUBSCRIPTION_ID}" \
      -var="storage_account_name=${sa}" \
      -var="location=${loc}" \
      -var="resource_group_name=${rg}" \
      -var="function_app_name=${func}" \
      -var="key_vault_name=${kv}" \
      -var="cortex_secret_name=${SECRET_NAME}"
    success "Terraform apply complete  [$loc]"

    step "2/3  Storing credentials in Key Vault ($loc)"
    az keyvault secret set \
      --vault-name "$kv" \
      --name       "$SECRET_NAME" \
      --value      "$CORTEX_JSON" \
      --output none
    success "Secret stored  →  $kv / $SECRET_NAME"

    step "3/3  Deploying Azure Function code ($loc)"
    az functionapp deployment source config-zip \
      --resource-group "$rg" \
      --name           "$func" \
      --src            "$AZ_ZIP" \
      --output none
    success "Function App code deployed  [$loc]"
  done

  header "Azure deployment complete  (${#REGIONS[@]} region(s))"
  for loc in "${REGIONS[@]}"; do
    echo -e "\n  ${DIM}Outputs — $loc${RESET}"
    tf_workspace_select "$TF_AZURE" "$loc" 2>/dev/null
    terraform -chdir="$TF_AZURE" output
  done
}

# =============================================================================
# RUN
# =============================================================================
$DO_AWS   && deploy_aws
$DO_AZURE && deploy_azure

echo
echo -e "${GREEN}${BOLD}All done.${RESET}  The scanners run every 6 hours automatically."
echo
echo -e "  To verify with a dry run (no Cortex POST):"
if $DO_AWS;   then echo -e "    ${DIM}AWS  ${RESET} python scripts/integration_test.py --source aws   --dry-run"; fi
if $DO_AZURE; then echo -e "    ${DIM}Azure${RESET} python scripts/integration_test.py --source azure --dry-run"; fi
echo

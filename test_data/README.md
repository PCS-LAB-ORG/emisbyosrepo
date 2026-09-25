# Test Data — End-to-End Testing Guide

This folder contains everything needed to run a full end-to-end test of the
ByobScanner batch pipeline against Cortex XDR using synthetic data — no real
AWS or Azure credentials required.

---

## Contents

| File | Description |
|---|---|
| `generate_mock_data.py` | Generates `mock_findings_cache.json.gz` — 4,600 assets, 71k findings, 103 batches |
| `mock_findings_cache.json.gz` | Generated cache file — **gitignored**, run `generate_mock_data.py` to create |
| `.env.example` | Template for your Cortex credentials |
| `run_e2e_test.sh` | One-command end-to-end test runner (generate → batch → push → verify) |

---

## Quick Start

```bash
# 1. Install dependencies (first time only)
pip install -e ".[dev]"

# 2. Copy the env template and fill in your Cortex credentials
cp test_data/.env.example test_data/.env

# 3. Edit test_data/.env with your real values
open test_data/.env   # or use any editor

# 4. Generate the mock cache file
python3 test_data/generate_mock_data.py

# 5. Run the full end-to-end test
bash test_data/run_e2e_test.sh
```

---

## Step 1 — Configure Cortex Credentials

Credentials can be supplied in three ways (checked in order):

### Option A — `.env` file (recommended for local testing)

Copy the template and fill in your values:

```bash
cp test_data/.env.example test_data/.env
```

Edit `test_data/.env`:

```dotenv
CORTEX_FQDN=api-<your-tenant>.xdr.us.paloaltonetworks.com
CORTEX_API_KEY=<your-api-key>
CORTEX_AUTH_ID=<your-api-key-id>
```

The `run_e2e_test.sh` script loads this file automatically before running.

> ⚠️ `test_data/.env` is gitignored — your credentials will never be committed.

### Option B — Shell environment variables

```bash
export CORTEX_FQDN="api-<your-tenant>.xdr.us.paloaltonetworks.com"
export CORTEX_API_KEY="<your-api-key>"
export CORTEX_AUTH_ID="<your-api-key-id>"
```

### Option C — CLI flags (no env setup needed)

Pass credentials directly to `batch_push.py`:

```bash
python3 scripts/batch_push.py \
  --source aws \
  --from-cache \
  --cache-file test_data/mock_findings_cache.json.gz \
  --cortex-fqdn   api-<tenant>.xdr.us.paloaltonetworks.com \
  --cortex-api-key <key> \
  --cortex-auth-id <id>
```

### Where to find your Cortex credentials

1. Log in to **Cortex XDR**
2. Go to **Settings → Configurations → API Keys**
3. Click **+ New Key** → select **Standard** → enable **Vulnerability Management** scope
4. Copy the key (shown once only), the numeric Key ID, and the API URL shown on that page

| Value | Example |
|---|---|
| `CORTEX_FQDN` | `api-abc123.xdr.us.paloaltonetworks.com` |
| `CORTEX_API_KEY` | Long alphanumeric string (shown once at creation) |
| `CORTEX_AUTH_ID` | Short numeric ID (e.g. `42`) |

---

## Step 2 — Generate the Mock Cache

```bash
# Default output: test_data/mock_findings_cache.json.gz  (~7 MB, ~1 second)
python3 test_data/generate_mock_data.py
```

What gets generated (seed 42 — reproducible):

| Asset type | Assets | Findings | Details |
|---|---|---|---|
| EC2 instances | 2,000 | ~25,000 | 5 accounts × 4 regions × 100 instances; varied OS, instance type, VPC |
| Lambda functions | 1,100 | ~8,000 | 5 accounts × 4 regions × 55 functions; varied runtimes |
| ECR images | 1,500 | ~38,000 | 5 accounts × 3 repos × 100 images; varied tags, architectures |
| **Total** | **4,600** | **~71,000** | **103 batch files at 45 assets/batch** |

Options:

```bash
# Different seed → different random asset/CVE distribution
python3 test_data/generate_mock_data.py --seed 99

# Uncompressed (for manual inspection)
python3 test_data/generate_mock_data.py --out test_data/mock_findings_cache.json

# Custom output path
python3 test_data/generate_mock_data.py --out /tmp/test_findings.json.gz
```

---

## Step 3 — Inspect Before Pushing (Optional)

Before posting anything to Cortex, review the data:

```bash
# Full summary — asset counts per type, vuln counts, EXPIRES IN column
python3 scripts/cache_summary.py --cache-file test_data/mock_findings_cache.json.gz

# ECR images only
python3 scripts/cache_summary.py \
  --cache-file test_data/mock_findings_cache.json.gz \
  --resource-type ecr

# List all origin_asset_ids (check for duplicates)
python3 scripts/cache_summary.py \
  --cache-file test_data/mock_findings_cache.json.gz \
  --list-ids

# Download batch files for manual inspection (does NOT push to Cortex)
python3 scripts/batch_push.py \
  --source aws \
  --from-cache \
  --cache-file test_data/mock_findings_cache.json.gz \
  --download-only \
  --yes

# Inspect a specific batch file
cat .byob-batches/batch_0001.json | python3 -m json.tool | head -100

# Clean up batch files when done
rm -rf .byob-batches
```

---

## Step 4 — Run the End-to-End Test

### Full push (all 103 batches)

```bash
# Using .env file
bash test_data/run_e2e_test.sh

# Using env vars already exported in shell
bash test_data/run_e2e_test.sh

# Using CLI flags
bash test_data/run_e2e_test.sh \
  --cortex-fqdn   api-<tenant>.xdr.us.paloaltonetworks.com \
  --cortex-api-key <key> \
  --cortex-auth-id <id>
```

### Subset push (useful for a quick smoke test)

```bash
# Push EC2 assets only
python3 scripts/batch_push.py \
  --source aws \
  --from-cache \
  --cache-file test_data/mock_findings_cache.json.gz \
  --resource-type ec2 \
  --yes

# Push ECR images only
python3 scripts/batch_push.py \
  --source aws \
  --from-cache \
  --cache-file test_data/mock_findings_cache.json.gz \
  --resource-type ecr \
  --yes

# Push Lambda functions only
python3 scripts/batch_push.py \
  --source aws \
  --from-cache \
  --cache-file test_data/mock_findings_cache.json.gz \
  --resource-type lambda \
  --yes
```

### Resume after an interruption

If the push is interrupted (rate limit, network error), simply re-run:

```bash
bash test_data/run_e2e_test.sh
```

The script detects any remaining `.byob-batches/batch_*.json` files and
resumes from where it left off — no re-download needed.

---

## Step 5 — Verify in Cortex XDR

After the push completes, check Cortex XDR:

1. Go to **Vulnerability Management → Assets**
2. Filter by tag `cloud:aws` — you should see 4,600 new assets
3. Filter by tag `resource_type:ec2_instance` — should show 2,000 assets
4. Filter by tag `resource_type:ecr_container_image` — should show 1,500 assets
5. Filter by tag `resource_type:lambda_function` — should show 1,100 assets

Assets use the tag `source:mock_test` so they are easy to find and clean up.

### Clean up test assets

Run the expire script to clear all mock findings after testing:

```bash
python3 scripts/expire_findings.py \
  --cache-file test_data/mock_findings_cache.json.gz
```

This posts empty vulnerability lists for all 4,600 assets, which clears their
findings in Cortex immediately. The assets themselves will age out after 30 days
of no activity.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `No Cortex credentials found` | `.env` not loaded or vars not exported | Run `source test_data/.env` or use `--cortex-*` flags |
| `Payload validation failed (422)` | Malformed finding in mock data | Re-generate: `python3 test_data/generate_mock_data.py` |
| `Connection aborted / TimeoutError` | Large batch write timeout | Script retries automatically; re-run to resume |
| `Rate limit exhausted (429)` | Too many requests | Script stops and saves remaining batches; re-run to resume |
| `mock_findings_cache.json.gz not found` | Cache not generated yet | Run `python3 test_data/generate_mock_data.py` |
| `ModuleNotFoundError` | Dependencies not installed | Run `pip install -e ".[dev]"` |

---

## Environment Variable Reference

| Variable | Required | Description |
|---|---|---|
| `CORTEX_FQDN` | ✅ | Cortex API URL — e.g. `api-tenant.xdr.us.paloaltonetworks.com` |
| `CORTEX_API_KEY` | ✅ | Cortex API key (Standard key, Vulnerability Management scope) |
| `CORTEX_AUTH_ID` | ✅ | Cortex API key ID (numeric) |
| `CORTEX_SECRET_NAME` | Alternative | AWS Secrets Manager or Azure Key Vault secret name (instead of individual vars) |
| `CORTEX_KEYVAULT_URL` | With secret name | Required when using Azure Key Vault — e.g. `https://vault.vault.azure.net/` |
| `AWS_DEFAULT_REGION` | Optional | AWS region for Secrets Manager lookup (default: `us-east-1`) |

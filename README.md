# Bring Your Own Build - Scanner

Pushes vulnerability findings from **AWS Inspector2**, **Azure Defender for Cloud**, and **Tenable Vulnerability Management** to **Cortex XDR** via the Bring Your Own Scanner (BYOS) API.

```
AWS Inspector2         ──→  Lambda (Python 3.12)       ──┐
Azure Defender         ──→  Azure Function (Python 3.12) ─┼──→  Cortex XDR  (BYOS API)
Tenable Vulnerability  ──→  integration_test.py / Lambda ─┘
```

The AWS Lambda runs on a **6-hour schedule** (4 EventBridge rules, one per severity, staggered 30 min apart) and also triggers in real time on new findings. The Azure Function runs on a timer and Event Grid trigger. Tenable exports are run via the integration test script for the initial bulk import and can be wired to a Lambda or cron for delta runs. Credentials are stored in cloud-native secrets stores — no secrets in code or environment variables.

---

## Getting Started

### 1. Unzip the archive

```bash
unzip ByobScanner-share.zip
cd ByobScanner
```

### 2. Install prerequisites

| Tool | Version | Install |
|---|---|---|
| Python | 3.12+ | [python.org/downloads](https://www.python.org/downloads/) — macOS: `brew install python@3.12` · Windows: installer · Linux: `apt/yum install python3.12` |
| Terraform | 1.5+ | [developer.hashicorp.com/terraform/install](https://developer.hashicorp.com/terraform/install) — macOS: `brew install terraform` · Windows: `choco install terraform` · Linux: see HashiCorp APT/YUM repo |
| AWS CLI | v2 | [docs.aws.amazon.com/cli](https://aws.amazon.com/cli/) — macOS: `brew install awscli` · Windows: MSI installer · Linux: `curl` installer (see link) |
| zip | any | Pre-installed on macOS/Linux — Windows: use WSL or `7-Zip` |

Verify everything is ready:

```bash
terraform  --version   # Terraform v1.5+
python3    --version   # Python 3.12+
aws        --version   # aws-cli/2.x
zip        --version
```

### 3. Authenticate the AWS CLI

```bash
aws configure
# or, if using SSO:
aws sso login --profile <your-profile>
```

Confirm it is working:

```bash
aws sts get-caller-identity
```

### 4. Have your Cortex XDR API credentials ready

Open Cortex XDR → **Settings → Configurations → API Keys** and create a **Standard** key with the **Vulnerability Management** permission scope. You will need:

| Value | Where to find it |
|---|---|
| API key | Shown once at creation — copy it now |
| API key ID | Numeric ID shown next to the key |
| API URL | Shown in the API Keys settings page — e.g. `api-tenant.xdr.us.paloaltonetworks.com` |

### 5. Deploy to AWS

Run the interactive deploy script:

```bash
chmod +x scripts/deploy.sh
./scripts/deploy.sh aws
```

The script prompts you through every value. When it asks for an **AWS region** you can enter a **single region** or a **comma-separated list** to deploy to multiple regions at once:

```
Single region:    us-east-1
Multiple regions: us-east-1,us-west-2,eu-west-1
```

Each region is managed as its own Terraform workspace so all states are kept separate. The IAM role is a global AWS resource and is created once; the Lambda, EventBridge rule, and Secrets Manager secret are created per region.

The script performs these steps automatically:

```
[1/4]  Build dist/byob_lambda.zip  (once, shared)
         Installs byob_core dependencies for Linux x86-64
         Packages handler.py into a Lambda-ready zip

[2/4]  terraform apply  →  terraform/aws/global/  (once)
         Creates the shared IAM role + policy (byob-scanner-lambda-role)

[3/4]  terraform workspace select <region>  +  terraform apply  →  terraform/aws/regional/
         Per region: Lambda function, EventBridge schedule,
                     Secrets Manager secret placeholder

[4/4]  aws secretsmanager put-secret-value  --region <region>
         Stores your Cortex credentials in Secrets Manager
```

When it finishes you will see the Terraform outputs for each region:

```
lambda_function_name = "byob-scanner"
lambda_function_arn  = "arn:aws:lambda:us-east-1:..."
eventbridge_rule_arn = "arn:aws:events:us-east-1:..."
secret_arn           = "arn:aws:secretsmanager:us-east-1:..."
```

### 6. Verify the deployment

Run a dry-run integration test to confirm findings are collected and normalised correctly (no data is posted to Cortex):

```bash
pip install -e ".[dev]"   # install byob_core locally (first time only)

python3 scripts/integration_test.py --source aws --dry-run --region us-east-1
```

You should see a summary like:

```
INFO: Inspector2 filters — statuses: ['ACTIVE']  severities: ['MEDIUM', 'HIGH', 'CRITICAL']
INFO: Collecting from aws ...
INFO: Inspector2: 1115 raw findings — 1115 kept ...
INFO: Normalized 7 asset(s) into 1 batch(es)
INFO: Batch 1/1 — 7 asset(s), 1115 vuln(s)
INFO: --- DRY RUN: first batch payload ---
```

Override the default severity and status filters at the command line:

```bash
# Only CRITICAL findings
python3 scripts/integration_test.py --source aws --dry-run --region us-east-1 \
  --severities CRITICAL

# HIGH and CRITICAL, active findings only
python3 scripts/integration_test.py --source aws --dry-run --region us-east-1 \
  --severities HIGH,CRITICAL \
  --statuses ACTIVE
```

To do a live end-to-end test (posts to Cortex):

```bash
python3 scripts/integration_test.py --source aws --post --region us-east-1 \
  --severities HIGH,CRITICAL \
  --cortex-fqdn   api-tenant.xdr.us.paloaltonetworks.com \
  --cortex-api-key <key> \
  --cortex-auth-id <id>
```

### 7. Invoke the Lambda manually

```bash
aws lambda invoke \
  --function-name byob-scanner \
  --region us-east-1 \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  response.json && cat response.json
```

A successful response looks like:

```json
{"status": "ok", "findings_count": 1115, "batches": 1, "assets_pushed": 7, "vulnerabilities_pushed": 1115}
```

Check the logs in CloudWatch:

```bash
aws logs tail /aws/lambda/byob-scanner --follow --region us-east-1
```

---

## Teardown

To destroy all cloud resources created by the deploy script, pass `--delete`:

```bash
# Remove AWS resources
./scripts/deploy.sh aws --delete

# Remove Azure resources
./scripts/deploy.sh azure --delete

# Remove both
./scripts/deploy.sh both --delete
```

When prompted for region(s), enter the same value(s) you used at deploy time — a **single region** or a **comma-separated list**:

```
Single region:    us-east-1
Multiple regions: us-east-1,us-west-2,eu-west-1
```

The script selects the matching Terraform workspace for each region, shows a warning listing every resource that will be destroyed, and requires you to type `yes` to confirm before running `terraform destroy`.

**AWS resources removed (destroy order):**

Regional resources (per region, destroyed first):
- Lambda function (`byob-scanner`)
- EventBridge scheduled rule
- Secrets Manager secret

Global resources (destroyed last — shared across all regions):
- IAM role and policy (`byob-scanner-lambda-role`)

**Azure resources removed per region:**
- Function App
- App Service plan
- Key Vault
- Storage account
- Event Grid system topic
- Resource group

---

## Table of Contents

- [Getting Started](#getting-started)
  - [1. Unzip the archive](#1-unzip-the-archive)
  - [2. Install prerequisites](#2-install-prerequisites)
  - [3. Authenticate the AWS CLI](#3-authenticate-the-aws-cli)
  - [4. Have your Cortex XDR API credentials ready](#4-have-your-cortex-xdr-api-credentials-ready)
  - [5. Deploy to AWS](#5-deploy-to-aws)
  - [6. Verify the deployment](#6-verify-the-deployment)
  - [7. Invoke the Lambda manually](#7-invoke-the-lambda-manually)
- [Prerequisites](#prerequisites)
- [Repository structure](#repository-structure)
- [Cortex XDR credentials](#cortex-xdr-credentials)
- [Deploy](#deploy)
  - [AWS](#aws)
  - [Azure](#azure)
  - [Both clouds](#both-clouds)
- [What the script does](#what-the-script-does)
  - [Prompts — AWS](#prompts--aws)
  - [Prompts — Azure](#prompts--azure)
- [Terraform variable reference](#terraform-variable-reference)
  - [AWS — global](#aws--global-terraformawsglobal)
  - [AWS — regional](#aws--regional-terraformawsregional)
- [Environment variables reference](#environment-variables-reference)
- [Asset tags sent to Cortex XDR](#asset-tags-sent-to-cortex-xdr)
- [Tenable Vulnerability Management](#tenable-vulnerability-management)
  - [How it works](#how-it-works)
  - [Tenable credentials](#tenable-credentials)
  - [Tenable environment variables](#tenable-environment-variables)
  - [First bulk import](#first-bulk-import)
  - [Ongoing delta runs](#ongoing-delta-runs)
  - [Tenable → Cortex field mapping](#tenable--cortex-field-mapping)
  - [Tenable asset tags](#tenable-asset-tags)
- [Development setup](#development-setup)
- [Running tests](#running-tests)
- [Integration test](#integration-test)

---

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Python | 3.12+ | |
| Terraform | 1.5+ | |
| AWS CLI | v2 | authenticated; only needed for AWS deployment |
| Azure CLI | latest | `az login` done; only needed for Azure deployment |
| Cortex XDR | Exposure Management licence | BYOS API enabled |

---

## Repository structure

```
byob_core/                  shared Python library
  collectors/
    aws_inspector.py        AWS Inspector2 collector (status + severity + time filters)
    azure_defender.py       Azure Defender (Resource Graph) collector
    tenable_vm.py           Tenable VM vulnerability export collector (async export)
  cortex_client.py          Cortex BYOS POST + job status check
  models.py                 RawFinding, Credentials, JobResult dataclasses
  normalizer.py             field mapping, batching, 30-day age filter
  secrets.py                credential loader (Secrets Manager or Key Vault)
aws_lambda/
  handler.py                Lambda entry point (AWS Inspector2 + EventBridge input)
  requirements.txt
azure_function/
  function_app.py           Azure Function entry point (timer + event grid)
  host.json
  requirements.txt
terraform/
  aws/
    global/                 IAM role + policy (created once per account)
    regional/               Lambda, EventBridge rules (4 × severity), Secrets Manager
  azure/                    Function App, Key Vault, Event Grid, Managed Identity
scripts/
  deploy.sh                 interactive one-command deployment
  integration_test.py       dry-run / live test helper (aws, azure, tenable)
tests/                      unit tests (pytest)
```

---

## Cortex XDR credentials

Both functions read a single JSON secret:

```json
{
  "cortex_api_key":  "<your API key>",
  "cortex_auth_id":  "<your API key ID>",
  "cortex_fqdn":     "api-<tenant>.xdr.us.paloaltonetworks.com"
}
```

Find these in Cortex XDR → **Settings → Configurations → API Keys**.
The key needs the **Vulnerability Management** (Exposure Management) permission scope.

The deploy script prompts for these values and stores them directly in Secrets Manager or Key Vault — they are never written to disk.

---

## Deploy

`scripts/deploy.sh` handles the entire deployment interactively: it checks prerequisites, prompts for credentials and settings, builds the package, applies Terraform, stores the secret, and (for Azure) deploys the function code.

### AWS

```bash
./scripts/deploy.sh aws
```

The script will prompt for:

- Cortex API key *(hidden input)*
- Cortex API key ID
- Cortex API URL
- AWS region *(default: `us-east-1`)*
- Secrets Manager secret name *(default: `byob/cortex`)*

Then it will:

1. Build `dist/byob_lambda.zip` (Lambda-compatible package)
2. Run `terraform apply` → `terraform/aws/global/` (IAM role — once per account)
3. Per region: `terraform apply` → `terraform/aws/regional/` (Lambda, 4 EventBridge rules, Secrets Manager)
4. Per region: Store credentials in AWS Secrets Manager

### Azure

```bash
./scripts/deploy.sh azure
```

The script will prompt for:

- Cortex API key *(hidden input)*
- Cortex API key ID
- Cortex API URL
- Azure subscription ID *(auto-detected from `az account show`; confirm or override)*
- Storage account name *(required — must be globally unique, 3–24 lowercase chars)*
- Azure region *(default: `eastus`)*
- Resource group name *(default: `byob-scanner-rg`)*
- Function App name *(default: `byob-scanner-func`)*
- Key Vault name *(default: `byob-scanner-kv` — must be globally unique)*
- Key Vault secret name *(default: `cortex-credentials`)*

Then it will:

1. Run `terraform init` + `terraform apply` — creates the Function App with a system-assigned Managed Identity and wires the Key Vault access policy automatically
2. Store credentials in Azure Key Vault
3. Zip and deploy the Azure Function code

### Both clouds

```bash
./scripts/deploy.sh both
```

Runs the AWS flow then the Azure flow. Cortex credentials are prompted once and reused for both.

---

## What the script does

### Prompts — AWS

| Prompt | Default | Description |
|---|---|---|
| Cortex API key | — | Hidden input; not echoed or written to disk |
| Cortex API key ID | — | Numeric ID from the XDR console |
| Cortex API URL | — | e.g. `api-tenant.xdr.us.paloaltonetworks.com` |
| AWS region(s) | `us-east-1` | Single value or comma-separated list |
| Secret name | `byob/cortex` | Secrets Manager path for the credentials JSON |

> **Note:** Severity and status filters are no longer prompted during deploy. They are passed per-execution via the 4 EventBridge rules (one per severity level: CRITICAL, HIGH, MEDIUM, LOW), each with a staggered schedule so only one Lambda runs at a time and Cortex rate limits are respected.

**Steps performed:**

```
[1/4]  Build dist/byob_lambda.zip  (once)
         pip install byob_core --target dist/lambda_pkg
           --platform manylinux2014_x86_64 --python-version 3.12
         copy aws_lambda/handler.py → dist/lambda_pkg/
         zip dist/lambda_pkg/ → dist/byob_lambda.zip

[2/4]  terraform -chdir=terraform/aws/global apply  (once per account)
         Creates: IAM role + policy (byob-scanner-lambda-role)

[3/4]  terraform workspace select <region>
       terraform -chdir=terraform/aws/regional apply  (once per region)
         Creates: Lambda function,
                  4 EventBridge rules (byob-scanner-critical/high/medium/low),
                  Secrets Manager secret (placeholder)

[4/4]  aws secretsmanager put-secret-value  --region <region>
         Stores: {"cortex_api_key":..., "cortex_auth_id":..., "cortex_fqdn":...}
```

### Prompts — Azure

| Prompt | Default | Description |
|---|---|---|
| Cortex API key | — | Hidden input |
| Cortex API key ID | — | |
| Cortex API URL | — | e.g. `api-tenant.xdr.us.paloaltonetworks.com` |
| Subscription ID | auto-detected | Confirmed or overridden |
| Storage account name | *(required)* | 3–24 lowercase chars, globally unique |
| Azure region | `eastus` | Region for all resources |
| Resource group | `byob-scanner-rg` | |
| Function App name | `byob-scanner-func` | |
| Key Vault name | `byob-scanner-kv` | Globally unique |
| Secret name | `cortex-credentials` | Key Vault secret path |

**Steps performed:**

```
[1/3]  terraform -chdir=terraform/azure init
       terraform -chdir=terraform/azure apply
         Creates: Resource group, Storage account, App Service plan,
                  Linux Function App (Python 3.12, system-assigned identity),
                  Key Vault + access policies (deployer + managed identity),
                  Event Grid system topic (Microsoft.Security.Assessments)
                    → subscription to EventDrivenSync function endpoint

[2/3]  az keyvault secret set
         --vault-name <kv_name>
         --name <secret_name>
         --value '{"cortex_api_key":...}'

[3/3]  zip azure_function/ → dist/byob_azure.zip
       az functionapp deployment source config-zip
         --name <func_app_name>
         --src dist/byob_azure.zip
```

---

## Terraform variable reference

### AWS — global (`terraform/aws/global/`)

Created once per AWS account. No workspace needed.

| Variable | Default | Description |
|---|---|---|
| `cortex_secret_name` | `byob/cortex` | Used to scope the IAM policy to the correct secret ARN |

**Outputs:**

| Output | Description |
|---|---|
| `lambda_role_arn` | ARN of the shared IAM role passed to each regional deployment |
| `lambda_role_name` | Name of the IAM role |

### AWS — regional (`terraform/aws/regional/`)

One Terraform workspace per region.

| Variable | Default | Description |
|---|---|---|
| `aws_region` | `us-east-1` | Region for Lambda, EventBridge, Secrets Manager |
| `lambda_zip_path` | `../../../dist/byob_lambda.zip` | Path to the built Lambda zip |
| `lambda_role_arn` | *(required)* | ARN from the global module output |
| `cortex_secret_name` | `byob/cortex` | Secrets Manager secret name |
| `inspector2_statuses` | `ACTIVE` | Comma-separated finding statuses; passed to Lambda via each EventBridge rule input payload |
| `inspector2_lookback_hours` | `6` | Only return findings updated in the last N hours. Lambda default is `6` (runs every 4 hours with a 6-hour window for overlap). Code default when env var unset is `720` (30 days — matches Cortex API limit). `0` = no time filter |

**EventBridge rules created per region:**

| Rule name | Schedule | Severity passed in payload |
|---|---|---|
| `byob-scanner-critical` | Every 4 h, on the hour | `CRITICAL` |
| `byob-scanner-high` | Every 4 h, :30 past the hour | `HIGH` |
| `byob-scanner-medium` | Every 4 h, 1:00 past the hour | `MEDIUM` |
| `byob-scanner-low` | Every 4 h, 1:30 past the hour | `LOW` |

Rules are staggered 30 minutes apart so only one Lambda runs at a time, avoiding Cortex rate limits. Each rule passes its severity (and the configured statuses and lookback window) as a static JSON input to the Lambda.

**Outputs:**

| Output | Description |
|---|---|
| `lambda_function_name` | Lambda function name |
| `lambda_function_arn` | Lambda function ARN |
| `eventbridge_rule_arns` | Map of severity → EventBridge rule ARN |
| `secret_arn` | Secrets Manager secret ARN |

### Azure variables

| Variable | Default | Description |
|---|---|---|
| `subscription_id` | *(required)* | Azure subscription ID |
| `storage_account_name` | *(required)* | Globally unique storage account name |
| `location` | `eastus` | Azure region |
| `resource_group_name` | `byob-scanner-rg` | Resource group name |
| `function_app_name` | `byob-scanner-func` | Function App name |
| `key_vault_name` | `byob-scanner-kv` | Key Vault name (globally unique) |
| `cortex_secret_name` | `cortex-credentials` | Key Vault secret name |

**Outputs:**

| Output | Description |
|---|---|
| `function_app_id` | Function App resource ID |
| `function_app_name` | Function App name |
| `function_app_default_hostname` | Public hostname |
| `keyvault_id` | Key Vault resource ID |
| `keyvault_uri` | Key Vault URI |
| `event_grid_topic_id` | Event Grid system topic resource ID |
| `managed_identity_principal_id` | Principal ID of the system-assigned identity |

---

## Environment variables reference

These are set automatically by Terraform — no manual configuration needed.

### AWS Lambda

| Variable | Default | Description |
|---|---|---|
| `CORTEX_SECRET_NAME` | *(from deploy)* | Secrets Manager secret name |
| `INSPECTOR2_STATUSES` | `ACTIVE` | Comma-separated finding statuses. Valid: `ACTIVE`, `SUPPRESSED`, `CLOSED`. Set at Lambda level as a baseline; each EventBridge rule can override this via its input payload |
| `INSPECTOR2_LOOKBACK_HOURS` | `6` (Lambda) / `720` (code default) | Only return findings updated in the last N hours. Lambda is set to `6` to match the 4-hour run interval with overlap. Code default when unset is `720` (30 days), matching the Cortex API hard limit — findings older than 30 days are rejected with HTTP 422. Set to `0` to disable. |

> **Severity is not an env var.** Each EventBridge rule passes `inspector2_severities` directly in its input payload (e.g. `"CRITICAL"`, `"HIGH"`, etc.), so the Lambda runs four separate scans at different severity tiers without needing four separate Lambda functions.

To change the lookback window or statuses after deployment:

```bash
aws lambda update-function-configuration \
  --function-name byob-scanner \
  --region us-east-1 \
  --environment "Variables={CORTEX_SECRET_NAME=byob/cortex,INSPECTOR2_STATUSES=ACTIVE,INSPECTOR2_LOOKBACK_HOURS=6}"
```

### Azure Function

| Variable | Description |
|---|---|
| `CORTEX_KEYVAULT_URL` | Key Vault URI (e.g. `https://byob-scanner-kv.vault.azure.net/`) |
| `CORTEX_SECRET_NAME` | Key Vault secret name |
| `AZURE_SUBSCRIPTION_ID` | Subscription ID used by the Resource Graph collector |

---

## Development setup

```bash
git clone <repo>
cd ByobScanner
pip install -e ".[dev]"
```

Installs `byob_core` plus `pytest`, `pytest-mock`, `responses`, and `moto`.

---

## Asset tags sent to Cortex XDR

Every asset pushed to Cortex includes cloud metadata tags alongside any user-defined resource tags. Tags use `key:value` format.

### EC2 instance

| Tag | Example |
|---|---|
| `cloud:aws` | |
| `resource_type:ec2_instance` | |
| `aws_account:<account-id>` | `aws_account:123456789012` |
| `aws_region:<region>` | `aws_region:us-east-1` |
| `instance_id:<id>` | `instance_id:i-0abc1234def56789` |
| `instance_type:<type>` | `instance_type:t3.medium` |
| `platform:<platform>` | `platform:AMAZON_LINUX_2` |
| `vpc:<vpc-id>` | `vpc:vpc-0abc1234` |
| `subnet:<subnet-id>` | `subnet:subnet-0abc1234` |
| User tags (from resource) | `env:prod`, `team:platform` |

### ECR container image

| Tag | Example |
|---|---|
| `cloud:aws` | |
| `resource_type:ecr_container_image` | |
| `aws_account:<registry-id>` | `aws_account:123456789012` |
| `aws_region:<region>` | `aws_region:us-east-1` |
| `ecr_repository:<name>` | `ecr_repository:my-app` |
| `architecture:<arch>` | `architecture:x86_64` |
| `image_hash:<digest>` | `image_hash:sha256:abcd1234` |
| `image_tags:<tags>` | `image_tags:latest,v1.0` |
| User tags (from resource) | `team:platform` |

> The `Name` tag is used as the asset name and is not duplicated in the tag list.

---

## Tenable Vulnerability Management

### How it works

Tenable uses an **asynchronous export** pattern — no real-time events, just scheduled pulls:

```
1. POST /vulns/export  →  {"export_uuid": "..."}          (start export with filters)
2. GET  /vulns/export/{uuid}/status  →  poll every 30 s   (wait for FINISHED)
3. GET  /vulns/export/{uuid}/chunks/{id}                   (download each chunk)
4. Parse records → RawFinding → normalizer → Cortex BYOS
```

Key behaviours:
- **Delta export**: the `since` filter (Unix timestamp) restricts the export to findings seen on or after a given date, equivalent to the `updatedAt` filter in Inspector2.
- **One finding per CVE**: a single Tenable plugin can map to multiple CVEs. The collector creates one `RawFinding` per CVE so each vulnerability gets its own `vulnerability_id` entry in Cortex.
- **Severity sort**: findings are sorted CRITICAL → HIGH → MEDIUM → LOW before normalisation, so the most critical vulnerabilities survive the per-asset 1,000-finding cap.
- **409 deduplication**: if an identical export is already in progress (Tenable returns HTTP 409), the collector reuses the existing job UUID instead of failing.
- **States**: only `OPEN` and `REOPENED` findings are exported — `FIXED` findings are not forwarded to Cortex.

### Tenable credentials

The collector reads credentials from environment variables:

| Variable | Description |
|---|---|
| `TENABLE_ACCESS_KEY` | Tenable API access key |
| `TENABLE_SECRET_KEY` | Tenable API secret key |

Create a Tenable API key pair in **Settings → My Account → API Keys** (or ask your Tenable admin). The account needs at least the **Basic** role and **Can View** access on all assets.

### Tenable environment variables

| Variable | Default | Description |
|---|---|---|
| `TENABLE_ACCESS_KEY` | *(required)* | Tenable API access key |
| `TENABLE_SECRET_KEY` | *(required)* | Tenable API secret key |
| `TENABLE_SEVERITIES` | `medium,high,critical` | Comma-separated severity levels. Valid (lowercase): `info`, `low`, `medium`, `high`, `critical` |
| `TENABLE_LOOKBACK_HOURS` | `720` (30 days) | Only return findings seen in the last N hours. Matches the Cortex API hard limit — findings older than 30 days are rejected with HTTP 422. Set to `0` to disable (full export — use for first bulk import). |
| `TENABLE_BASE_URL` | `https://cloud.tenable.com` | Override for on-premises Tenable Security Center (if applicable) |

### First bulk import

Run once to push all findings from the last 30 days into Cortex:

```bash
# Dry run first — see what will be posted without sending anything
python3 scripts/integration_test.py --source tenable --dry-run \
  --tenable-access-key <access_key> \
  --tenable-secret-key <secret_key>

# Full 30-day import (default --hours 720)
python3 scripts/integration_test.py --source tenable --post \
  --tenable-access-key <access_key> \
  --tenable-secret-key <secret_key> \
  --cortex-fqdn   api-tenant.xdr.us.paloaltonetworks.com \
  --cortex-api-key <key> \
  --cortex-auth-id <id>

# No time filter — export everything (first import when you want all historical data)
python3 scripts/integration_test.py --source tenable --post \
  --tenable-access-key <access_key> \
  --tenable-secret-key <secret_key> \
  --hours 0 \
  --cortex-fqdn   api-tenant.xdr.us.paloaltonetworks.com \
  --cortex-api-key <key> \
  --cortex-auth-id <id>
```

### Ongoing delta runs

After the initial import, run with a short lookback window to pick up only new/updated findings:

```bash
# Delta — last 6 hours (run on a 4-hour schedule with overlap)
python3 scripts/integration_test.py --source tenable --post \
  --tenable-access-key <access_key> \
  --tenable-secret-key <secret_key> \
  --hours 6

# Critical and high only
python3 scripts/integration_test.py --source tenable --post \
  --tenable-access-key <access_key> \
  --tenable-secret-key <secret_key> \
  --hours 6 \
  --severities HIGH,CRITICAL
```

You can also store the credentials as environment variables and omit the CLI flags:

```bash
export TENABLE_ACCESS_KEY=<access_key>
export TENABLE_SECRET_KEY=<secret_key>
export CORTEX_FQDN=api-tenant.xdr.us.paloaltonetworks.com
export CORTEX_API_KEY=<key>
export CORTEX_AUTH_ID=<id>

python3 scripts/integration_test.py --source tenable --post --hours 6
```

### Tenable → Cortex field mapping

| Tenable field | Cortex / `RawFinding` field | Notes |
|---|---|---|
| `asset.uuid` | `asset_id` | Stable UUID — use to match assets across exports |
| `asset.hostname` / `asset.fqdn[0]` | `asset_name` | Best available display name |
| `asset.ipv4` | `ipv4` | List |
| `asset.ipv6` | `ipv6` | List |
| `asset.fqdn` | `fqdn` | List |
| `asset.operating_system` | `os_name` | String or list → first value |
| `asset.tags` + cloud fields | `tags` | See below |
| `last_found` (Unix seconds) | `last_seen_ms` | Multiplied by 1,000 for milliseconds |
| `plugin.cve[i]` | `cve_id` | One `RawFinding` per CVE; records with no CVE are skipped |
| `severity` | `severity` | `critical→CRITICAL`, `high→HIGH`, `medium→MEDIUM`, `low→LOW`, `info→INFORMATIONAL` |
| `plugin.description` | `description` | Truncated at 1,000 characters |
| `plugin.id` + `plugin.name` + `cvss3_base_score` | `evidence` | `"Plugin 12345: Apache Log4Shell \| CVSS3: 10.0"` — truncated at 500 chars |
| `state` + `solution` + `output` | `raw_output` | Truncated at 2,000 characters |

### Tenable asset tags

Tags are sent to Cortex in `key:value` format. Cloud provider metadata is detected automatically from the Tenable asset record.

**All Tenable assets:**

| Tag | Example |
|---|---|
| `cloud:tenable_vm` | Always present |
| User-defined tags from Tenable | `env:production`, `team:platform` |

**AWS assets (when EC2 metadata is present):**

| Tag | Example |
|---|---|
| `instance_id:<id>` | `instance_id:i-0abc1234def56789` |
| `instance_type:<type>` | `instance_type:t3.medium` |
| `aws_region:<region>` | `aws_region:us-east-1` |
| `aws_availability_zone:<az>` | `aws_availability_zone:us-east-1a` |
| `aws_account:<account-id>` | `aws_account:123456789012` |

**Azure assets (when Azure metadata is present):**

| Tag | Example |
|---|---|
| `azure_vm_id:<id>` | `azure_vm_id:vm-0abc1234` |
| `azure_resource_group:<rg>` | `azure_resource_group:my-rg` |
| `azure_subscription_id:<id>` | `azure_subscription_id:sub-0abc1234` |

**GCP assets (when GCP metadata is present):**

| Tag | Example |
|---|---|
| `gcp_project:<project>` | `gcp_project:my-project-123` |
| `gcp_instance_id:<id>` | `gcp_instance_id:1234567890` |
| `gcp_zone:<zone>` | `gcp_zone:us-central1-a` |

---

## Running tests

```bash
pytest tests/ -v
```

All 79 unit tests run entirely offline — no AWS, Azure, or Tenable credentials required.

---

## Integration test

Connects to real scanner APIs but does **not** POST to Cortex by default.

### AWS Inspector2

```bash
# Initial full import — default 30-day window (--hours 720), matches Cortex API limit
python3 scripts/integration_test.py --source aws  --dry-run

# Tight delta — last 6 hours only (matches Lambda behaviour)
python3 scripts/integration_test.py --source aws --dry-run \
  --hours 6

# Override severity filter (one or more comma-separated values)
python3 scripts/integration_test.py --source aws --dry-run \
  --severities HIGH,CRITICAL

# Override both severity and status filters
python3 scripts/integration_test.py --source aws --dry-run \
  --severities CRITICAL \
  --statuses ACTIVE,SUPPRESSED

# Specify AWS region
python3 scripts/integration_test.py --source aws --dry-run \
  --region us-west-2 \
  --severities HIGH,CRITICAL

# Full import to Cortex (first run — 30-day window, no --hours needed)
python3 scripts/integration_test.py --source aws --post \
  --region us-east-1 \
  --severities HIGH,CRITICAL \
  --statuses ACTIVE \
  --cortex-fqdn   api-tenant.xdr.us.paloaltonetworks.com \
  --cortex-api-key <key> \
  --cortex-auth-id <id>

# Delta run to Cortex (subsequent runs — last 6 hours)
python3 scripts/integration_test.py --source aws --post \
  --region us-east-1 \
  --hours 6 \
  --severities HIGH,CRITICAL \
  --statuses ACTIVE \
  --cortex-fqdn   api-tenant.xdr.us.paloaltonetworks.com \
  --cortex-api-key <key> \
  --cortex-auth-id <id>
```

### Azure Defender

```bash
# Azure (no severity/status/hours flags — not applicable)
python3 scripts/integration_test.py --source azure --dry-run
python3 scripts/integration_test.py --source azure --post
```

### Tenable Vulnerability Management

```bash
# Dry run — 30-day delta (default), medium/high/critical (default)
python3 scripts/integration_test.py --source tenable --dry-run \
  --tenable-access-key <access_key> \
  --tenable-secret-key <secret_key>

# First bulk import — disable time filter to export all findings
python3 scripts/integration_test.py --source tenable --post \
  --tenable-access-key <access_key> \
  --tenable-secret-key <secret_key> \
  --hours 0 \
  --cortex-fqdn   api-tenant.xdr.us.paloaltonetworks.com \
  --cortex-api-key <key> \
  --cortex-auth-id <id>

# Delta run — last 6 hours
python3 scripts/integration_test.py --source tenable --post \
  --tenable-access-key <access_key> \
  --tenable-secret-key <secret_key> \
  --hours 6

# Critical and high only
python3 scripts/integration_test.py --source tenable --post \
  --tenable-access-key <access_key> \
  --tenable-secret-key <secret_key> \
  --hours 6 \
  --severities HIGH,CRITICAL

# Use env vars for credentials
TENABLE_ACCESS_KEY=... TENABLE_SECRET_KEY=... \
  python3 scripts/integration_test.py --source tenable --post --hours 6
```

### Flag reference

| Flag | Default | Description |
|---|---|---|
| `--source` | *(required)* | `aws`, `azure`, or `tenable` |
| `--dry-run` | on | Preview payload — no POST to Cortex |
| `--post` | off | Submit all batches to Cortex XDR |
| `--region` | `AWS_DEFAULT_REGION` or `us-east-1` | AWS region for Inspector2 (AWS only) |
| `--severities` | `MEDIUM,HIGH,CRITICAL` | Comma-separated severity levels. For AWS: `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `UNTRIAGED`. For Tenable: same values, case-insensitive. (Not used for Azure) |
| `--statuses` | `ACTIVE` | Comma-separated Inspector2 finding statuses. Valid: `ACTIVE`, `SUPPRESSED`, `CLOSED`. (AWS only) |
| `--hours` | `720` (30 days) | Only collect findings updated in the last N hours. Matches the Cortex API hard limit — findings older than 30 days are rejected anyway. Use `6` to match Lambda delta behaviour. `0` = no time filter (full export — use for first Tenable bulk import). (Not used for Azure) |
| `--tenable-access-key` | `TENABLE_ACCESS_KEY` env var | Tenable API access key (Tenable only) |
| `--tenable-secret-key` | `TENABLE_SECRET_KEY` env var | Tenable API secret key (Tenable only) |
| `--cortex-fqdn` | `CORTEX_FQDN` env var | Cortex API URL |
| `--cortex-api-key` | `CORTEX_API_KEY` env var | Cortex API key |
| `--cortex-auth-id` | `CORTEX_AUTH_ID` env var | Cortex API key ID |

**Valid `--severities` values (AWS):** `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `UNTRIAGED`

**Valid `--severities` values (Tenable):** `info`, `low`, `medium`, `high`, `critical` (case-insensitive)

**Valid `--statuses` values (AWS):** `ACTIVE`, `SUPPRESSED`, `CLOSED`

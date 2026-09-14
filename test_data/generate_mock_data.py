#!/usr/bin/env python3
"""
Generate a mock AWS Inspector2 findings cache file for testing.

Produces enough assets to create at least 100 batch files when run through
batch_push.py (MAX_ASSETS_PER_BATCH = 45 → need ≥ 4,500 assets).

Asset breakdown (4,600 total → 102+ batches):
  EC2 instances  : 2,000  (5 accounts × 4 regions × 100 instances)
  Lambda functions: 1,100  (5 accounts × 4 regions × 55 functions)
  ECR images     : 1,500  (5 accounts × 3 registries × 100 images)

Usage:
  python3 test_data/generate_mock_data.py
  python3 test_data/generate_mock_data.py --out test_data/mock_findings_cache.json.gz
  python3 test_data/generate_mock_data.py --seed 99 --out /tmp/findings.json.gz
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configurable counts
# ---------------------------------------------------------------------------
EC2_ACCOUNTS        = 5
EC2_REGIONS         = 4
EC2_PER_BUCKET      = 100   # instances per (account × region)

LAMBDA_ACCOUNTS     = 5
LAMBDA_REGIONS      = 4
LAMBDA_PER_BUCKET   = 55    # functions per (account × region)

ECR_ACCOUNTS        = 5
ECR_REPOS_PER_ACCT  = 3
ECR_IMAGES_PER_REPO = 100   # images per repo

# CVEs per asset (min, max)
EC2_CVE_RANGE    = (5, 20)
LAMBDA_CVE_RANGE = (3, 12)
ECR_CVE_RANGE    = (10, 40)

DEFAULT_SEED = 42
DEFAULT_OUT  = Path(__file__).parent / "mock_findings_cache.json.gz"

# ---------------------------------------------------------------------------
# Reference data pools
# ---------------------------------------------------------------------------
REGIONS = [
    "us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1",
    "us-east-2", "eu-central-1", "ap-northeast-1", "sa-east-1",
]

INSTANCE_TYPES = [
    "t3.micro", "t3.small", "t3.medium", "t3.large", "t3.xlarge",
    "m5.large", "m5.xlarge", "m5.2xlarge", "c5.large", "c5.xlarge",
    "r5.large", "r5.xlarge", "t2.micro", "t2.small", "t2.medium",
]

EC2_PLATFORMS = [
    "AMAZON_LINUX_2", "AMAZON_LINUX_2023", "UBUNTU_20_04", "UBUNTU_22_04",
    "RED_HAT_8", "CENTOS_7", "WINDOWS_SERVER_2019", "WINDOWS_SERVER_2022",
    "DEBIAN_11", "SUSE_15",
]

EC2_OS_NAMES = {
    "AMAZON_LINUX_2":       "Amazon Linux 2",
    "AMAZON_LINUX_2023":    "Amazon Linux 2023",
    "UBUNTU_20_04":         "Ubuntu 20.04",
    "UBUNTU_22_04":         "Ubuntu 22.04",
    "RED_HAT_8":            "Red Hat Enterprise Linux 8",
    "CENTOS_7":             "CentOS 7",
    "WINDOWS_SERVER_2019":  "Windows Server 2019",
    "WINDOWS_SERVER_2022":  "Windows Server 2022",
    "DEBIAN_11":            "Debian 11",
    "SUSE_15":              "SUSE Linux Enterprise 15",
}

LAMBDA_RUNTIMES = [
    "python3.9", "python3.10", "python3.11", "python3.12",
    "nodejs18.x", "nodejs20.x",
    "java11", "java17", "java21",
    "dotnet6", "dotnet8",
    "go1.x", "ruby3.2",
]

LAMBDA_NAMES = [
    "api-gateway-handler", "auth-service", "data-processor", "event-consumer",
    "file-converter", "image-resizer", "notification-sender", "order-processor",
    "payment-handler", "queue-worker", "report-generator", "s3-trigger",
    "scheduled-cleanup", "sns-publisher", "sqs-consumer", "stream-processor",
    "user-service", "webhook-receiver", "cache-warmer", "log-forwarder",
    "db-migrator", "health-check", "rate-limiter", "token-refresher",
    "billing-calculator", "audit-logger", "session-manager", "config-updater",
    "metric-collector", "alert-dispatcher",
]

ECR_REPOS = [
    "app/frontend", "app/backend", "app/api-gateway", "app/worker",
    "services/auth", "services/payments", "services/notifications",
    "infra/nginx", "infra/envoy", "infra/fluentd",
    "tools/scanner", "tools/migrator", "tools/seeder",
    "base/python3.11", "base/node20", "base/java17",
]

IMAGE_TAGS = [
    "latest", "stable", "v1.0.0", "v1.1.0", "v1.2.0", "v2.0.0", "v2.1.0",
    "main", "develop", "release-2024", "release-2025",
    "1.0", "1.1", "2.0", "prod", "staging", "qa",
]

ARCHITECTURES = ["x86_64", "arm64"]

# Large pool of real-looking CVEs (mix of years 2018–2025)
CVE_POOL = [
    # Critical / High — well-known
    "CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832",
    "CVE-2022-22965", "CVE-2022-22963", "CVE-2022-22947", "CVE-2022-0847",
    "CVE-2023-44487", "CVE-2023-46604", "CVE-2023-38545", "CVE-2023-36844",
    "CVE-2024-3094",  "CVE-2024-6387",  "CVE-2024-21626", "CVE-2024-23897",
    # Medium
    "CVE-2021-3156",  "CVE-2021-3711",  "CVE-2021-3712",  "CVE-2021-22947",
    "CVE-2022-1292",  "CVE-2022-2068",  "CVE-2022-3602",  "CVE-2022-3786",
    "CVE-2022-25315", "CVE-2022-25314", "CVE-2022-25313", "CVE-2022-23990",
    "CVE-2023-0464",  "CVE-2023-0465",  "CVE-2023-0466",  "CVE-2023-2650",
    "CVE-2023-3446",  "CVE-2023-3817",  "CVE-2023-5363",  "CVE-2023-6129",
    "CVE-2024-0727",  "CVE-2024-2511",  "CVE-2024-4603",  "CVE-2024-5535",
    # Low / Info — library vulns
    "CVE-2018-25032", "CVE-2019-11253", "CVE-2019-16168", "CVE-2019-20916",
    "CVE-2020-14343", "CVE-2020-25659", "CVE-2020-36242", "CVE-2020-8492",
    "CVE-2021-23336", "CVE-2021-23337", "CVE-2021-33503", "CVE-2021-3572",
    "CVE-2022-40897", "CVE-2022-42919", "CVE-2022-45061", "CVE-2022-40674",
    "CVE-2023-32681", "CVE-2023-37920", "CVE-2023-43804", "CVE-2023-45803",
    "CVE-2024-35195", "CVE-2024-37891", "CVE-2024-39689",
    # More padding
    "CVE-2017-18342", "CVE-2018-20225", "CVE-2019-8341",  "CVE-2019-11358",
    "CVE-2020-7598",  "CVE-2020-15168", "CVE-2021-43138", "CVE-2022-0536",
    "CVE-2022-21724", "CVE-2022-23491", "CVE-2022-24329", "CVE-2022-24785",
    "CVE-2023-26136", "CVE-2023-26159", "CVE-2023-28155", "CVE-2023-29827",
    "CVE-2023-44270", "CVE-2023-45857", "CVE-2023-48631", "CVE-2024-28863",
    "CVE-2024-29041", "CVE-2024-30255", "CVE-2024-37168", "CVE-2024-45296",
]

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_WEIGHTS = [0.10, 0.25, 0.45, 0.20]

DESCRIPTIONS = {
    "CRITICAL": (
        "A critical remote code execution vulnerability allows an unauthenticated attacker "
        "to execute arbitrary code with root privileges via a specially crafted request."
    ),
    "HIGH": (
        "An improper input validation vulnerability allows a remote attacker to cause a "
        "denial of service or potentially execute arbitrary code."
    ),
    "MEDIUM": (
        "A vulnerability in the affected package may allow an attacker to perform "
        "unintended actions, potentially exposing sensitive data or affecting availability."
    ),
    "LOW": (
        "A low-severity vulnerability that may expose minor information or cause limited "
        "disruption under specific conditions."
    ),
}

ENV_TAGS = ["env:prod", "env:staging", "env:dev", "env:qa"]
TEAM_TAGS = ["team:platform", "team:security", "team:backend", "team:data", "team:frontend"]
APP_TAGS  = ["app:ecommerce", "app:analytics", "app:ml-pipeline", "app:customer-portal", "app:internal-tools"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _rand_ip(rng: random.Random, private: bool = True) -> str:
    if private:
        return f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
    return f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def _rand_account(rng: random.Random, idx: int) -> str:
    """Deterministic-ish 12-digit account ID."""
    return str(100_000_000_000 + idx * 11_111_111_111 + rng.randint(0, 999))[:12]


def _now_minus_days(rng: random.Random, max_days: int = 25) -> int:
    """Return a last_seen_ms within the last max_days days (always within 30-day window)."""
    days_ago = rng.uniform(0, max_days)
    dt = datetime.now(tz=timezone.utc) - timedelta(days=days_ago)
    return int(dt.timestamp() * 1000)


def _pick_cves(rng: random.Random, count: int) -> list[str]:
    return rng.sample(CVE_POOL, min(count, len(CVE_POOL)))


def _rand_tags(rng: random.Random, extra: list[str]) -> list[str]:
    return [
        rng.choice(ENV_TAGS),
        rng.choice(TEAM_TAGS),
        rng.choice(APP_TAGS),
    ] + extra


def _finding(
    asset_id: str,
    asset_name: str,
    ipv4: list[str],
    ipv6: list[str],
    fqdn: list[str],
    mac_address: str | None,
    os_name: str | None,
    tags: list[str],
    last_seen_ms: int,
    cve_id: str,
    rng: random.Random,
) -> dict:
    severity = rng.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0]
    return {
        "asset_id":    asset_id,
        "asset_name":  asset_name,
        "ipv4":        ipv4,
        "ipv6":        ipv6,
        "fqdn":        fqdn,
        "mac_address": mac_address,
        "os_name":     os_name,
        "tags":        tags,
        "last_seen_ms": last_seen_ms,
        "cve_id":      cve_id,
        "severity":    severity,
        "description": DESCRIPTIONS[severity],
        "evidence":    f"CVSS:{rng.uniform(1.0,10.0):.1f} AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "raw_output":  f"Package affected, fixed in patched version. Score: {rng.uniform(1.0,10.0):.1f}",
        "source":      "aws_inspector",
    }


# ---------------------------------------------------------------------------
# Asset generators
# ---------------------------------------------------------------------------

def gen_ec2(rng: random.Random, accounts: list[str], regions: list[str]) -> list[dict]:
    findings = []
    instance_counter = 0
    for account_id in accounts:
        for region in regions:
            for i in range(EC2_PER_BUCKET):
                instance_counter += 1
                instance_id = f"i-{_sha256(f'{account_id}{region}{i}')[:16]}"
                platform    = rng.choice(EC2_PLATFORMS)
                itype       = rng.choice(INSTANCE_TYPES)
                os_name     = EC2_OS_NAMES[platform]
                ipv4        = [_rand_ip(rng)]
                vpc_id      = f"vpc-{_sha256(f'{account_id}{region}')[:8]}"
                subnet_id   = f"subnet-{_sha256(f'{account_id}{region}{i//10}')[:8]}"
                name_tag    = f"ec2-{region[:2]}-{platform.lower()[:6]}-{instance_counter:04d}"

                asset_id = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
                tags = [
                    "cloud:aws",
                    f"resource_type:ec2_instance",
                    f"aws_account:{account_id}",
                    f"aws_region:{region}",
                    f"instance_id:{instance_id}",
                    f"instance_type:{itype}",
                    f"platform:{platform}",
                    f"vpc:{vpc_id}",
                    f"subnet:{subnet_id}",
                    f"Name:{name_tag}",
                ] + _rand_tags(rng, [])

                last_seen_ms = _now_minus_days(rng, 20)
                cve_count    = rng.randint(*EC2_CVE_RANGE)
                for cve in _pick_cves(rng, cve_count):
                    findings.append(_finding(
                        asset_id, name_tag, ipv4, [], [], None, os_name, tags,
                        last_seen_ms + rng.randint(-86_400_000, 0), cve, rng,
                    ))
    return findings


def gen_lambda(rng: random.Random, accounts: list[str], regions: list[str]) -> list[dict]:
    findings = []
    func_counter = 0
    for account_id in accounts:
        for region in regions:
            for i in range(LAMBDA_PER_BUCKET):
                func_counter += 1
                base_name = rng.choice(LAMBDA_NAMES)
                func_name = f"{base_name}-{func_counter:04d}"
                runtime   = rng.choice(LAMBDA_RUNTIMES)
                version   = f"$LATEST"
                asset_id  = f"arn:aws:lambda:{region}:{account_id}:function:{func_name}"
                os_name   = f"Lambda ({runtime})"
                tags = [
                    "cloud:aws",
                    "resource_type:lambda_function",
                    f"aws_account:{account_id}",
                    f"aws_region:{region}",
                    f"function_name:{func_name}",
                    f"runtime:{runtime}",
                ] + _rand_tags(rng, [])

                last_seen_ms = _now_minus_days(rng, 18)
                cve_count    = rng.randint(*LAMBDA_CVE_RANGE)
                for cve in _pick_cves(rng, cve_count):
                    findings.append(_finding(
                        asset_id, func_name, [], [], [], None, os_name, tags,
                        last_seen_ms + rng.randint(-86_400_000, 0), cve, rng,
                    ))
    return findings


def gen_ecr(rng: random.Random, accounts: list[str]) -> list[dict]:
    findings = []
    image_counter = 0
    regions_ecr = REGIONS[:4]
    for account_id in accounts:
        registry = f"{account_id}.dkr.ecr.us-east-1.amazonaws.com"
        for repo_name in rng.sample(ECR_REPOS, ECR_REPOS_PER_ACCT):
            for i in range(ECR_IMAGES_PER_REPO):
                image_counter += 1
                digest   = _sha256(f"{account_id}{repo_name}{i}")
                tag      = rng.choice(IMAGE_TAGS)
                arch     = rng.choice(ARCHITECTURES)
                region   = rng.choice(regions_ecr)
                registry = f"{account_id}.dkr.ecr.{region}.amazonaws.com"

                asset_id   = f"{registry}/{repo_name}@sha256:{digest}"
                asset_name = f"sha256:{digest}"
                fqdn       = [f"{registry}/{repo_name}:{tag}"]
                os_name    = rng.choice(["Amazon Linux 2", "Alpine 3.18", "Debian 11", "Ubuntu 22.04", None])

                tags = [
                    "cloud:aws",
                    "resource_type:ecr_container_image",
                    f"aws_account:{account_id}",
                    f"aws_region:{region}",
                    f"ecr_repository:{repo_name}",
                    f"architecture:{arch}",
                    f"image_hash:sha256:{digest[:12]}",
                    f"image_tags:{tag}",
                ] + _rand_tags(rng, [])

                last_seen_ms = _now_minus_days(rng, 15)
                cve_count    = rng.randint(*ECR_CVE_RANGE)
                for cve in _pick_cves(rng, cve_count):
                    findings.append(_finding(
                        asset_id, asset_name, [], [], fqdn, None, os_name, tags,
                        last_seen_ms + rng.randint(-86_400_000, 0), cve, rng,
                    ))
    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out",  default=str(DEFAULT_OUT), help="Output cache file path")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Random seed for reproducibility")
    args = parser.parse_args()

    rng = random.Random(args.seed)

    # Build deterministic account IDs
    ec2_accounts    = [_rand_account(rng, i) for i in range(EC2_ACCOUNTS)]
    lambda_accounts = [_rand_account(rng, i + 10) for i in range(LAMBDA_ACCOUNTS)]
    ecr_accounts    = [_rand_account(rng, i + 20) for i in range(ECR_ACCOUNTS)]
    ec2_regions     = REGIONS[:EC2_REGIONS]
    lambda_regions  = REGIONS[:LAMBDA_REGIONS]

    print(f"Generating EC2 findings  ({EC2_ACCOUNTS} accounts × {EC2_REGIONS} regions × {EC2_PER_BUCKET} instances) ...")
    ec2_findings = gen_ec2(rng, ec2_accounts, ec2_regions)

    print(f"Generating Lambda findings ({LAMBDA_ACCOUNTS} accounts × {LAMBDA_REGIONS} regions × {LAMBDA_PER_BUCKET} functions) ...")
    lambda_findings = gen_lambda(rng, lambda_accounts, lambda_regions)

    print(f"Generating ECR findings  ({ECR_ACCOUNTS} accounts × {ECR_REPOS_PER_ACCT} repos × {ECR_IMAGES_PER_REPO} images) ...")
    ecr_findings = gen_ecr(rng, ecr_accounts)

    all_findings = ec2_findings + lambda_findings + ecr_findings
    rng.shuffle(all_findings)

    # Count unique assets
    unique_assets = len({f["asset_id"] for f in all_findings})
    expected_batches = (unique_assets + 44) // 45   # ceil(assets / 45)

    print(f"\nSummary:")
    print(f"  EC2 findings    : {len(ec2_findings):>8,}")
    print(f"  Lambda findings : {len(lambda_findings):>8,}")
    print(f"  ECR findings    : {len(ecr_findings):>8,}")
    print(f"  Total findings  : {len(all_findings):>8,}")
    print(f"  Unique assets   : {unique_assets:>8,}")
    print(f"  Expected batches: {expected_batches:>8,}  (at 45 assets/batch)")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    cached_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = {
        "cached_at":      cached_at,
        "source":         "aws",
        "region":         "us-east-1",
        "lookback_hours": 0,
        "coverage_hours": None,
        "findings_count": len(all_findings),
        "findings":       all_findings,
    }

    print(f"\nWriting {out_path} ...")
    raw = json.dumps(data, indent=2).encode()
    if str(out_path).endswith(".gz"):
        out_path.write_bytes(gzip.compress(raw, compresslevel=6))
    else:
        out_path.write_bytes(raw)
    size_mb = out_path.stat().st_size / (1024 * 1024)
    orig_mb = len(raw) / (1024 * 1024)
    if str(out_path).endswith(".gz"):
        print(f"Done — {out_path}  ({size_mb:.1f} MB compressed, {orig_mb:.1f} MB uncompressed, {orig_mb/size_mb:.1f}x ratio)")
    else:
        print(f"Done — {out_path}  ({size_mb:.1f} MB)")
    print(f"\nUsage:")
    print(f"  python3 scripts/batch_push.py --source aws --from-cache --cache-file {out_path} --download-only")
    print(f"  python3 scripts/cache_summary.py --cache-file {out_path}")


if __name__ == "__main__":
    main()

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

import boto3
from tenacity import retry, stop_after_attempt, wait_exponential

from byob_core.models import RawFinding

logger = logging.getLogger(__name__)

# On Lambda the region is set by the runtime (AWS_DEFAULT_REGION).
# Locally, set AWS_DEFAULT_REGION in your environment or pass --region to the
# integration test script. Falls back to us-east-1 so the client always starts.
_DEFAULT_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

# ---------------------------------------------------------------------------
# Filtering — controlled via environment variables so customers can tune
# without code changes or redeployment (just update the Lambda env vars).
#
#   INSPECTOR2_STATUSES        comma-separated; default: ACTIVE
#                              Valid values: ACTIVE, SUPPRESSED, CLOSED
#
#   INSPECTOR2_SEVERITIES      comma-separated; default: MEDIUM,HIGH,CRITICAL
#                              Valid values: INFORMATIONAL, LOW, MEDIUM, HIGH,
#                                            CRITICAL, UNTRIAGED
#
#   INSPECTOR2_LOOKBACK_HOURS  integer; default: 720 (30 days)
#                              When > 0, only findings updated in the last N
#                              hours are returned.  Defaults to 720 (30 days)
#                              to match the Cortex API's hard limit — findings
#                              older than 30 days are rejected with HTTP 422,
#                              so downloading them wastes time and bandwidth.
#                              Set to 12 on Lambda (runs every 6 hours) for a
#                              tight delta with overlap.  Set to 0 to disable
#                              the time filter entirely (no upper bound).
# ---------------------------------------------------------------------------
_VALID_STATUSES = {"ACTIVE", "SUPPRESSED", "CLOSED"}
_VALID_SEVERITIES = {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNTRIAGED"}

# Lower index = higher priority; UNTRIAGED sits between LOW and INFORMATIONAL
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNTRIAGED", "INFORMATIONAL"]
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_ORDER)}

def _parse_env_list(env_var: str, valid: set[str], default: list[str]) -> list[str]:
    raw = os.environ.get(env_var, "")
    if not raw.strip():
        return default
    values = [v.strip().upper() for v in raw.split(",") if v.strip()]
    unknown = set(values) - valid
    if unknown:
        logger.warning(
            "Unknown %s values ignored: %s — valid values are: %s",
            env_var, unknown, valid,
        )
    return [v for v in values if v in valid] or default


def _lookback_hours() -> int:
    """Return INSPECTOR2_LOOKBACK_HOURS as a non-negative int.

    Default is 720 (30 days) — the Cortex API rejects findings with
    last_seen older than 30 days (HTTP 422), so there is no point
    downloading them.  Set to 0 to disable the time filter entirely.
    """
    raw = os.environ.get("INSPECTOR2_LOOKBACK_HOURS", "720").strip()
    try:
        val = int(raw)
        return max(val, 0)
    except ValueError:
        logger.warning("INSPECTOR2_LOOKBACK_HOURS=%r is not an integer — defaulting to 720 (30 days)", raw)
        return 720


def collect(mode: str, finding_arn: str | None = None, region: str | None = None) -> list[RawFinding]:
    """Collect findings. The boto3 client is created once; transient errors are retried per-call."""
    client = boto3.client("inspector2", region_name=region or _DEFAULT_REGION)
    statuses = _parse_env_list("INSPECTOR2_STATUSES", _VALID_STATUSES, ["ACTIVE"])
    severities = _parse_env_list("INSPECTOR2_SEVERITIES", _VALID_SEVERITIES, ["MEDIUM", "HIGH", "CRITICAL"])
    hours = _lookback_hours()
    logger.info(
        "Inspector2 filters — statuses: %s  severities: %s  lookback_hours: %s",
        statuses, severities, hours if hours > 0 else "disabled (full scan)",
    )
    return _collect_with_retry(client, mode, finding_arn, statuses, severities, hours)


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=8))
def _collect_with_retry(
    client: Any,
    mode: str,
    finding_arn: str | None,
    statuses: list[str],
    severities: list[str],
    lookback_hours: int,
) -> list[RawFinding]:
    paginator = client.get_paginator("list_findings")
    kwargs: dict[str, Any] = {"PaginationConfig": {"PageSize": 100}}

    if mode == "event" and finding_arn:
        # Event-driven: fetch the exact finding — status/severity filters not applied
        # so the finding is always returned even if it falls outside the normal range.
        kwargs["filterCriteria"] = {
            "findingArn": [{"comparison": "EQUALS", "value": finding_arn}]
        }
    else:
        criteria: dict[str, Any] = {
            "findingStatus": [{"comparison": "EQUALS", "value": s} for s in statuses],
            "severity":       [{"comparison": "EQUALS", "value": s} for s in severities],
        }
        if lookback_hours > 0:
            now = datetime.now(tz=timezone.utc)
            start = datetime.fromtimestamp(
                now.timestamp() - lookback_hours * 3600, tz=timezone.utc
            )
            criteria["updatedAt"] = [{"startInclusive": start, "endInclusive": now}]
            logger.info(
                "Inspector2 time window: %s → %s (UTC)",
                start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        kwargs["filterCriteria"] = criteria
    findings: list[RawFinding] = []
    raw_total = 0
    skipped_no_cve = 0
    skipped_no_resource = 0
    page_num = 0
    for page in paginator.paginate(**kwargs):
        page_num += 1
        page_findings = page.get("findings", [])
        page_kept = 0
        for raw in page_findings:
            raw_total += 1
            finding_type = raw.get("type", "UNKNOWN")
            if not raw.get("resources"):
                skipped_no_resource += 1
                logger.debug("Skipped (no resources): %s", raw.get("findingArn", ""))
                continue
            pkg_vuln = raw.get("packageVulnerabilityDetails") or raw.get("packageVulnerability") or {}
            if not pkg_vuln.get("vulnerabilityId"):
                skipped_no_cve += 1
                logger.debug(
                    "Skipped (no CVE — type=%s): %s",
                    finding_type, raw.get("findingArn", ""),
                )
                continue
            parsed = _parse(raw)
            if parsed:
                findings.append(parsed)
                page_kept += 1
        logger.info(
            "Page %d: %d raw / %d kept (running total: %d kept / %d raw)",
            page_num, len(page_findings), page_kept, len(findings), raw_total,
        )

    logger.info(
        "Inspector2 collection done: %d raw findings — %d kept, %d skipped (no CVE/package), "
        "%d skipped (no resource)  [mode=%s, pages=%d]",
        raw_total, len(findings), skipped_no_cve, skipped_no_resource, mode, page_num,
    )
    if skipped_no_cve:
        logger.warning(
            "%d findings had no packageVulnerability.vulnerabilityId and were skipped. "
            "These are likely network-reachability or code findings — "
            "only PACKAGE_VULNERABILITY findings are forwarded to Cortex.",
            skipped_no_cve,
        )
    # Sort highest severity first so that when the normalizer groups findings by asset
    # and the Cortex batch limit (1000 assets) is reached, the most critical vulns
    # are included rather than being truncated by API page order.
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity.upper(), len(_SEVERITY_ORDER)))
    return findings


def _parse(raw: dict) -> RawFinding | None:
    resources = raw.get("resources", [])
    if not resources:
        return None
    resource = resources[0]
    resource_id = resource.get("id", "")
    region = resource.get("region", "")
    aws_account = resource.get("providerAccountId", "")

    resource_type = resource.get("type", "")
    if resource_type == "AWS_ECR_CONTAINER_IMAGE":
        ecr = resource.get("details", {}).get("awsEcrContainerImage", {})
        asset_name = ecr.get("repositoryName") or resource_id
        # Tags can appear at the resource level and/or inside the detail block — merge both
        user_tags: dict = {
            **resource.get("tags", {}),
            **ecr.get("tags", {}),
        }
        os_name = ecr.get("platform")
        ipv4: list = []
        ipv6: list = []
        registry = ecr.get("registry", "") or aws_account
        repo = ecr.get("repositoryName", "")
        fqdn: list = (
            [f"{registry}.dkr.ecr.{region}.amazonaws.com/{repo}"]
            if registry and region and repo else []
        )
        image_tags = ecr.get("imageTags", [])
        cloud_meta: list[str] = [
            "cloud:aws",
            "resource_type:ecr_container_image",
            f"aws_account:{registry}",
            f"aws_region:{region}",
            f"ecr_repository:{repo}",
            f"architecture:{ecr.get('architecture', '')}",
            f"image_hash:{ecr.get('imageHash', '')}",
        ]
        if image_tags:
            cloud_meta.append(f"image_tags:{','.join(image_tags)}")
    else:
        ec2 = resource.get("details", {}).get("awsEc2Instance", {})
        # Tags can appear at the resource level and/or inside the EC2 detail block — merge both
        user_tags = {
            **resource.get("tags", {}),
            **ec2.get("tags", {}),
        }
        asset_name = user_tags.get("Name") or resource_id
        os_name = ec2.get("platform")
        ipv4 = ec2.get("ipV4Addresses", [])
        ipv6 = ec2.get("ipV6Addresses", [])
        fqdn = []
        cloud_meta = [
            "cloud:aws",
            "resource_type:ec2_instance",
            f"aws_account:{aws_account}",
            f"aws_region:{region}",
            f"instance_id:{resource_id}",
            f"instance_type:{ec2.get('type', '')}",
            f"platform:{ec2.get('platform', '')}",
            f"vpc:{ec2.get('vpcId', '')}",
            f"subnet:{ec2.get('subnetId', '')}",
        ]

    # Cloud metadata first, then user-defined resource tags (excluding Name — used as asset_name)
    tags = cloud_meta + [f"{k}:{v}" for k, v in user_tags.items() if k != "Name"]

    # Inspector2 API returns the field as "packageVulnerabilityDetails"
    pkg_vuln = raw.get("packageVulnerabilityDetails") or raw.get("packageVulnerability") or {}
    cve_id = pkg_vuln.get("vulnerabilityId", "")
    if not cve_id:
        return None

    updated_at = raw.get("updatedAt")
    last_seen_ms = int(updated_at.timestamp() * 1000) if updated_at else int(time.time() * 1000)
    score = raw.get("inspectorScore", 0)
    remediation = (raw.get("remediation") or {}).get("recommendation", {}).get("text", "")
    raw_output = f"score:{score} | {remediation}"[:2000]
    return RawFinding(
        asset_id=resource_id,
        asset_name=asset_name,
        ipv4=ipv4,
        ipv6=ipv6,
        fqdn=fqdn,
        mac_address=None,
        os_name=os_name,
        tags=tags,
        last_seen_ms=last_seen_ms,
        cve_id=cve_id,
        severity=raw.get("severity", "MEDIUM"),
        description=raw.get("description", ""),
        evidence=f"CVSS: {pkg_vuln.get('cvss', [])}",
        raw_output=raw_output,
        source="aws_inspector",
    )

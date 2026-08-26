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
#
#   INSPECTOR2_COVERAGE_FILTER  "true" (default) | "false"
#                              When true, list-coverage is called to identify
#                              resources that Inspector2 has actually scanned
#                              in the coverage window.  Findings for resources
#                              that have NOT been scanned in that window are
#                              dropped before normalisation.  This is the most
#                              accurate way to exclude stale/terminated assets:
#                              lastScannedAt reflects the actual scan clock,
#                              not the vulnerability finding age.
#                              Set to "false" to skip the coverage pre-check
#                              (e.g. if the IAM role lacks
#                              inspector2:ListCoverage permission).
#
#   INSPECTOR2_COVERAGE_HOURS  integer; default: 720 (30 days)
#                              The lastScannedAt window used by list-coverage.
#                              Only resources scanned within the last N hours
#                              are considered active.  Set to 72 to restrict
#                              to assets scanned in the last 3 days.
#                              Ignored when INSPECTOR2_COVERAGE_FILTER=false.
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


def _parse_raw_list(raw: str, valid: set[str], default: list[str], label: str) -> list[str]:
    """Parse a comma-separated string directly (used for EventBridge event overrides)."""
    values = [v.strip().upper() for v in raw.split(",") if v.strip()]
    unknown = set(values) - valid
    if unknown:
        logger.warning(
            "Unknown %s values ignored: %s — valid values are: %s",
            label, unknown, valid,
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


def _coverage_filter_enabled() -> bool:
    """Return True unless INSPECTOR2_COVERAGE_FILTER is explicitly set to 'false'."""
    return os.environ.get("INSPECTOR2_COVERAGE_FILTER", "true").strip().lower() != "false"


def _coverage_hours() -> int:
    """Return INSPECTOR2_COVERAGE_HOURS as a positive int.

    Controls the ``lastScannedAt`` window passed to ``list_coverage``.
    Default is 720 (30 days) — resources not scanned in this window are
    considered stale.  Set to a smaller value (e.g. 72) to restrict to
    assets scanned very recently.
    """
    raw = os.environ.get("INSPECTOR2_COVERAGE_HOURS", "720").strip()
    try:
        val = int(raw)
        return max(val, 1)
    except ValueError:
        logger.warning(
            "INSPECTOR2_COVERAGE_HOURS=%r is not an integer — defaulting to 720 (30 days)", raw
        )
        return 720


def _active_resource_ids(client: Any, lookback_hours: int = 720) -> set[str]:
    """Return the set of resource IDs that Inspector2 has scanned within *lookback_hours*.

    Uses the ``list_coverage`` API with a ``lastScannedAt`` filter so that only
    resources with a confirmed recent scan are returned.  Resources that have been
    terminated or removed from Inspector2's scope will have an old (or absent)
    ``lastScannedAt`` and will not appear in the result set.

    If the call fails for any reason (e.g. missing IAM permission) a warning is
    logged and an empty set is returned — the caller should treat that as "no
    filter applied" to avoid silently dropping all findings.
    """
    now = datetime.now(tz=timezone.utc)
    cutoff = datetime.fromtimestamp(now.timestamp() - lookback_hours * 3600, tz=timezone.utc)
    try:
        paginator = client.get_paginator("list_coverage")
        resource_ids: set[str] = set()
        for page in paginator.paginate(
            filterCriteria={
                "lastScannedAt": [{"startInclusive": cutoff, "endInclusive": now}],
            },
            PaginationConfig={"PageSize": 200},
        ):
            for resource in page.get("coveredResources", []):
                rid = resource.get("resourceId", "")
                if rid:
                    # Normalise Lambda ARNs to base form; ECR images bypass the
                    # coverage filter entirely so no ECR normalisation needed here.
                    resource_ids.add(_lambda_base_arn(rid))
        logger.info(
            "Coverage filter: %d resource(s) scanned in the last %d hours.",
            len(resource_ids), lookback_hours,
        )
        return resource_ids
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "list_coverage call failed (%s) — coverage filter skipped. "
            "Grant inspector2:ListCoverage to the IAM role, or set "
            "INSPECTOR2_COVERAGE_FILTER=false to suppress this warning.",
            exc,
        )
        return set()


def collect(
    mode: str,
    finding_arn: str | None = None,
    region: str | None = None,
    severities: str | None = None,
    statuses: str | None = None,
    lookback_hours: int | None = None,
    coverage_hours: int | None = None,
) -> list[RawFinding]:
    """Collect findings.

    ``severities``, ``statuses``, ``lookback_hours``, and ``coverage_hours``
    may be passed explicitly (e.g. from an EventBridge input payload) and take
    priority over the corresponding env vars.  When not provided the env vars
    are read as normal.
    """
    client = boto3.client("inspector2", region_name=region or _DEFAULT_REGION)

    if statuses is not None:
        resolved_statuses = _parse_raw_list(statuses, _VALID_STATUSES, ["ACTIVE"], "statuses")
    else:
        resolved_statuses = _parse_env_list("INSPECTOR2_STATUSES", _VALID_STATUSES, ["ACTIVE"])

    if severities is not None:
        resolved_severities = _parse_raw_list(severities, _VALID_SEVERITIES, ["MEDIUM", "HIGH", "CRITICAL","LOW"], "severities")
    else:
        resolved_severities = _parse_env_list("INSPECTOR2_SEVERITIES", _VALID_SEVERITIES, ["MEDIUM", "HIGH", "CRITICAL","LOW"])

    resolved_hours = _lookback_hours() if lookback_hours is None else max(int(lookback_hours), 0)

    source = (
        "event-override"
        if any(v is not None for v in (severities, statuses, lookback_hours))
        else "env-vars"
    )
    logger.info(
        "Inspector2 filters — statuses: %s  severities: %s  lookback_hours: %s  [source: %s]",
        resolved_statuses,
        resolved_severities,
        resolved_hours if resolved_hours > 0 else "disabled (full scan)",
        source,
    )

    # ------------------------------------------------------------------
    # Coverage pre-filter: drop findings for assets that haven't been
    # scanned by Inspector2 within the coverage window.  This is more
    # reliable than relying on finding timestamps because list-coverage
    # reflects the actual scan schedule — a terminated or out-of-scope
    # EC2 instance will not appear here even if its findings are ACTIVE.
    # ------------------------------------------------------------------
    active_ids: set[str] | None = None
    if _coverage_filter_enabled():
        resolved_coverage_hours = _coverage_hours() if coverage_hours is None else max(int(coverage_hours), 1)
        logger.info("Coverage filter window: last %d hours.", resolved_coverage_hours)
        active_ids = _active_resource_ids(client, lookback_hours=resolved_coverage_hours)
        if not active_ids:
            logger.warning(
                "Coverage filter returned zero resources — filter will not be applied. "
                "All findings will be included regardless of scan age."
            )
            active_ids = None  # treat as disabled

    return _collect_with_retry(client, mode, finding_arn, resolved_statuses, resolved_severities, resolved_hours, active_ids)


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=8))
def _collect_with_retry(
    client: Any,
    mode: str,
    finding_arn: str | None,
    statuses: list[str],
    severities: list[str],
    lookback_hours: int,
    active_ids: set[str] | None = None,
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
    raw_rtype_counts: dict[str, int] = {}  # raw resource types from Inspector2 before any filtering
    for page in paginator.paginate(**kwargs):
        page_num += 1
        page_findings = page.get("findings", [])
        page_kept = 0
        for raw in page_findings:
            raw_total += 1
            # Track raw resource type counts for diagnostics
            rtype = (raw.get("resources") or [{}])[0].get("type", "UNKNOWN")
            raw_rtype_counts[rtype] = raw_rtype_counts.get(rtype, 0) + 1
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
                # Coverage filter — skip assets Inspector2 hasn't scanned recently.
                # ECR images are scanned once on push (not on a rolling schedule) so
                # they are intentionally excluded from the coverage check; their
                # findings remain valid regardless of when the image was pushed.
                raw_resource_type = raw.get("resources", [{}])[0].get("type", "")
                if raw_resource_type != "AWS_ECR_CONTAINER_IMAGE":
                    if raw_resource_type == "AWS_LAMBDA_FUNCTION":
                        coverage_check_id = _lambda_base_arn(parsed.asset_id)
                    else:
                        coverage_check_id = parsed.asset_id
                    if active_ids is not None and coverage_check_id not in active_ids:
                        logger.debug(
                            "Coverage filter: skipped finding for resource '%s' "
                            "(not scanned in last 30 days).",
                            parsed.asset_id,
                        )
                        continue
                findings.append(parsed)
                page_kept += 1
        logger.info(
            "Page %d: %d raw / %d kept (running total: %d kept / %d raw)",
            page_num, len(page_findings), page_kept, len(findings), raw_total,
        )

    logger.info(
        "Inspector2 collection done: %d raw findings — %d kept, %d skipped (no CVE/package), "
        "%d skipped (no resource)%s  [mode=%s, pages=%d]",
        raw_total, len(findings), skipped_no_cve, skipped_no_resource,
        f", coverage filter active ({len(active_ids)} resources)" if active_ids is not None else "",
        mode, page_num,
    )
    logger.info("Resource type breakdown (raw from Inspector2): %s", raw_rtype_counts)
    # Per-resource-type breakdown to aid debugging
    from collections import Counter   # noqa: PLC0415
    rtype_counts = Counter(
        next((t[len("resource_type:"):] for t in f.tags if t.startswith("resource_type:")), "unknown")
        for f in findings
    )
    logger.info("Resource type breakdown (kept): %s", dict(rtype_counts))
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


def _parse_lambda_arn(arn: str) -> tuple[str, str]:
    """Return (function_name, version_qualifier) from a Lambda ARN.

    Handles:
      arn:aws:lambda:REGION:ACCOUNT:function:NAME          → ("NAME", "$LATEST")
      arn:aws:lambda:REGION:ACCOUNT:function:NAME:$LATEST  → ("NAME", "$LATEST")
      arn:aws:lambda:REGION:ACCOUNT:function:NAME:3        → ("NAME", "3")
      arn:aws:lambda:REGION:ACCOUNT:function:NAME:prod     → ("NAME", "prod")
    """
    parts = arn.split(":")
    if len(parts) >= 8 and parts[5] == "function":
        return parts[6], parts[7]
    if len(parts) >= 7 and parts[5] == "function":
        return parts[6], "$LATEST"
    return parts[-1] if parts else arn, "$LATEST"


def _lambda_base_arn(arn: str) -> str:
    """Strip any version/alias qualifier from a Lambda ARN.

    Inspector2 list_findings may return  arn:...:function:my-fn:$LATEST
    while list_coverage returns          arn:...:function:my-fn
    Normalising to the base ARN ensures the coverage filter matches correctly.
    """
    parts = arn.split(":")
    if len(parts) >= 8 and parts[5] == "function":
        return ":".join(parts[:7])
    return arn


def _ecr_coverage_id(asset_id: str) -> str:
    """Extract the bare digest from an ECR asset_id for coverage-filter lookup.

    We store asset_id as  registry/repo@sha256:...  for Cortex uniqueness,
    but list_coverage returns just the raw digest (sha256:...) as resourceId.
    """
    if "@" in asset_id:
        return asset_id.split("@", 1)[1]
    return asset_id


def _parse(raw: dict) -> RawFinding | None:
    resources = raw.get("resources", [])
    if not resources:
        return None
    resource = resources[0]
    resource_id = resource.get("id", "")
    region = resource.get("region", "")
    aws_account = resource.get("providerAccountId", "")

    resource_type = resource.get("type", "")
    ecr_asset_id = resource_id  # overridden below for ECR; kept as fallback for Lambda/EC2
    if resource_type == "AWS_ECR_CONTAINER_IMAGE":
        ecr = resource.get("details", {}).get("awsEcrContainerImage", {})
        image_hash = ecr.get("imageHash", "")
        # asset_name = digest so each unique image is a distinct Cortex asset.
        # The repo name is preserved in the tags below.
        asset_name = image_hash or resource_id
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
        # Build a globally unique asset_id: registry/repo@digest.
        # Inspector2 returns resource.id as just the bare digest (sha256:...) which
        # is NOT unique across repos or accounts — two repos that share the same
        # base image will have the same digest but are distinct Cortex assets.
        # Using registry/repo@digest guarantees uniqueness.
        if registry and repo and image_hash:
            ecr_asset_id = f"{registry}.dkr.ecr.{region}.amazonaws.com/{repo}@{image_hash}"
        else:
            ecr_asset_id = resource_id
        cloud_meta: list[str] = [
            "cloud:aws",
            "resource_type:ecr_container_image",
            f"aws_account:{registry}",
            f"aws_region:{region}",
            f"ecr_repository:{repo}",
            f"ecr_repo_name:{repo}",
            f"architecture:{ecr.get('architecture', '')}",
            f"image_hash:{image_hash}",
        ]
        if image_tags:
            cloud_meta.append(f"image_tags:{','.join(image_tags)}")
    elif resource_type == "AWS_LAMBDA_FUNCTION":
        lam = resource.get("details", {}).get("awsLambdaFunction", {})
        user_tags = {
            **resource.get("tags", {}),
            **lam.get("functionTags", {}),
        }
        # Extract function name and version qualifier from the ARN.
        # Inspector2 list_findings may return the ARN with a version qualifier
        # (e.g. :$LATEST or :3) while list_coverage returns the base ARN.
        # We normalise asset_id to the base ARN so the coverage filter matches,
        # and store the qualifier separately in tags.
        fn_name, fn_version = _parse_lambda_arn(resource_id)
        asset_name = lam.get("functionName") or fn_name or resource_id
        runtime = lam.get("runtime", "")
        layers  = lam.get("layers", [])
        os_name = None
        ipv4    = []
        ipv6    = []
        fqdn    = []
        cloud_meta = [
            "cloud:aws",
            "resource_type:lambda_function",
            f"aws_account:{aws_account}",
            f"aws_region:{region}",
            f"function_name:{asset_name}",
            f"runtime:{runtime}",
            f"lambda_version:{fn_version}",
        ]
        if layers:
            cloud_meta.append(f"lambda_layers:{','.join(layers)}")
        # Keep the full versioned ARN as asset_id (origin_asset_id in Cortex) so
        # each Lambda version is a distinct asset.  The base-ARN normalisation
        # needed for the coverage filter is handled at the lookup site in
        # _collect_with_retry, not here.
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
    # ECR uses ecr_asset_id (registry/repo@digest); all others use resource_id.
    final_asset_id = ecr_asset_id if resource_type == "AWS_ECR_CONTAINER_IMAGE" else resource_id
    return RawFinding(
        asset_id=final_asset_id,
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

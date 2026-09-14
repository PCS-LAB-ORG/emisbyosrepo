from __future__ import annotations

import datetime
import json
import logging
import os
import re
import time
import uuid

from azure.identity import DefaultAzureCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
from azure.mgmt.subscription import SubscriptionClient
from tenacity import retry, stop_after_attempt, wait_exponential

from byob_core.models import RawFinding

logger = logging.getLogger(__name__)

# Suppress noisy Azure SDK HTTP wire logs
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)
logging.getLogger("azure.identity").setLevel(logging.WARNING)
logging.getLogger("azure.mgmt").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

_BASE_QUERY = (
    "securityresources "
    "| where type == 'microsoft.security/assessments/subassessments' "
    "| where properties.id != '' "
    "| project id, name, properties"
)

# Matches: /subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}/...
_ARM_RE = re.compile(
    r"/subscriptions/(?P<sub>[^/]+)"
    r"(?:/resourceGroups/(?P<rg>[^/]+))?"
    r"(?:/providers/(?P<ns>[^/]+)/(?P<rtype>[^/]+)/(?P<rname>[^/]+))?",
    re.IGNORECASE,
)


def _parse_arm_id(arm_id: str) -> dict[str, str]:
    """Extract subscription, resource group, provider namespace, type and name from an ARM id."""
    m = _ARM_RE.match(arm_id or "")
    if not m:
        return {}
    return {k: v or "" for k, v in m.groupdict().items()}


def _is_guid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def _resolve_subscription_ids(names_or_ids: list[str], credential: DefaultAzureCredential) -> list[str]:
    """Resolve a list of subscription display names or GUIDs to GUIDs.

    Values that are already valid GUIDs are passed through unchanged.
    Display names are looked up via the Azure Subscription API.
    """
    # Fast path: all already GUIDs
    if all(_is_guid(v) for v in names_or_ids):
        return names_or_ids

    logger.info("Resolving subscription names to GUIDs ...")
    sub_client = SubscriptionClient(credential)
    name_to_id: dict[str, str] = {}
    for sub in sub_client.subscriptions.list():
        name_to_id[sub.display_name] = sub.subscription_id

    resolved = []
    for v in names_or_ids:
        if _is_guid(v):
            resolved.append(v)
        elif v in name_to_id:
            logger.info("  Resolved '%s' → %s", v, name_to_id[v])
            resolved.append(name_to_id[v])
        else:
            raise ValueError(
                f"Subscription '{v}' is not a GUID and was not found in your Azure tenant. "
                f"Available names: {sorted(name_to_id.keys())}"
            )
    return resolved


def _resolve_scope(credential: DefaultAzureCredential) -> tuple[list[str], list[str]]:
    """Return (subscriptions, management_groups) to pass to Resource Graph QueryRequest.

    Resolution order:
    1. AZURE_MANAGEMENT_GROUP_ID — query all subscriptions under the management group.
       Resource Graph fans out automatically; no need to enumerate subscriptions first.
    2. AZURE_SUBSCRIPTION_IDS   — comma-separated list of explicit subscription IDs.
    3. AZURE_SUBSCRIPTION_ID    — single subscription (backward-compatible default).
    """
    mgmt_group = os.environ.get("AZURE_MANAGEMENT_GROUP_ID", "").strip()
    if mgmt_group:
        logger.info("Azure scope: management group '%s'", mgmt_group)
        return [], [mgmt_group]

    multi = os.environ.get("AZURE_SUBSCRIPTION_IDS", "").strip()
    if multi:
        raw = [s.strip() for s in multi.split(",") if s.strip()]
        subs = _resolve_subscription_ids(raw, credential)
        logger.info("Azure scope: %d explicit subscription(s)", len(subs))
        return subs, []

    single = os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
    if not single:
        raise ValueError(
            "Set one of AZURE_MANAGEMENT_GROUP_ID, AZURE_SUBSCRIPTION_IDS, "
            "or AZURE_SUBSCRIPTION_ID."
        )
    resolved = _resolve_subscription_ids([single], credential)
    logger.info("Azure scope: single subscription '%s'", resolved[0])
    return resolved, []


def collect(mode: str, resource_id: str | None = None) -> list[RawFinding]:
    credential = DefaultAzureCredential()
    subscriptions, management_groups = _resolve_scope(credential)
    client = ResourceGraphClient(credential)
    return _collect_with_retry(client, subscriptions, management_groups, mode, resource_id)


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=8))
def _collect_with_retry(
    client: ResourceGraphClient,
    subscriptions: list[str],
    management_groups: list[str],
    mode: str,
    resource_id: str | None,
) -> list[RawFinding]:
    query = _BASE_QUERY
    if mode == "event" and resource_id:
        safe_id = resource_id.replace("'", "\\'")
        query = f"{_BASE_QUERY} | where id startswith '{safe_id}'"

    # Log the exact query and scope being used
    logger.info("=" * 80)
    logger.info("AZURE RESOURCE GRAPH QUERY:")
    logger.info("Query: %s", query)
    logger.info("Subscriptions: %s", subscriptions or "None (using management groups)")
    logger.info("Management Groups: %s", management_groups or "None")
    logger.info("=" * 80)

    # Diagnostic: check what security resource types exist in scope at all
    try:
        diag_req = QueryRequest(
            subscriptions=subscriptions or None,
            management_groups=management_groups or None,
            query="securityresources | summarize count() by type | order by count_ desc",
        )
        diag_result = client.resources(diag_req)
        diag_rows = diag_result.data if diag_result.data else []
        if diag_rows:
            logger.info("Security resource types in scope:")
            for r in diag_rows:
                logger.info("  type=%-60s  count=%s", r.get("type", "?"), r.get("count_", "?"))
        else:
            logger.warning("Diagnostic query returned 0 rows — no securityresources found in this scope at all.")
    except Exception as diag_exc:
        logger.warning("Diagnostic query failed: %s", diag_exc)

    findings: list[RawFinding] = []
    skipped_no_cve = 0
    raw_total = 0
    skip_token = None
    while True:
        req = QueryRequest(
            subscriptions=subscriptions or None,
            management_groups=management_groups or None,
            query=query,
        )
        if skip_token:
            req.options = QueryRequestOptions(skip_token=skip_token)
        result = client.resources(req)
        # result.data is the list of row dicts directly — not nested
        rows = result.data if result.data else []
        logger.info("Azure Resource Graph page: %d rows returned", len(rows))

        if not rows:
            logger.info("Empty page — raw result dump: total_records=%s, skip_token=%s, data=%s",
                        getattr(result, "total_records", "?"),
                        getattr(result, "skip_token", "?"),
                        str(result.data)[:500])

        # Show first few rows in detail for debugging
        if rows and raw_total == 0:
            logger.info("=" * 80)
            logger.info("DEFENDER API RESPONSE - First 3 rows:")
            logger.info("=" * 80)
            for i, row in enumerate(rows[:3], 1):
                logger.info(f"\n--- Row {i} ---")
                logger.info(json.dumps(row, indent=2, default=str))
            logger.info("=" * 80)
        for row in rows:
            raw_total += 1
            parsed = _parse(row)
            if parsed:
                findings.append(parsed)
            else:
                skipped_no_cve += 1
                # Log why this row was skipped (first 5 skips only to avoid spam)
                if skipped_no_cve <= 5:
                    props = row.get("properties", {})
                    logger.warning(
                        "Skipped row %d (no CVE found) - displayName: '%s', "
                        "properties.id: '%s', additionalData keys: %s",
                        raw_total,
                        props.get("displayName", "N/A"),
                        props.get("id", "N/A"),
                        list(props.get("additionalData", {}).keys())
                    )
        skip_token = getattr(result, "skip_token", None)
        if not skip_token:
            break
    scope_desc = (
        f"management group(s) {management_groups}"
        if management_groups
        else f"{len(subscriptions)} subscription(s)"
    )
    logger.info(
        "Azure Defender: %d raw findings — %d kept, %d skipped (no CVE)  "
        "[mode=%s, scope=%s]",
        raw_total, len(findings), skipped_no_cve, mode, scope_desc,
    )
    return findings


def _parse(row: dict) -> RawFinding | None:
    props = row.get("properties", {})
    additional = props.get("additionalData", {})

    # Extract CVE ID from various possible locations
    cve_id = ""
    cve_source = ""

    # Option 1: additionalData.cve (array of CVE objects)
    cve_list = additional.get("cve", [])
    if cve_list and isinstance(cve_list, list) and len(cve_list) > 0:
        if isinstance(cve_list[0], dict):
            cve_id = cve_list[0].get("id", "") or cve_list[0].get("cve", "")
            if cve_id:
                cve_source = "additionalData.cve[]"
        elif isinstance(cve_list[0], str):
            cve_id = cve_list[0]
            if cve_id:
                cve_source = "additionalData.cve[]"

    # Option 2: additionalData.vulnerabilityId
    if not cve_id:
        cve_id = additional.get("vulnerabilityId", "")
        if cve_id:
            cve_source = "additionalData.vulnerabilityId"

    # Option 3: Extract from displayName (e.g., "CVE-2024-12345: Some description")
    if not cve_id:
        display_name = props.get("displayName", "")
        if display_name and "CVE-" in display_name:
            match = re.search(r'(CVE-\d{4}-\d+)', display_name, re.IGNORECASE)
            if match:
                cve_id = match.group(1).upper()
                cve_source = "displayName (regex)"

    # Option 4: Fall back to properties.id (legacy behavior)
    if not cve_id:
        cve_id = props.get("id", "")
        if cve_id:
            cve_source = "properties.id"

    if not cve_id:
        return None

    # Log first 5 successful CVE extractions to show which method is working
    if not hasattr(_parse, "_log_count"):
        _parse._log_count = 0
    if _parse._log_count < 5:
        _parse._log_count += 1
        logger.info("✓ Extracted CVE '%s' from %s", cve_id, cve_source)

    arm_id: str = row.get("id", "")
    arm = _parse_arm_id(arm_id)
    subscription_id = arm.get("sub", "")
    resource_group = arm.get("rg", "")
    provider_ns = arm.get("ns", "")       # e.g. Microsoft.ContainerRegistry
    resource_type = arm.get("rtype", "")  # e.g. registries
    resource_name_arm = arm.get("rname", "")

    resource_details = props.get("resourceDetails", {})
    resource_name = resource_details.get("resourceName") or resource_name_arm or arm_id
    resource_source = resource_details.get("source", "")  # Azure, OnPremise, etc.

    # Container image metadata (present when the finding is on a registry image)
    registry = additional.get("registry", "")
    repo = additional.get("repositoryName", "")
    image_tag = additional.get("imageTag", "")
    image_digest = additional.get("imageDigest", "")
    os_name = additional.get("osDetails") or additional.get("platform") or None

    # FQDN: full ACR image reference when registry metadata is available
    fqdn: list[str] = []
    if registry and repo:
        ref = f"{registry}/{repo}"
        if image_tag:
            ref = f"{ref}:{image_tag}"
        fqdn = [ref]

    # Cloud metadata tags
    cloud_meta: list[str] = [
        "cloud:azure",
        f"azure_subscription:{subscription_id}",
        f"azure_resource_group:{resource_group}",
        f"azure_provider:{provider_ns}",
        f"azure_resource_type:{resource_type}",
        f"azure_resource_name:{resource_name_arm}",
        f"source:{resource_source}",
    ]
    if registry:
        cloud_meta.append(f"registry:{registry}")
    if repo:
        cloud_meta.append(f"repository:{repo}")
    if image_tag:
        cloud_meta.append(f"image_tag:{image_tag}")
    if image_digest:
        cloud_meta.append(f"image_digest:{image_digest}")

    severity = (props.get("severity") or {}).get("severity", "Medium").upper()
    evidence = str(additional.get("cvss", ""))[:2000]
    time_generated = props.get("timeGenerated", "")
    try:
        dt = datetime.datetime.fromisoformat(time_generated.replace("Z", "+00:00"))
        last_seen_ms = int(dt.timestamp() * 1000)
    except Exception:
        last_seen_ms = int(time.time() * 1000)

    return RawFinding(
        asset_id=arm_id,
        asset_name=resource_name,
        ipv4=[],
        ipv6=[],
        fqdn=fqdn,
        mac_address=None,
        os_name=os_name,
        tags=cloud_meta,
        last_seen_ms=last_seen_ms,
        cve_id=cve_id,
        severity=severity,
        description=props.get("description", ""),
        evidence=evidence,
        raw_output=evidence,
        source="azure_defender",
    )

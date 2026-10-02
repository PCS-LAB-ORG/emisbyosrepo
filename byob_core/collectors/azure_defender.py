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

# Microsoft Defender Vulnerability Management (MDVM) publishes vulnerabilities as
# one assessment *per software package*, under microsoft.security/assessments —
# NOT under .../subassessments, which is the legacy (Qualys/BYOL) shape and is
# empty on MDVM-enabled subscriptions. The CVEs live in a JSON-encoded string at
# properties.additionalData.CvesDetails, so one row expands into many findings.
#
# No resource-type restriction here on purpose: the collector gathers every
# resource type Defender assesses (VMs, scale sets, App Service / function apps,
# K8s containers, ...). Narrowing to a subset is a caller concern — see
# batch_push.py's --resource-type flag, which filters on the resource_type: tag.
_BASE_QUERY = (
    "securityresources "
    "| where type == 'microsoft.security/assessments' "
    "| where isnotempty(tostring(properties.additionalData.CvesDetails)) "
    "| project id, name, properties"
)

# Azure Defender status.code -> the ACTIVE/CLOSED vocabulary Cortex expects.
# Cortex consumes evidence as {"status": "ACTIVE"|"CLOSED"} — exactly two
# values. Only Healthy means the vulnerability is gone; anything unrecognised
# falls through to ACTIVE so a live finding is never reported as resolved. The
# native Defender value is kept verbatim in the azure_status: tag.
#
# NotApplicable means Defender could not assess the resource; it asserts neither
# presence nor absence of a vulnerability, so those rows are dropped rather than
# guessed either way. In practice Defender strips CvesDetails from Healthy and
# NotApplicable assessments, so only Unhealthy rows carry CVEs at all.
_STATUS_MAP = {
    "UNHEALTHY": "ACTIVE",
    "HEALTHY": "CLOSED",
}
_STATUS_SKIP = {"NOTAPPLICABLE"}

# resourceDetails.ResourceType -> resource_type: tag value. Mirrors the AWS
# collector's tagging so --resource-type works the same way for both clouds.
_RESOURCE_TYPE_TAGS = {
    "microsoft.compute/virtualmachines":         "virtual_machine",
    "microsoft.compute/virtualmachinescalesets": "vm_scale_set",
    "microsoft.web/sites/functionapp":           "function_app",
    "microsoft.web/sites":                       "app_service",
    "microsoft.containerregistry/registries":    "container_registry",
    "k8s-container":                             "k8s_container",
}


def _resource_type_tag(resource_type: str) -> str:
    """Map an Azure resourceDetails.ResourceType to a stable resource_type: tag."""
    key = (resource_type or "").lower()
    if key in _RESOURCE_TYPE_TAGS:
        return _RESOURCE_TYPE_TAGS[key]
    if not key:
        return "unknown"
    # Unmapped type: derive a readable slug from the last path segment so the
    # finding is still filterable (e.g. Microsoft.Sql/servers -> servers).
    return re.sub(r"[^a-z0-9]+", "_", key.split("/")[-1]).strip("_") or "unknown"

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
    logger.info(
        "Azure Resource Graph query [mode=%s, scope=%s]",
        mode,
        f"management group(s) {management_groups}" if management_groups
        else f"{len(subscriptions)} subscription(s)",
    )
    logger.debug("Query: %s", query)
    logger.debug("Subscriptions: %s | Management groups: %s",
                 subscriptions or "none", management_groups or "none")

    # Diagnostic: what security resource types exist in scope at all. Only worth
    # the extra round-trip when debugging an empty or unexpected result.
    if logger.isEnabledFor(logging.DEBUG):
        try:
            diag_req = QueryRequest(
                subscriptions=subscriptions or None,
                management_groups=management_groups or None,
                query="securityresources | summarize count() by type | order by count_ desc",
            )
            diag_result = client.resources(diag_req)
            diag_rows = diag_result.data if diag_result.data else []
            if diag_rows:
                logger.debug("Security resource types in scope:")
                for r in diag_rows:
                    logger.debug("  type=%-60s count=%s", r.get("type", "?"), r.get("count_", "?"))
            else:
                logger.warning(
                    "Diagnostic query returned 0 rows — no securityresources in this scope at all."
                )
        except Exception as diag_exc:
            logger.warning("Diagnostic query failed: %s", diag_exc)

    findings: list[RawFinding] = []
    skipped_rows = 0
    skipped_notapplicable = 0
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
            logger.warning(
                "Empty page from Resource Graph — total_records=%s, skip_token=%s. "
                "If this is the first page, no CVE-bearing assessments exist in scope.",
                getattr(result, "total_records", "?"),
                getattr(result, "skip_token", "?"),
            )

        # Full rows are several KB each — DEBUG only. Enable with
        # logging.getLogger("byob_core.collectors.azure_defender").setLevel(DEBUG)
        # to inspect the raw shape when a tenant returns unexpected fields.
        if rows and raw_total == 0 and logger.isEnabledFor(logging.DEBUG):
            for i, row in enumerate(rows[:3], 1):
                logger.debug("Raw assessment row %d/%d: %s", i, min(3, len(rows)),
                             json.dumps(row, indent=2, default=str))
        for row in rows:
            raw_total += 1
            parsed = _parse(row)
            if parsed:
                findings.extend(parsed)
                continue
            skipped_rows += 1
            props = row.get("properties", {}) or {}
            status_code = str((props.get("status") or {}).get("code", "")).upper()
            if status_code in _STATUS_SKIP:
                skipped_notapplicable += 1
                continue
            # Log why this row yielded nothing (first 5 only, to avoid spam)
            if skipped_rows - skipped_notapplicable <= 5:
                logger.warning(
                    "Skipped row %d (no CVEs extracted) - displayName: '%s', "
                    "status: '%s', additionalData keys: %s",
                    raw_total,
                    props.get("displayName", "N/A"),
                    status_code or "N/A",
                    list((props.get("additionalData") or {}).keys()),
                )
        skip_token = getattr(result, "skip_token", None)
        if not skip_token:
            break
    scope_desc = (
        f"management group(s) {management_groups}"
        if management_groups
        else f"{len(subscriptions)} subscription(s)"
    )
    if skipped_notapplicable:
        logger.info(
            "Skipped %d assessment(s) with status NotApplicable (Defender could not "
            "assess the resource — no vulnerability asserted either way).",
            skipped_notapplicable,
        )
    logger.info(
        "Azure Defender: %d assessment row(s) → %d finding(s) across %d asset(s); "
        "%d row(s) yielded no CVEs  [mode=%s, scope=%s]",
        raw_total, len(findings), len({f.asset_id for f in findings}),
        skipped_rows, mode, scope_desc,
    )
    if findings:
        by_type: dict[str, int] = {}
        for f in findings:
            tag = next((t[len("resource_type:"):] for t in f.tags
                        if t.startswith("resource_type:")), "unknown")
            by_type[tag] = by_type.get(tag, 0) + 1
        logger.info("Findings by resource type:")
        for tag, count in sorted(by_type.items(), key=lambda kv: -kv[1]):
            logger.info("  resource_type:%-22s %d finding(s)", tag, count)
    return findings


def _parse_timestamp(status: dict) -> int | None:
    """Milliseconds for the most recent evaluation of this assessment.

    MDVM assessments carry no ``properties.timeGenerated`` — the previous code
    read that field, so every finding silently fell back to the import time and
    real finding age was lost. Prefer statusChangeDate, then firstEvaluationDate.
    """
    for key in ("statusChangeDate", "firstEvaluationDate"):
        value = status.get(key)
        if not value:
            continue
        try:
            parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            continue
        return int(parsed.timestamp() * 1000)
    return None


def _parse_cves(additional: dict) -> list[dict]:
    """Decode additionalData.CvesDetails, which Defender stores as a JSON string."""
    blob = additional.get("CvesDetails")
    if not blob:
        return []
    if isinstance(blob, list):          # already decoded by the SDK
        return [c for c in blob if isinstance(c, dict)]
    try:
        parsed = json.loads(blob)
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [c for c in parsed if isinstance(c, dict)]


def _parse(row: dict) -> list[RawFinding]:
    """Expand one MDVM assessment row into one RawFinding per CVE."""
    props = row.get("properties", {}) or {}
    additional = props.get("additionalData", {}) or {}
    status = props.get("status", {}) or {}
    metadata = props.get("metadata", {}) or {}
    details = props.get("resourceDetails", {}) or {}

    raw_status = str(status.get("code", "")).upper()
    if raw_status in _STATUS_SKIP:
        return []
    # Unrecognised statuses fall through to ACTIVE — never report a live finding
    # as resolved on the strength of a value we do not know.
    mapped_status = _STATUS_MAP.get(raw_status, "ACTIVE")

    cves = _parse_cves(additional)
    if not cves:
        return []

    # asset_id must identify the *resource*, not the per-package assessment.
    # row["id"] is the assessment ARM id and is unique per software package, so
    # using it fragmented one VM into hundreds of single-vuln Cortex assets.
    asset_id = (
        details.get("NativeResourceId")
        or details.get("ResourceId")
        or details.get("Id")
        or row.get("id", "")
    )
    if not asset_id:
        return []

    arm = _parse_arm_id(asset_id)
    resource_type = str(details.get("ResourceType") or "")
    software = str(additional.get("SoftwareName") or "")
    asset_name = details.get("ResourceName") or arm.get("rname", "") or asset_id

    tags: list[str] = [
        "cloud:azure",
        f"azure_subscription:{arm.get('sub', '')}",
        f"azure_resource_group:{arm.get('rg', '')}",
        f"azure_provider:{arm.get('ns', '')}",
        f"azure_resource_type:{arm.get('rtype', '')}",
        f"azure_resource_name:{arm.get('rname', '')}",
        f"source:{details.get('Source', '')}",
        f"resource_type:{_resource_type_tag(resource_type)}",
        f"status:{mapped_status}",
    ]
    native_status = str(status.get("code", "") or "")
    if native_status:
        tags.append(f"azure_status:{native_status}")
    if software:
        tags.append(f"software:{software}")
    package_type = additional.get("PackageType")
    if package_type:
        tags.append(f"package_type:{package_type}")

    last_seen_ms = _parse_timestamp(status)
    if last_seen_ms is None:
        last_seen_ms = int(time.time() * 1000)

    fallback_severity = str(metadata.get("severity") or "MEDIUM").upper()
    max_cvss = additional.get("MaxCvssScore") or ""
    detected = additional.get("DetectedSoftwareVersions") or ""
    description = str(metadata.get("description") or props.get("displayName") or "")

    findings: list[RawFinding] = []
    for cve in cves:
        cve_id = str(cve.get("CveId") or "").strip()
        if not cve_id:
            continue
        severity = str(cve.get("Severity") or "").upper() or fallback_severity
        # Cortex consumes evidence as exactly {"status": "ACTIVE"|"CLOSED"}.
        # Fix details live in raw_output so nothing is lost.
        evidence = json.dumps({"status": mapped_status})
        fix_status = str(cve.get("FixStatus") or "")
        fixed_version = str(cve.get("FixedVersion") or "")
        parts = [f"score:{max_cvss}", software or "unknown package"]
        if detected:
            parts.append(str(detected))
        if fix_status:
            parts.append(fix_status)
        if fixed_version:
            parts.append(f"fixed in {fixed_version}")
        raw_output = " | ".join(p for p in parts if p)
        findings.append(RawFinding(
            asset_id=asset_id,
            asset_name=asset_name,
            ipv4=[],
            ipv6=[],
            fqdn=[],
            mac_address=None,
            os_name=None,
            tags=tags,
            last_seen_ms=last_seen_ms,
            cve_id=cve_id,
            severity=severity,
            description=description,
            evidence=evidence,
            raw_output=raw_output[:2000],
            source="azure_defender",
        ))
    return findings

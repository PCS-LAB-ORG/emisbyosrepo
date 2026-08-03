from __future__ import annotations

import datetime
import logging
import os
import re
import time

from azure.identity import DefaultAzureCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
from tenacity import retry, stop_after_attempt, wait_exponential

from byob_core.models import RawFinding

logger = logging.getLogger(__name__)

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


def collect(mode: str, resource_id: str | None = None) -> list[RawFinding]:
    subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
    credential = DefaultAzureCredential()
    client = ResourceGraphClient(credential)
    return _collect_with_retry(client, subscription_id, mode, resource_id)


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=8))
def _collect_with_retry(
    client: ResourceGraphClient,
    subscription_id: str,
    mode: str,
    resource_id: str | None,
) -> list[RawFinding]:
    query = _BASE_QUERY
    if mode == "event" and resource_id:
        safe_id = resource_id.replace("'", "\\'")
        query = f"{_BASE_QUERY} | where id startswith '{safe_id}'"
    findings: list[RawFinding] = []
    skipped_no_cve = 0
    raw_total = 0
    skip_token = None
    while True:
        req = QueryRequest(subscriptions=[subscription_id], query=query)
        if skip_token:
            req.options = QueryRequestOptions(skip_token=skip_token)
        result = client.resources(req)
        rows = result.data[0] if result.data else []
        for row in rows:
            raw_total += 1
            if not (row.get("properties") or {}).get("id"):
                skipped_no_cve += 1
                continue
            parsed = _parse(row)
            if parsed:
                findings.append(parsed)
        skip_token = getattr(result, "skip_token", None)
        if not skip_token:
            break
    logger.info(
        "Azure Defender: %d raw findings — %d kept, %d skipped (no CVE)  [mode=%s]",
        raw_total, len(findings), skipped_no_cve, mode,
    )
    return findings


def _parse(row: dict) -> RawFinding | None:
    props = row.get("properties", {})
    cve_id = props.get("id", "")
    if not cve_id:
        return None

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

    additional = props.get("additionalData", {})

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

from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests

from byob_core.models import RawFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tenable Vulnerability Management — vuln export collector
#
# Filtering — controlled via environment variables:
#
#   TENABLE_ACCESS_KEY         Tenable API access key (required)
#   TENABLE_SECRET_KEY         Tenable API secret key (required)
#
#   TENABLE_SEVERITIES         comma-separated; default: medium,high,critical
#                              Valid (lowercase): info, low, medium, high, critical
#
#   TENABLE_LOOKBACK_HOURS     integer; default: 720 (30 days)
#                              When > 0, only vulns seen in the last N hours are
#                              returned via the "since" filter.  Set to 0 to
#                              disable (full export — for first bulk import).
#
# Credentials are read from env vars first; callers (integration_test.py,
# Lambda handler) may set TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY before
# calling collect().
# ---------------------------------------------------------------------------

TENABLE_BASE_URL = os.environ.get("TENABLE_BASE_URL", "https://cloud.tenable.com")

_VALID_TENABLE_SEVERITIES = {"info", "low", "medium", "high", "critical"}

# Severity order for sorting — lower index = higher priority
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_ORDER)}

# Tenable severity string → normalised uppercase value used by Cortex
_SEVERITY_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFORMATIONAL",
}

# Vuln states sent to Cortex — FIXED vulnerabilities are not forwarded
_DEFAULT_STATES = ["OPEN", "REOPENED"]

# Async export polling
_POLL_INTERVAL_SEC = 30
_POLL_MAX_ATTEMPTS = 40  # 40 × 30 s = 20 minutes max


def _credentials() -> tuple[str, str]:
    access_key = os.environ.get("TENABLE_ACCESS_KEY", "")
    secret_key = os.environ.get("TENABLE_SECRET_KEY", "")
    if not access_key or not secret_key:
        raise EnvironmentError(
            "TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY must be set before calling the Tenable collector."
        )
    return access_key, secret_key


def _headers(access_key: str, secret_key: str) -> dict[str, str]:
    return {
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _parse_severities(raw: str | None) -> list[str]:
    """Return a list of lowercase Tenable severity names from a comma-separated string."""
    if not raw:
        return ["medium", "high", "critical"]
    values = [v.strip().lower() for v in raw.split(",") if v.strip()]
    unknown = set(values) - _VALID_TENABLE_SEVERITIES
    if unknown:
        logger.warning(
            "Unknown TENABLE_SEVERITIES values ignored: %s — valid values: %s",
            unknown, _VALID_TENABLE_SEVERITIES,
        )
    result = [v for v in values if v in _VALID_TENABLE_SEVERITIES]
    return result or ["medium", "high", "critical"]


def _lookback_hours(override: int | None) -> int:
    if override is not None:
        return max(int(override), 0)
    raw = os.environ.get("TENABLE_LOOKBACK_HOURS", "720").strip()
    try:
        return max(int(raw), 0)
    except ValueError:
        logger.warning("TENABLE_LOOKBACK_HOURS=%r is not an integer — defaulting to 720", raw)
        return 720


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def collect(
    mode: str = "scheduled",
    lookback_hours: int | None = None,
    severities: str | None = None,
) -> list[RawFinding]:
    """Export Tenable VM vulnerabilities and return a list of RawFinding objects.

    Parameters
    ----------
    mode:
        Kept for API parity with the other collectors.  Currently unused
        (Tenable has no event-driven mode analogous to Inspector2 SNS events).
    lookback_hours:
        When provided, overrides TENABLE_LOOKBACK_HOURS env var.  Pass 0 to
        disable the time filter entirely (full export — first bulk import).
    severities:
        Comma-separated severity names (uppercase or lowercase).  Overrides
        TENABLE_SEVERITIES env var when provided.
    """
    access_key, secret_key = _credentials()
    hdrs = _headers(access_key, secret_key)

    resolved_severities = _parse_severities(
        severities if severities is not None else os.environ.get("TENABLE_SEVERITIES")
    )
    resolved_hours = _lookback_hours(lookback_hours)

    logger.info(
        "Tenable VM filters — severities: %s  lookback_hours: %s",
        resolved_severities,
        resolved_hours if resolved_hours > 0 else "disabled (full export)",
    )

    export_uuid = _start_export(hdrs, resolved_severities, resolved_hours)
    chunks = _wait_for_export(hdrs, export_uuid)
    findings = _download_all_chunks(hdrs, export_uuid, chunks)

    # Sort highest severity first so the most critical findings survive any
    # per-asset truncation in the normalizer (1,000 vuln cap per asset).
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity.upper(), len(_SEVERITY_ORDER)))

    logger.info(
        "Tenable VM collection done: %d RawFinding(s) from %d chunk(s) [mode=%s]",
        len(findings), len(chunks), mode,
    )
    return findings


# ---------------------------------------------------------------------------
# Export lifecycle helpers
# ---------------------------------------------------------------------------

def _start_export(headers: dict, severities: list[str], lookback_hours: int) -> str:
    """POST /vulns/export → return export_uuid."""
    filters: dict[str, Any] = {
        "state": _DEFAULT_STATES,
        "severity": severities,
    }
    if lookback_hours > 0:
        since_ts = int(time.time()) - lookback_hours * 3600
        filters["since"] = since_ts
        logger.info(
            "Tenable VM time window: since %s (now − %d h)",
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(since_ts)),
            lookback_hours,
        )

    body: dict[str, Any] = {
        "num_assets": 100,
        "filters": filters,
    }

    resp = requests.post(
        f"{TENABLE_BASE_URL}/vulns/export",
        headers=headers,
        json=body,
        timeout=30,
    )

    # 409 = identical export already in progress — reuse it
    if resp.status_code == 409:
        data = resp.json()
        existing_uuid = data.get("active_job_id", "")
        logger.warning(
            "Tenable export 409 — duplicate export in progress; reusing existing job %s",
            existing_uuid,
        )
        if not existing_uuid:
            resp.raise_for_status()
        return existing_uuid

    resp.raise_for_status()
    export_uuid = resp.json()["export_uuid"]
    logger.info("Tenable export started: export_uuid=%s", export_uuid)
    return export_uuid


def _wait_for_export(headers: dict, export_uuid: str) -> list[int]:
    """Poll /vulns/export/{uuid}/status until FINISHED; return chunk IDs."""
    url = f"{TENABLE_BASE_URL}/vulns/export/{export_uuid}/status"
    for attempt in range(1, _POLL_MAX_ATTEMPTS + 1):
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        status = data.get("status", "UNKNOWN")
        chunks_available = data.get("chunks_available", [])
        logger.info(
            "Tenable export poll %d/%d: status=%s  chunks_available=%d",
            attempt, _POLL_MAX_ATTEMPTS, status, len(chunks_available),
        )
        if status == "FINISHED":
            return chunks_available
        if status in ("ERROR", "CANCELLED"):
            raise RuntimeError(f"Tenable export {export_uuid} ended with status={status}")
        time.sleep(_POLL_INTERVAL_SEC)

    raise TimeoutError(
        f"Tenable export {export_uuid} did not finish within "
        f"{_POLL_MAX_ATTEMPTS * _POLL_INTERVAL_SEC} seconds"
    )


def _download_all_chunks(
    headers: dict,
    export_uuid: str,
    chunk_ids: list[int],
) -> list[RawFinding]:
    """Download every chunk and parse each record into RawFinding objects."""
    findings: list[RawFinding] = []
    skipped_no_cve = 0

    for chunk_id in chunk_ids:
        url = f"{TENABLE_BASE_URL}/vulns/export/{export_uuid}/chunks/{chunk_id}"
        resp = requests.get(url, headers=headers, timeout=120)
        resp.raise_for_status()
        records: list[dict] = resp.json()
        chunk_findings, chunk_skipped = _parse_chunk(records)
        findings.extend(chunk_findings)
        skipped_no_cve += chunk_skipped
        logger.info(
            "Chunk %s: %d records → %d findings kept, %d skipped (no CVE)",
            chunk_id, len(records), len(chunk_findings), chunk_skipped,
        )

    if skipped_no_cve:
        logger.warning(
            "%d Tenable vuln records had no plugin.cve and were skipped. "
            "These are typically informational / non-CVE plugins.",
            skipped_no_cve,
        )
    return findings


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _parse_chunk(records: list[dict]) -> tuple[list[RawFinding], int]:
    """Parse a list of vuln export records; returns (findings, skipped_count)."""
    findings: list[RawFinding] = []
    skipped = 0
    for record in records:
        plugin = record.get("plugin") or {}
        cve_list: list[str] = plugin.get("cve") or []
        if not cve_list:
            skipped += 1
            continue
        # One RawFinding per CVE so each CVE gets its own vulnerability_id in Cortex
        for cve_id in cve_list:
            rf = _to_raw_finding(record, plugin, cve_id)
            if rf:
                findings.append(rf)
    return findings, skipped


def _to_raw_finding(record: dict, plugin: dict, cve_id: str) -> RawFinding | None:
    asset: dict = record.get("asset") or {}

    asset_uuid: str = asset.get("uuid") or asset.get("id") or ""
    if not asset_uuid:
        return None

    # Best available name: hostname > first FQDN > UUID
    hostname: str = (asset.get("hostname") or "").strip()
    fqdn_list: list[str] = _coerce_list(asset.get("fqdn"))
    asset_name = hostname or (fqdn_list[0] if fqdn_list else asset_uuid)

    ipv4_list: list[str] = _coerce_list(asset.get("ipv4"))
    ipv6_list: list[str] = _coerce_list(asset.get("ipv6"))

    # operating_system may be a string or a list depending on API version
    os_raw = asset.get("operating_system") or asset.get("operating_systems") or ""
    if isinstance(os_raw, list):
        os_name: str | None = os_raw[0] if os_raw else None
    else:
        os_name = os_raw or None

    # Tags — Tenable returns [{key, value}, ...]; also include cloud provider metadata
    tag_kv: list[dict] = asset.get("tags") or []
    user_tags = [f"{t.get('key', '')}:{t.get('value', '')}" for t in tag_kv if t.get("key")]

    cloud_meta = _build_cloud_meta(asset)
    tags = cloud_meta + user_tags

    # Timestamps — Tenable exports Unix seconds; Cortex wants milliseconds
    last_found: int | None = record.get("last_found") or record.get("last_seen")
    last_seen_ms = int(last_found) * 1000 if last_found else int(time.time() * 1000)

    severity_raw: str = record.get("severity") or "medium"
    severity = _SEVERITY_MAP.get(severity_raw.lower(), "MEDIUM")

    plugin_id: int = plugin.get("id", 0)
    plugin_name: str = plugin.get("name", "")
    description: str = plugin.get("description") or plugin.get("synopsis") or ""
    cvss3: float | None = plugin.get("cvss3_base_score") or plugin.get("cvss_base_score")
    solution: str = plugin.get("solution") or ""
    cvss3_vector: str = plugin.get("cvss3_vector") or plugin.get("cvss_vector") or ""
    output: str = record.get("output") or ""
    state: str = record.get("state") or "OPEN"

    evidence = f"Plugin {plugin_id}: {plugin_name}"
    if cvss3 is not None:
        evidence += f" | CVSS3: {cvss3}"
    evidence = evidence[:500]

    raw_output = f"state:{state} | solution:{solution} | cvss3_vector:{cvss3_vector}"
    if output:
        raw_output += f" | output:{output}"
    raw_output = raw_output[:2000]

    mac_address = asset.get("mac_address") or None
    if isinstance(mac_address, list):
        mac_address = mac_address[0] if mac_address else None

    return RawFinding(
        asset_id=asset_uuid,
        asset_name=asset_name,
        ipv4=ipv4_list,
        ipv6=ipv6_list,
        fqdn=fqdn_list,
        mac_address=mac_address,
        os_name=os_name,
        tags=tags,
        last_seen_ms=last_seen_ms,
        cve_id=cve_id,
        severity=severity,
        description=description[:1000],
        evidence=evidence,
        raw_output=raw_output,
        source="tenable_vm",
    )


def _build_cloud_meta(asset: dict) -> list[str]:
    """Build a list of cloud-metadata tags from known Tenable asset cloud fields."""
    meta: list[str] = ["cloud:tenable_vm"]

    # AWS
    ec2_id = asset.get("aws_ec2_instance_id") or ""
    ec2_type = asset.get("aws_ec2_instance_type") or ""
    aws_region = asset.get("aws_region") or ""
    aws_az = asset.get("aws_availability_zone") or ""
    aws_account = asset.get("aws_owner_id") or ""
    if ec2_id:
        meta.append(f"instance_id:{ec2_id}")
    if ec2_type:
        meta.append(f"instance_type:{ec2_type}")
    if aws_region:
        meta.append(f"aws_region:{aws_region}")
    if aws_az:
        meta.append(f"aws_availability_zone:{aws_az}")
    if aws_account:
        meta.append(f"aws_account:{aws_account}")

    # Azure
    azure_vm_id = asset.get("azure_vm_id") or ""
    azure_resource_group = asset.get("azure_resource_group") or ""
    azure_subscription_id = asset.get("azure_subscription_id") or ""
    if azure_vm_id:
        meta.append(f"azure_vm_id:{azure_vm_id}")
    if azure_resource_group:
        meta.append(f"azure_resource_group:{azure_resource_group}")
    if azure_subscription_id:
        meta.append(f"azure_subscription_id:{azure_subscription_id}")

    # GCP
    gcp_project = asset.get("gcp_project_id") or ""
    gcp_instance = asset.get("gcp_instance_id") or ""
    gcp_zone = asset.get("gcp_zone") or ""
    if gcp_project:
        meta.append(f"gcp_project:{gcp_project}")
    if gcp_instance:
        meta.append(f"gcp_instance_id:{gcp_instance}")
    if gcp_zone:
        meta.append(f"gcp_zone:{gcp_zone}")

    return meta


def _coerce_list(value: Any) -> list[str]:
    """Normalise a field that might be a string, list, or None to list[str]."""
    if not value:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return [str(value)]

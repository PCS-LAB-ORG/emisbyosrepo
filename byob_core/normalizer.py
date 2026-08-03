from __future__ import annotations
import json
import logging
import time
from byob_core.models import RawFinding

logger = logging.getLogger(__name__)

MAX_ASSETS_PER_BATCH = 40
MAX_VULNS_PER_ASSET = 1_000
MAX_VULNS_PER_BATCH = MAX_ASSETS_PER_BATCH * MAX_VULNS_PER_ASSET  # 10,000
MAX_RAW_OUTPUT = 2_000
MAX_DESCRIPTION = 1_000  # CVE descriptions can be several KB each
MAX_EVIDENCE = 500
# Cortex rejects payloads over ~10 MB; stay well under with a 4 MB soft cap.
# Batches are split on this boundary after all other limits are applied.
MAX_BATCH_BYTES = 8 * 1024 * 1024  # 4 MB
THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000

_VENDOR_MAP = {
    "aws_inspector": ("AWS", "Inspector2"),
    "azure_defender": ("Microsoft", "DefenderForCloud"),
}


def normalize(findings: list[RawFinding], source: str) -> list[dict]:
    if source not in _VENDOR_MAP:
        raise ValueError(f"Unknown source {source!r}. Valid: {list(_VENDOR_MAP)}")
    vendor, product = _VENDOR_MAP[source]
    now_ms = int(time.time() * 1000)
    cutoff_ms = now_ms - THIRTY_DAYS_MS

    grouped: dict[str, list[RawFinding]] = {}
    skipped_old = 0
    for f in findings:
        if f.last_seen_ms < cutoff_ms:
            skipped_old += 1
            continue
        grouped.setdefault(f.asset_id, []).append(f)

    if skipped_old:
        logger.warning(
            "Normalizer dropped %d findings last seen more than 30 days ago.",
            skipped_old,
        )

    assets: list[dict] = []
    for asset_id, asset_findings in grouped.items():
        first = asset_findings[0]
        vulnerabilities = []
        for f in asset_findings:
            vulnerabilities.append({
                "vulnerability_id": f.cve_id,
                "cve_id": [f.cve_id],
                "last_seen": f.last_seen_ms,
                "confidence": "Confirmed" if f.severity in ("CRITICAL", "HIGH") else "Potential",
                "description": f.description[:MAX_DESCRIPTION],
                "evidence": f.evidence[:MAX_EVIDENCE],
                "raw_output": f.raw_output[:MAX_RAW_OUTPUT],
                "scan_name": source,
            })
        if len(vulnerabilities) > MAX_VULNS_PER_ASSET:
            logger.warning(
                "Asset %s has %d vulnerabilities — truncating to %d (API limit).",
                asset_id, len(vulnerabilities), MAX_VULNS_PER_ASSET,
            )
            vulnerabilities = vulnerabilities[:MAX_VULNS_PER_ASSET]
        assets.append({
            "origin_asset_id": asset_id,
            "asset_name": first.asset_name,
            "ipv4": first.ipv4,
            "ipv6": first.ipv6,
            "fqdn": first.fqdn,
            "mac_address": first.mac_address,
            "os_name": first.os_name,
            "origin_tags": first.tags,
            "last_seen": first.last_seen_ms,
            "vulnerabilities": vulnerabilities,
        })

    # Split into batches respecting the per-batch asset cap, the per-batch
    # vulnerability cap, and a payload byte-size cap (to avoid HTTP 413).
    # A new batch is started whenever any limit would be exceeded.
    batches: list[dict] = []
    current: list[dict] = []
    current_vuln_count = 0
    current_bytes = 0

    for asset in assets:
        asset_vuln_count = len(asset["vulnerabilities"])
        asset_bytes = len(json.dumps(asset).encode())

        over_asset_limit = len(current) >= MAX_ASSETS_PER_BATCH
        over_vuln_limit  = current_vuln_count + asset_vuln_count > MAX_VULNS_PER_BATCH
        over_byte_limit  = current_bytes + asset_bytes > MAX_BATCH_BYTES

        if current and (over_asset_limit or over_vuln_limit or over_byte_limit):
            if over_byte_limit:
                logger.warning(
                    "Batch byte limit reached (%d bytes) — starting new batch after %d asset(s).",
                    current_bytes, len(current),
                )
            batches.append({"vendor": vendor, "product": product, "assets": current})
            current = []
            current_vuln_count = 0
            current_bytes = 0

        current.append(asset)
        current_vuln_count += asset_vuln_count
        current_bytes += asset_bytes

    if current:
        batches.append({"vendor": vendor, "product": product, "assets": current})

    logger.info(
        "Normalized %d asset(s) and %d vuln(s) into %d batch(es) "
        "(max %d assets / %d vulns / %d MB per batch)",
        len(assets),
        sum(len(a["vulnerabilities"]) for a in assets),
        len(batches),
        MAX_ASSETS_PER_BATCH,
        MAX_VULNS_PER_BATCH,
        MAX_BATCH_BYTES // (1024 * 1024),
    )
    return batches

from __future__ import annotations
import json
import logging
import time
from byob_core.models import RawFinding

logger = logging.getLogger(__name__)

MAX_ASSETS_PER_BATCH = 45
MAX_VULNS_PER_ASSET = 1_000
MAX_VULNS_PER_BATCH = MAX_ASSETS_PER_BATCH * MAX_VULNS_PER_ASSET  # 10,000
MAX_RAW_OUTPUT = 2_000
MAX_DESCRIPTION = 1_500  # CVE descriptions can be several KB each
MAX_EVIDENCE = 500
# Cortex rejects payloads over ~10 MB; stay well under with a 4 MB soft cap.
# Batches are split on this boundary after all other limits are applied.
MAX_BATCH_BYTES = 9 * 1024 * 1024  # 4 MB
THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000

_VENDOR_MAP = {
    "aws_inspector": ("AWS", "Inspector2"),
    "azure_defender": ("Microsoft", "DefenderForCloud"),
    "tenable_vm": ("Tenable", "VulnerabilityManagement"),
}

_TAG_OVER_30_DAYS = "over30day:true"


def normalize(findings: list[RawFinding], source: str, clamp_old_findings: bool = False) -> list[dict]:
    """Normalise a list of RawFinding objects into Cortex BYOS batch payloads.

    Filtering rules
    ---------------
    * **Asset-level filter** — an asset is considered "old" when its most
      recently updated vulnerability was last seen more than 30 days ago.
      Old assets are dropped by default.  When *clamp_old_findings* is True,
      old assets are included but their last_seen (and every vuln last_seen
      that is also old) is clamped to the current import time, and the tag
      ``over30day:true`` is added to the asset's ``origin_tags``.

    * **Vuln-level — no drop** — all vulnerabilities for a qualifying asset
      are always included regardless of their individual last_seen.  If an
      individual vuln's last_seen is older than 30 days (which would cause
      Cortex to reject the payload with HTTP 422), it is silently clamped to
      the current import time and the ``over30day:true`` tag is added.

    Parameters
    ----------
    findings:
        Raw findings from a collector.
    source:
        Key into _VENDOR_MAP — determines the vendor/product fields.
    clamp_old_findings:
        When True, assets whose most-recent vuln is older than 30 days are
        included with their last_seen reset to the current import time.
        When False (default), those assets are dropped entirely.

        In both modes, individual vuln last_seen values older than 30 days
        are clamped (Cortex hard-rejects values older than 30 days with 422).
        The ``over30day:true`` tag is appended to the asset whenever any
        timestamp was clamped.
    """
    if source not in _VENDOR_MAP:
        raise ValueError(f"Unknown source {source!r}. Valid: {list(_VENDOR_MAP)}")
    vendor, product = _VENDOR_MAP[source]
    now_ms = int(time.time() * 1000)
    cutoff_ms = now_ms - THIRTY_DAYS_MS

    # ---- Step 1: group ALL findings by asset (no per-vuln timestamp filter) --
    grouped: dict[str, list[RawFinding]] = {}
    for f in findings:
        grouped.setdefault(f.asset_id, []).append(f)

    # ---- Step 2: asset-level age check ----------------------------------------
    included: dict[str, list[RawFinding]] = {}
    skipped_old_assets = 0

    for asset_id, asset_findings in grouped.items():
        asset_last_seen = max(f.last_seen_ms for f in asset_findings)
        if asset_last_seen < cutoff_ms:
            if not clamp_old_findings:
                skipped_old_assets += 1
                continue
        included[asset_id] = asset_findings

    if skipped_old_assets:
        logger.warning(
            "Normalizer dropped %d asset(s) with no findings in the last 30 days. "
            "Use --clamp-old to include them at import time instead.",
            skipped_old_assets,
        )

    # ---- Step 3: build asset payloads; clamp any old vuln timestamps ----------
    assets: list[dict] = []
    total_clamped_assets = 0

    for asset_id, asset_findings in included.items():
        first = asset_findings[0]
        tags: list[str] = list(first.tags)
        needs_tag = False

        vulnerabilities = []
        for f in asset_findings:
            vuln_last_seen = f.last_seen_ms
            if vuln_last_seen < cutoff_ms:
                vuln_last_seen = now_ms
                needs_tag = True
            vulnerabilities.append({
                "vulnerability_id": f.cve_id,
                "cve_id": [f.cve_id],
                "last_seen": vuln_last_seen,
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

        # Asset last_seen = most recent (post-clamp) vuln timestamp
        asset_last_seen_out = max(v["last_seen"] for v in vulnerabilities)

        if needs_tag:
            total_clamped_assets += 1
            if _TAG_OVER_30_DAYS not in tags:
                tags.append(_TAG_OVER_30_DAYS)

        assets.append({
            "origin_asset_id": asset_id,
            "asset_name": first.asset_name,
            "ipv4": first.ipv4,
            "ipv6": first.ipv6,
            "fqdn": first.fqdn,
            "mac_address": first.mac_address,
            "os_name": first.os_name,
            "origin_tags": tags,
            "last_seen": asset_last_seen_out,
            "vulnerabilities": vulnerabilities,
        })

    if total_clamped_assets:
        logger.info(
            "Clamped last_seen to import time for %d asset(s) with old vuln timestamps; "
            "tagged with '%s'.",
            total_clamped_assets, _TAG_OVER_30_DAYS,
        )

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

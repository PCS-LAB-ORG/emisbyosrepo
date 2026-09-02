#!/usr/bin/env python3
"""Expire BYOS findings in Cortex by re-submitting them with a near-expiry timestamp.

Loads findings from the local cache file, sets every last_seen timestamp to
29 days ago (the oldest value Cortex will accept without a 422 rejection), then
re-submits to Cortex.  Cortex updates the existing records — matched by
origin_asset_id — with the backdated timestamp.

If Cortex has an internal TTL for BYOS assets (expected: ~30 days), those
records will be marked stale or removed within ~24 hours, giving you a clean
slate for a fresh import.

WARNING
-------
This is a destructive operation.  It intentionally ages out all findings
currently in Cortex.  Do not run this unless you intend to do a full
re-import immediately after.

Usage
-----
  # Dry-run: see what would be submitted without posting anything
  python3 scripts/expire_findings.py --dry-run

  # Expire all resource types (prompts for confirmation)
  python3 scripts/expire_findings.py

  # Expire a specific resource type only
  python3 scripts/expire_findings.py --resource-type lambda

  # Skip confirmation prompt
  python3 scripts/expire_findings.py --yes

  # Custom cache file
  python3 scripts/expire_findings.py --cache-file .byob-cache-us-east-1.json
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)

DEFAULT_CACHE_FILE = ".byob-findings-cache.json"
TWENTY_NINE_DAYS_MS = 29 * 24 * 60 * 60 * 1000

_RESOURCE_TYPE_TAG = {
    "lambda": "resource_type:lambda_function",
    "ecr":    "resource_type:ecr_container_image",
    "ec2":    "resource_type:ec2_instance",
}

_VENDOR_MAP = {
    "aws_inspector": ("AWS", "Inspector2"),
    "azure_defender": ("Microsoft", "DefenderForCloud"),
}


def _load_cache(cache_path: pathlib.Path) -> list[dict]:
    if not cache_path.exists():
        logger.error(
            "Cache file '%s' not found. Run --cache-findings first.", cache_path
        )
        sys.exit(1)
    try:
        data = json.loads(cache_path.read_text())
    except Exception as exc:
        logger.error("Failed to read cache '%s': %s", cache_path, exc)
        sys.exit(1)

    findings = data.get("findings", [])
    logger.info(
        "Loaded %d finding(s) from '%s' (cached_at=%s  region=%s).",
        len(findings), cache_path,
        data.get("cached_at", "unknown"),
        data.get("region", "unknown"),
    )
    return findings


def _resource_type(tags: list[str]) -> str:
    for t in tags:
        if t.startswith("resource_type:"):
            return t[len("resource_type:"):]
    return "unknown"


def _build_expiry_batches(
    findings: list[dict],
    resource_type_filter: str | None,
    expire_ms: int,
    source: str = "aws_inspector",
) -> list[dict]:
    """Build BYOS batches with every last_seen set to expire_ms."""
    vendor, product = _VENDOR_MAP.get(source, ("AWS", "Inspector2"))
    max_assets = 45
    max_batch_bytes = 9 * 1024 * 1024   # 9 MB — same cap as the normalizer

    # Filter by resource type if requested
    if resource_type_filter:
        tag = _RESOURCE_TYPE_TAG[resource_type_filter]
        findings = [f for f in findings if tag in f.get("tags", [])]
        logger.info(
            "Resource type filter '%s': %d finding(s) selected.",
            resource_type_filter, len(findings),
        )

    if not findings:
        return []

    # Group by asset_id
    grouped: dict[str, list[dict]] = {}
    for f in findings:
        grouped.setdefault(f["asset_id"], []).append(f)

    assets = []
    for asset_id, asset_findings in grouped.items():
        first = asset_findings[0]
        # Submit with an empty vulnerabilities list so Cortex clears all findings
        # for this asset immediately.  Combined with a backdated last_seen the
        # asset itself will be dropped by Cortex on the next cleanup cycle.
        assets.append({
            "origin_asset_id": asset_id,
            "asset_name":      first.get("asset_name", asset_id),
            "ipv4":            first.get("ipv4", []),
            "ipv6":            first.get("ipv6", []),
            "fqdn":            first.get("fqdn", []),
            "os_name":         first.get("os_name"),
            "origin_tags":     first.get("tags", []),
            "last_seen":       expire_ms,
            "vulnerabilities": [],
        })

    # Chunk into batches respecting both asset count and byte-size limits.
    # ECR assets can carry thousands of CVEs; without a size cap the payload
    # can exceed ~20 MB and cause a write-timeout mid-upload.
    batches = []
    current_assets: list[dict] = []
    current_bytes = 0
    base_overhead = len(json.dumps({"vendor": vendor, "product": product, "assets": []}).encode())

    for asset in assets:
        asset_bytes = len(json.dumps(asset).encode())
        would_exceed_count = len(current_assets) >= max_assets
        would_exceed_size  = current_bytes + asset_bytes + base_overhead > max_batch_bytes
        if current_assets and (would_exceed_count or would_exceed_size):
            batches.append({"vendor": vendor, "product": product, "assets": current_assets})
            current_assets = []
            current_bytes  = 0
        current_assets.append(asset)
        current_bytes += asset_bytes

    if current_assets:
        batches.append({"vendor": vendor, "product": product, "assets": current_assets})

    return batches


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Expire BYOS findings in Cortex by backdating their last_seen timestamp.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--cache-file", default=DEFAULT_CACHE_FILE, metavar="PATH",
        help=f"Findings cache file to read (default: {DEFAULT_CACHE_FILE}).",
    )
    parser.add_argument(
        "--resource-type", default=None,
        choices=["lambda", "ecr", "ec2"], metavar="TYPE",
        help="Expire only a specific resource type. Default: all types.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be submitted without actually posting to Cortex.",
    )
    parser.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip confirmation prompt.",
    )
    parser.add_argument(
        "--cortex-fqdn",    default=None, metavar="FQDN")
    parser.add_argument(
        "--cortex-api-key", default=None, metavar="KEY")
    parser.add_argument(
        "--cortex-auth-id", default=None, metavar="ID")
    args = parser.parse_args()

    if args.cortex_fqdn:
        os.environ["CORTEX_FQDN"] = args.cortex_fqdn
    if args.cortex_api_key:
        os.environ["CORTEX_API_KEY"] = args.cortex_api_key
    if args.cortex_auth_id:
        os.environ["CORTEX_AUTH_ID"] = args.cortex_auth_id

    # ── Load cache ────────────────────────────────────────────────────────────
    cache_path = pathlib.Path(args.cache_file)
    findings   = _load_cache(cache_path)

    # ── Build expiry timestamp: 29 days ago ───────────────────────────────────
    now_ms     = int(time.time() * 1000)
    expire_ms  = now_ms - TWENTY_NINE_DAYS_MS
    expire_iso = __import__("datetime").datetime.fromtimestamp(
        expire_ms / 1000
    ).strftime("%Y-%m-%d %H:%M:%S")
    logger.info(
        "Expiry timestamp: %s  (%d ms) — 29 days ago, "
        "1 day within Cortex 30-day acceptance window.",
        expire_iso, expire_ms,
    )

    # ── Build batches ─────────────────────────────────────────────────────────
    source   = json.loads(cache_path.read_text()).get("source", "aws_inspector")
    batches  = _build_expiry_batches(findings, args.resource_type, expire_ms, source)

    if not batches:
        logger.warning("No findings matched — nothing to expire.")
        sys.exit(0)

    total_assets = sum(len(b["assets"]) for b in batches)
    logger.info(
        "Prepared %d batch(es) — %d unique asset(s) to expire (no vulnerabilities posted).",
        len(batches), total_assets,
    )

    if args.dry_run:
        logger.info("DRY RUN — first batch preview:")
        preview = json.dumps(batches[0], indent=2)
        print(preview[:2000] + ("\n... (truncated)" if len(preview) > 2000 else ""))
        logger.info("DRY RUN complete. No data was sent to Cortex.")
        sys.exit(0)

    # ── Confirmation ──────────────────────────────────────────────────────────
    print()
    print("  !! WARNING !!")
    print(f"  This will re-submit {total_assets} asset(s) to Cortex with")
    print(f"  last_seen = {expire_iso} (29 days ago) and NO vulnerabilities.")
    scope = args.resource_type or "ALL resource types"
    print(f"  Scope: {scope}")
    print()
    print("  Cortex will clear all findings for these assets immediately.")
    print("  Assets should be eligible for expiry within ~24 hours.")
    print("  Run a fresh import AFTER Cortex has aged them out.")
    print()

    if not args.yes:
        try:
            answer = input("  Proceed? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            logger.info("Aborted.")
            sys.exit(0)
        if not answer.startswith("y"):
            logger.info("Aborted — no changes made.")
            sys.exit(0)

    # ── Submit ────────────────────────────────────────────────────────────────
    from byob_core import secrets, cortex_client                       # noqa: PLC0415

    secrets.verify_credentials()
    creds = secrets.load_credentials()

    pushed = 0
    for i, batch in enumerate(batches, start=1):
        n_a = len(batch["assets"])
        logger.info("Submitting batch %d/%d — %d asset(s) (no vulns) ...",
                    i, len(batches), n_a)
        try:
            results = cortex_client.submit_all([batch], creds)
            for r in results:
                logger.info(
                    "  Accepted | job_id=%s  status=%s  assets=%d  vulns=%d",
                    r.job_id, r.status, r.assets_count, r.vulnerabilities_count,
                )
            pushed += 1
        except Exception as exc:
            # Print type + a short message only — avoids echoing the full payload
            short = str(exc)
            if len(short) > 300:
                short = short[:300] + " ... [truncated]"
            logger.error("  Failed on batch %d [%s]: %s", i, type(exc).__name__, short)

    logger.info(
        "Done — %d/%d batch(es) submitted.",
        pushed, len(batches),
    )
    logger.info(
        "Next step: wait ~24 hours for Cortex to age out these records, "
        "then run a fresh import with: "
        "python3 scripts/batch_push.py --source aws --from-cache --yes"
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Queued batch push — download findings into local JSON files, push one at a time.

Each batch is saved as a numbered JSON file.  After a successful POST to Cortex
the file is deleted.  If the run is interrupted (Cortex error, rate limit, network
timeout), the remaining files stay on disk and the next run picks up exactly where
the previous one stopped — no need to re-query Inspector2 or Azure.

Typical workflow
----------------
  # Step 1 — first run: downloads findings, saves batches, then offers to push
  python3 scripts/batch_push.py --source aws

  # Step 2 — if the run was interrupted, re-run to resume from where it stopped
  python3 scripts/batch_push.py --source aws

  # The script detects leftover batch files and asks:
  #   Found 3 pending batches (of 5 total). Continue pushing? [Y/n/redownload]:

Other modes
-----------
  # Download only — inspect the files before committing to push
  python3 scripts/batch_push.py --source aws --download-only

  # Push only — use an already-downloaded set of batches
  python3 scripts/batch_push.py --push-only \\
      --cortex-fqdn api-tenant.xdr.us.paloaltonetworks.com \\
      --cortex-api-key <key> --cortex-auth-id <id>

  # Non-interactive: auto-continue pending batches, auto-push after download
  python3 scripts/batch_push.py --source aws --yes

  # Custom batch directory
  python3 scripts/batch_push.py --source aws --batch-dir /tmp/my-batches

  # Use a secret stored in AWS Secrets Manager for Cortex credentials
  CORTEX_SECRET_NAME=byob-scanner/cortex \\
      python3 scripts/batch_push.py --source aws

Batch files
-----------
  Batches are stored as:  <batch-dir>/batch_NNNN.json
  A manifest is stored as: <batch-dir>/.manifest.json  (source, timestamp, counts)

  Files are deleted one by one as each batch is accepted by Cortex.
  When all files are gone the batch directory itself is removed.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import sys
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)

DEFAULT_BATCH_DIR = ".byob-batches"
BATCH_FILE_GLOB = "batch_*.json"
MANIFEST_FILE = ".manifest.json"
DEFAULT_CACHE_FILE = ".byob-findings-cache.json"


# ---------------------------------------------------------------------------
# Findings cache — serialize / deserialize RawFinding objects
# ---------------------------------------------------------------------------

def _save_findings_cache(
    findings: list,
    cache_path: pathlib.Path,
    source: str,
    region: str | None,
    lookback_hours: int,
    coverage_hours: int | None,
) -> None:
    """Serialise findings to a JSON cache file with metadata."""
    data = {
        "cached_at":      datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source":         source,
        "region":         region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        "lookback_hours": lookback_hours,
        "coverage_hours": coverage_hours,
        "findings_count": len(findings),
        "findings": [
            {
                "asset_id":    f.asset_id,
                "asset_name":  f.asset_name,
                "ipv4":        f.ipv4,
                "ipv6":        f.ipv6,
                "fqdn":        f.fqdn,
                "mac_address": f.mac_address,
                "os_name":     f.os_name,
                "tags":        f.tags,
                "last_seen_ms":f.last_seen_ms,
                "cve_id":      f.cve_id,
                "severity":    f.severity,
                "description": f.description,
                "evidence":    f.evidence,
                "raw_output":  f.raw_output,
                "source":      f.source,
            }
            for f in findings
        ],
    }
    cache_path.write_text(json.dumps(data, indent=2))
    logger.info(
        "Cached %d finding(s) to '%s' (cached_at=%s).",
        len(findings), cache_path, data["cached_at"],
    )


def _load_findings_cache(cache_path: pathlib.Path) -> tuple[list, dict]:
    """Load findings from a cache file. Returns (findings, metadata)."""
    from byob_core.models import RawFinding                            # noqa: PLC0415
    if not cache_path.exists():
        logger.error(
            "Cache file '%s' not found. "
            "Run first with --cache-findings to create it.",
            cache_path,
        )
        sys.exit(1)

    try:
        data = json.loads(cache_path.read_text())
    except Exception as exc:
        logger.error("Failed to read cache file '%s': %s", cache_path, exc)
        sys.exit(1)

    meta = {
        "cached_at":      data.get("cached_at", "unknown"),
        "source":         data.get("source", "unknown"),
        "region":         data.get("region", "unknown"),
        "lookback_hours": data.get("lookback_hours"),
        "coverage_hours": data.get("coverage_hours"),
        "findings_count": data.get("findings_count", 0),
    }

    findings = []
    for d in data.get("findings", []):
        try:
            findings.append(RawFinding(
                asset_id=   d["asset_id"],
                asset_name= d["asset_name"],
                ipv4=       d.get("ipv4", []),
                ipv6=       d.get("ipv6", []),
                fqdn=       d.get("fqdn", []),
                mac_address=d.get("mac_address"),
                os_name=    d.get("os_name"),
                tags=       d.get("tags", []),
                last_seen_ms=d["last_seen_ms"],
                cve_id=     d["cve_id"],
                severity=   d.get("severity", "MEDIUM"),
                description=d.get("description", ""),
                evidence=   d.get("evidence", ""),
                raw_output= d.get("raw_output", ""),
                source=     d.get("source", "aws_inspector"),
            ))
        except KeyError as exc:
            logger.warning("Skipping malformed cache entry (missing field %s).", exc)

    logger.info(
        "Loaded %d finding(s) from cache '%s' (cached_at=%s, source=%s, region=%s).",
        len(findings), cache_path,
        meta["cached_at"], meta["source"], meta["region"],
    )
    return findings, meta


# ---------------------------------------------------------------------------
# Batch directory helpers
# ---------------------------------------------------------------------------

def _batch_files(batch_dir: pathlib.Path) -> list[pathlib.Path]:
    """Return sorted list of pending batch files."""
    return sorted(batch_dir.glob(BATCH_FILE_GLOB))


def _batch_summary(files: list[pathlib.Path]) -> tuple[int, int]:
    """Return (total_assets, total_vulns) across a list of batch files."""
    total_assets = total_vulns = 0
    for f in files:
        try:
            data = json.loads(f.read_text())
            assets = data.get("assets", [])
            total_assets += len(assets)
            total_vulns += sum(len(a.get("vulnerabilities", [])) for a in assets)
        except Exception:
            pass
    return total_assets, total_vulns


def _write_manifest(batch_dir: pathlib.Path, source: str, n_batches: int,
                    total_assets: int, total_vulns: int) -> None:
    manifest = {
        "source": source,
        "downloaded_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_batches": n_batches,
        "total_assets": total_assets,
        "total_vulns": total_vulns,
    }
    (batch_dir / MANIFEST_FILE).write_text(json.dumps(manifest, indent=2))


def _read_manifest(batch_dir: pathlib.Path) -> dict:
    mf = batch_dir / MANIFEST_FILE
    if mf.exists():
        try:
            return json.loads(mf.read_text())
        except Exception:
            pass
    return {}


def _save_batches(batch_dir: pathlib.Path, batches: list[dict], source: str) -> list[pathlib.Path]:
    """Persist each batch as a numbered JSON file; return the list of paths."""
    batch_dir.mkdir(parents=True, exist_ok=True)
    paths: list[pathlib.Path] = []
    for i, batch in enumerate(batches, start=1):
        path = batch_dir / f"batch_{i:04d}.json"
        path.write_text(json.dumps(batch, indent=2))
        paths.append(path)

    total_assets, total_vulns = _batch_summary(paths)
    _write_manifest(batch_dir, source, len(batches), total_assets, total_vulns)
    return paths


def _cleanup_dir(batch_dir: pathlib.Path) -> None:
    """Remove the batch directory if it is empty (after all files pushed)."""
    manifest = batch_dir / MANIFEST_FILE
    if manifest.exists():
        manifest.unlink()
    try:
        batch_dir.rmdir()
        logger.info("Batch directory '%s' removed (all batches pushed).", batch_dir)
    except OSError:
        pass  # not empty — leave it alone


# ---------------------------------------------------------------------------
# Credential verification — shared implementation from byob_core.secrets
# ---------------------------------------------------------------------------

def _verify_cortex_credentials() -> None:
    from byob_core import secrets as _secrets  # noqa: PLC0415
    _secrets.verify_credentials()


# ---------------------------------------------------------------------------
# Interactive prompt helpers
# ---------------------------------------------------------------------------

def _ask(prompt: str, default_yes: bool = True) -> bool:
    """Prompt the user for a yes/no answer; return True for yes."""
    hint = "[Y/n]" if default_yes else "[y/N]"
    try:
        answer = input(f"{prompt} {hint}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not answer:
        return default_yes
    return answer.startswith("y")


def _ask_pending(n_pending: int, n_total: int, total_assets: int, total_vulns: int,
                 auto_yes: bool) -> str:
    """Ask what to do with pending batches.

    Returns one of: 'continue', 'redownload', 'abort'
    """
    of_total = f" (of {n_total} total)" if n_total and n_total != n_pending else ""
    logger.info(
        "Found %d pending batch file(s)%s — %d asset(s), %d vuln(s) waiting to be pushed.",
        n_pending, of_total, total_assets, total_vulns,
    )
    if auto_yes:
        logger.info("--yes flag set: continuing with pending batches.")
        return "continue"

    print()
    print("  Options:")
    print("    [Y] / Enter  — continue pushing pending batches")
    print("    [r]          — delete pending batches and re-download fresh findings")
    print("    [a]          — abort (leave pending batches, exit now)")
    print()
    try:
        answer = input("  Choice [Y/r/a]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return "abort"

    if answer in ("r", "re", "redownload"):
        return "redownload"
    if answer in ("a", "abort", "q", "quit"):
        return "abort"
    return "continue"


# ---------------------------------------------------------------------------
# Push loop
# ---------------------------------------------------------------------------

_TAG_OVER_30_DAYS = "over30day:true"


def _clamp_batch_last_seen(batch: dict, now_ms: int) -> int:
    """Clamp every last_seen value older than 30 days to now_ms, in-place.

    Modifies both asset-level and vulnerability-level last_seen fields.
    When any timestamp on an asset is clamped, the tag ``over30day:true`` is
    appended to the asset's ``origin_tags`` list (if not already present).
    Returns the count of individual entries (asset + vuln combined) that were
    clamped.
    """
    thirty_days_ms = 30 * 24 * 60 * 60 * 1000
    cutoff_ms = now_ms - thirty_days_ms
    clamped = 0
    for asset in batch.get("assets", []):
        asset_clamped = False
        if asset.get("last_seen", now_ms) < cutoff_ms:
            asset["last_seen"] = now_ms
            clamped += 1
            asset_clamped = True
        for vuln in asset.get("vulnerabilities", []):
            if vuln.get("last_seen", now_ms) < cutoff_ms:
                vuln["last_seen"] = now_ms
                clamped += 1
                asset_clamped = True
        if asset_clamped:
            tags = asset.setdefault("origin_tags", [])
            if _TAG_OVER_30_DAYS not in tags:
                tags.append(_TAG_OVER_30_DAYS)
    return clamped


def _push_batches(files: list[pathlib.Path], creds, clamp_old: bool = False) -> bool:
    """Push each batch file to Cortex one at a time; delete on success.

    When clamp_old=True every last_seen value older than 30 days is updated to
    the current time before submission.  This works on both freshly downloaded
    batches and on batch files that were saved in a previous run without the
    --clamp-old flag.

    Returns True if all batches were pushed successfully, False if stopped early.
    """
    from byob_core import cortex_client                                # noqa: PLC0415
    from byob_core.cortex_client import CortexRateLimitError, CortexValidationError  # noqa: PLC0415

    pushed = 0
    failed = 0
    skipped_validation = 0
    total = len(files)

    for i, path in enumerate(files, start=1):
        logger.info("─── Pushing batch %d/%d: %s", i, total, path.name)
        try:
            batch = json.loads(path.read_text())
        except Exception as exc:
            logger.error("Failed to read batch file '%s': %s — skipping.", path.name, exc)
            failed += 1
            continue

        if clamp_old:
            now_ms = int(__import__("time").time() * 1000)
            n_clamped = _clamp_batch_last_seen(batch, now_ms)
            if n_clamped:
                logger.info(
                    "  Clamped %d last_seen value(s) older than 30 days to import time.",
                    n_clamped,
                )

        try:
            results = cortex_client.submit_all([batch], creds)
            for r in results:
                logger.info(
                    "  Accepted | job_id=%s  status=%s  assets=%d  vulns=%d",
                    r.job_id, r.status, r.assets_count, r.vulnerabilities_count,
                )
            path.unlink()
            logger.info("  Deleted %s", path.name)
            pushed += 1

        except CortexValidationError as exc:
            # Payload was rejected permanently — log it and skip to the next batch
            # rather than stopping entirely (the data won't become valid on retry).
            logger.error(
                "  Batch %s rejected by Cortex (validation error): %s\n"
                "  Skipping this batch — other batches will still be pushed.",
                path.name, exc,
            )
            skipped_validation += 1

        except CortexRateLimitError as exc:
            logger.error(
                "  Rate limit exhausted on batch %s: %s\n\n"
                "  Remaining batches (%d of %d) are still saved in '%s'.\n"
                "  Re-run this script to continue pushing from where it stopped.",
                path.name, exc,
                total - pushed - skipped_validation - 1,
                total,
                path.parent,
            )
            failed += 1
            return False

        except Exception as exc:
            logger.error(
                "  Unexpected error pushing batch %s: %s\n\n"
                "  Remaining batches (%d of %d) are still saved in '%s'.\n"
                "  Re-run this script to continue pushing from where it stopped.",
                path.name, exc,
                total - pushed - skipped_validation,
                total,
                path.parent,
            )
            failed += 1
            return False

    logger.info(
        "─── Push complete: %d pushed, %d skipped (validation error), %d failed.",
        pushed, skipped_validation, failed,
    )
    return failed == 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Queued batch push — saves Inspector2/Azure findings as local JSON files "
            "and pushes them to Cortex one at a time, resuming safely after any failure."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--download-only",
        action="store_true",
        help=(
            "Download and save batches to disk but do not push to Cortex. "
            "Note: not needed with --cache-findings — that flag already exits "
            "after saving the cache without creating batch files."
        ),
    )
    mode.add_argument(
        "--push-only",
        action="store_true",
        help=(
            "Skip download entirely — push existing batch files from the batch directory. "
            "Exits with an error if no batch files are found."
        ),
    )

    parser.add_argument(
        "--source",
        choices=["aws", "azure"],
        default=None,
        help="Vulnerability source to collect from. Required unless --push-only is set.",
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help=(
            "Non-interactive mode: automatically continue pending batches and push "
            "after download without prompting."
        ),
    )
    parser.add_argument(
        "--batch-dir",
        default=DEFAULT_BATCH_DIR,
        metavar="DIR",
        help=f"Directory to store batch files (default: {DEFAULT_BATCH_DIR}).",
    )
    parser.add_argument(
        "--region",
        default=None,
        metavar="REGION",
        help="AWS region for Inspector2 (e.g. us-east-1). Ignored for --source azure.",
    )
    parser.add_argument(
        "--severities",
        default=None,
        metavar="SEVERITIES",
        help=(
            "Comma-separated Inspector2 severities. "
            "Valid: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL, UNTRIAGED. "
            "Default: MEDIUM,HIGH,CRITICAL,LOW"
        ),
    )
    parser.add_argument(
        "--statuses",
        default=None,
        metavar="STATUSES",
        help=(
            "Comma-separated Inspector2 finding statuses. "
            "Valid: ACTIVE, SUPPRESSED, CLOSED. Default: ACTIVE."
        ),
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=720,
        metavar="N",
        help=(
            "Only collect findings updated in the last N hours. "
            "Default: 720 (30 days). "
            "Set to 0 for no time filter (unlimited — fetches all findings regardless of age). "
            "Use --hours 0 with --clamp-old for a full historical import."
        ),
    )
    parser.add_argument(
        "--clamp-old",
        action="store_true",
        default=False,
        help=(
            "Instead of dropping findings older than 30 days, stamp their last_seen "
            "with the current import time so Cortex accepts them. "
            "Use together with --hours 0 for a full historical import: "
            "--hours 0 fetches all findings from Inspector2; "
            "--clamp-old ensures none are discarded by the 30-day Cortex API limit."
        ),
    )
    parser.add_argument(
        "--coverage-hours",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Only include assets that Inspector2 has scanned in the last N hours "
            "(uses the list-coverage API). "
            "Default: 720 (30 days). "
            "Example: --coverage-hours 72 limits to assets scanned in the last 3 days. "
            "Overrides the INSPECTOR2_COVERAGE_HOURS env var. AWS only."
        ),
    )
    parser.add_argument(
        "--resource-type",
        default=None,
        choices=["lambda", "ecr", "ec2"],
        metavar="TYPE",
        help=(
            "Restrict the import to a single AWS resource type after collection. "
            "Valid values: lambda, ecr, ec2. "
            "Example: --resource-type lambda imports only Lambda function findings; "
            "--resource-type ecr imports only ECR container image findings. "
            "AWS only. When omitted all resource types are imported."
        ),
    )
    parser.add_argument(
        "--images-only",
        action="store_true",
        default=False,
        help="Alias for --resource-type ecr (kept for backwards compatibility).",
    )
    parser.add_argument(
        "--cache-findings",
        action="store_true",
        default=False,
        help=(
            "After collecting from Inspector2, save all findings to a local cache file. "
            "Use with --from-cache on subsequent runs to skip the Inspector2 API calls entirely. "
            "Combine with --resource-type to import subsets from the same cached dataset. "
            "AWS only."
        ),
    )
    parser.add_argument(
        "--from-cache",
        action="store_true",
        default=False,
        help=(
            "Load findings from the local cache file instead of calling Inspector2. "
            "Requires a prior run with --cache-findings. "
            "All --resource-type, --clamp-old, and --hours filters still apply. "
            "AWS only."
        ),
    )
    parser.add_argument(
        "--cache-file",
        default=DEFAULT_CACHE_FILE,
        metavar="PATH",
        help=f"Path to the findings cache file (default: {DEFAULT_CACHE_FILE}).",
    )
    parser.add_argument(
        "--cortex-fqdn",
        default=None,
        metavar="FQDN",
        help="Cortex XDR tenant FQDN. Sets CORTEX_FQDN.",
    )
    parser.add_argument(
        "--cortex-api-key",
        default=None,
        metavar="KEY",
        help="Cortex XDR API key. Sets CORTEX_API_KEY.",
    )
    parser.add_argument(
        "--cortex-auth-id",
        default=None,
        metavar="ID",
        help="Cortex XDR API key ID (numeric). Sets CORTEX_AUTH_ID.",
    )
    args = parser.parse_args()

    # Validate arg combinations
    if not args.push_only and not args.source:
        parser.error("--source is required unless --push-only is set.")

    batch_dir = pathlib.Path(args.batch_dir)

    # Apply any CLI credential flags to env vars immediately
    if args.cortex_fqdn:
        os.environ["CORTEX_FQDN"] = args.cortex_fqdn
    if args.cortex_api_key:
        os.environ["CORTEX_API_KEY"] = args.cortex_api_key
    if args.cortex_auth_id:
        os.environ["CORTEX_AUTH_ID"] = args.cortex_auth_id

    # ------------------------------------------------------------------
    # Detect existing batch files
    # ------------------------------------------------------------------
    existing = _batch_files(batch_dir)
    do_download = True

    if existing:
        manifest = _read_manifest(batch_dir)
        n_total = manifest.get("total_batches", 0)
        total_assets, total_vulns = _batch_summary(existing)

        if args.push_only:
            # --push-only: never download, always use what's on disk
            logger.info(
                "Push-only mode: %d batch file(s) found in '%s'.", len(existing), batch_dir
            )
            do_download = False
        else:
            decision = _ask_pending(
                n_pending=len(existing),
                n_total=n_total,
                total_assets=total_assets,
                total_vulns=total_vulns,
                auto_yes=args.yes,
            )
            if decision == "abort":
                logger.info("Aborted. Batch files are still in '%s'.", batch_dir)
                sys.exit(0)
            elif decision == "redownload":
                logger.info("Deleting %d existing batch file(s) ...", len(existing))
                for f in existing:
                    f.unlink()
                mf = batch_dir / MANIFEST_FILE
                if mf.exists():
                    mf.unlink()
                existing = []
                do_download = True
            else:
                do_download = False

    elif args.push_only:
        logger.error(
            "No batch files found in '%s'. "
            "Run without --push-only first to download findings.",
            batch_dir,
        )
        sys.exit(1)

    # ------------------------------------------------------------------
    # Download step
    # ------------------------------------------------------------------
    if do_download:
        if args.source == "aws":
            if args.severities:
                os.environ["INSPECTOR2_SEVERITIES"] = args.severities.upper()
                logger.info("Inspector2 severities: %s", os.environ["INSPECTOR2_SEVERITIES"])
            if args.statuses:
                os.environ["INSPECTOR2_STATUSES"] = args.statuses.upper()
                logger.info("Inspector2 statuses:   %s", os.environ["INSPECTOR2_STATUSES"])
            if args.hours > 0:
                os.environ["INSPECTOR2_LOOKBACK_HOURS"] = str(args.hours)
                logger.info("Inspector2 lookback:   last %d hours", args.hours)
            else:
                os.environ["INSPECTOR2_LOOKBACK_HOURS"] = "0"
                logger.info("Inspector2 lookback:   disabled (no time filter)")

        if args.source == "aws":
            from byob_core.collectors.aws_inspector import collect    # noqa: PLC0415
            source_key = "aws_inspector"
        else:
            from byob_core.collectors.azure_defender import collect   # noqa: PLC0415
            source_key = "azure_defender"

        from byob_core import normalizer                              # noqa: PLC0415

        cache_path = pathlib.Path(args.cache_file)

        # ── Overwrite confirmation — before any API calls ──────────────────
        if args.cache_findings and not args.from_cache and args.source == "aws":
            if cache_path.exists():
                try:
                    existing_meta = json.loads(cache_path.read_text())
                    logger.warning(
                        "Cache file '%s' already exists "
                        "(cached_at=%s  findings=%s  region=%s).",
                        cache_path,
                        existing_meta.get("cached_at", "unknown"),
                        existing_meta.get("findings_count", "unknown"),
                        existing_meta.get("region", "unknown"),
                    )
                except Exception:
                    logger.warning("Cache file '%s' already exists.", cache_path)

                if not args.yes:
                    try:
                        answer = input("Overwrite existing cache? [y/N]: ").strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        logger.info("Aborted — existing cache kept.")
                        sys.exit(0)
                    if not answer.startswith("y"):
                        logger.info("Aborted — existing cache kept.")
                        sys.exit(0)
                else:
                    logger.info("--yes flag set: overwriting existing cache.")

        if args.from_cache:
            # ── Load from cache ────────────────────────────────────────────
            if args.source != "aws":
                logger.error("--from-cache is only supported with --source aws.")
                sys.exit(1)
            findings, cache_meta = _load_findings_cache(cache_path)
            logger.info(
                "Cache info: source=%s  region=%s  cached_at=%s  "
                "lookback_hours=%s  coverage_hours=%s",
                cache_meta["source"], cache_meta["region"], cache_meta["cached_at"],
                cache_meta["lookback_hours"], cache_meta["coverage_hours"],
            )
        else:
            # ── Live collection from Inspector2 / Azure ────────────────────
            logger.info("Collecting findings from %s ...", args.source)
            collect_kwargs: dict = {"mode": "scheduled"}
            if args.source == "aws" and args.region:
                collect_kwargs["region"] = args.region
            if args.source == "aws" and args.coverage_hours is not None:
                collect_kwargs["coverage_hours"] = args.coverage_hours
                logger.info("Coverage filter window: last %d hours.", args.coverage_hours)

            findings = collect(**collect_kwargs)
            logger.info("Collected %d findings.", len(findings))

            if args.cache_findings:
                if args.source != "aws":
                    logger.warning("--cache-findings is only supported with --source aws; skipped.")
                else:
                    _save_findings_cache(
                        findings, cache_path,
                        source=source_key,
                        region=args.region,
                        lookback_hours=args.hours,
                        coverage_hours=args.coverage_hours,
                    )
                    # ── Post-save summary table ────────────────────────────
                    from collections import defaultdict                # noqa: PLC0415
                    assets_by_type:   dict[str, set] = defaultdict(set)
                    findings_by_type: dict[str, int] = defaultdict(int)
                    for f in findings:
                        rtype = next(
                            (t[len("resource_type:"):] for t in f.tags
                             if t.startswith("resource_type:")), "unknown"
                        )
                        assets_by_type[rtype].add(f.asset_id)
                        findings_by_type[rtype] += 1
                    W = max(24, max((len(t) for t in assets_by_type), default=0))
                    div = "─" * (W + 30)
                    logger.info(div)
                    logger.info(
                        "  %-*s  %8s  %10s  %s",
                        W, "RESOURCE TYPE", "ASSETS", "FINDINGS", "IMPORT FLAG",
                    )
                    logger.info(div)
                    _FLAG = {
                        "lambda_function":     "--resource-type lambda",
                        "ec2_instance":        "--resource-type ec2",
                        "ecr_container_image": "--resource-type ecr",
                    }
                    for rtype in sorted(assets_by_type):
                        logger.info(
                            "  %-*s  %8d  %10d  %s",
                            W, rtype,
                            len(assets_by_type[rtype]),
                            findings_by_type[rtype],
                            _FLAG.get(rtype, ""),
                        )
                    logger.info(div)
                    logger.info(
                        "Re-run with --from-cache --resource-type <type> "
                        "to import without re-fetching Inspector2."
                    )
                    sys.exit(0)

        # --resource-type / --images-only filtering
        _RESOURCE_TYPE_TAG = {
            "lambda": "resource_type:lambda_function",
            "ecr":    "resource_type:ecr_container_image",
            "ec2":    "resource_type:ec2_instance",
        }
        resource_type_filter = args.resource_type
        if args.images_only and not resource_type_filter:
            resource_type_filter = "ecr"

        if resource_type_filter:
            if args.source != "aws":
                logger.warning("--resource-type is only supported with --source aws; flag ignored.")
            else:
                tag = _RESOURCE_TYPE_TAG[resource_type_filter]
                before = len(findings)
                findings = [f for f in findings if tag in f.tags]
                dropped = before - len(findings)
                logger.info(
                    "--resource-type %s: kept %d finding(s), dropped %d finding(s).",
                    resource_type_filter, len(findings), dropped,
                )
                if not findings:
                    logger.warning(
                        "No %s findings found — nothing to import. "
                        "Check that Inspector2 is scanning this resource type.",
                        resource_type_filter,
                    )
                    sys.exit(0)

        if args.clamp_old:
            logger.info(
                "--clamp-old enabled: findings older than 30 days will have "
                "last_seen set to import time instead of being dropped."
            )
        batches = normalizer.normalize(findings, source_key, clamp_old_findings=args.clamp_old)
        if not batches:
            logger.warning(
                "No batches produced — all findings were filtered out. "
                "Nothing to save or push."
            )
            sys.exit(0)

        logger.info("Saving %d batch(es) to '%s' ...", len(batches), batch_dir)
        existing = _save_batches(batch_dir, batches, source_key)

        total_assets, total_vulns = _batch_summary(existing)
        logger.info(
            "Saved %d batch file(s) — %d asset(s), %d vuln(s) total.",
            len(existing), total_assets, total_vulns,
        )
        for f in existing:
            data = json.loads(f.read_text())
            n_a = len(data.get("assets", []))
            n_v = sum(len(a.get("vulnerabilities", [])) for a in data.get("assets", []))
            logger.info("  %s — %d asset(s), %d vuln(s)", f.name, n_a, n_v)

        if args.download_only:
            logger.info(
                "Download-only mode: batches saved. "
                "Re-run without --download-only (or with --push-only) to push."
            )
            sys.exit(0)

        if not args.yes:
            if not _ask(f"\nPush {len(existing)} batch(es) to Cortex now?", default_yes=True):
                logger.info(
                    "Push deferred. Re-run this script (with or without --source) "
                    "to push the saved batches."
                )
                sys.exit(0)

    # ------------------------------------------------------------------
    # Push step — verify credentials first, then submit batch by batch
    # ------------------------------------------------------------------
    _verify_cortex_credentials()

    from byob_core import secrets                                      # noqa: PLC0415
    creds = secrets.load_credentials()

    files_to_push = _batch_files(batch_dir)
    logger.info("Starting push of %d batch file(s) ...", len(files_to_push))

    success = _push_batches(files_to_push, creds, clamp_old=args.clamp_old)

    remaining = _batch_files(batch_dir)
    if not remaining:
        _cleanup_dir(batch_dir)
        logger.info("All batches pushed successfully.")
    else:
        logger.warning(
            "%d batch file(s) still pending in '%s'. "
            "Re-run this script to continue.",
            len(remaining), batch_dir,
        )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

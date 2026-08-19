#!/usr/bin/env python3
"""Re-import ECR container image findings with asset_name = repository:tag.

This script is used to test whether Cortex updates an existing BYOS asset in
place when the same ``origin_asset_id`` is submitted with a different
``asset_name``.  The ``origin_asset_id`` for ECR images is the full ECR
resource ARN — unchanged from previous imports — so Cortex should match the
existing record and update the name field rather than creating a duplicate.

``asset_name`` is constructed as  ``<repository>:<tag>``
  - repository  — from the ``ecr_repo_name:`` tag on each finding
  - tag         — first tag in ``image_tags:``; ``latest`` is preferred if
                  present; falls back to the image digest if no tags exist

Usage
-----
  python3 scripts/reimport_images.py \\
      --source aws \\
      --images-only \\
      --coverage-hours 720 \\
      --hours 0

Dry-run (save batches to disk without pushing):
  python3 scripts/reimport_images.py \\
      --source aws --images-only --coverage-hours 720 --hours 0 \\
      --download-only

Resume a previously interrupted push:
  python3 scripts/reimport_images.py --push-only
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import sys

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)

DEFAULT_BATCH_DIR = ".byob-reimport-images"
BATCH_FILE_GLOB = "batch_*.json"
MANIFEST_FILE = ".manifest.json"

# ---------------------------------------------------------------------------
# asset_name reconstruction
# ---------------------------------------------------------------------------

def _repo_tag_name(finding) -> str:
    """Return ``repo:tag`` from a RawFinding's tags, or fall back to asset_name.

    Tag format written by the collector:
      ecr_repo_name:<name>
      image_tags:<tag1>,<tag2>,...

    Selection rule for the tag portion:
      1. Use ``latest`` if it appears in image_tags.
      2. Otherwise use the first entry in image_tags.
      3. If image_tags is absent, fall back to the digest (existing asset_name).
    """
    repo = ""
    raw_tags = ""
    for t in finding.tags:
        if t.startswith("ecr_repo_name:"):
            repo = t[len("ecr_repo_name:"):]
        elif t.startswith("image_tags:"):
            raw_tags = t[len("image_tags:"):]

    if not repo:
        # Not an ECR image or tags missing — leave name as-is
        return finding.asset_name

    if raw_tags:
        tag_list = [t.strip() for t in raw_tags.split(",") if t.strip()]
        tag = "latest" if "latest" in tag_list else (tag_list[0] if tag_list else "")
    else:
        tag = ""

    if tag:
        return f"{repo}:{tag}"
    # No docker tag available — use repo:digest (truncated for readability)
    digest = finding.asset_name  # sha256:abcd1234...
    short_digest = digest.replace("sha256:", "")[:12] if digest.startswith("sha256:") else digest
    return f"{repo}@{short_digest}"


# ---------------------------------------------------------------------------
# Batch file helpers (same pattern as batch_push.py)
# ---------------------------------------------------------------------------

def _batch_files(batch_dir: pathlib.Path) -> list[pathlib.Path]:
    return sorted(batch_dir.glob(BATCH_FILE_GLOB))


def _batch_summary(files: list[pathlib.Path]) -> tuple[int, int]:
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


def _save_batches(batch_dir: pathlib.Path, batches: list[dict]) -> list[pathlib.Path]:
    batch_dir.mkdir(parents=True, exist_ok=True)
    paths: list[pathlib.Path] = []
    for i, batch in enumerate(batches, start=1):
        path = batch_dir / f"batch_{i:04d}.json"
        path.write_text(json.dumps(batch, indent=2))
        paths.append(path)
    return paths


def _cleanup_dir(batch_dir: pathlib.Path) -> None:
    manifest = batch_dir / MANIFEST_FILE
    if manifest.exists():
        manifest.unlink()
    try:
        batch_dir.rmdir()
        logger.info("Batch directory '%s' removed.", batch_dir)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Push loop
# ---------------------------------------------------------------------------

def _push_batches(files: list[pathlib.Path], creds) -> bool:
    from byob_core import cortex_client                                # noqa: PLC0415
    from byob_core.cortex_client import CortexRateLimitError, CortexValidationError  # noqa: PLC0415

    pushed = skipped = failed = 0
    total = len(files)

    for i, path in enumerate(files, start=1):
        logger.info("─── Pushing batch %d/%d: %s", i, total, path.name)
        try:
            batch = json.loads(path.read_text())
        except Exception as exc:
            logger.error("Failed to read '%s': %s — skipping.", path.name, exc)
            failed += 1
            continue

        try:
            results = cortex_client.submit_all([batch], creds)
            for r in results:
                logger.info(
                    "  Accepted | job_id=%s  status=%s  assets=%d  vulns=%d",
                    r.job_id, r.status, r.assets_count, r.vulnerabilities_count,
                )
            path.unlink()
            pushed += 1

        except CortexValidationError as exc:
            logger.error("  Batch %s rejected (validation): %s — skipping.", path.name, exc)
            skipped += 1

        except CortexRateLimitError as exc:
            logger.error(
                "  Rate limit on batch %s: %s\n"
                "  Remaining batches saved in '%s'. Re-run with --push-only to continue.",
                path.name, exc, path.parent,
            )
            failed += 1
            return False

        except Exception as exc:
            logger.error(
                "  Unexpected error on batch %s: %s\n"
                "  Remaining batches saved in '%s'. Re-run with --push-only to continue.",
                path.name, exc, path.parent,
            )
            failed += 1
            return False

    logger.info(
        "─── Push complete: %d pushed, %d skipped (validation), %d failed.",
        pushed, skipped, failed,
    )
    return failed == 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Re-import ECR container image findings with asset_name = repository:tag.\n"
            "Uses the same origin_asset_id as the original import so Cortex updates\n"
            "existing records in place rather than creating duplicates."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--download-only",
        action="store_true",
        help="Save batch files to disk without pushing to Cortex.",
    )
    mode.add_argument(
        "--push-only",
        action="store_true",
        help="Skip collection — push existing batch files from the batch directory.",
    )

    parser.add_argument(
        "--source",
        choices=["aws"],
        default="aws",
        help="Vulnerability source (only 'aws' is supported). Default: aws.",
    )
    parser.add_argument(
        "--resource-type",
        default="ecr",
        choices=["lambda", "ecr", "ec2"],
        metavar="TYPE",
        help=(
            "Resource type to reimport. Valid values: lambda, ecr, ec2. "
            "Default: ecr. Example: --resource-type lambda reimports Lambda findings."
        ),
    )
    parser.add_argument(
        "--images-only",
        action="store_true",
        default=False,
        help="Alias for --resource-type ecr (kept for backwards compatibility).",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Only collect findings updated in the last N hours. "
            "Default: 0 (no time filter — all image findings). "
        ),
    )
    parser.add_argument(
        "--coverage-hours",
        type=int,
        default=720,
        metavar="N",
        help=(
            "Only include images that Inspector2 has scanned in the last N hours "
            "(list-coverage pre-filter). Default: 720 (30 days)."
        ),
    )
    parser.add_argument(
        "--region",
        default=None,
        metavar="REGION",
        help="AWS region for Inspector2 (e.g. us-east-1).",
    )
    parser.add_argument(
        "--batch-dir",
        default=DEFAULT_BATCH_DIR,
        metavar="DIR",
        help=f"Directory to store batch files (default: {DEFAULT_BATCH_DIR}).",
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Non-interactive — push without prompting.",
    )
    parser.add_argument(
        "--cortex-fqdn",
        default=None, metavar="FQDN",
        help="Cortex XDR tenant FQDN. Sets CORTEX_FQDN.",
    )
    parser.add_argument(
        "--cortex-api-key",
        default=None, metavar="KEY",
        help="Cortex XDR API key. Sets CORTEX_API_KEY.",
    )
    parser.add_argument(
        "--cortex-auth-id",
        default=None, metavar="ID",
        help="Cortex XDR API key ID (numeric). Sets CORTEX_AUTH_ID.",
    )
    args = parser.parse_args()

    batch_dir = pathlib.Path(args.batch_dir)

    if args.cortex_fqdn:
        os.environ["CORTEX_FQDN"] = args.cortex_fqdn
    if args.cortex_api_key:
        os.environ["CORTEX_API_KEY"] = args.cortex_api_key
    if args.cortex_auth_id:
        os.environ["CORTEX_AUTH_ID"] = args.cortex_auth_id

    # ------------------------------------------------------------------
    # Push-only: skip collection, push whatever is on disk
    # ------------------------------------------------------------------
    if args.push_only:
        existing = _batch_files(batch_dir)
        if not existing:
            logger.error(
                "No batch files found in '%s'. Run without --push-only first.", batch_dir
            )
            sys.exit(1)
        logger.info("Push-only mode: %d batch file(s) in '%s'.", len(existing), batch_dir)
    else:
        # ------------------------------------------------------------------
        # Collection
        # ------------------------------------------------------------------
        from byob_core.collectors.aws_inspector import collect         # noqa: PLC0415
        from byob_core import normalizer                               # noqa: PLC0415

        if args.hours > 0:
            os.environ["INSPECTOR2_LOOKBACK_HOURS"] = str(args.hours)
            logger.info("Inspector2 lookback: last %d hours.", args.hours)
        else:
            os.environ["INSPECTOR2_LOOKBACK_HOURS"] = "0"
            logger.info("Inspector2 lookback: disabled (all findings).")

        collect_kwargs: dict = {"mode": "scheduled"}
        if args.region:
            collect_kwargs["region"] = args.region
        collect_kwargs["coverage_hours"] = args.coverage_hours
        logger.info("Coverage filter window: last %d hours.", args.coverage_hours)

        logger.info("Collecting Inspector2 findings ...")
        all_findings = collect(**collect_kwargs)
        logger.info("Collected %d finding(s) total.", len(all_findings))

        # Resolve resource type (--images-only is an alias for ecr)
        _RESOURCE_TYPE_TAG = {
            "lambda": "resource_type:lambda_function",
            "ecr":    "resource_type:ecr_container_image",
            "ec2":    "resource_type:ec2_instance",
        }
        _RESOURCE_TYPE_LABEL = {
            "lambda": "Lambda function",
            "ecr":    "ECR container image",
            "ec2":    "EC2 instance",
        }
        resource_type = "ecr" if args.images_only else args.resource_type
        tag = _RESOURCE_TYPE_TAG[resource_type]
        label = _RESOURCE_TYPE_LABEL[resource_type]

        findings = [f for f in all_findings if tag in f.tags]
        dropped = len(all_findings) - len(findings)
        logger.info(
            "Filtered to %d %s finding(s) (%d finding(s) from other resource types dropped).",
            len(findings), label, dropped,
        )

        if not findings:
            logger.warning(
                "No %s findings found. "
                "Check that Inspector2 is scanning this resource type in this region.",
                label,
            )
            sys.exit(0)

        # Override asset_name for ECR images → repo:tag format
        # For other resource types the existing asset_name is already correct.
        renamed = 0
        if resource_type == "ecr":
            for f in findings:
                new_name = _repo_tag_name(f)
                if new_name != f.asset_name:
                    f.asset_name = new_name
                    renamed += 1
            logger.info(
                "Renamed %d finding(s): asset_name set to repository:tag format.", renamed
            )

        # Log a sample so the user can verify before pushing
        seen_assets: set[str] = set()
        sample_count = 0
        for f in findings:
            if f.asset_id not in seen_assets:
                seen_assets.add(f.asset_id)
                logger.info(
                    "  Sample asset | origin_asset_id=%-60s  asset_name=%s",
                    f.asset_id, f.asset_name,
                )
                sample_count += 1
                if sample_count >= 10:
                    remaining = len(set(f.asset_id for f in findings)) - sample_count
                    if remaining > 0:
                        logger.info("  ... and %d more unique image(s).", remaining)
                    break

        # Normalize (clamp_old=True so findings older than 30 days are included)
        batches = normalizer.normalize(findings, "aws_inspector", clamp_old_findings=True)
        if not batches:
            logger.warning("No batches produced — all findings were filtered out.")
            sys.exit(0)

        logger.info("Saving %d batch(es) to '%s' ...", len(batches), batch_dir)
        existing = _save_batches(batch_dir, batches)
        total_assets, total_vulns = _batch_summary(existing)
        logger.info(
            "Saved %d batch file(s) — %d asset(s), %d vuln(s).",
            len(existing), total_assets, total_vulns,
        )

        if args.download_only:
            logger.info(
                "Download-only mode: inspect batches in '%s', then re-run with --push-only.",
                batch_dir,
            )
            sys.exit(0)

        if not args.yes:
            try:
                answer = input(f"\nPush {len(existing)} batch(es) to Cortex now? [Y/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                logger.info("Aborted. Batches saved in '%s'.", batch_dir)
                sys.exit(0)
            if answer and not answer.startswith("y"):
                logger.info(
                    "Push deferred. Re-run with --push-only to push the saved batches."
                )
                sys.exit(0)

    # ------------------------------------------------------------------
    # Push
    # ------------------------------------------------------------------
    from byob_core import secrets                                      # noqa: PLC0415
    from byob_core import secrets as _secrets                         # noqa: PLC0415
    _secrets.verify_credentials()
    creds = secrets.load_credentials()

    files_to_push = _batch_files(batch_dir)
    logger.info("Pushing %d batch file(s) ...", len(files_to_push))
    success = _push_batches(files_to_push, creds)

    remaining = _batch_files(batch_dir)
    if not remaining:
        _cleanup_dir(batch_dir)
        logger.info("All batches pushed successfully.")
    else:
        logger.warning(
            "%d batch file(s) still pending in '%s'. Re-run with --push-only to continue.",
            len(remaining), batch_dir,
        )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

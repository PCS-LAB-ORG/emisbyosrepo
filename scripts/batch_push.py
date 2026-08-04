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

def _push_batches(files: list[pathlib.Path], creds) -> bool:
    """Push each batch file to Cortex one at a time; delete on success.

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
        help="Download and save batches to disk but do not push to Cortex.",
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
            "Default: MEDIUM,HIGH,CRITICAL."
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
            "Default: 720 (30 days). Set to 0 for no time filter."
        ),
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

        logger.info("Collecting findings from %s ...", args.source)
        collect_kwargs: dict = {"mode": "scheduled"}
        if args.source == "aws" and args.region:
            collect_kwargs["region"] = args.region

        findings = collect(**collect_kwargs)
        logger.info("Collected %d findings.", len(findings))

        batches = normalizer.normalize(findings, source_key)
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

    success = _push_batches(files_to_push, creds)

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

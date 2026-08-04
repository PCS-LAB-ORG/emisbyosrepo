#!/usr/bin/env python3
"""Integration test. Run with --dry-run (default) to preview payload, --post to submit.

Usage:
    python3 scripts/integration_test.py --source aws --dry-run
    python3 scripts/integration_test.py --source aws --dry-run --region eu-west-1

    # Filter by severity and/or status (defaults match the Lambda defaults)
    python3 scripts/integration_test.py --source aws --dry-run \\
        --severities HIGH,CRITICAL
    python3 scripts/integration_test.py --source aws --dry-run \\
        --severities CRITICAL --statuses ACTIVE,SUPPRESSED

    # Time-based delta (match Lambda behaviour — last 12 hours)
    python3 scripts/integration_test.py --source aws --dry-run \\
        --hours 12

    # Initial full import — no --hours flag uses 30-day default (matches Cortex API limit)
    python3 scripts/integration_test.py --source aws --post

    # Disable time filter entirely (download everything, including pre-30-day findings
    # that the normalizer will still drop — useful for diagnostics only)
    python3 scripts/integration_test.py --source aws --dry-run \\
        --hours 0

    # Post to Cortex using individual env vars:
    CORTEX_API_KEY=... CORTEX_AUTH_ID=... CORTEX_FQDN=... \\
        python3 scripts/integration_test.py --source aws --post

    # Post to Cortex using CLI flags:
    python3 scripts/integration_test.py --source aws --post \\
        --cortex-fqdn foo.xdr.us.paloaltonetworks.com \\
        --cortex-api-key <key> \\
        --cortex-auth-id <id>

    # Post using a secret already stored in AWS Secrets Manager:
    CORTEX_SECRET_NAME=byob-scanner/cortex \\
        python3 scripts/integration_test.py --source aws --post

    # Post using a secret stored in AWS Secrets Manager with explicit region:
    CORTEX_SECRET_NAME=byob-scanner/cortex AWS_DEFAULT_REGION=us-east-1 \\
        python3 scripts/integration_test.py --source aws --post
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)

DRY_RUN_PAYLOAD_MAX_CHARS = 500


def _verify_cortex_credentials() -> None:
    """Delegate to the shared implementation in byob_core.secrets."""
    from byob_core import secrets as _secrets  # noqa: PLC0415
    _secrets.verify_credentials()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ByobScanner integration test — preview or submit findings to Cortex XDR."
    )
    parser.add_argument(
        "--source",
        choices=["aws", "azure"],
        required=True,
        help="Vulnerability source to collect from.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Print first batch payload without posting to Cortex (default).",
    )
    parser.add_argument(
        "--post",
        action="store_true",
        default=False,
        help="Submit all batches to Cortex XDR and print JobResult summaries.",
    )
    parser.add_argument(
        "--region",
        default=None,
        metavar="REGION",
        help=(
            "AWS region for Inspector2 (e.g. us-east-1). "
            "Falls back to AWS_DEFAULT_REGION env var, then us-east-1. "
            "Ignored for --source azure."
        ),
    )
    parser.add_argument(
        "--severities",
        default=None,
        metavar="SEVERITIES",
        help=(
            "Comma-separated Inspector2 severities to collect. "
            "Valid: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL, UNTRIAGED. "
            "Default: MEDIUM,HIGH,CRITICAL. "
            "Ignored for --source azure."
        ),
    )
    parser.add_argument(
        "--statuses",
        default=None,
        metavar="STATUSES",
        help=(
            "Comma-separated Inspector2 finding statuses to collect. "
            "Valid: ACTIVE, SUPPRESSED, CLOSED. "
            "Default: ACTIVE. "
            "Ignored for --source azure."
        ),
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=720,
        metavar="N",
        help=(
            "Only collect findings updated in the last N hours. "
            "Default: 720 (30 days) — matches the Cortex API hard limit, so findings "
            "older than this are rejected anyway. "
            "Set to 12 to match the Lambda delta behaviour. "
            "Set to 0 to disable the time filter entirely (no upper bound). "
            "Ignored for --source azure."
        ),
    )
    parser.add_argument(
        "--cortex-fqdn",
        default=None,
        metavar="FQDN",
        help=(
            "Cortex XDR tenant FQDN (e.g. foo.xdr.us.paloaltonetworks.com). "
            "Sets CORTEX_FQDN. Overrides the env var if both are present."
        ),
    )
    parser.add_argument(
        "--cortex-api-key",
        default=None,
        metavar="KEY",
        help="Cortex XDR API key. Sets CORTEX_API_KEY. Overrides the env var if both are present.",
    )
    parser.add_argument(
        "--cortex-auth-id",
        default=None,
        metavar="ID",
        help=(
            "Cortex XDR API key ID (numeric). "
            "Sets CORTEX_AUTH_ID. Overrides the env var if both are present."
        ),
    )
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # When --post is requested: apply any CLI credential flags into env
    # vars first, then verify the secret is accessible before spending
    # time collecting findings.
    # ------------------------------------------------------------------
    if args.post:
        if args.cortex_fqdn:
            os.environ["CORTEX_FQDN"] = args.cortex_fqdn
        if args.cortex_api_key:
            os.environ["CORTEX_API_KEY"] = args.cortex_api_key
        if args.cortex_auth_id:
            os.environ["CORTEX_AUTH_ID"] = args.cortex_auth_id
        _verify_cortex_credentials()

    # Apply Inspector2 filter overrides before the collector reads env vars.
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
        from byob_core.collectors.aws_inspector import collect  # noqa: PLC0415
        source_key = "aws_inspector"
    else:
        from byob_core.collectors.azure_defender import collect  # noqa: PLC0415
        source_key = "azure_defender"

    from byob_core import normalizer  # noqa: PLC0415

    logger.info("Collecting from %s ...", args.source)
    collect_kwargs: dict = {"mode": "scheduled"}
    if args.source == "aws" and args.region:
        collect_kwargs["region"] = args.region
    findings = collect(**collect_kwargs)
    logger.info("Collected %d findings", len(findings))

    batches = normalizer.normalize(findings, source_key)

    if not args.post:
        if not batches:
            logger.warning(
                "No batches to display — all findings were filtered out. "
                "Check the WARNING lines above for the reason (no CVE, no resource, or >30 days old)."
            )
            return
        for i, batch in enumerate(batches):
            n_assets = len(batch.get("assets", []))
            n_vulns = sum(len(a.get("vulnerabilities", [])) for a in batch.get("assets", []))
            logger.info("Batch %d/%d — %d asset(s), %d vuln(s)", i + 1, len(batches), n_assets, n_vulns)
        logger.info("--- DRY RUN: first batch payload (truncated to %d chars) ---", DRY_RUN_PAYLOAD_MAX_CHARS)
        first_batch_json = json.dumps(batches[0] if batches else {}, indent=2, default=str)
        print(first_batch_json[:DRY_RUN_PAYLOAD_MAX_CHARS])
        if len(first_batch_json) > DRY_RUN_PAYLOAD_MAX_CHARS:
            print("... (truncated)")
        return

    from byob_core import secrets, cortex_client  # noqa: PLC0415

    creds = secrets.load_credentials()
    results = cortex_client.submit_all(batches, creds)
    for r in results:
        logger.info(
            "Job %s: %s -- %d assets, %d vulns",
            r.job_id,
            r.status,
            r.assets_count,
            r.vulnerabilities_count,
        )


if __name__ == "__main__":
    main()


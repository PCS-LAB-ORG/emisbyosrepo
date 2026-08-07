from __future__ import annotations
import logging
import os
import time
from typing import Any
from byob_core.collectors import aws_inspector
from byob_core import normalizer, cortex_client, secrets

logging.getLogger().setLevel(logging.INFO)  # Lambda pre-attaches its handler; basicConfig is a no-op
logger = logging.getLogger(__name__)


def lambda_handler(event: dict, context: Any) -> dict:
    start_ms = int(time.time() * 1000)

    # ── invocation context ────────────────────────────────────────────────────
    fn_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "local")
    fn_version = os.environ.get("AWS_LAMBDA_FUNCTION_VERSION", "?")
    region = os.environ.get("AWS_DEFAULT_REGION", "?")
    remaining_ms = getattr(context, "get_remaining_time_in_millis", lambda: None)()
    logger.info(
        "=== ByobScanner Lambda start | function=%s version=%s region=%s "
        "remaining_ms=%s ===",
        fn_name, fn_version, region, remaining_ms,
    )
    logger.info("Event: %s", event)

    try:
        # ── determine scan mode ───────────────────────────────────────────────
        if event.get("detail-type") == "Inspector2 Finding":
            mode = "event"
            finding_arn = event.get("detail", {}).get("findingArn")
            if finding_arn is None:
                logger.warning(
                    "detail-type is 'Inspector2 Finding' but findingArn missing — "
                    "falling back to full scheduled scan"
                )
                mode = "scheduled"
            else:
                logger.info("Mode: event-driven | findingArn=%s", finding_arn)
        else:
            mode = "scheduled"
            finding_arn = None
            logger.info("Mode: scheduled full scan")

        # ── apply per-invocation filter overrides from EventBridge input ──────
        # EventBridge rules can pass a static JSON payload via the "input" field,
        # allowing a single Lambda to be invoked by multiple rules with different
        # filter settings (e.g. CRITICAL every hour, HIGH,CRITICAL every 6 hours).
        # Values in the event take priority over Lambda env vars.
        # Event-driven Inspector2 finding invocations are never overridden —
        # they always use the env var defaults.
        overrides: dict[str, str] = {}
        if mode == "scheduled":
            if "inspector2_severities" in event:
                overrides["severities"] = str(event["inspector2_severities"])
                logger.info(
                    "Filter override from EventBridge: severities=%s",
                    overrides["severities"],
                )
            if "inspector2_statuses" in event:
                overrides["statuses"] = str(event["inspector2_statuses"])
                logger.info(
                    "Filter override from EventBridge: statuses=%s",
                    overrides["statuses"],
                )
            if "inspector2_lookback_hours" in event:
                overrides["lookback_hours"] = int(event["inspector2_lookback_hours"])
                logger.info(
                    "Filter override from EventBridge: lookback_hours=%s",
                    overrides["lookback_hours"],
                )
            if "inspector2_coverage_hours" in event:
                overrides["coverage_hours"] = int(event["inspector2_coverage_hours"])
                logger.info(
                    "Filter override from EventBridge: coverage_hours=%s",
                    overrides["coverage_hours"],
                )

        # ── load credentials ──────────────────────────────────────────────────
        logger.info("Loading Cortex credentials ...")
        creds = secrets.load_credentials()
        logger.info("Credentials loaded | fqdn=%s auth_id=%s", creds.cortex_fqdn, creds.cortex_auth_id)

        # ── collect findings ──────────────────────────────────────────────────
        logger.info("Collecting Inspector2 findings (mode=%s) ...", mode)
        t0 = time.time()
        findings = aws_inspector.collect(mode=mode, finding_arn=finding_arn, **overrides)
        logger.info(
            "Collection complete | findings=%d elapsed=%.1fs",
            len(findings), time.time() - t0,
        )

        if not findings:
            logger.warning("No findings collected — nothing to push to Cortex")
            return {"status": "ok", "findings_count": 0, "batches": 0,
                    "assets_pushed": 0, "vulnerabilities_pushed": 0}

        # ── normalise ─────────────────────────────────────────────────────────
        logger.info("Normalising %d findings ...", len(findings))
        t0 = time.time()
        batches = normalizer.normalize(findings, "aws_inspector")
        total_assets = sum(len(b.get("assets", [])) for b in batches)
        total_vulns = sum(
            len(a.get("vulnerabilities", []))
            for b in batches for a in b.get("assets", [])
        )
        logger.info(
            "Normalisation complete | batches=%d assets=%d vulns=%d elapsed=%.1fs",
            len(batches), total_assets, total_vulns, time.time() - t0,
        )
        for i, batch in enumerate(batches):
            n_a = len(batch.get("assets", []))
            n_v = sum(len(a.get("vulnerabilities", [])) for a in batch.get("assets", []))
            logger.info("  Batch %d/%d — %d asset(s), %d vuln(s)", i + 1, len(batches), n_a, n_v)

        # ── submit to Cortex ──────────────────────────────────────────────────
        logger.info("Submitting %d batch(es) to Cortex XDR ...", len(batches))
        t0 = time.time()
        results = cortex_client.submit_all(batches, creds)
        pushed_assets = sum(r.assets_count for r in results)
        pushed_vulns = sum(r.vulnerabilities_count for r in results)
        logger.info(
            "Cortex submission complete | jobs=%d assets_confirmed=%d vulns_confirmed=%d elapsed=%.1fs",
            len(results), pushed_assets, pushed_vulns, time.time() - t0,
        )
        for r in results:
            logger.info(
                "  Job %s | status=%s assets=%d vulns=%d",
                r.job_id, r.status, r.assets_count, r.vulnerabilities_count,
            )
            if getattr(r, "error_log", None):
                logger.warning("  Job %s errors: %s", r.job_id, r.error_log)

        elapsed_total = (int(time.time() * 1000) - start_ms) / 1000
        logger.info(
            "=== ByobScanner Lambda complete | status=ok total_elapsed=%.1fs ===",
            elapsed_total,
        )
        return {
            "status": "ok",
            "findings_count": len(findings),
            "batches": len(results),
            "assets_pushed": pushed_assets,
            "vulnerabilities_pushed": pushed_vulns,
        }

    except Exception as exc:
        elapsed_total = (int(time.time() * 1000) - start_ms) / 1000
        logger.exception(
            "=== ByobScanner Lambda failed | total_elapsed=%.1fs error=%s ===",
            elapsed_total, exc,
        )
        return {"status": "error", "error": str(exc)}

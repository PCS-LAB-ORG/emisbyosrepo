#!/usr/bin/env python3
"""List Inspector2 coverage for Lambda functions with a summary + detail table.

Calls ``inspector2:list_coverage`` filtered to ``AWS_LAMBDA_FUNCTION`` and
prints:
  1. A summary table grouped by scanType × scanStatus
  2. A detail table with one row per function × scanType

Usage
-----
  # Default region (AWS_DEFAULT_REGION env var or us-east-1)
  python3 scripts/lambda_coverage.py

  # Specific region
  python3 scripts/lambda_coverage.py --region eu-west-1

  # Filter to a specific scan type (PACKAGE | NETWORK | CODE)
  python3 scripts/lambda_coverage.py --scan-type PACKAGE

  # Filter to a specific status (ACTIVE | INACTIVE | UNSCANNED ...)
  python3 scripts/lambda_coverage.py --status ACTIVE

  # Sort detail table by a column
  python3 scripts/lambda_coverage.py --sort last_scan
  python3 scripts/lambda_coverage.py --sort function
  python3 scripts/lambda_coverage.py --sort status
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import boto3

# ── ANSI colours ─────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

_STATUS_COLOUR = {
    "ACTIVE":            GREEN,
    "INACTIVE":          RED,
    "UNSCANNED":         YELLOW,
    "PENDING":           CYAN,
    "SCANNING":          CYAN,
}

_SCAN_TYPE_COLOUR = {
    "PACKAGE":  CYAN,
    "NETWORK":  YELLOW,
    "CODE":     "\033[95m",  # magenta
}


def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"


def _status_c(status: str) -> str:
    return _c(_STATUS_COLOUR.get(status, RESET), status)


def _scan_type_c(scan_type: str) -> str:
    return _c(_SCAN_TYPE_COLOUR.get(scan_type, RESET), scan_type)


def _fmt_ts(ts) -> str:
    """Format a datetime or None to a readable local string."""
    if ts is None:
        return "—"
    if isinstance(ts, datetime):
        # Convert to local time for display
        local = ts.astimezone()
        return local.strftime("%Y-%m-%d %H:%M")
    return str(ts)


def _age(ts) -> str:
    """Return human-readable age since ts (e.g. '3d 2h', '45m')."""
    if ts is None:
        return "—"
    if not isinstance(ts, datetime):
        return "—"
    delta = datetime.now(tz=timezone.utc) - ts.astimezone(timezone.utc)
    total_sec = int(delta.total_seconds())
    if total_sec < 0:
        return "future"
    d, rem = divmod(total_sec, 86400)
    h, rem = divmod(rem, 3600)
    m, _   = divmod(rem, 60)
    if d > 0:
        return f"{d}d {h}h"
    if h > 0:
        return f"{h}h {m}m"
    return f"{m}m"


# ── Collection ────────────────────────────────────────────────────────────────

def _fetch_lambda_coverage(
    region: str,
    scan_type_filter: str | None,
    status_filter: str | None,
) -> list[dict]:
    """Return raw coveredResource records for Lambda functions."""
    client = boto3.client("inspector2", region_name=region)

    criteria: dict = {
        "resourceType": [{"comparison": "EQUALS", "value": "AWS_LAMBDA_FUNCTION"}],
    }
    if scan_type_filter:
        criteria["scanType"] = [{"comparison": "EQUALS", "value": scan_type_filter.upper()}]
    if status_filter:
        criteria["scanStatusCode"] = [{"comparison": "EQUALS", "value": status_filter.upper()}]

    resources: list[dict] = []
    try:
        paginator = client.get_paginator("list_coverage")
        for page in paginator.paginate(
            filterCriteria=criteria,
            PaginationConfig={"PageSize": 200},
        ):
            resources.extend(page.get("coveredResources", []))
    except Exception as exc:
        print(f"{RED}Error calling Inspector2 list_coverage: {exc}{RESET}", file=sys.stderr)
        sys.exit(1)

    return resources


def _parse_record(r: dict) -> dict:
    meta      = r.get("resourceMetadata", {}).get("lambdaFunction", {})
    status    = r.get("scanStatus", {})
    arn       = r.get("resourceId", "")
    fn_name, version = _split_arn(arn)
    return {
        "resource_id":   arn,
        "function_name": meta.get("functionName") or fn_name,
        "version":       version,
        "runtime":       meta.get("runtime", "—"),
        "scan_type":     r.get("scanType", "—"),
        "status_code":   status.get("statusCode", "—"),
        "status_reason": status.get("reason", "—"),
        "last_scanned":  r.get("lastScannedAt"),
        "account_id":    r.get("accountId", "—"),
    }


def _split_arn(arn: str) -> tuple[str, str]:
    """Return (function_name, version_qualifier) from a Lambda ARN.

    ARN formats:
      arn:aws:lambda:REGION:ACCOUNT:function:NAME          → ("NAME", "—")
      arn:aws:lambda:REGION:ACCOUNT:function:NAME:$LATEST  → ("NAME", "$LATEST")
      arn:aws:lambda:REGION:ACCOUNT:function:NAME:3        → ("NAME", "3")
    """
    parts = arn.split(":")
    # A fully-qualified Lambda ARN has 7 parts (no version) or 8 parts (with version)
    if len(parts) >= 8 and parts[5] == "function":
        return parts[6], parts[7]
    if len(parts) >= 7 and parts[5] == "function":
        return parts[6], "—"
    # Fallback for non-ARN resource IDs
    return parts[-1] if parts else arn, "—"


# ── Rendering ─────────────────────────────────────────────────────────────────

def _divider(width: int, bold: bool = False) -> str:
    line = "─" * width
    return f"{BOLD}{line}{RESET}" if bold else line


def _print_summary(rows: list[dict], region: str) -> None:
    """Print summary table grouped by scanType × statusCode."""
    # Build counts
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for r in rows:
        counts[(r["scan_type"], r["status_code"])] += 1

    # Collect unique scan types and statuses (sorted)
    scan_types  = sorted({k[0] for k in counts})
    status_codes = sorted({k[1] for k in counts})

    W_TYPE   = max(10, max(len(s) for s in scan_types))
    W_STATUS = max(12, max(len(s) for s in status_codes))
    W_COUNT  = 7

    # Header row
    header = f"  {'SCAN TYPE':<{W_TYPE}}  {'STATUS':<{W_STATUS}}  {'COUNT':>{W_COUNT}}"
    div    = _divider(len(header) + 2)

    print(f"\n{_divider(len(header) + 2, bold=True)}")
    print(f"{BOLD}  LAMBDA INSPECTOR2 COVERAGE SUMMARY  —  region: {region}{RESET}")
    print(f"{BOLD}  Total Lambda scan records : {len(rows)}{RESET}")
    print(_divider(len(header) + 2, bold=True))
    print(f"{BOLD}{header}{RESET}")
    print(div)

    for scan_type in scan_types:
        for status in status_codes:
            count = counts.get((scan_type, status), 0)
            if count == 0:
                continue
            row_str = (
                f"  {_scan_type_c(scan_type):<{W_TYPE + 10}}  "
                f"{_status_c(status):<{W_STATUS + 10}}  "
                f"{count:>{W_COUNT}}"
            )
            print(row_str)

    print(div)


def _print_detail(rows: list[dict], sort_by: str) -> None:
    """Print per-function detail table."""
    if not rows:
        print(f"\n{YELLOW}  No Lambda coverage records found.{RESET}\n")
        return

    # Sort
    sort_key = {
        "function": lambda r: r["function_name"].lower(),
        "status":   lambda r: (r["status_code"], r["function_name"].lower()),
        "scan_type":lambda r: (r["scan_type"], r["function_name"].lower()),
        "last_scan": lambda r: (
            r["last_scanned"] or datetime.min.replace(tzinfo=timezone.utc),
        ),
    }.get(sort_by, lambda r: r["function_name"].lower())
    rows = sorted(rows, key=sort_key)

    # Column widths
    W_FN      = max(16, max(len(r["function_name"]) for r in rows))
    W_VER     = max(7,  max(len(r["version"])       for r in rows))
    W_RT      = max(10, max(len(r["runtime"])       for r in rows))
    W_TYPE    = max(8,  max(len(r["scan_type"])     for r in rows))
    W_STATUS  = max(8,  max(len(r["status_code"])   for r in rows))
    W_REASON  = max(14, max(len(r["status_reason"]) for r in rows))
    W_LAST    = 16
    W_AGE     = 10

    header = (
        f"  {'FUNCTION':<{W_FN}}  {'VERSION':<{W_VER}}  {'RUNTIME':<{W_RT}}  "
        f"{'SCAN TYPE':<{W_TYPE}}  {'STATUS':<{W_STATUS}}  "
        f"{'REASON':<{W_REASON}}  {'LAST SCAN':<{W_LAST}}  {'AGE':<{W_AGE}}"
    )
    div = _divider(len(header) + 2)

    print(f"\n{_divider(len(header) + 2, bold=True)}")
    print(f"{BOLD}  LAMBDA FUNCTION DETAIL  —  {len(rows)} record(s){RESET}")
    print(_divider(len(header) + 2, bold=True))
    print(f"{BOLD}{header}{RESET}")
    print(div)

    prev_fn = None
    for r in rows:
        fn      = r["function_name"]
        ver     = r["version"]
        rt      = r["runtime"]
        stype   = r["scan_type"]
        scode   = r["status_code"]
        sreason = r["status_reason"]
        last    = _fmt_ts(r["last_scanned"])
        age     = _age(r["last_scanned"])

        # Dim repeated function names for readability
        fn_str = fn if fn != prev_fn else _c(DIM, fn)
        prev_fn = fn

        print(
            f"  {fn_str:<{W_FN}}  {ver:<{W_VER}}  {rt:<{W_RT}}  "
            f"{_scan_type_c(stype):<{W_TYPE + 10}}  "
            f"{_status_c(scode):<{W_STATUS + 10}}  "
            f"{sreason:<{W_REASON}}  "
            f"{last:<{W_LAST}}  {age:<{W_AGE}}"
        )

    print(div)
    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Show Inspector2 coverage status for Lambda functions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--region", default=None, metavar="REGION",
        help="AWS region (default: AWS_DEFAULT_REGION env var, then us-east-1).",
    )
    parser.add_argument(
        "--scan-type", default=None, metavar="TYPE",
        choices=["PACKAGE", "NETWORK", "CODE"],
        help="Filter to a specific scan type: PACKAGE, NETWORK, or CODE.",
    )
    parser.add_argument(
        "--status", default=None, metavar="STATUS",
        help="Filter to a specific scan status code (e.g. ACTIVE, INACTIVE, UNSCANNED).",
    )
    parser.add_argument(
        "--sort", default="function",
        choices=["function", "status", "scan_type", "last_scan"],
        help="Sort the detail table by column (default: function).",
    )
    args = parser.parse_args()

    region = args.region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

    print(f"\n{CYAN}Fetching Lambda coverage from Inspector2 (region={region}) ...{RESET}")
    raw = _fetch_lambda_coverage(region, args.scan_type, args.status)

    if not raw:
        print(f"\n{YELLOW}No Lambda coverage records found.")
        print(f"Check that Inspector2 is enabled and scanning Lambda in region '{region}'.{RESET}\n")
        sys.exit(0)

    rows = [_parse_record(r) for r in raw]

    _print_summary(rows, region)
    _print_detail(rows, args.sort)


if __name__ == "__main__":
    main()

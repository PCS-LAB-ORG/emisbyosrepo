#!/usr/bin/env python3
"""Summarise a findings cache file before importing.

Reads the JSON cache produced by --cache-findings and prints:
  1. A header with cache metadata (created, region, total findings)
  2. A summary table: resource type × asset count × findings count
  3. A per-account breakdown when multiple AWS accounts are present

Usage
-----
  python3 scripts/cache_summary.py
  python3 scripts/cache_summary.py --cache-file .byob-cache-us-east-1.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

DEFAULT_CACHE_FILE = ".byob-findings-cache.json"

# ── ANSI colours ─────────────────────────────────────────────────────────────
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
DIM    = "\033[2m"
RESET  = "\033[0m"

_RESOURCE_TYPE_COLOURS = {
    "lambda_function":       CYAN,
    "ec2_instance":          GREEN,
    "ecr_container_image":   "\033[95m",  # magenta
}

_IMPORT_FLAG = {
    "lambda_function":       "--resource-type lambda",
    "ec2_instance":          "--resource-type ec2",
    "ecr_container_image":   "--resource-type ecr",
}


def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"


def _resource_type(tags: list[str]) -> str:
    for t in tags:
        if t.startswith("resource_type:"):
            return t[len("resource_type:"):]
    return "unknown"


def _account_id(tags: list[str]) -> str:
    for t in tags:
        if t.startswith("aws_account:"):
            return t[len("aws_account:"):]
    return "unknown"


def _divider(width: int, bold: bool = False) -> str:
    line = "─" * width
    return f"{BOLD}{line}{RESET}" if bold else line


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Print a summary of a findings cache file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--cache-file",
        default=DEFAULT_CACHE_FILE,
        metavar="PATH",
        help=f"Path to the findings cache file (default: {DEFAULT_CACHE_FILE}).",
    )
    args = parser.parse_args()

    cache_path = args.cache_file
    if not os.path.exists(cache_path):
        print(f"\n{YELLOW}Cache file '{cache_path}' not found.")
        print(f"Run:  python3 scripts/batch_push.py --source aws --hours 0 --cache-findings{RESET}\n")
        sys.exit(1)

    try:
        data = json.loads(open(cache_path).read())
    except Exception as exc:
        print(f"\n\033[91mFailed to read '{cache_path}': {exc}{RESET}\n")
        sys.exit(1)

    findings = data.get("findings", [])
    cached_at      = data.get("cached_at", "unknown")
    source         = data.get("source", "unknown")
    region         = data.get("region", "unknown")
    lookback_hours = data.get("lookback_hours")
    coverage_hours = data.get("coverage_hours")

    # ── Aggregate ─────────────────────────────────────────────────────────────
    # resource_type → set of unique asset_ids
    assets_by_type:   dict[str, set[str]] = defaultdict(set)
    # resource_type → finding count
    findings_by_type: dict[str, int]      = defaultdict(int)
    # account_id → resource_type → set of asset_ids
    assets_by_acct:   dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    for f in findings:
        tags    = f.get("tags", [])
        rtype   = _resource_type(tags)
        acct    = _account_id(tags)
        aid     = f.get("asset_id", "")
        assets_by_type[rtype].add(aid)
        findings_by_type[rtype] += 1
        assets_by_acct[acct][rtype].add(aid)

    all_types   = sorted(assets_by_type.keys())
    all_accounts = sorted(assets_by_acct.keys())
    multi_account = len(all_accounts) > 1

    total_assets   = sum(len(v) for v in assets_by_type.values())
    total_findings = len(findings)

    # ── Header ────────────────────────────────────────────────────────────────
    W_TYPE   = max(22, max((len(t) for t in all_types), default=0))
    W_ASSETS = 9
    W_FINDS  = 10
    W_FLAG   = max(22, max((len(_IMPORT_FLAG.get(t, "")) for t in all_types), default=0))

    header_width = 4 + W_TYPE + 2 + W_ASSETS + 2 + W_FINDS + 2 + W_FLAG

    print(f"\n{_divider(header_width, bold=True)}")
    print(f"{BOLD}  FINDINGS CACHE SUMMARY{RESET}")
    print(_divider(header_width))
    print(f"  {'File':<16}: {cache_path}")
    print(f"  {'Cached at':<16}: {cached_at}")
    print(f"  {'Source':<16}: {source}  |  region: {region}")
    lh = f"{lookback_hours}h" if lookback_hours is not None else "none"
    ch = f"{coverage_hours}h" if coverage_hours is not None else "default (720h)"
    print(f"  {'Lookback':<16}: {lh}  |  coverage: {ch}")
    print(f"  {'Total findings':<16}: {total_findings}")
    print(f"  {'Unique assets':<16}: {total_assets}")
    if multi_account:
        print(f"  {'AWS accounts':<16}: {', '.join(all_accounts)}")
    print(_divider(header_width, bold=True))

    # ── Summary table ─────────────────────────────────────────────────────────
    col_header = (
        f"  {'RESOURCE TYPE':<{W_TYPE}}  "
        f"{'ASSETS':>{W_ASSETS}}  "
        f"{'FINDINGS':>{W_FINDS}}  "
        f"{'IMPORT FLAG':<{W_FLAG}}"
    )
    print(f"\n{BOLD}{col_header}{RESET}")
    print(_divider(len(col_header)))

    for rtype in all_types:
        n_assets   = len(assets_by_type[rtype])
        n_findings = findings_by_type[rtype]
        flag       = _IMPORT_FLAG.get(rtype, f"(unsupported: {rtype})")
        colour     = _RESOURCE_TYPE_COLOURS.get(rtype, RESET)
        print(
            f"  {_c(colour, rtype):<{W_TYPE + 10}}  "
            f"{n_assets:>{W_ASSETS}}  "
            f"{n_findings:>{W_FINDS}}  "
            f"{_c(DIM, flag)}"
        )

    print(_divider(len(col_header)))
    print(
        f"  {_c(BOLD, 'TOTAL'):<{W_TYPE + 10}}  "
        f"{_c(BOLD, str(total_assets)):>{W_ASSETS + 8}}  "
        f"{_c(BOLD, str(total_findings)):>{W_FINDS + 8}}"
    )
    print(_divider(len(col_header)))

    # ── Per-account breakdown (only when multi-account) ───────────────────────
    if multi_account:
        print(f"\n{BOLD}  PER-ACCOUNT BREAKDOWN{RESET}")
        print(_divider(len(col_header)))

        acct_header = (
            f"  {'ACCOUNT':<14}  {'RESOURCE TYPE':<{W_TYPE}}  "
            f"{'ASSETS':>{W_ASSETS}}  {'FINDINGS':>{W_FINDS}}"
        )
        print(f"{BOLD}{acct_header}{RESET}")
        print(_divider(len(acct_header)))

        for acct in all_accounts:
            first = True
            for rtype in sorted(assets_by_acct[acct].keys()):
                n_assets   = len(assets_by_acct[acct][rtype])
                n_findings = sum(
                    1 for f in findings
                    if _account_id(f.get("tags", [])) == acct
                    and _resource_type(f.get("tags", [])) == rtype
                )
                colour   = _RESOURCE_TYPE_COLOURS.get(rtype, RESET)
                acct_str = acct[-6:] if len(acct) >= 6 else acct
                print(
                    f"  {acct_str if first else '':<14}  "
                    f"{_c(colour, rtype):<{W_TYPE + 10}}  "
                    f"{n_assets:>{W_ASSETS}}  "
                    f"{n_findings:>{W_FINDS}}"
                )
                first = False
        print(_divider(len(acct_header)))

    # ── Import commands ───────────────────────────────────────────────────────
    print(f"\n{BOLD}  IMPORT COMMANDS{RESET}")
    print(_divider(header_width))
    for rtype in all_types:
        flag = _IMPORT_FLAG.get(rtype)
        if not flag:
            continue
        colour = _RESOURCE_TYPE_COLOURS.get(rtype, RESET)
        print(
            f"  {_c(colour, rtype):<{W_TYPE + 10}}  "
            f"python3 scripts/batch_push.py --source aws --from-cache {flag} --clamp-old --yes"
        )
    print(_divider(header_width))
    print()


if __name__ == "__main__":
    main()

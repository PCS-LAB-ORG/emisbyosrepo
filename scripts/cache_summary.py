#!/usr/bin/env python3
"""Summarise a findings cache file before importing.

Reads the JSON cache produced by --cache-findings and prints:
  1. A header with cache metadata (created, region, total findings)
  2. A summary table: resource type × asset count × findings count
  3. A per-account breakdown when multiple AWS accounts are present
  4. A last-scan age table: how soon each asset will be dropped by Cortex
  5. An ECR repo breakdown: images grouped by repository with tags

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
import time
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

DEFAULT_CACHE_FILE = ".byob-findings-cache.json"

# ── ANSI colours ─────────────────────────────────────────────────────────────
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"
MAGENTA = "\033[95m"
RESET  = "\033[0m"

_RESOURCE_TYPE_COLOURS = {
    "lambda_function":       CYAN,
    "ec2_instance":          GREEN,
    "ecr_container_image":   MAGENTA,
}

_IMPORT_FLAG = {
    "lambda_function":       "--resource-type lambda",
    "ec2_instance":          "--resource-type ec2",
    "ecr_container_image":   "--resource-type ecr",
}

THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000

# Age buckets: (label, max_days, colour)
# max_days=None means "> 30 days"
_AGE_BUCKETS = [
    ("< 7 days",    7,   GREEN),
    ("7 – 14 days", 14,  GREEN),
    ("14 – 21 days",21,  YELLOW),
    ("21 – 28 days",28,  YELLOW),
    ("28 – 30 days",30,  RED),
    ("> 30 days",   None, RED),    # already past 30-day Cortex window
]


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


def _tag_val(tags: list[str], prefix: str, default: str = "") -> str:
    for t in tags:
        if t.startswith(prefix):
            return t[len(prefix):]
    return default


def _age_bucket(last_seen_ms: int, now_ms: int) -> tuple[str, str]:
    """Return (bucket_label, colour) for a last_seen_ms value."""
    age_days = (now_ms - last_seen_ms) / (24 * 60 * 60 * 1000)
    for label, max_d, colour in _AGE_BUCKETS:
        if max_d is None or age_days < max_d:
            return label, colour
    return "> 30 days", RED


def _divider(width: int, bold: bool = False) -> str:
    line = "─" * width
    return f"{BOLD}{line}{RESET}" if bold else line


def _print_age_table(findings: list[dict], now_ms: int) -> None:
    """Table: assets grouped by last_seen age bucket → how soon Cortex drops them."""

    # For each unique asset, take the MAX last_seen_ms (most recently seen vuln)
    asset_max_seen: dict[str, int] = {}
    asset_type: dict[str, str] = {}
    for f in findings:
        aid = f.get("asset_id", "")
        lsm = f.get("last_seen_ms", 0)
        if aid not in asset_max_seen or lsm > asset_max_seen[aid]:
            asset_max_seen[aid] = lsm
            asset_type[aid] = _resource_type(f.get("tags", []))

    # Count assets per (bucket, resource_type)
    bucket_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for aid, lsm in asset_max_seen.items():
        label, _ = _age_bucket(lsm, now_ms)
        bucket_counts[label][asset_type[aid]] += 1

    all_rtypes = sorted({asset_type[aid] for aid in asset_max_seen})

    W_BUCKET = max(14, max(len(b[0]) for b in _AGE_BUCKETS))
    W_TYPE   = max(10, max((len(r) for r in all_rtypes), default=0))
    W_CNT    = 8
    W_NOTE   = 32

    header = (
        f"  {'AGE SINCE LAST SCAN':<{W_BUCKET}}  "
        f"{'RESOURCE TYPE':<{W_TYPE}}  "
        f"{'ASSETS':>{W_CNT}}  "
        f"{'CORTEX STATUS':<{W_NOTE}}"
    )
    div = _divider(len(header))

    print(f"\n{_divider(len(header), bold=True)}")
    print(f"{BOLD}  LAST-SCAN AGE  —  how soon Cortex will drop each asset{RESET}")
    print(f"{DIM}  Cortex rejects last_seen > 30 days. Assets in the red zone need --clamp-old.{RESET}")
    print(_divider(len(header), bold=True))
    print(f"{BOLD}{header}{RESET}")
    print(div)

    for label, max_d, colour in _AGE_BUCKETS:
        if label not in bucket_counts:
            continue
        if max_d is None:
            note = _c(RED, "WILL BE REJECTED (>30d) — use --clamp-old")
        elif max_d <= 28:
            days_left = 30 - (max_d - 7 if max_d > 7 else 0)
            note = _c(colour, f"safe — expires in ~{30 - max_d + 7}d if not refreshed")
        else:
            note = _c(YELLOW, "expiring soon — refresh within 1–2 days")

        # one row per resource type in this bucket
        rtypes_in_bucket = sorted(bucket_counts[label].keys())
        for i, rtype in enumerate(rtypes_in_bucket):
            cnt = bucket_counts[label][rtype]
            lbl_str  = _c(colour, label) if i == 0 else " " * len(label)
            note_str = note if i == 0 else ""
            rtype_c  = _c(_RESOURCE_TYPE_COLOURS.get(rtype, RESET), rtype)
            print(
                f"  {lbl_str:<{W_BUCKET + 10}}  "
                f"{rtype_c:<{W_TYPE + 10}}  "
                f"{cnt:>{W_CNT}}  "
                f"{note_str}"
            )

    print(div)


def _drops_in(last_seen_ms: int, now_ms: int) -> tuple[str, str]:
    """Return (label, colour) showing how long until Cortex drops this asset.

    Cortex drops findings whose last_seen is > 30 days old.
    """
    expiry_ms  = last_seen_ms + THIRTY_DAYS_MS
    remaining  = expiry_ms - now_ms   # ms until dropped; negative = already dropped
    if remaining <= 0:
        return _c(RED, "EXPIRED"), RED
    days  = remaining // (24 * 60 * 60 * 1000)
    hours = (remaining % (24 * 60 * 60 * 1000)) // (60 * 60 * 1000)
    label = f"{days}d {hours}h" if days > 0 else f"{hours}h"
    if days >= 7:
        colour = GREEN
    elif days >= 2:
        colour = YELLOW
    else:
        colour = RED
    return _c(colour, label), colour


def _print_ecr_repo_table(findings: list[dict], now_ms: int) -> None:
    """Table: ECR images grouped by repo name, showing tags, digest, and drop time."""

    ecr_findings = [
        f for f in findings
        if "resource_type:ecr_container_image" in f.get("tags", [])
    ]
    if not ecr_findings:
        return

    # Deduplicate by asset_id; track max last_seen_ms per asset
    seen: dict[str, dict] = {}
    asset_max_seen: dict[str, int] = {}
    for f in ecr_findings:
        aid = f.get("asset_id", "")
        lsm = f.get("last_seen_ms", 0)
        if lsm > asset_max_seen.get(aid, 0):
            asset_max_seen[aid] = lsm
        if aid in seen:
            continue
        tags = f.get("tags", [])
        repo  = _tag_val(tags, "ecr_repo_name:") or _tag_val(tags, "ecr_repository:")
        image_tags_raw = _tag_val(tags, "image_tags:")
        image_tags = [t.strip() for t in image_tags_raw.split(",") if t.strip()] if image_tags_raw else []
        digest = _tag_val(tags, "image_hash:", aid)
        short_digest = ("…" + digest[-12:]) if len(digest) > 12 else digest
        seen[aid] = {
            "repo":       repo or "unknown",
            "image_tags": image_tags,
            "digest":     short_digest,
            "aid":        aid,
        }

    # Group by repo
    repos: dict[str, list[dict]] = defaultdict(list)
    for meta in seen.values():
        repos[meta["repo"]].append(meta)

    # Count findings per asset
    findings_per_asset: dict[str, int] = defaultdict(int)
    for f in ecr_findings:
        findings_per_asset[f.get("asset_id", "")] += 1

    # Pre-compute drop labels for width calculation
    drop_labels: dict[str, str] = {}
    for aid in seen:
        lsm = asset_max_seen.get(aid, 0)
        label, _ = _drops_in(lsm, now_ms)
        drop_labels[aid] = label

    W_REPO  = max(16, max((len(r) for r in repos), default=0))
    W_TAG   = min(40, max(12, max(
        (len(", ".join(m["image_tags"]) or "—") for m in seen.values()), default=0,
    )))
    W_DIGEST = 16
    W_IMGS   = 8
    W_CNT    = 10
    W_DROP   = max(12, max(
        (len(v.replace("\033[92m","").replace("\033[93m","").replace("\033[91m","").replace("\033[0m",""))
         for v in drop_labels.values()),
        default=0,
    ))

    col_header = (
        f"  {'REPOSITORY':<{W_REPO}}  "
        f"{'DOCKER TAGS':<{W_TAG}}  "
        f"{'DIGEST (SHORT)':<{W_DIGEST}}  "
        f"{'# IMAGES':>{W_IMGS}}  "
        f"{'FINDINGS':>{W_CNT}}  "
        f"{'EXPIRES IN':<{W_DROP}}"
    )
    div      = _divider(len(col_header))
    bold_div = _divider(len(col_header), bold=True)

    print(f"\n{bold_div}")
    print(f"{BOLD}  ECR IMAGE BREAKDOWN  —  {len(seen)} unique image(s) across {len(repos)} repo(s){RESET}")
    print(bold_div)
    print(f"{BOLD}{col_header}{RESET}")
    print(div)

    for repo in sorted(repos.keys()):
        images = sorted(repos[repo], key=lambda m: m["image_tags"][0] if m["image_tags"] else "")
        repo_total_finds = sum(
            findings_per_asset[aid]
            for aid, meta in seen.items()
            if meta["repo"] == repo
        )
        for i, meta in enumerate(images):
            aid      = meta["aid"]
            repo_str = _c(MAGENTA, repo) if i == 0 else _c(DIM, "  ↳")
            tag_str  = ", ".join(meta["image_tags"])[:W_TAG] or _c(DIM, "—")
            digest   = meta["digest"]
            n_finds  = findings_per_asset.get(aid, 0)
            imgs_str = str(len(images)) if i == 0 else ""
            drop_str = drop_labels.get(aid, "—")
            print(
                f"  {repo_str:<{W_REPO + 10}}  "
                f"{tag_str:<{W_TAG}}  "
                f"{digest:<{W_DIGEST}}  "
                f"{imgs_str:>{W_IMGS}}  "
                f"{n_finds:>{W_CNT}}  "
                f"{drop_str}"
            )
        # Repo subtotal row
        print(
            f"  {_c(DIM, '─' * W_REPO)}  "
            f"{_c(DIM, 'subtotal'):<{W_TAG + 10}}  "
            f"{'':<{W_DIGEST}}  "
            f"{_c(BOLD, str(len(images))):>{W_IMGS + 8}}  "
            f"{_c(BOLD, str(repo_total_finds)):>{W_CNT + 8}}"
        )
        print(div)

    print()


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
    parser.add_argument(
        "--list-ids",
        action="store_true",
        help=(
            "Print one origin_asset_id per line and exit — no summary tables. "
            "Combine with --resource-type to scope to a single type. "
            "Tip: pipe through 'sort | uniq -d' to surface any duplicates."
        ),
    )
    parser.add_argument(
        "--resource-type",
        choices=["ecr", "lambda", "ec2"],
        default=None,
        metavar="TYPE",
        help="When used with --list-ids, restrict output to ecr / lambda / ec2.",
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

    now_ms = int(time.time() * 1000)

    # ── --list-ids: print unique asset IDs and exit ───────────────────────────
    if args.list_ids:
        _TAG_FILTER = {
            "ecr":    "resource_type:ecr_container_image",
            "lambda": "resource_type:lambda_function",
            "ec2":    "resource_type:ec2_instance",
        }
        seen_ids: dict[str, str] = {}   # asset_id -> resource_type label
        for f in findings:
            aid   = f.get("asset_id", "")
            tags  = f.get("tags", [])
            rtype = _resource_type(tags)
            if args.resource_type and _TAG_FILTER.get(args.resource_type) not in tags:
                continue
            seen_ids[aid] = rtype

        total = len(seen_ids)
        # Group by type for the header line
        by_type: dict[str, int] = defaultdict(int)
        for rtype in seen_ids.values():
            by_type[rtype] += 1
        type_summary = "  ".join(f"{rtype}:{cnt}" for rtype, cnt in sorted(by_type.items()))
        print(f"# {total} unique asset ID(s)  [{type_summary}]")
        print(f"# source: {source}  cached_at: {cached_at}")
        print(f"# Tip: pipe through  sort | uniq -d  to find duplicates")
        print()
        for aid in sorted(seen_ids.keys()):
            print(aid)
        sys.exit(0)

    # ── Aggregate ─────────────────────────────────────────────────────────────
    assets_by_type:   dict[str, set[str]] = defaultdict(set)
    findings_by_type: dict[str, int]      = defaultdict(int)
    assets_by_acct:   dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    for f in findings:
        tags    = f.get("tags", [])
        rtype   = _resource_type(tags)
        acct    = _account_id(tags)
        aid     = f.get("asset_id", "")
        assets_by_type[rtype].add(aid)
        findings_by_type[rtype] += 1
        assets_by_acct[acct][rtype].add(aid)

    all_types    = sorted(assets_by_type.keys())
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

    # ── Last-scan age table ───────────────────────────────────────────────────
    _print_age_table(findings, now_ms)

    # ── ECR repo breakdown ────────────────────────────────────────────────────
    _print_ecr_repo_table(findings, now_ms)

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

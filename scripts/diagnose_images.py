#!/usr/bin/env python3
"""Diagnose which ECR image assets are returned at each pipeline stage.

Runs two collections back-to-back — once with the coverage filter OFF and once
with it ON — then prints a side-by-side table so you can see exactly which
images are being dropped and why.

Usage
-----
  # Default: coverage window 720 h (30 days), no lookback limit
  python3 scripts/diagnose_images.py

  # Narrow the coverage window to 3 days
  python3 scripts/diagnose_images.py --coverage-hours 72

  # Restrict to a specific region
  python3 scripts/diagnose_images.py --region eu-west-1

  # Also show images that have NO CVE findings (requires extra list-coverage call)
  python3 scripts/diagnose_images.py --show-no-cve
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── ANSI colours ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"


# ── Tag helpers ──────────────────────────────────────────────────────────────

def _tag_val(tags: list[str], prefix: str, default: str = "—") -> str:
    for t in tags:
        if t.startswith(prefix):
            return t[len(prefix):]
    return default


def _collect_images(coverage_filter: bool, coverage_hours: int, region: str | None) -> dict[str, dict]:
    """Run collect() and return a dict keyed by asset_id with image metadata."""
    import importlib
    # Re-import the module each time so env var changes take effect
    import byob_core.collectors.aws_inspector as mod
    importlib.reload(mod)

    kwargs: dict = {"mode": "scheduled"}
    if region:
        kwargs["region"] = region
    if coverage_filter:
        kwargs["coverage_hours"] = coverage_hours

    findings = mod.collect(**kwargs)

    images: dict[str, dict] = {}
    for f in findings:
        if "resource_type:ecr_container_image" not in f.tags:
            continue
        if f.asset_id in images:
            continue
        repo  = _tag_val(f.tags, "ecr_repo_name:")
        dtags = _tag_val(f.tags, "image_tags:", "")
        tag_list = [t.strip() for t in dtags.split(",") if t.strip()] if dtags else []
        display_tag = "latest" if "latest" in tag_list else (tag_list[0] if tag_list else "—")
        images[f.asset_id] = {
            "repo":      repo,
            "tag":       display_tag,
            "all_tags":  ", ".join(tag_list) if tag_list else "—",
            "digest":    _tag_val(f.tags, "image_hash:"),
            "region":    _tag_val(f.tags, "aws_region:"),
            "account":   _tag_val(f.tags, "aws_account:"),
        }
    return images


def _collect_coverage_ids(coverage_hours: int, region: str | None) -> set[str]:
    """Return all resource IDs from list-coverage regardless of findings."""
    import boto3
    from datetime import datetime, timezone
    region_name = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    client = boto3.client("inspector2", region_name=region_name)
    now = datetime.now(tz=timezone.utc)
    cutoff = datetime.fromtimestamp(now.timestamp() - coverage_hours * 3600, tz=timezone.utc)
    ids: set[str] = set()
    try:
        pag = client.get_paginator("list_coverage")
        for page in pag.paginate(
            filterCriteria={"lastScannedAt": [{"startInclusive": cutoff, "endInclusive": now}]},
            PaginationConfig={"PageSize": 200},
        ):
            for r in page.get("coveredResources", []):
                if r.get("resourceType") == "AWS_ECR_CONTAINER_IMAGE":
                    rid = r.get("resourceId", "")
                    if rid:
                        ids.add(rid)
    except Exception as exc:
        print(f"{YELLOW}  Warning: list_coverage call failed: {exc}{RESET}")
    return ids


def _divider(width: int, char: str = "─") -> str:
    return char * width


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Diagnose ECR image coverage at each pipeline stage.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--coverage-hours", type=int, default=720, metavar="N",
                        help="Coverage filter window in hours (default: 720 = 30 days).")
    parser.add_argument("--region", default=None, metavar="REGION",
                        help="AWS region (default: AWS_DEFAULT_REGION env var).")
    parser.add_argument("--show-no-cve", action="store_true",
                        help="Also list images in coverage but with zero CVE findings.")
    args = parser.parse_args()

    # ── Stage 1: coverage filter OFF ────────────────────────────────────────
    print(f"\n{BOLD}Stage 1 — collecting with coverage filter OFF (all findings) ...{RESET}")
    os.environ["INSPECTOR2_LOOKBACK_HOURS"]  = "0"
    os.environ["INSPECTOR2_COVERAGE_FILTER"] = "false"
    stage1 = _collect_images(coverage_filter=False,
                             coverage_hours=args.coverage_hours,
                             region=args.region)
    print(f"  → {len(stage1)} unique ECR image asset(s) with CVE findings")

    # ── Stage 2: coverage filter ON ─────────────────────────────────────────
    print(f"\n{BOLD}Stage 2 — collecting with coverage filter ON ({args.coverage_hours}h window) ...{RESET}")
    os.environ["INSPECTOR2_COVERAGE_FILTER"] = "true"
    stage2 = _collect_images(coverage_filter=True,
                             coverage_hours=args.coverage_hours,
                             region=args.region)
    print(f"  → {len(stage2)} unique ECR image asset(s) after coverage filter")

    # ── Stage 3 (optional): images in coverage but no CVE findings ──────────
    no_cve_ids: set[str] = set()
    if args.show_no_cve:
        print(f"\n{BOLD}Stage 3 — fetching all covered ECR images (including no-CVE) ...{RESET}")
        all_covered = _collect_coverage_ids(args.coverage_hours, args.region)
        no_cve_ids = all_covered - set(stage1.keys())
        print(f"  → {len(no_cve_ids)} image(s) covered by Inspector2 but have NO CVE findings")

    # ── Build unified table ──────────────────────────────────────────────────
    # Collect all unique asset IDs across both stages + no-cve set
    all_ids = sorted(
        set(stage1) | set(stage2) | no_cve_ids,
        key=lambda aid: (
            stage1.get(aid, stage2.get(aid, {})).get("repo", ""),
            stage1.get(aid, stage2.get(aid, {})).get("tag", ""),
        ),
    )

    dropped    = set(stage1) - set(stage2)
    added      = set(stage2) - set(stage1)   # shouldn't happen but guard anyway
    present    = set(stage1) & set(stage2)

    # Column widths
    W_REPO   = max(20, max((len(stage1.get(i, stage2.get(i, {})).get("repo", "")) for i in all_ids), default=4))
    W_TAG    = max(10, max((len(stage1.get(i, stage2.get(i, {})).get("tag", "")) for i in all_ids), default=3))
    W_DIGEST = 19  # sha256: + 12 chars
    W_STATUS = 14

    HDR = (
        f"  {'REPOSITORY':<{W_REPO}}  {'TAG':<{W_TAG}}  {'DIGEST':<{W_DIGEST}}  "
        f"{'NO-FILTER':<9}  {'COVERAGE':<9}  STATUS"
    )
    DIV = _divider(len(HDR) + 4)

    print(f"\n{BOLD}{DIV}{RESET}")
    print(f"{BOLD}  ECR IMAGE ASSET DIAGNOSTIC TABLE{RESET}")
    print(f"  Coverage window : {args.coverage_hours} h  |  "
          f"Region: {args.region or os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')}")
    print(f"{BOLD}{DIV}{RESET}")
    print(f"{BOLD}{HDR}{RESET}")
    print(DIV)

    for aid in all_ids:
        meta = stage1.get(aid) or stage2.get(aid) or {}
        repo   = meta.get("repo",   "—")
        tag    = meta.get("tag",    "—")
        digest = meta.get("digest", "")
        short  = ("sha256:…" + digest[-12:]) if len(digest) > 19 else digest

        in1 = aid in stage1
        in2 = aid in stage2
        in_no_cve = aid in no_cve_ids

        col1 = _c(GREEN, "✔ yes    ") if in1 else (_c(YELLOW, "— no-cve  ") if in_no_cve else _c(RED, "✘ no     "))
        col2 = _c(GREEN, "✔ yes    ") if in2 else (_c(YELLOW, "— no-cve  ") if in_no_cve else _c(RED, "✘ no     "))

        if in_no_cve:
            status = _c(YELLOW, "NO CVE FINDINGS")
        elif in1 and in2:
            status = _c(GREEN, "OK")
        elif in1 and not in2:
            status = _c(RED, "DROPPED by coverage")
        else:
            status = _c(CYAN, "coverage-only (new?)")

        print(
            f"  {repo:<{W_REPO}}  {tag:<{W_TAG}}  {short:<{W_DIGEST}}  "
            f"{col1}  {col2}  {status}"
        )

    print(DIV)

    # ── Summary ─────────────────────────────────────────────────────────────
    print(f"\n{BOLD}SUMMARY{RESET}")
    print(f"  Total unique image assets with CVE findings : {_c(BOLD, str(len(stage1)))}")
    print(f"  Passed coverage filter ({args.coverage_hours}h)             : {_c(GREEN, str(len(present)))}")
    if dropped:
        print(f"  {_c(RED, f'Dropped by coverage filter               : {len(dropped)}')}")
        print(f"    → These images have CVE findings but Inspector2 has not")
        print(f"      scanned them in the last {args.coverage_hours} h (lastScannedAt is older).")
        print(f"      Re-run with a wider window:  --coverage-hours {args.coverage_hours * 2}")
        print(f"      Or disable the filter:       INSPECTOR2_COVERAGE_FILTER=false")
    if no_cve_ids:
        print(f"  {_c(YELLOW, f'Covered but no CVE findings              : {len(no_cve_ids)}')}")
        print(f"    → Inspector2 scanned these images but found no package vulnerabilities.")
        print(f"      They will not appear in Cortex (nothing to import).")
    if not dropped and not no_cve_ids:
        print(f"  {_c(GREEN, 'No images dropped — all findings are within the coverage window.')}")
    print()


if __name__ == "__main__":
    main()

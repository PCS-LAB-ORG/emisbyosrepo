#!/usr/bin/env python3
"""Poll the status of one or more Cortex BYOS import jobs by job_id.

The Cortex BYOS API processes imports asynchronously.  Use this script to
check the current status and error log of any job after it has been submitted.

Usage
-----
  # Poll a single job
  python3 scripts/job_status.py <job_id>

  # Poll multiple jobs
  python3 scripts/job_status.py <job_id1> <job_id2> <job_id3>

  # Watch a job until it reaches a terminal state (COMPLETED / FAILED)
  python3 scripts/job_status.py --watch <job_id>

  # Watch with a custom poll interval (seconds, default 15)
  python3 scripts/job_status.py --watch --interval 30 <job_id>

Terminal states: COMPLETED  COMPLETED_WITH_ERRORS  FAILED
"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ── ANSI colours ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

_TERMINAL = {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}

_STATUS_COLOUR = {
    "INITIATED":               CYAN,
    "PROCESSING":              CYAN,
    "COMPLETED":               GREEN,
    "COMPLETED_WITH_ERRORS":   YELLOW,
    "FAILED":                  RED,
}


def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"


def _status_str(status: str) -> str:
    return _c(_STATUS_COLOUR.get(status, RESET), status)


def _fetch(base: str, headers: dict, job_id: str) -> dict:
    import requests
    url = f"{base}/public_api/vulnerability-management/v1/external-scans/assets/jobs/{job_id}"
    resp = requests.get(url, headers=headers, timeout=(10, 30))
    if resp.status_code == 404:
        return {"job_id": job_id, "job_status": "NOT_FOUND", "error_log": None}
    resp.raise_for_status()
    return resp.json()


def _print_job(data: dict) -> None:
    job_id    = data.get("job_id", "—")
    status    = data.get("job_status", "UNKNOWN")
    created   = data.get("created_timestamp", "—")
    updated   = data.get("last_updated", "—")
    error_log = data.get("error_log")

    print(f"\n  {'Job ID':<16}: {BOLD}{job_id}{RESET}")
    print(f"  {'Status':<16}: {_status_str(status)}")
    print(f"  {'Created':<16}: {created}")
    print(f"  {'Last updated':<16}: {updated}")

    if error_log:
        print(f"  {'Error log':<16}:")
        # error_log may be a raw string or JSON; print it readable
        if isinstance(error_log, list):
            for line in error_log:
                print(f"    {_c(RED, str(line))}")
        else:
            for line in str(error_log).splitlines():
                print(f"    {_c(RED, line)}")
    else:
        print(f"  {'Error log':<16}: {_c(GREEN, 'none')}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Poll Cortex BYOS import job status.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("job_ids", nargs="+", metavar="JOB_ID",
                        help="One or more job UUIDs returned by the BYOS submit endpoint.")
    parser.add_argument("--watch", action="store_true",
                        help="Keep polling until all jobs reach a terminal state.")
    parser.add_argument("--interval", type=int, default=15, metavar="SECS",
                        help="Seconds between polls when --watch is set (default: 15).")
    parser.add_argument("--cortex-fqdn",    default=None, metavar="FQDN")
    parser.add_argument("--cortex-api-key", default=None, metavar="KEY")
    parser.add_argument("--cortex-auth-id", default=None, metavar="ID")
    args = parser.parse_args()

    if args.cortex_fqdn:
        os.environ["CORTEX_FQDN"] = args.cortex_fqdn
    if args.cortex_api_key:
        os.environ["CORTEX_API_KEY"] = args.cortex_api_key
    if args.cortex_auth_id:
        os.environ["CORTEX_AUTH_ID"] = args.cortex_auth_id

    from byob_core import secrets                                      # noqa: PLC0415
    from byob_core.cortex_client import _headers                       # noqa: PLC0415

    creds   = secrets.load_credentials()
    fqdn    = creds.cortex_fqdn.removeprefix("https://").removeprefix("http://").rstrip("/")
    base    = f"https://{fqdn}"
    headers = _headers(creds)

    divider = "─" * 64

    if not args.watch:
        # ── Single poll ─────────────────────────────────────────────────────
        print(f"\n{BOLD}{divider}{RESET}")
        print(f"{BOLD}  BYOS JOB STATUS  —  {len(args.job_ids)} job(s){RESET}")
        print(f"{BOLD}{divider}{RESET}")
        any_errors = False
        for job_id in args.job_ids:
            try:
                data = _fetch(base, headers, job_id)
                _print_job(data)
                if data.get("job_status") in ("FAILED", "COMPLETED_WITH_ERRORS", "NOT_FOUND"):
                    any_errors = True
            except Exception as exc:
                print(f"\n  {_c(RED, f'Error fetching job {job_id}: {exc}')}")
                any_errors = True
        print(f"\n{divider}\n")
        sys.exit(1 if any_errors else 0)

    # ── Watch mode ──────────────────────────────────────────────────────────
    pending = list(args.job_ids)
    poll = 0
    while pending:
        poll += 1
        ts = time.strftime("%H:%M:%S")
        print(f"\n{BOLD}{divider}{RESET}")
        print(f"{BOLD}  POLL #{poll}  {ts}  —  {len(pending)} job(s) pending{RESET}")
        print(f"{BOLD}{divider}{RESET}")

        still_pending = []
        for job_id in pending:
            try:
                data = _fetch(base, headers, job_id)
                _print_job(data)
                status = data.get("job_status", "UNKNOWN")
                if status not in _TERMINAL:
                    still_pending.append(job_id)
                else:
                    print(f"  {_c(GREEN, '✔ reached terminal state')}")
            except Exception as exc:
                print(f"\n  {_c(RED, f'Error fetching {job_id}: {exc}')}")
                still_pending.append(job_id)

        pending = still_pending
        if pending:
            print(f"\n  {len(pending)} job(s) still in progress — next poll in {args.interval}s ...")
            time.sleep(args.interval)

    print(f"\n{BOLD}{divider}{RESET}")
    print(f"{BOLD}{_c(GREEN, '  All jobs reached terminal state.')}{RESET}")
    print(f"{BOLD}{divider}{RESET}\n")


if __name__ == "__main__":
    main()

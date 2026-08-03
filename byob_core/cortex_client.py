from __future__ import annotations
import logging
import time
import requests
from tenacity import retry, retry_if_not_exception_type, stop_after_attempt, wait_exponential
from byob_core.models import Credentials, JobResult

logger = logging.getLogger(__name__)

SUBMIT_PATH = "/public_api/vulnerability-management/v1/external-scans/assets"
JOB_PATH = "/public_api/vulnerability-management/v1/external-scans/assets/jobs/{job_id}"
CONNECT_TIMEOUT_SEC = 10
# Large batches can take several minutes to upload on a slow connection.
SUBMIT_TIMEOUT_SEC = 300   # 5 minutes
POLL_TIMEOUT_SEC = 30

# 429 rate-limit back-off sequence: wait 30 s, then 60 s, then give up.
_RATE_LIMIT_WAITS = (30, 60)


class CortexValidationError(Exception):
    pass


class CortexJobFailedError(Exception):
    pass


class CortexRateLimitError(Exception):
    pass


def _headers(credentials: Credentials) -> dict:
    return {
        "Authorization": credentials.cortex_api_key,
        "x-xdr-auth-id": credentials.cortex_auth_id,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _post_with_rate_limit_retry(url: str, headers: dict, payload: dict) -> requests.Response:
    """POST with explicit 429 handling: wait 30 s, retry; wait 60 s, retry; then raise."""
    waits = iter(_RATE_LIMIT_WAITS)
    attempt = 0
    while True:
        attempt += 1
        resp = requests.post(url, json=payload, headers=headers,
                             timeout=(CONNECT_TIMEOUT_SEC, SUBMIT_TIMEOUT_SEC))
        if resp.status_code != 429:
            return resp
        wait = next(waits, None)
        if wait is None:
            logger.error(
                "Rate limited (429) on all %d attempts — giving up.",
                attempt,
            )
            raise CortexRateLimitError(
                f"Cortex returned 429 after {attempt} attempt(s); "
                "reduce posting frequency or contact Palo Alto support."
            )
        retry_after = int(resp.headers.get("Retry-After", wait))
        actual_wait = max(wait, retry_after)
        logger.warning(
            "Rate limited (429) on attempt %d — waiting %d s before retry ...",
            attempt, actual_wait,
        )
        time.sleep(actual_wait)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=2, min=5, max=30),
    reraise=True,
    retry=retry_if_not_exception_type((CortexValidationError, CortexRateLimitError)),
)
def _submit_one(base: str, headers: dict, payload: dict) -> JobResult:
    """POST a single batch and return a JobResult with the initial status from the response."""
    n_assets = len(payload.get("assets", []))
    n_vulns = sum(len(a.get("vulnerabilities", [])) for a in payload.get("assets", []))
    logger.info("POST %s%s  [%d assets, %d vulns]", base, SUBMIT_PATH, n_assets, n_vulns)

    resp = _post_with_rate_limit_retry(f"{base}{SUBMIT_PATH}", headers, payload)

    if resp.status_code == 422:
        errors = resp.json().get("detail", [])
        logger.error("Cortex validation error: %s", errors)
        raise CortexValidationError(f"Payload validation failed: {errors}")

    resp.raise_for_status()
    data = resp.json()
    job_id = data["job_id"]
    assets_count = data.get("assets_count", 0)
    vulnerabilities_count = data.get("vulnerabilities_count", 0)
    logger.info("Accepted | job_id=%s assets=%d vulns=%d", job_id, assets_count, vulnerabilities_count)
    return JobResult(job_id=job_id, status="SUBMITTED",
                     assets_count=assets_count, vulnerabilities_count=vulnerabilities_count)


def _check_status(base: str, headers: dict, job_id: str) -> str:
    """Single status GET for a job — returns the job_status string."""
    resp = requests.get(
        f"{base}{JOB_PATH.format(job_id=job_id)}",
        headers=headers,
        timeout=(CONNECT_TIMEOUT_SEC, POLL_TIMEOUT_SEC),
    )
    resp.raise_for_status()
    return resp.json().get("job_status", "UNKNOWN")


def submit_all(batches: list[dict], credentials: Credentials) -> list[JobResult]:
    """Submit all batches, then do a single status check on every job and log a summary."""
    fqdn = credentials.cortex_fqdn.removeprefix("https://").removeprefix("http://").rstrip("/")
    base = f"https://{fqdn}"
    headers = _headers(credentials)

    # submit all batches
    results: list[JobResult] = []
    for i, batch in enumerate(batches):
        logger.info("Submitting batch %d/%d ...", i + 1, len(batches))
        result = _submit_one(base, headers, batch)
        results.append(result)

    # single status pass after all POSTs are done
    logger.info("All batches submitted — checking job statuses ...")
    for result in results:
        try:
            status = _check_status(base, headers, result.job_id)
            result.status = status
        except Exception as exc:
            logger.warning("Could not fetch status for job %s: %s", result.job_id, exc)
            result.status = "UNKNOWN"

    # summary
    logger.info("─── Job summary ───────────────────────────────")
    for r in results:
        logger.info("  job_id=%-40s  status=%s  assets=%d  vulns=%d",
                    r.job_id, r.status, r.assets_count, r.vulnerabilities_count)
    logger.info("───────────────────────────────────────────────")
    return results

import responses as resp
import pytest
from byob_core.models import Credentials
from byob_core.cortex_client import (
    submit_all,
    CortexValidationError,
    CortexRateLimitError,
    _post_with_rate_limit_retry,
    SUBMIT_PATH,
)

CREDS = Credentials(
    cortex_api_key="testkey",
    cortex_auth_id="7",
    cortex_fqdn="api-test.xdr.us.paloaltonetworks.com",
)
BASE_URL = "https://api-test.xdr.us.paloaltonetworks.com"
SUBMIT_URL = f"{BASE_URL}{SUBMIT_PATH}"
JOB_URL = f"{BASE_URL}/public_api/vulnerability-management/v1/external-scans/assets/jobs/job-abc"

PAYLOAD = {"vendor": "AWS", "product": "Inspector2", "assets": []}


# ---------------------------------------------------------------------------
# submit_all — happy path
# ---------------------------------------------------------------------------

@resp.activate
def test_submit_all_single_batch_accepted(monkeypatch):
    monkeypatch.setattr("byob_core.cortex_client.time.sleep", lambda _: None)
    resp.add(resp.POST, SUBMIT_URL, json={
        "job_id": "job-abc", "assets_count": 1, "vulnerabilities_count": 2,
    }, status=200)
    resp.add(resp.GET, JOB_URL, json={"job_status": "COMPLETED"}, status=200)

    results = submit_all([PAYLOAD], CREDS)
    assert len(results) == 1
    assert results[0].job_id == "job-abc"
    assert results[0].assets_count == 1


@resp.activate
def test_submit_all_multiple_batches(monkeypatch):
    monkeypatch.setattr("byob_core.cortex_client.time.sleep", lambda _: None)
    for i in range(3):
        resp.add(resp.POST, SUBMIT_URL, json={
            "job_id": f"job-{i}", "assets_count": 1, "vulnerabilities_count": 1,
        }, status=200)
    for i in range(3):
        resp.add(resp.GET,
                 f"{BASE_URL}/public_api/vulnerability-management/v1/external-scans/assets/jobs/job-{i}",
                 json={"job_status": "COMPLETED"}, status=200)

    results = submit_all([PAYLOAD, PAYLOAD, PAYLOAD], CREDS)
    assert len(results) == 3
    assert all(r.status == "COMPLETED" for r in results)


# ---------------------------------------------------------------------------
# 422 validation error
# ---------------------------------------------------------------------------

@resp.activate
def test_submit_all_raises_on_422(monkeypatch):
    monkeypatch.setattr("byob_core.cortex_client.time.sleep", lambda _: None)
    resp.add(resp.POST, SUBMIT_URL, json={
        "detail": [{"loc": ["assets", 0], "msg": "field required", "type": "value_error"}]
    }, status=422)

    with pytest.raises(CortexValidationError, match="Payload validation failed"):
        submit_all([PAYLOAD], CREDS)


# ---------------------------------------------------------------------------
# 429 rate-limit handling via _post_with_rate_limit_retry
# ---------------------------------------------------------------------------

@resp.activate
def test_429_retries_after_30s_then_succeeds(monkeypatch):
    slept = []
    monkeypatch.setattr("byob_core.cortex_client.time.sleep", slept.append)

    resp.add(resp.POST, SUBMIT_URL, status=429)          # attempt 1 → wait 30 s
    resp.add(resp.POST, SUBMIT_URL, json={               # attempt 2 → success
        "job_id": "job-abc", "assets_count": 1, "vulnerabilities_count": 1,
    }, status=200)

    headers = {"Authorization": "k", "x-xdr-auth-id": "7",
               "Content-Type": "application/json", "Accept": "application/json"}
    response = _post_with_rate_limit_retry(SUBMIT_URL, headers, PAYLOAD)

    assert response.status_code == 200
    assert slept == [30]


@resp.activate
def test_429_retries_after_30s_then_60s_then_succeeds(monkeypatch):
    slept = []
    monkeypatch.setattr("byob_core.cortex_client.time.sleep", slept.append)

    resp.add(resp.POST, SUBMIT_URL, status=429)          # attempt 1 → wait 30 s
    resp.add(resp.POST, SUBMIT_URL, status=429)          # attempt 2 → wait 60 s
    resp.add(resp.POST, SUBMIT_URL, json={               # attempt 3 → success
        "job_id": "job-abc", "assets_count": 1, "vulnerabilities_count": 1,
    }, status=200)

    headers = {"Authorization": "k", "x-xdr-auth-id": "7",
               "Content-Type": "application/json", "Accept": "application/json"}
    response = _post_with_rate_limit_retry(SUBMIT_URL, headers, PAYLOAD)

    assert response.status_code == 200
    assert slept == [30, 60]


@resp.activate
def test_429_retries_30s_60s_300s_then_succeeds(monkeypatch):
    slept = []
    monkeypatch.setattr("byob_core.cortex_client.time.sleep", slept.append)

    resp.add(resp.POST, SUBMIT_URL, status=429)   # attempt 1 → wait 30 s
    resp.add(resp.POST, SUBMIT_URL, status=429)   # attempt 2 → wait 60 s
    resp.add(resp.POST, SUBMIT_URL, status=429)   # attempt 3 → wait 300 s
    resp.add(resp.POST, SUBMIT_URL, json={        # attempt 4 → success
        "job_id": "job-abc", "assets_count": 1, "vulnerabilities_count": 1,
    }, status=200)

    headers = {"Authorization": "k", "x-xdr-auth-id": "7",
               "Content-Type": "application/json", "Accept": "application/json"}
    response = _post_with_rate_limit_retry(SUBMIT_URL, headers, PAYLOAD)

    assert response.status_code == 200
    assert slept == [30, 60, 300]


@resp.activate
def test_429_raises_after_all_retries_exhausted(monkeypatch):
    monkeypatch.setattr("byob_core.cortex_client.time.sleep", lambda _: None)

    resp.add(resp.POST, SUBMIT_URL, status=429)   # attempt 1
    resp.add(resp.POST, SUBMIT_URL, status=429)   # attempt 2 (after 30 s)
    resp.add(resp.POST, SUBMIT_URL, status=429)   # attempt 3 (after 60 s)
    resp.add(resp.POST, SUBMIT_URL, status=429)   # attempt 4 (after 300 s) → give up

    headers = {"Authorization": "k", "x-xdr-auth-id": "7",
               "Content-Type": "application/json", "Accept": "application/json"}
    with pytest.raises(CortexRateLimitError):
        _post_with_rate_limit_retry(SUBMIT_URL, headers, PAYLOAD)


@resp.activate
def test_429_honours_retry_after_header(monkeypatch):
    """Retry-After header value is used when it exceeds the default wait."""
    slept = []
    monkeypatch.setattr("byob_core.cortex_client.time.sleep", slept.append)

    resp.add(resp.POST, SUBMIT_URL,
             headers={"Retry-After": "45"}, status=429)  # server asks for 45 s
    resp.add(resp.POST, SUBMIT_URL, json={
        "job_id": "job-abc", "assets_count": 1, "vulnerabilities_count": 1,
    }, status=200)

    headers = {"Authorization": "k", "x-xdr-auth-id": "7",
               "Content-Type": "application/json", "Accept": "application/json"}
    _post_with_rate_limit_retry(SUBMIT_URL, headers, PAYLOAD)

    assert slept == [45]   # used Retry-After (45) instead of default (30)


@resp.activate
def test_429_retry_after_unix_timestamp_is_converted(monkeypatch):
    """Retry-After as a Unix timestamp is converted to a relative delay and capped at 120 s."""
    import time as time_mod
    slept = []
    monkeypatch.setattr("byob_core.cortex_client.time.sleep", slept.append)
    # Cortex returns a Unix timestamp ~10 hours in the future (reproduces the reported bug)
    future_ts = int(time_mod.time()) + 37917

    resp.add(resp.POST, SUBMIT_URL,
             headers={"Retry-After": str(future_ts)}, status=429)
    resp.add(resp.POST, SUBMIT_URL, json={
        "job_id": "job-abc", "assets_count": 1, "vulnerabilities_count": 1,
    }, status=200)

    headers = {"Authorization": "k", "x-xdr-auth-id": "7",
               "Content-Type": "application/json", "Accept": "application/json"}
    _post_with_rate_limit_retry(SUBMIT_URL, headers, PAYLOAD)

    # Must have slept exactly once and never more than the 120-second cap
    assert len(slept) == 1
    assert slept[0] <= 120


# ---------------------------------------------------------------------------
# 429 propagates through submit_all as CortexRateLimitError
# ---------------------------------------------------------------------------

@resp.activate
def test_submit_all_raises_rate_limit_error(monkeypatch):
    monkeypatch.setattr("byob_core.cortex_client.time.sleep", lambda _: None)

    # Exhaust all 3 waits (4 attempts total)
    resp.add(resp.POST, SUBMIT_URL, status=429)
    resp.add(resp.POST, SUBMIT_URL, status=429)
    resp.add(resp.POST, SUBMIT_URL, status=429)
    resp.add(resp.POST, SUBMIT_URL, status=429)

    with pytest.raises(CortexRateLimitError):
        submit_all([PAYLOAD], CREDS)

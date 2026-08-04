"""Unit tests for byob_core/collectors/tenable_vm.py."""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch, call

import pytest

from byob_core.collectors import tenable_vm
from byob_core.collectors.tenable_vm import (
    _build_cloud_meta,
    _coerce_list,
    _parse_chunk,
    _parse_severities,
    _to_raw_finding,
    _wait_for_export,
)
from byob_core.models import RawFinding


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _vuln_record(
    *,
    asset_uuid: str = "asset-uuid-1",
    hostname: str = "web01.example.com",
    ipv4: list | None = None,
    fqdn: list | None = None,
    os: str = "Amazon Linux 2",
    severity: str = "high",
    state: str = "OPEN",
    cve_list: list | None = None,
    plugin_id: int = 99999,
    plugin_name: str = "Test Plugin",
    description: str = "A test vulnerability.",
    cvss3: float = 8.5,
    last_found: int | None = None,
    output: str = "Plugin output text",
    aws_ec2_instance_id: str = "i-0abc123",
) -> dict:
    return {
        "asset": {
            "uuid": asset_uuid,
            "hostname": hostname,
            "ipv4": ipv4 or ["10.0.0.1"],
            "ipv6": [],
            "fqdn": fqdn or ["web01.example.com"],
            "operating_system": os,
            "tags": [{"key": "env", "value": "production"}],
            "aws_ec2_instance_id": aws_ec2_instance_id,
            "aws_region": "us-east-1",
        },
        "plugin": {
            "id": plugin_id,
            "name": plugin_name,
            "description": description,
            "cve": cve_list if cve_list is not None else ["CVE-2021-44228"],
            "cvss3_base_score": cvss3,
            "solution": "Upgrade immediately",
            "cvss3_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        },
        "severity": severity,
        "state": state,
        "last_found": last_found or int(time.time()) - 3600,
        "output": output,
    }


# ---------------------------------------------------------------------------
# _parse_severities
# ---------------------------------------------------------------------------

def test_parse_severities_default_when_none():
    assert _parse_severities(None) == ["medium", "high", "critical"]


def test_parse_severities_uppercase_normalised():
    assert _parse_severities("HIGH,CRITICAL") == ["high", "critical"]


def test_parse_severities_ignores_unknown():
    result = _parse_severities("HIGH,BOGUS,CRITICAL")
    assert result == ["high", "critical"]


def test_parse_severities_all_unknown_returns_default():
    result = _parse_severities("BOGUS")
    assert result == ["medium", "high", "critical"]


def test_parse_severities_all_levels():
    result = _parse_severities("info,low,medium,high,critical")
    assert result == ["info", "low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# _coerce_list
# ---------------------------------------------------------------------------

def test_coerce_list_from_list():
    assert _coerce_list(["10.0.0.1", "10.0.0.2"]) == ["10.0.0.1", "10.0.0.2"]


def test_coerce_list_from_string():
    assert _coerce_list("10.0.0.1") == ["10.0.0.1"]


def test_coerce_list_none():
    assert _coerce_list(None) == []


def test_coerce_list_empty_list():
    assert _coerce_list([]) == []


# ---------------------------------------------------------------------------
# _to_raw_finding
# ---------------------------------------------------------------------------

def test_to_raw_finding_basic():
    record = _vuln_record()
    plugin = record["plugin"]
    rf = _to_raw_finding(record, plugin, "CVE-2021-44228")

    assert rf is not None
    assert rf.asset_id == "asset-uuid-1"
    assert rf.asset_name == "web01.example.com"
    assert rf.cve_id == "CVE-2021-44228"
    assert rf.severity == "HIGH"
    assert rf.source == "tenable_vm"
    assert rf.ipv4 == ["10.0.0.1"]
    assert rf.os_name == "Amazon Linux 2"


def test_to_raw_finding_severity_mapping():
    for tenable_sev, expected in [
        ("critical", "CRITICAL"),
        ("high", "HIGH"),
        ("medium", "MEDIUM"),
        ("low", "LOW"),
        ("info", "INFORMATIONAL"),
    ]:
        record = _vuln_record(severity=tenable_sev)
        rf = _to_raw_finding(record, record["plugin"], "CVE-2021-44228")
        assert rf.severity == expected, f"Failed for severity={tenable_sev}"


def test_to_raw_finding_returns_none_when_no_asset_uuid():
    record = _vuln_record()
    record["asset"]["uuid"] = ""
    record["asset"]["id"] = ""
    rf = _to_raw_finding(record, record["plugin"], "CVE-2021-44228")
    assert rf is None


def test_to_raw_finding_last_seen_ms_from_last_found():
    ts = 1706745600
    record = _vuln_record(last_found=ts)
    rf = _to_raw_finding(record, record["plugin"], "CVE-2021-44228")
    assert rf.last_seen_ms == ts * 1000


def test_to_raw_finding_description_truncated():
    record = _vuln_record(description="x" * 2000)
    rf = _to_raw_finding(record, record["plugin"], "CVE-2021-44228")
    assert len(rf.description) <= 1000


def test_to_raw_finding_evidence_contains_plugin_id_and_cvss():
    record = _vuln_record(plugin_id=12345, cvss3=9.8)
    rf = _to_raw_finding(record, record["plugin"], "CVE-2021-44228")
    assert "12345" in rf.evidence
    assert "9.8" in rf.evidence


def test_to_raw_finding_cloud_meta_in_tags():
    record = _vuln_record(aws_ec2_instance_id="i-0abc123")
    rf = _to_raw_finding(record, record["plugin"], "CVE-2021-44228")
    assert "cloud:tenable_vm" in rf.tags
    assert "instance_id:i-0abc123" in rf.tags
    assert "aws_region:us-east-1" in rf.tags


def test_to_raw_finding_user_tags_included():
    record = _vuln_record()
    record["asset"]["tags"] = [{"key": "Department", "value": "Engineering"}]
    rf = _to_raw_finding(record, record["plugin"], "CVE-2021-44228")
    assert "Department:Engineering" in rf.tags


# ---------------------------------------------------------------------------
# _parse_chunk
# ---------------------------------------------------------------------------

def test_parse_chunk_skips_records_with_no_cve():
    records = [
        _vuln_record(cve_list=[]),
        _vuln_record(cve_list=["CVE-2021-44228"]),
        _vuln_record(cve_list=None),  # uses default which has one CVE
    ]
    records[2]["plugin"]["cve"] = []  # override the default
    findings, skipped = _parse_chunk(records)
    assert skipped == 2
    assert len(findings) == 1


def test_parse_chunk_one_finding_per_cve():
    """A plugin with 3 CVEs should produce 3 RawFinding objects."""
    record = _vuln_record(cve_list=["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"])
    findings, skipped = _parse_chunk([record])
    assert skipped == 0
    assert len(findings) == 3
    cve_ids = {f.cve_id for f in findings}
    assert cve_ids == {"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"}


def test_parse_chunk_all_share_same_asset():
    """All findings from the same record should share the same asset_id."""
    record = _vuln_record(
        asset_uuid="shared-uuid",
        cve_list=["CVE-2021-44228", "CVE-2021-45046"],
    )
    findings, _ = _parse_chunk([record])
    assert all(f.asset_id == "shared-uuid" for f in findings)


# ---------------------------------------------------------------------------
# _build_cloud_meta
# ---------------------------------------------------------------------------

def test_build_cloud_meta_aws():
    asset = {
        "aws_ec2_instance_id": "i-0abc",
        "aws_ec2_instance_type": "t3.medium",
        "aws_region": "us-west-2",
        "aws_availability_zone": "us-west-2a",
        "aws_owner_id": "123456789012",
    }
    meta = _build_cloud_meta(asset)
    assert "cloud:tenable_vm" in meta
    assert "instance_id:i-0abc" in meta
    assert "instance_type:t3.medium" in meta
    assert "aws_region:us-west-2" in meta
    assert "aws_account:123456789012" in meta


def test_build_cloud_meta_azure():
    asset = {
        "azure_vm_id": "azure-vm-1",
        "azure_resource_group": "my-rg",
        "azure_subscription_id": "sub-123",
    }
    meta = _build_cloud_meta(asset)
    assert "azure_vm_id:azure-vm-1" in meta
    assert "azure_resource_group:my-rg" in meta


def test_build_cloud_meta_empty_asset():
    meta = _build_cloud_meta({})
    assert meta == ["cloud:tenable_vm"]


# ---------------------------------------------------------------------------
# _wait_for_export — polling logic
# ---------------------------------------------------------------------------

def _status_response(status: str, chunks: list[int] | None = None) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {
        "status": status,
        "chunks_available": chunks or [],
    }
    return resp


def test_wait_for_export_returns_chunks_on_finished():
    headers = {}
    responses = [
        _status_response("PROCESSING"),
        _status_response("PROCESSING"),
        _status_response("FINISHED", [1, 2, 3]),
    ]
    with patch("byob_core.collectors.tenable_vm.requests.get", side_effect=responses), \
         patch("byob_core.collectors.tenable_vm.time.sleep"):
        chunks = _wait_for_export(headers, "uuid-1")
    assert chunks == [1, 2, 3]


def test_wait_for_export_raises_on_error_status():
    headers = {}
    responses = [
        _status_response("ERROR"),
    ]
    with patch("byob_core.collectors.tenable_vm.requests.get", side_effect=responses), \
         patch("byob_core.collectors.tenable_vm.time.sleep"):
        with pytest.raises(RuntimeError, match="status=ERROR"):
            _wait_for_export(headers, "uuid-1")


def test_wait_for_export_raises_on_timeout(monkeypatch):
    monkeypatch.setattr(tenable_vm, "_POLL_MAX_ATTEMPTS", 3)
    headers = {}
    responses = [_status_response("PROCESSING")] * 3
    with patch("byob_core.collectors.tenable_vm.requests.get", side_effect=responses), \
         patch("byob_core.collectors.tenable_vm.time.sleep"):
        with pytest.raises(TimeoutError):
            _wait_for_export(headers, "uuid-1")


# ---------------------------------------------------------------------------
# collect() — end-to-end with mocked HTTP
# ---------------------------------------------------------------------------

def _mock_post_response(export_uuid: str = "test-export-uuid") -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"export_uuid": export_uuid}
    return resp


def _mock_status_finished(chunks: list[int]) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"status": "FINISHED", "chunks_available": chunks}
    return resp


def _mock_chunk_response(records: list[dict]) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = records
    return resp


def test_collect_returns_findings(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "access-key")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "secret-key")
    monkeypatch.setenv("TENABLE_LOOKBACK_HOURS", "720")

    record = _vuln_record(severity="critical")

    with patch("byob_core.collectors.tenable_vm.requests.post", return_value=_mock_post_response()), \
         patch("byob_core.collectors.tenable_vm.requests.get", side_effect=[
             _mock_status_finished([1]),
             _mock_chunk_response([record]),
         ]), \
         patch("byob_core.collectors.tenable_vm.time.sleep"):
        findings = tenable_vm.collect(mode="scheduled")

    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2021-44228"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].source == "tenable_vm"


def test_collect_sorted_by_severity_descending(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "k")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "s")
    monkeypatch.setenv("TENABLE_LOOKBACK_HOURS", "720")

    records = [
        _vuln_record(asset_uuid="a1", severity="low"),
        _vuln_record(asset_uuid="a2", severity="critical"),
        _vuln_record(asset_uuid="a3", severity="medium"),
    ]

    with patch("byob_core.collectors.tenable_vm.requests.post", return_value=_mock_post_response()), \
         patch("byob_core.collectors.tenable_vm.requests.get", side_effect=[
             _mock_status_finished([1]),
             _mock_chunk_response(records),
         ]), \
         patch("byob_core.collectors.tenable_vm.time.sleep"):
        findings = tenable_vm.collect()

    severities = [f.severity for f in findings]
    assert severities == ["CRITICAL", "MEDIUM", "LOW"]


def test_collect_reuses_job_on_409(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "k")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "s")
    monkeypatch.setenv("TENABLE_LOOKBACK_HOURS", "0")

    conflict_resp = MagicMock()
    conflict_resp.status_code = 409
    conflict_resp.raise_for_status = MagicMock()
    conflict_resp.json.return_value = {
        "active_job_id": "existing-uuid",
        "failure_reason": "duplicate",
    }

    record = _vuln_record()
    with patch("byob_core.collectors.tenable_vm.requests.post", return_value=conflict_resp), \
         patch("byob_core.collectors.tenable_vm.requests.get", side_effect=[
             _mock_status_finished([1]),
             _mock_chunk_response([record]),
         ]), \
         patch("byob_core.collectors.tenable_vm.time.sleep"):
        findings = tenable_vm.collect()

    assert len(findings) == 1


def test_collect_raises_when_credentials_missing(monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)

    with pytest.raises(EnvironmentError, match="TENABLE_ACCESS_KEY"):
        tenable_vm.collect()


def test_collect_since_filter_set_for_delta(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "k")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "s")
    monkeypatch.setenv("TENABLE_LOOKBACK_HOURS", "12")

    captured_body: dict = {}

    def fake_post(url, headers, json, timeout):
        captured_body.update(json)
        return _mock_post_response()

    with patch("byob_core.collectors.tenable_vm.requests.post", side_effect=fake_post), \
         patch("byob_core.collectors.tenable_vm.requests.get", side_effect=[
             _mock_status_finished([]),
         ]), \
         patch("byob_core.collectors.tenable_vm.time.sleep"):
        tenable_vm.collect()

    assert "since" in captured_body["filters"]
    since_ts = captured_body["filters"]["since"]
    now = int(time.time())
    assert abs(since_ts - (now - 12 * 3600)) < 5


def test_collect_no_since_filter_when_hours_zero(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "k")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "s")
    monkeypatch.setenv("TENABLE_LOOKBACK_HOURS", "0")

    captured_body: dict = {}

    def fake_post(url, headers, json, timeout):
        captured_body.update(json)
        return _mock_post_response()

    with patch("byob_core.collectors.tenable_vm.requests.post", side_effect=fake_post), \
         patch("byob_core.collectors.tenable_vm.requests.get", side_effect=[
             _mock_status_finished([]),
         ]), \
         patch("byob_core.collectors.tenable_vm.time.sleep"):
        tenable_vm.collect()

    assert "since" not in captured_body.get("filters", {})

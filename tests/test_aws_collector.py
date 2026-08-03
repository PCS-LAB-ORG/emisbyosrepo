import datetime
import os
from unittest.mock import patch, MagicMock

import pytest

from byob_core.collectors.aws_inspector import collect, _parse_env_list
from byob_core.models import RawFinding

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
def _make_ec2_finding(severity: str = "CRITICAL") -> dict:
    return {
        "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/abc",
        "severity": severity,
        "updatedAt": datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        "description": "A vulnerability",
        "resources": [{
            "id": "i-0abc123def456",
            "type": "AWS_EC2_INSTANCE",
            "region": "us-east-1",
            "providerAccountId": "123456789012",
            "tags": {"Name": "web-1", "env": "prod"},
            "details": {
                "awsEc2Instance": {
                    "ipV4Addresses": ["10.0.0.1"],
                    "ipV6Addresses": [],
                    "platform": "AMAZON_LINUX_2",
                    "type": "t3.medium",
                    "vpcId": "vpc-abc",
                    "subnetId": "subnet-abc",
                }
            },
        }],
        # Inspector2 API uses "packageVulnerabilityDetails" (not "packageVulnerability")
        "packageVulnerabilityDetails": {
            "vulnerabilityId": "CVE-2024-12345",
            "cvss": [{"baseScore": 9.8}],
        },
        "inspectorScore": 9.8,
        "remediation": {"recommendation": {"text": "Patch now"}},
    }


def _make_ecr_finding(severity: str = "HIGH") -> dict:
    return {
        "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/ecr-xyz",
        "severity": severity,
        "updatedAt": datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        "description": "Container vuln",
        "resources": [{
            "id": "sha256:abcd1234",
            "type": "AWS_ECR_CONTAINER_IMAGE",
            "region": "us-east-1",
            "providerAccountId": "123456789012",
            "tags": {"team": "platform"},
            "details": {
                "awsEcrContainerImage": {
                    "repositoryName": "my-app",
                    "registry": "123456789012",
                    "imageHash": "sha256:abcd1234",
                    "imageTags": ["latest", "v1.0"],
                    "architecture": "x86_64",
                    "platform": "LINUX",
                }
            },
        }],
        "packageVulnerabilityDetails": {
            "vulnerabilityId": "CVE-2024-99999",
            "cvss": [{"baseScore": 7.5}],
        },
        "inspectorScore": 7.5,
        "remediation": {"recommendation": {"text": "Update base image"}},
    }


def _mock_paginator(findings: list[dict]) -> MagicMock:
    mock_pag = MagicMock()
    mock_pag.paginate.return_value = [{"findings": findings}]
    mock_client = MagicMock()
    mock_client.get_paginator.return_value = mock_pag
    return mock_client, mock_pag


# ---------------------------------------------------------------------------
# Basic collection
# ---------------------------------------------------------------------------
def test_collect_scheduled_returns_raw_findings():
    mock_client, mock_pag = _mock_paginator([_make_ec2_finding()])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, RawFinding)
    assert f.cve_id == "CVE-2024-12345"
    assert f.severity == "CRITICAL"
    assert f.source == "aws_inspector"
    assert "10.0.0.1" in f.ipv4


def test_collect_returns_empty_on_no_findings():
    mock_client, _ = _mock_paginator([])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")
    assert findings == []


# ---------------------------------------------------------------------------
# Scheduled-mode filter criteria
# ---------------------------------------------------------------------------
def test_scheduled_filter_uses_status_and_severity_defaults():
    """Default filters: status=ACTIVE, severity in MEDIUM/HIGH/CRITICAL."""
    mock_client, mock_pag = _mock_paginator([])
    with patch("boto3.client", return_value=mock_client):
        collect(mode="scheduled")

    call_kwargs = mock_pag.paginate.call_args[1]
    fc = call_kwargs["filterCriteria"]

    status_values = {e["value"] for e in fc["findingStatus"]}
    severity_values = {e["value"] for e in fc["severity"]}

    assert status_values == {"ACTIVE"}
    assert severity_values == {"MEDIUM", "HIGH", "CRITICAL"}


def test_scheduled_filter_multi_severity_all_present_in_criteria():
    """All requested severities must appear as separate EQUALS entries (OR at API level)."""
    mock_client, mock_pag = _mock_paginator([])
    env = {"INSPECTOR2_SEVERITIES": "HIGH,CRITICAL", "INSPECTOR2_STATUSES": "ACTIVE"}
    with patch("boto3.client", return_value=mock_client), patch.dict(os.environ, env):
        collect(mode="scheduled")

    call_kwargs = mock_pag.paginate.call_args[1]
    fc = call_kwargs["filterCriteria"]
    severity_values = {e["value"] for e in fc["severity"]}

    assert severity_values == {"HIGH", "CRITICAL"}, (
        "Both HIGH and CRITICAL must be passed as separate EQUALS entries "
        "so Inspector2 ORs them at the API level"
    )


def test_scheduled_filter_single_severity():
    mock_client, mock_pag = _mock_paginator([])
    env = {"INSPECTOR2_SEVERITIES": "CRITICAL", "INSPECTOR2_STATUSES": "ACTIVE"}
    with patch("boto3.client", return_value=mock_client), patch.dict(os.environ, env):
        collect(mode="scheduled")

    fc = mock_pag.paginate.call_args[1]["filterCriteria"]
    assert {e["value"] for e in fc["severity"]} == {"CRITICAL"}


def test_scheduled_filter_all_severities():
    mock_client, mock_pag = _mock_paginator([])
    env = {
        "INSPECTOR2_SEVERITIES": "INFORMATIONAL,LOW,MEDIUM,HIGH,CRITICAL,UNTRIAGED",
        "INSPECTOR2_STATUSES": "ACTIVE",
    }
    with patch("boto3.client", return_value=mock_client), patch.dict(os.environ, env):
        collect(mode="scheduled")

    fc = mock_pag.paginate.call_args[1]["filterCriteria"]
    assert {e["value"] for e in fc["severity"]} == {
        "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNTRIAGED"
    }


def test_scheduled_filter_multi_status():
    mock_client, mock_pag = _mock_paginator([])
    env = {"INSPECTOR2_STATUSES": "ACTIVE,SUPPRESSED", "INSPECTOR2_SEVERITIES": "HIGH"}
    with patch("boto3.client", return_value=mock_client), patch.dict(os.environ, env):
        collect(mode="scheduled")

    fc = mock_pag.paginate.call_args[1]["filterCriteria"]
    assert {e["value"] for e in fc["findingStatus"]} == {"ACTIVE", "SUPPRESSED"}


def test_invalid_severity_values_are_ignored_and_default_used():
    mock_client, mock_pag = _mock_paginator([])
    env = {"INSPECTOR2_SEVERITIES": "BOGUS,INVALID"}
    with patch("boto3.client", return_value=mock_client), patch.dict(os.environ, env):
        collect(mode="scheduled")

    fc = mock_pag.paginate.call_args[1]["filterCriteria"]
    # Falls back to default: MEDIUM, HIGH, CRITICAL
    assert {e["value"] for e in fc["severity"]} == {"MEDIUM", "HIGH", "CRITICAL"}


# ---------------------------------------------------------------------------
# Event-driven mode — no status/severity filter applied
# ---------------------------------------------------------------------------
def test_collect_event_mode_passes_arn_filter_only():
    """Event mode must use findingArn filter only — no status/severity filtering."""
    mock_client, mock_pag = _mock_paginator([_make_ec2_finding()])
    with patch("boto3.client", return_value=mock_client):
        collect(mode="event", finding_arn="arn:aws:inspector2:us-east-1:123:finding/abc")

    fc = mock_pag.paginate.call_args[1]["filterCriteria"]
    assert list(fc.keys()) == ["findingArn"]
    assert fc["findingArn"][0]["value"] == "arn:aws:inspector2:us-east-1:123:finding/abc"
    assert "severity" not in fc
    assert "findingStatus" not in fc


# ---------------------------------------------------------------------------
# EC2 parsing — instance_id in tags
# ---------------------------------------------------------------------------
def test_ec2_finding_includes_instance_id_in_tags():
    mock_client, _ = _mock_paginator([_make_ec2_finding()])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")

    assert len(findings) == 1
    tags = findings[0].tags
    instance_id_tags = [t for t in tags if t.startswith("instance_id:")]
    assert len(instance_id_tags) == 1
    assert instance_id_tags[0] == "instance_id:i-0abc123def456"


def test_ec2_finding_includes_cloud_metadata_tags():
    mock_client, _ = _mock_paginator([_make_ec2_finding()])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")

    tags = findings[0].tags
    tag_set = set(tags)
    assert "cloud:aws" in tag_set
    assert "resource_type:ec2_instance" in tag_set
    assert any(t.startswith("aws_region:") for t in tags)
    assert any(t.startswith("instance_type:") for t in tags)
    assert any(t.startswith("vpc:") for t in tags)


# ---------------------------------------------------------------------------
# ECR parsing
# ---------------------------------------------------------------------------
def test_ecr_finding_parsed_correctly():
    mock_client, _ = _mock_paginator([_make_ecr_finding()])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")

    assert len(findings) == 1
    f = findings[0]
    assert f.cve_id == "CVE-2024-99999"
    tags = set(f.tags)
    assert "cloud:aws" in tags
    assert "resource_type:ecr_container_image" in tags
    assert any(t.startswith("ecr_repository:") for t in f.tags)
    assert any(t.startswith("image_hash:") for t in f.tags)
    # ECR FQDN constructed from registry + region + repo
    assert len(f.fqdn) == 1
    assert "dkr.ecr" in f.fqdn[0]


# ---------------------------------------------------------------------------
# _parse_env_list unit tests
# ---------------------------------------------------------------------------
def test_parse_env_list_empty_returns_default():
    result = _parse_env_list("NONEXISTENT_VAR_XYZ", {"A", "B"}, ["A"])
    assert result == ["A"]


def test_parse_env_list_single_value():
    with patch.dict(os.environ, {"TEST_VAR": "A"}):
        result = _parse_env_list("TEST_VAR", {"A", "B", "C"}, ["C"])
    assert result == ["A"]


def test_parse_env_list_multiple_values():
    with patch.dict(os.environ, {"TEST_VAR": "A,B"}):
        result = _parse_env_list("TEST_VAR", {"A", "B", "C"}, ["C"])
    assert set(result) == {"A", "B"}


def test_parse_env_list_strips_whitespace_and_upcases():
    with patch.dict(os.environ, {"TEST_VAR": " a , b "}):
        result = _parse_env_list("TEST_VAR", {"A", "B"}, ["C"])
    assert set(result) == {"A", "B"}


def test_parse_env_list_all_invalid_falls_back_to_default():
    with patch.dict(os.environ, {"TEST_VAR": "X,Y,Z"}):
        result = _parse_env_list("TEST_VAR", {"A", "B"}, ["A", "B"])
    assert result == ["A", "B"]

import datetime
import os
from unittest.mock import patch, MagicMock

import pytest

from byob_core.collectors.aws_inspector import (
    collect, _parse_env_list, _active_resource_ids, _coverage_filter_enabled, _coverage_hours,
    _parse_lambda_arn, _lambda_base_arn,
)
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


def _make_coverage_page(resource_ids: list[str]) -> dict:
    """Return a fake list_coverage page for the given resource IDs."""
    return {
        "coveredResources": [
            {"resourceId": rid, "lastScannedAt": datetime.datetime.now(tz=datetime.timezone.utc)}
            for rid in resource_ids
        ]
    }


def _mock_paginator(findings: list[dict], covered_ids: list[str] | None = None):
    """Build a mock boto3 inspector2 client.

    *covered_ids* controls what list_coverage returns.  When None, defaults to
    the resource IDs extracted from *findings* so existing tests keep passing.
    For Lambda findings the versioned ARN is automatically normalised to the
    base ARN (no qualifier) to match what list_coverage returns in production.
    Pass an explicit list (including empty list) to test coverage filtering.
    """
    if covered_ids is None:
        covered_ids = []
        for f in findings:
            if not f.get("resources"):
                continue
            rid = f["resources"][0]["id"]
            # Normalise Lambda ARNs to base form (strip :$LATEST / :N / :alias)
            parts = rid.split(":")
            if len(parts) == 8 and parts[5] == "function":
                rid = ":".join(parts[:7])
            covered_ids.append(rid)

    findings_pag = MagicMock()
    findings_pag.paginate.return_value = [{"findings": findings}]

    coverage_pag = MagicMock()
    coverage_pag.paginate.return_value = [_make_coverage_page(covered_ids)]

    def _get_paginator(name: str) -> MagicMock:
        if name == "list_findings":
            return findings_pag
        if name == "list_coverage":
            return coverage_pag
        return MagicMock()

    mock_client = MagicMock()
    mock_client.get_paginator.side_effect = _get_paginator
    return mock_client, findings_pag


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
    """Default filters: status=ACTIVE, severity in MEDIUM/HIGH/CRITICAL/LOW."""
    mock_client, mock_pag = _mock_paginator([])
    clean_env = {"INSPECTOR2_SEVERITIES": "", "INSPECTOR2_STATUSES": ""}
    with patch("boto3.client", return_value=mock_client), patch.dict(os.environ, clean_env):
        collect(mode="scheduled")

    call_kwargs = mock_pag.paginate.call_args[1]
    fc = call_kwargs["filterCriteria"]

    status_values = {e["value"] for e in fc["findingStatus"]}
    severity_values = {e["value"] for e in fc["severity"]}

    assert status_values == {"ACTIVE"}
    assert severity_values == {"MEDIUM", "HIGH", "CRITICAL", "LOW"}


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
    env = {"INSPECTOR2_SEVERITIES": "BOGUS,INVALID", "INSPECTOR2_STATUSES": "ACTIVE"}
    with patch("boto3.client", return_value=mock_client), patch.dict(os.environ, env):
        collect(mode="scheduled")

    fc = mock_pag.paginate.call_args[1]["filterCriteria"]
    # Falls back to default: MEDIUM, HIGH, CRITICAL, LOW
    assert {e["value"] for e in fc["severity"]} == {"MEDIUM", "HIGH", "CRITICAL", "LOW"}


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


def test_ecr_asset_id_is_registry_repo_digest():
    """asset_id must be registry/repo@digest — NOT the bare digest.

    Inspector2 returns resource.id as the bare sha256 digest, which is shared
    across any repos/accounts that pull the same base image.  Using a bare
    digest as origin_asset_id causes Cortex to collapse them into one asset.
    """
    mock_client, _ = _mock_paginator([_make_ecr_finding()])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")

    f = findings[0]
    # Expected: <registry>.dkr.ecr.<region>.amazonaws.com/<repo>@<digest>
    expected = "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app@sha256:abcd1234"
    assert f.asset_id == expected, (
        f"ECR asset_id should be registry/repo@digest for uniqueness, got: {f.asset_id!r}"
    )


def test_ecr_asset_name_is_image_digest():
    """asset_name must be the image digest, not the repo name."""
    mock_client, _ = _mock_paginator([_make_ecr_finding()])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")

    f = findings[0]
    assert f.asset_name == "sha256:abcd1234", (
        "ECR asset_name should be the imageHash digest, not the repository name"
    )


def test_ecr_repo_name_in_tags():
    """Repository name must appear as ecr_repo_name:<name> in origin tags."""
    mock_client, _ = _mock_paginator([_make_ecr_finding()])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")

    tags = findings[0].tags
    repo_name_tags = [t for t in tags if t.startswith("ecr_repo_name:")]
    assert len(repo_name_tags) == 1
    assert repo_name_tags[0] == "ecr_repo_name:my-app"


def test_ec2_asset_name_unchanged():
    """EC2 asset_name must still come from the Name tag, not a digest."""
    mock_client, _ = _mock_paginator([_make_ec2_finding()])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")

    f = findings[0]
    assert f.asset_name == "web-1", (
        "EC2 asset_name should remain the Name tag value — digest change is ECR-only"
    )


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


# ---------------------------------------------------------------------------
# Coverage filter
# ---------------------------------------------------------------------------
def test_coverage_filter_drops_stale_asset():
    """Findings for assets NOT in list_coverage are dropped when coverage has other resources."""
    finding = _make_ec2_finding()
    # coverage returns a *different* resource — our EC2 is absent (stale/terminated)
    mock_client, _ = _mock_paginator([finding], covered_ids=["i-OTHER999999"])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")
    assert findings == [], "Stale asset should have been filtered out by coverage check"


def test_coverage_filter_keeps_active_asset():
    """Findings for assets IN list_coverage are kept."""
    finding = _make_ec2_finding()
    resource_id = finding["resources"][0]["id"]
    mock_client, _ = _mock_paginator([finding], covered_ids=[resource_id])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")
    assert len(findings) == 1
    assert findings[0].asset_id == resource_id


def test_coverage_filter_partial_filter():
    """Only findings for assets in list_coverage are kept; others are dropped."""
    ec2 = _make_ec2_finding()
    ecr = _make_ecr_finding()
    ec2_id = ec2["resources"][0]["id"]    # i-0abc123def456
    ecr_id = ecr["resources"][0]["id"]   # sha256:abcd1234
    # Only EC2 is in coverage (ECR image was pulled long ago)
    mock_client, _ = _mock_paginator([ec2, ecr], covered_ids=[ec2_id])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")
    assert len(findings) == 1
    assert findings[0].asset_id == ec2_id


def test_coverage_filter_disabled_via_env_var():
    """INSPECTOR2_COVERAGE_FILTER=false must bypass the coverage API call entirely."""
    finding = _make_ec2_finding()
    mock_client, _ = _mock_paginator([finding], covered_ids=[])  # coverage would drop it
    env = {"INSPECTOR2_COVERAGE_FILTER": "false"}
    with patch("boto3.client", return_value=mock_client), patch.dict(os.environ, env):
        findings = collect(mode="scheduled")
    # list_coverage should not have been called
    paginators_requested = [c.args[0] for c in mock_client.get_paginator.call_args_list]
    assert "list_coverage" not in paginators_requested
    assert len(findings) == 1


def test_coverage_filter_zero_results_does_not_drop_all_findings():
    """If list_coverage returns empty unexpectedly, treat as disabled (no filter)."""
    finding = _make_ec2_finding()
    # Simulate list_coverage returning no resources (permissions issue / empty account)
    mock_client, _ = _mock_paginator([finding], covered_ids=[])
    # Patch _active_resource_ids to return empty set (mimics permission failure path)
    with patch("boto3.client", return_value=mock_client), \
         patch("byob_core.collectors.aws_inspector._active_resource_ids", return_value=set()):
        findings = collect(mode="scheduled")
    # With empty coverage set, filter is bypassed — finding should be kept
    assert len(findings) == 1


def test_coverage_filter_enabled_flag():
    assert _coverage_filter_enabled() is True
    with patch.dict(os.environ, {"INSPECTOR2_COVERAGE_FILTER": "false"}):
        assert _coverage_filter_enabled() is False
    with patch.dict(os.environ, {"INSPECTOR2_COVERAGE_FILTER": "true"}):
        assert _coverage_filter_enabled() is True


def test_coverage_hours_default_and_override():
    """_coverage_hours() reads INSPECTOR2_COVERAGE_HOURS; default 720."""
    assert _coverage_hours() == 720
    with patch.dict(os.environ, {"INSPECTOR2_COVERAGE_HOURS": "72"}):
        assert _coverage_hours() == 72
    with patch.dict(os.environ, {"INSPECTOR2_COVERAGE_HOURS": "bogus"}):
        assert _coverage_hours() == 720  # falls back to default


def test_coverage_hours_flag_passed_to_active_resource_ids():
    """--coverage-hours N must be forwarded to _active_resource_ids as lookback_hours=N."""
    finding = _make_ec2_finding()
    resource_id = finding["resources"][0]["id"]
    mock_client, _ = _mock_paginator([finding], covered_ids=[resource_id])

    with patch("boto3.client", return_value=mock_client), \
         patch("byob_core.collectors.aws_inspector._active_resource_ids",
               wraps=lambda client, lookback_hours=720: {resource_id}) as mock_cov:
        collect(mode="scheduled", coverage_hours=72)

    mock_cov.assert_called_once()
    _, kwargs = mock_cov.call_args
    assert kwargs.get("lookback_hours") == 72


# ---------------------------------------------------------------------------
# Lambda ARN helpers
# ---------------------------------------------------------------------------
def test_parse_lambda_arn_no_qualifier():
    fn, ver = _parse_lambda_arn("arn:aws:lambda:us-east-1:123456789012:function:my-fn")
    assert fn == "my-fn"
    assert ver == "$LATEST"


def test_parse_lambda_arn_latest():
    fn, ver = _parse_lambda_arn("arn:aws:lambda:us-east-1:123456789012:function:my-fn:$LATEST")
    assert fn == "my-fn"
    assert ver == "$LATEST"


def test_parse_lambda_arn_version_number():
    fn, ver = _parse_lambda_arn("arn:aws:lambda:us-east-1:123456789012:function:my-fn:3")
    assert fn == "my-fn"
    assert ver == "3"


def test_parse_lambda_arn_alias():
    fn, ver = _parse_lambda_arn("arn:aws:lambda:us-east-1:123456789012:function:my-fn:prod")
    assert fn == "my-fn"
    assert ver == "prod"


def test_lambda_base_arn_strips_qualifier():
    base = _lambda_base_arn("arn:aws:lambda:us-east-1:123456789012:function:my-fn:$LATEST")
    assert base == "arn:aws:lambda:us-east-1:123456789012:function:my-fn"


def test_lambda_base_arn_no_qualifier_unchanged():
    arn = "arn:aws:lambda:us-east-1:123456789012:function:my-fn"
    assert _lambda_base_arn(arn) == arn


# ---------------------------------------------------------------------------
# Lambda finding fixture + parsing tests
# ---------------------------------------------------------------------------
def _make_lambda_finding(
    severity: str = "HIGH",
    arn: str = "arn:aws:lambda:us-east-1:123456789012:function:my-fn:$LATEST",
) -> dict:
    return {
        "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/lambda-xyz",
        "severity": severity,
        "updatedAt": datetime.datetime(2024, 6, 1, tzinfo=datetime.timezone.utc),
        "description": "Lambda vuln",
        "resources": [{
            "id": arn,
            "type": "AWS_LAMBDA_FUNCTION",
            "region": "us-east-1",
            "providerAccountId": "123456789012",
            "tags": {"env": "prod"},
            "details": {
                "awsLambdaFunction": {
                    "functionName": "my-fn",
                    "runtime": "python3.12",
                    "layers": ["arn:aws:lambda:us-east-1:123456789012:layer:my-layer:1"],
                    "functionTags": {"team": "platform"},
                }
            },
        }],
        "packageVulnerabilityDetails": {
            "vulnerabilityId": "CVE-2024-55555",
            "cvss": [{"baseScore": 7.8}],
        },
        "inspectorScore": 7.8,
        "remediation": {"recommendation": {"text": "Update runtime"}},
    }


def test_lambda_finding_parsed_correctly():
    mock_client, _ = _mock_paginator([_make_lambda_finding()])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")

    assert len(findings) == 1
    f = findings[0]
    assert f.cve_id == "CVE-2024-55555"
    assert f.asset_name == "my-fn"


def test_lambda_asset_id_is_versioned_arn():
    """origin_asset_id must keep the version qualifier so each Lambda version is a distinct Cortex asset."""
    arn_with_version = "arn:aws:lambda:us-east-1:123456789012:function:my-fn:$LATEST"
    mock_client, _ = _mock_paginator([_make_lambda_finding(arn=arn_with_version)])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")

    assert findings[0].asset_id == arn_with_version, (
        "Lambda asset_id must be the full versioned ARN so my-fn:$LATEST and "
        "my-fn:3 are distinct assets in Cortex"
    )


def test_lambda_has_correct_resource_type_tag():
    """Lambda findings must carry resource_type:lambda_function, not resource_type:ec2_instance."""
    mock_client, _ = _mock_paginator([_make_lambda_finding()])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")

    tags = findings[0].tags
    assert "resource_type:lambda_function" in tags
    assert not any(t == "resource_type:ec2_instance" for t in tags), (
        "Lambda findings must not be tagged as ec2_instance"
    )


def test_lambda_version_in_tags():
    """Version qualifier extracted from ARN must appear as lambda_version: tag."""
    mock_client, _ = _mock_paginator([_make_lambda_finding()])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")

    tags = findings[0].tags
    version_tags = [t for t in tags if t.startswith("lambda_version:")]
    assert len(version_tags) == 1
    assert version_tags[0] == "lambda_version:$LATEST"


def test_lambda_runtime_in_tags():
    mock_client, _ = _mock_paginator([_make_lambda_finding()])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")

    tags = findings[0].tags
    assert any(t.startswith("runtime:") for t in tags)


def test_lambda_coverage_filter_uses_base_arn():
    """Coverage filter must match Lambda findings even when list_findings returns versioned ARN."""
    arn_with_version = "arn:aws:lambda:us-east-1:123456789012:function:my-fn:$LATEST"
    base_arn         = "arn:aws:lambda:us-east-1:123456789012:function:my-fn"
    finding = _make_lambda_finding(arn=arn_with_version)
    # list_coverage returns the base ARN (no version qualifier)
    mock_client, _ = _mock_paginator([finding], covered_ids=[base_arn])
    with patch("boto3.client", return_value=mock_client):
        findings = collect(mode="scheduled")
    assert len(findings) == 1, (
        "Lambda finding with versioned ARN should be kept when the base ARN is in coverage"
    )


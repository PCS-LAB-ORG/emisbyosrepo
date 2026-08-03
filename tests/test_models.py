import time
from byob_core.models import RawFinding, Credentials, JobResult


def test_raw_finding_required_fields():
    now_ms = int(time.time() * 1000)
    f = RawFinding(
        asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
        asset_name="web-server-1",
        ipv4=["10.0.0.1"],
        ipv6=[],
        fqdn=[],
        mac_address=None,
        os_name="Amazon Linux 2",
        tags=["env:prod"],
        last_seen_ms=now_ms,
        cve_id="CVE-2024-12345",
        severity="CRITICAL",
        description="A critical vulnerability",
        evidence="CVSS 9.8",
        raw_output="score: 9.8",
        source="aws_inspector",
    )
    assert f.asset_id == "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123"
    assert f.severity == "CRITICAL"
    assert f.source == "aws_inspector"


def test_credentials_fields():
    creds = Credentials(
        cortex_api_key="key123",
        cortex_auth_id="42",
        cortex_fqdn="api-tenant.xdr.us.paloaltonetworks.com",
    )
    assert creds.cortex_fqdn == "api-tenant.xdr.us.paloaltonetworks.com"


def test_job_result_fields():
    r = JobResult(job_id="abc-123", status="COMPLETED", assets_count=10, vulnerabilities_count=25)
    assert r.status == "COMPLETED"

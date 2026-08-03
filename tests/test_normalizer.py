import time
import pytest
from byob_core.models import RawFinding
from byob_core.normalizer import normalize


def _now_ms():
    return int(time.time() * 1000)


def _make_finding(asset_id="i-abc", severity="CRITICAL", source="aws_inspector",
                  last_seen_ms=None, cve_id="CVE-2024-12345"):
    return RawFinding(
        asset_id=asset_id,
        asset_name="web-1",
        ipv4=["10.0.0.1"],
        ipv6=[],
        fqdn=["web-1.internal"],
        mac_address=None,
        os_name="Amazon Linux 2",
        tags=["env:prod"],
        last_seen_ms=last_seen_ms or _now_ms(),
        cve_id=cve_id,
        severity=severity,
        description="A vuln",
        evidence="CVSS 9.8",
        raw_output="score: 9.8",
        source=source,
    )


def test_normalize_returns_aws_vendor():
    batches = normalize([_make_finding()], "aws_inspector")
    assert len(batches) == 1
    assert batches[0]["vendor"] == "AWS"
    assert batches[0]["product"] == "Inspector2"


def test_normalize_returns_azure_vendor():
    f = _make_finding(source="azure_defender")
    batches = normalize([f], "azure_defender")
    assert batches[0]["vendor"] == "Microsoft"
    assert batches[0]["product"] == "DefenderForCloud"


def test_normalize_groups_multiple_cves_under_one_asset():
    findings = [
        _make_finding(asset_id="i-abc", cve_id="CVE-2024-0001"),
        _make_finding(asset_id="i-abc", cve_id="CVE-2024-0002"),
    ]
    batches = normalize(findings, "aws_inspector")
    assert len(batches[0]["assets"]) == 1
    assert len(batches[0]["assets"][0]["vulnerabilities"]) == 2


def test_normalize_critical_high_maps_to_confirmed():
    for sev in ("CRITICAL", "HIGH"):
        f = _make_finding(severity=sev)
        batches = normalize([f], "aws_inspector")
        vuln = batches[0]["assets"][0]["vulnerabilities"][0]
        assert vuln["confidence"] == "Confirmed"


def test_normalize_medium_low_maps_to_potential():
    for sev in ("MEDIUM", "LOW"):
        f = _make_finding(severity=sev)
        batches = normalize([f], "aws_inspector")
        vuln = batches[0]["assets"][0]["vulnerabilities"][0]
        assert vuln["confidence"] == "Potential"


def test_normalize_filters_old_findings():
    old_ms = int(time.time() * 1000) - (31 * 24 * 60 * 60 * 1000)
    findings = [
        _make_finding(last_seen_ms=old_ms),
        _make_finding(asset_id="i-new"),
    ]
    batches = normalize(findings, "aws_inspector")
    asset_ids = [a["origin_asset_id"] for a in batches[0]["assets"]]
    assert "i-new" in asset_ids
    assert "i-abc" not in asset_ids


def test_normalize_batches_assets_across_multiple_batches():
    # 25 assets with the batch cap at 10 → 3 batches (10, 10, 5)
    findings = [_make_finding(asset_id=f"i-{n}") for n in range(25)]
    batches = normalize(findings, "aws_inspector")
    assert len(batches) == 3
    assert len(batches[0]["assets"]) == 10
    assert len(batches[1]["assets"]) == 10
    assert len(batches[2]["assets"]) == 5


def test_normalize_raw_output_truncated_to_2000():
    f = _make_finding()
    f.raw_output = "x" * 3000
    batches = normalize([f], "aws_inspector")
    vuln = batches[0]["assets"][0]["vulnerabilities"][0]
    assert len(vuln["raw_output"]) == 2000


def test_normalize_description_truncated():
    f = _make_finding()
    f.description = "d" * 2000
    batches = normalize([f], "aws_inspector")
    vuln = batches[0]["assets"][0]["vulnerabilities"][0]
    assert len(vuln["description"]) == 1000


def test_normalize_evidence_truncated():
    f = _make_finding()
    f.evidence = "e" * 1000
    batches = normalize([f], "aws_inspector")
    vuln = batches[0]["assets"][0]["vulnerabilities"][0]
    assert len(vuln["evidence"]) == 500


def test_normalize_byte_limit_splits_batch():
    import json
    from byob_core.normalizer import MAX_BATCH_BYTES
    # Each asset has a max-length description (~1000 chars) — around 1.2 KB per asset.
    # Pack enough assets so their combined size exceeds 4 MB.
    n_assets = (MAX_BATCH_BYTES // 1200) + 5
    findings = []
    for n in range(n_assets):
        f = _make_finding(asset_id=f"i-{n}")
        f.description = "d" * 1000
        findings.append(f)
    batches = normalize(findings, "aws_inspector")
    # Must have split into at least 2 batches due to byte limit
    assert len(batches) >= 2
    # No single batch should exceed the byte limit by more than one asset's worth
    for batch in batches:
        size = len(json.dumps(batch).encode())
        # Allow one asset of headroom (~5 KB) beyond the cap
        assert size < MAX_BATCH_BYTES + 5 * 1024


def test_normalize_raises_on_unknown_source():
    f = _make_finding()
    with pytest.raises(ValueError, match="Unknown source"):
        normalize([f], "unknown_scanner")

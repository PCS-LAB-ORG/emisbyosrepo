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


def test_normalize_filters_old_assets():
    """An asset whose MOST RECENT vuln is >30 days old is dropped by default."""
    old_ms = int(time.time() * 1000) - (31 * 24 * 60 * 60 * 1000)
    findings = [
        _make_finding(asset_id="i-old", last_seen_ms=old_ms),
        _make_finding(asset_id="i-new"),
    ]
    batches = normalize(findings, "aws_inspector")
    asset_ids = [a["origin_asset_id"] for a in batches[0]["assets"]]
    assert "i-new" in asset_ids
    assert "i-old" not in asset_ids


def test_normalize_active_asset_old_vuln_always_included():
    """An old vuln on an active asset must be included (clamped) not dropped."""
    now_ms = int(time.time() * 1000)
    old_ms = now_ms - (31 * 24 * 60 * 60 * 1000)
    findings = [
        _make_finding(asset_id="i-abc", cve_id="CVE-2024-0001"),           # recent
        _make_finding(asset_id="i-abc", cve_id="CVE-2024-0002", last_seen_ms=old_ms),  # old
    ]
    # Default (clamp_old_findings=False): old vuln on active asset is still included
    batches = normalize(findings, "aws_inspector")
    assert len(batches) == 1
    asset = batches[0]["assets"][0]
    cve_ids = [v["vulnerability_id"] for v in asset["vulnerabilities"]]
    assert "CVE-2024-0001" in cve_ids
    assert "CVE-2024-0002" in cve_ids
    # Old vuln last_seen must have been clamped to ≈ now
    old_vuln = next(v for v in asset["vulnerabilities"] if v["vulnerability_id"] == "CVE-2024-0002")
    assert old_vuln["last_seen"] >= now_ms
    # Asset must be tagged
    assert "over30day:true" in asset["origin_tags"]


def test_normalize_active_asset_recent_vuln_no_tag():
    """Active asset with only recent vulns must NOT get the over30day:true tag."""
    batches = normalize([_make_finding()], "aws_inspector")
    asset = batches[0]["assets"][0]
    assert "over30day:true" not in asset["origin_tags"]


def test_normalize_clamp_old_findings_included():
    """clamp_old_findings=True: old ASSETS are included with last_seen=now and over30day tag."""
    old_ms = int(time.time() * 1000) - (31 * 24 * 60 * 60 * 1000)
    finding = _make_finding(asset_id="i-old", last_seen_ms=old_ms)
    before_ms = int(time.time() * 1000)
    batches = normalize([finding], "aws_inspector", clamp_old_findings=True)
    after_ms = int(time.time() * 1000)

    assert len(batches) == 1
    asset = batches[0]["assets"][0]
    assert asset["origin_asset_id"] == "i-old"
    # last_seen on both the asset and the vuln must have been clamped to ≈ now
    assert before_ms <= asset["last_seen"] <= after_ms
    assert before_ms <= asset["vulnerabilities"][0]["last_seen"] <= after_ms
    # Must be tagged
    assert "over30day:true" in asset["origin_tags"]


def test_normalize_clamp_old_does_not_affect_recent_findings():
    """clamp_old_findings=True must not alter the last_seen of recent findings."""
    recent_ms = int(time.time() * 1000) - (5 * 24 * 60 * 60 * 1000)  # 5 days ago
    finding = _make_finding(last_seen_ms=recent_ms)
    batches = normalize([finding], "aws_inspector", clamp_old_findings=True)
    asset = batches[0]["assets"][0]
    assert asset["last_seen"] == recent_ms
    assert asset["vulnerabilities"][0]["last_seen"] == recent_ms


def test_normalize_clamp_false_still_drops_old():
    """Default behaviour (clamp_old_findings=False) still drops old findings."""
    old_ms = int(time.time() * 1000) - (31 * 24 * 60 * 60 * 1000)
    finding = _make_finding(last_seen_ms=old_ms)
    batches = normalize([finding], "aws_inspector", clamp_old_findings=False)
    assert batches == []


def test_normalize_vulns_sorted_by_severity_then_last_seen():
    """Vulns must be ordered CRITICAL → HIGH → MEDIUM → LOW, most-recent first within each tier."""
    now = _now_ms()
    one_day = 24 * 60 * 60 * 1000
    findings = [
        _make_finding(asset_id="i-abc", cve_id="CVE-LOW-OLD",      severity="LOW",      last_seen_ms=now - 5 * one_day),
        _make_finding(asset_id="i-abc", cve_id="CVE-CRITICAL-OLD",  severity="CRITICAL", last_seen_ms=now - 3 * one_day),
        _make_finding(asset_id="i-abc", cve_id="CVE-HIGH-RECENT",   severity="HIGH",     last_seen_ms=now - 1 * one_day),
        _make_finding(asset_id="i-abc", cve_id="CVE-CRITICAL-NEW",  severity="CRITICAL", last_seen_ms=now - 1 * one_day),
        _make_finding(asset_id="i-abc", cve_id="CVE-MEDIUM",        severity="MEDIUM",   last_seen_ms=now - 2 * one_day),
    ]
    batches = normalize(findings, "aws_inspector")
    vuln_ids = [v["vulnerability_id"] for v in batches[0]["assets"][0]["vulnerabilities"]]
    assert vuln_ids == [
        "CVE-CRITICAL-NEW",   # CRITICAL, most recent
        "CVE-CRITICAL-OLD",   # CRITICAL, older
        "CVE-HIGH-RECENT",    # HIGH
        "CVE-MEDIUM",         # MEDIUM
        "CVE-LOW-OLD",        # LOW
    ]


def test_normalize_batches_assets_across_multiple_batches():
    # 136 assets with the batch cap at 45 → 4 batches (45, 45, 45, 1)
    findings = [_make_finding(asset_id=f"i-{n}") for n in range(136)]
    batches = normalize(findings, "aws_inspector")
    assert len(batches) == 4
    assert len(batches[0]["assets"]) == 45
    assert len(batches[1]["assets"]) == 45
    assert len(batches[2]["assets"]) == 45
    assert len(batches[3]["assets"]) == 1


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
    assert len(vuln["description"]) == 1500


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

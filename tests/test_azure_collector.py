"""Tests for the Azure Defender collector.

Fixtures mirror real Microsoft Defender Vulnerability Management (MDVM) rows as
returned by Resource Graph from `securityresources`. MDVM publishes one
*assessment per software package*, with the CVEs packed into a JSON-encoded
string at `properties.additionalData.CvesDetails` — so one row expands into many
findings.
"""
import json
import time
from unittest.mock import patch, MagicMock

import pytest

from byob_core.collectors.azure_defender import collect
from byob_core.models import RawFinding

VM_RESOURCE_ID = (
    "/subscriptions/sub-1/resourceGroups/Expedition_Tool"
    "/providers/Microsoft.Compute/virtualMachines/Expedition-VM"
)
FUNC_RESOURCE_ID = (
    "/subscriptions/sub-1/resourceGroups/faahmed"
    "/providers/Microsoft.Web/sites/cortex-cloud-to-azure-devops-board"
)


def _cves(*specs):
    """Build the JSON *string* Defender puts in additionalData.CvesDetails."""
    return json.dumps([
        {
            "CveId": cve,
            "AdditionalIdentifiers": [],
            "Severity": sev,
            "FixStatus": "FixAvailable",
            "FixedVersion": fixed,
            "Tags": [],
        }
        for cve, sev, fixed in specs
    ])


def _row(
    resource_id=VM_RESOURCE_ID,
    resource_name="Expedition-VM",
    resource_type="Microsoft.Compute/virtualMachines",
    assessment_guid="f3c10408-1e45-1c05-bf4b-8656b2b9b7e0",
    status_code="Unhealthy",
    cves_details=None,
    software="libc-bin_for_linux",
    max_cvss="8.4",
    status_change="2026-09-15T20:48:57.0346801Z",
    first_eval="2026-09-15T20:48:57.0346801Z",
    metadata_severity="High",
    description="Update libc-bin to a later version to mitigate known vulnerabilities",
    detected_versions='["2.31-0ubuntu9.18"]',
):
    if cves_details is None:
        cves_details = _cves(("CVE-2025-15281", "Medium", ""))
    status = {"code": status_code}
    if first_eval:
        status["firstEvaluationDate"] = first_eval
    if status_change:
        status["statusChangeDate"] = status_change
    additional = {
        "MaxCvssScore": max_cvss,
        "PackageType": "OS",
        "ScannerName": "MdvmAgent",
        "SoftwareVendor": "ubuntu",
        "DetectedSoftwareVersions": detected_versions,
    }
    if cves_details is not False:
        additional["CvesDetails"] = cves_details
    if software is not None:
        additional["SoftwareName"] = software
    return {
        "id": f"{resource_id}/providers/Microsoft.Security/assessments/{assessment_guid}",
        "name": assessment_guid,
        "properties": {
            "additionalData": additional,
            "displayName": f"Update {software}",
            "metadata": {"severity": metadata_severity, "description": description},
            "resourceDetails": {
                "Id": resource_id,
                "NativeResourceId": resource_id,
                "ResourceId": resource_id,
                "ResourceName": resource_name,
                "ResourceProvider": resource_type.split("/")[0],
                "ResourceType": resource_type,
                "Source": "Azure",
            },
            "status": status,
        },
    }


def _run(rows, mode="scheduled", resource_id=None, monkeypatch=None):
    """Run collect() against a mocked Resource Graph returning *rows*."""
    result = MagicMock()
    result.data = rows
    result.skip_token = None
    client = MagicMock()
    client.resources.return_value = result
    with patch("byob_core.collectors.azure_defender.DefaultAzureCredential"), \
         patch("byob_core.collectors.azure_defender.ResourceGraphClient", return_value=client):
        findings = collect(mode=mode, resource_id=resource_id)
    return findings, client


@pytest.fixture(autouse=True)
def _scope(monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "11111111-2222-3333-4444-555555555555")


# --- CVE expansion ----------------------------------------------------------

def test_one_assessment_expands_into_one_finding_per_cve():
    """MDVM packs N CVEs into one assessment row — each must become a finding."""
    row = _row(cves_details=_cves(
        ("CVE-2025-15281", "Medium", ""),
        ("CVE-2025-8058", "Unknown", ""),
        ("CVE-2026-0861", "High", ""),
        ("CVE-2026-0915", "Medium", ""),
    ))
    findings, _ = _run([row])
    assert [f.cve_id for f in findings] == [
        "CVE-2025-15281", "CVE-2025-8058", "CVE-2026-0861", "CVE-2026-0915",
    ]
    assert all(isinstance(f, RawFinding) for f in findings)
    assert all(f.source == "azure_defender" for f in findings)


def test_row_without_cves_details_is_skipped():
    findings, _ = _run([_row(cves_details=False)])
    assert findings == []


def test_malformed_cves_details_is_skipped_without_raising():
    findings, _ = _run([_row(cves_details="{not valid json")])
    assert findings == []


def test_cve_entries_without_an_id_are_skipped():
    findings, _ = _run([_row(cves_details=json.dumps([{"Severity": "High"}]))])
    assert findings == []


def test_empty_result_returns_no_findings():
    findings, _ = _run([])
    assert findings == []


# --- asset identity (bug: asset_id was the assessment ARM id) ---------------

def test_asset_id_is_the_resource_not_the_assessment():
    """asset_id must be the VM, not the per-package assessment ARM id."""
    findings, _ = _run([_row()])
    assert findings[0].asset_id == VM_RESOURCE_ID
    assert "Microsoft.Security/assessments" not in findings[0].asset_id


def test_assessments_on_same_resource_share_one_asset_id():
    """Two software packages on one VM must collapse to a single asset."""
    rows = [
        _row(assessment_guid="aaaa", software="openssl"),
        _row(assessment_guid="bbbb", software="libc-bin_for_linux"),
    ]
    findings, _ = _run(rows)
    assert len({f.asset_id for f in findings}) == 1
    assert findings[0].asset_id == VM_RESOURCE_ID


def test_asset_name_comes_from_resource_details():
    findings, _ = _run([_row()])
    assert findings[0].asset_name == "Expedition-VM"


# --- last_seen (bug: silently fell back to now() for every finding) --------

def test_last_seen_comes_from_status_change_date():
    findings, _ = _run([_row(status_change="2026-09-15T20:48:57.0346801Z")])
    expected = int(
        __import__("datetime").datetime.fromisoformat(
            "2026-09-15T20:48:57.0346801+00:00"
        ).timestamp() * 1000
    )
    assert findings[0].last_seen_ms == expected


def test_last_seen_falls_back_to_first_evaluation_date():
    findings, _ = _run([_row(
        status_change=None, first_eval="2026-09-01T10:00:00.0000000Z",
    )])
    expected = int(
        __import__("datetime").datetime.fromisoformat(
            "2026-09-01T10:00:00+00:00"
        ).timestamp() * 1000
    )
    assert findings[0].last_seen_ms == expected


def test_last_seen_falls_back_to_now_when_no_timestamps():
    before = int(time.time() * 1000)
    findings, _ = _run([_row(status_change=None, first_eval=None)])
    after = int(time.time() * 1000)
    assert before <= findings[0].last_seen_ms <= after


# --- status mapping: Azure vocabulary -> Cortex vocabulary -----------------

def test_unhealthy_maps_to_active():
    findings, _ = _run([_row(status_code="Unhealthy")])
    assert json.loads(findings[0].evidence)["status"] == "ACTIVE"


def test_healthy_maps_to_closed():
    findings, _ = _run([_row(status_code="Healthy")])
    assert json.loads(findings[0].evidence)["status"] == "CLOSED"


def test_evidence_is_exactly_status_active_or_closed():
    """Cortex consumes evidence as {"status": "ACTIVE"|"CLOSED"} — no other keys."""
    findings, _ = _run([_row(status_code="Unhealthy")])
    assert list(json.loads(findings[0].evidence)) == ["status"]


def test_evidence_never_contains_an_azure_status_word():
    """Azure vocabulary must be translated, not passed through."""
    findings, _ = _run([_row(status_code="Unhealthy")])
    assert "Unhealthy" not in findings[0].evidence
    assert json.loads(findings[0].evidence) == {"status": "ACTIVE"}


def test_unrecognised_status_defaults_to_active():
    """An unmapped Defender status must not be reported as resolved."""
    findings, _ = _run([_row(status_code="SomeNewStatus")])
    assert json.loads(findings[0].evidence) == {"status": "ACTIVE"}


def test_native_azure_status_preserved_in_tags():
    findings, _ = _run([_row(status_code="Healthy")])
    assert "azure_status:Healthy" in findings[0].tags


def test_fix_information_preserved_in_raw_output():
    """fixStatus/fixedVersion leave evidence but must not be lost."""
    findings, _ = _run([_row(
        max_cvss="8.9", software="urllib3",
        cves_details=_cves(("CVE-A", "High", "2.7.0")),
    )])
    assert "2.7.0" in findings[0].raw_output
    assert "FixAvailable" in findings[0].raw_output


def test_notapplicable_rows_are_skipped():
    """NotApplicable means Defender could not assess — it asserts no vulnerability."""
    findings, _ = _run([_row(status_code="NotApplicable")])
    assert findings == []


def test_status_tag_uses_mapped_value():
    findings, _ = _run([_row(status_code="Unhealthy")])
    assert "status:ACTIVE" in findings[0].tags


# --- severity ---------------------------------------------------------------

def test_severity_comes_from_each_cve_not_the_assessment():
    row = _row(
        metadata_severity="High",
        cves_details=_cves(("CVE-A", "Critical", ""), ("CVE-B", "Low", "")),
    )
    findings, _ = _run([row])
    assert [f.severity for f in findings] == ["CRITICAL", "LOW"]


def test_severity_falls_back_to_assessment_metadata():
    row = _row(metadata_severity="High", cves_details=json.dumps([{"CveId": "CVE-A"}]))
    findings, _ = _run([row])
    assert findings[0].severity == "HIGH"


# --- resource_type tags (drive batch_push's --resource-type flag) ----------

@pytest.mark.parametrize("resource_type,expected", [
    ("Microsoft.Compute/virtualMachines", "resource_type:virtual_machine"),
    ("Microsoft.Web/sites/functionapp", "resource_type:function_app"),
    ("Microsoft.Compute/virtualMachineScaleSets", "resource_type:vm_scale_set"),
    ("K8s-container", "resource_type:k8s_container"),
])
def test_resource_type_tag(resource_type, expected):
    findings, _ = _run([_row(resource_type=resource_type)])
    assert expected in findings[0].tags


def test_unknown_resource_type_still_tagged():
    findings, _ = _run([_row(resource_type="Microsoft.Sql/servers")])
    tags = [t for t in findings[0].tags if t.startswith("resource_type:")]
    assert len(tags) == 1
    assert tags[0] != "resource_type:"


def test_azure_metadata_tags_preserved():
    findings, _ = _run([_row()])
    tags = findings[0].tags
    assert "cloud:azure" in tags
    assert "azure_subscription:sub-1" in tags
    assert "azure_resource_group:Expedition_Tool" in tags
    assert any(t.startswith("software:") for t in tags)


# --- payload fields ---------------------------------------------------------

def test_description_comes_from_metadata():
    findings, _ = _run([_row(description="Update libc-bin to mitigate 4 CVEs")])
    assert findings[0].description == "Update libc-bin to mitigate 4 CVEs"


def test_raw_output_contains_cvss_and_software():
    findings, _ = _run([_row(max_cvss="8.4", software="libc-bin_for_linux")])
    assert findings[0].raw_output.startswith("score:8.4")
    assert "libc-bin_for_linux" in findings[0].raw_output


def test_evidence_carries_only_status():
    findings, _ = _run([_row(cves_details=_cves(("CVE-A", "High", "2.7.0")))])
    ev = json.loads(findings[0].evidence)
    assert ev == {"status": "ACTIVE"}


# --- query shape ------------------------------------------------------------

def test_query_targets_assessments_not_subassessments():
    _, client = _run([_row()])
    queries = [c.kwargs.get("query") or c.args[0].query
               for c in client.resources.call_args_list]
    collection = [q for q in queries if "CvesDetails" in q]
    assert collection, f"no MDVM collection query issued; saw: {queries}"
    q = collection[0]
    assert "microsoft.security/assessments/subassessments" not in q
    assert "properties.id != ''" not in q


def test_query_collects_all_resource_types_by_default():
    """The collector must not restrict by resource type — filtering is a CLI concern."""
    _, client = _run([_row()])
    q = next(c.args[0].query for c in client.resources.call_args_list
             if "CvesDetails" in c.args[0].query)
    for word in ("virtualMachines", "functionapp", "K8s-container", "sites"):
        assert word not in q, f"query is scoped to {word!r}; must collect all types"


def test_event_mode_filters_by_resource_id():
    _, client = _run([_row()], mode="event", resource_id=VM_RESOURCE_ID)
    q = next(c.args[0].query for c in client.resources.call_args_list
             if "CvesDetails" in c.args[0].query)
    assert VM_RESOURCE_ID in q


# --- end to end through the normalizer -------------------------------------

def test_function_app_findings_survive_normalization():
    row = _row(
        resource_id=FUNC_RESOURCE_ID,
        resource_name="cortex-cloud-to-azure-devops-board",
        resource_type="Microsoft.Web/sites/functionapp",
        software="urllib3",
        cves_details=_cves(
            ("CVE-2026-44431", "High", "2.7.0"),
            ("CVE-2026-97688", "Medium", "2.8.0"),
        ),
    )
    findings, _ = _run([row])
    from byob_core.normalizer import normalize
    batches = normalize(findings, "azure_defender", clamp_old_findings=True)
    assert len(batches) == 1
    assets = batches[0]["assets"]
    assert len(assets) == 1
    assert assets[0]["origin_asset_id"] == FUNC_RESOURCE_ID
    assert len(assets[0]["vulnerabilities"]) == 2


def test_same_cve_from_two_packages_dedupes_per_asset():
    """Cortex rejects duplicate vulnerability_id per asset; the normalizer collapses them."""
    rows = [
        _row(assessment_guid="aaaa", software="openssl",
             cves_details=_cves(("CVE-2026-0861", "High", ""))),
        _row(assessment_guid="bbbb", software="libssl3",
             cves_details=_cves(("CVE-2026-0861", "High", ""))),
    ]
    findings, _ = _run(rows)
    assert len(findings) == 2
    from byob_core.normalizer import normalize
    batches = normalize(findings, "azure_defender", clamp_old_findings=True)
    vulns = batches[0]["assets"][0]["vulnerabilities"]
    ids = [v["vulnerability_id"] for v in vulns]
    assert ids == ["CVE-2026-0861"]
    assert len(ids) == len(set(ids))

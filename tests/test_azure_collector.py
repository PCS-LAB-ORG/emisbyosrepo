from unittest.mock import patch, MagicMock
from byob_core.collectors.azure_defender import collect
from byob_core.models import RawFinding

SAMPLE_SUB = {
    "id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute"
          "/virtualMachines/vm1/providers/Microsoft.Security/assessments"
          "/c0b7cfc6/subassessments/sub-abc",
    "name": "sub-abc",
    "properties": {
        "id": "CVE-2024-99999",
        "displayName": "Critical CVE",
        "description": "A critical vulnerability",
        "severity": {"severity": "High"},
        "additionalData": {"cvss": {"baseScore": 9.8}},
        "timeGenerated": "2025-01-15T00:00:00Z",
        "resourceDetails": {"source": "Azure", "resourceName": "vm1"},
    },
}


def test_collect_scheduled_returns_raw_findings(monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub1")
    mock_result = MagicMock()
    mock_result.data = [[SAMPLE_SUB]]
    mock_result.skip_token = None
    mock_arg = MagicMock()
    mock_arg.resources.return_value = mock_result
    with patch("byob_core.collectors.azure_defender.DefaultAzureCredential"), \
         patch("byob_core.collectors.azure_defender.ResourceGraphClient", return_value=mock_arg):
        findings = collect(mode="scheduled")
    assert len(findings) == 1
    assert isinstance(findings[0], RawFinding)
    assert findings[0].source == "azure_defender"
    assert findings[0].cve_id == "CVE-2024-99999"


def test_collect_returns_empty_on_no_data(monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub1")
    mock_result = MagicMock()
    mock_result.data = [[]]
    mock_result.skip_token = None
    mock_arg = MagicMock()
    mock_arg.resources.return_value = mock_result
    with patch("byob_core.collectors.azure_defender.DefaultAzureCredential"), \
         patch("byob_core.collectors.azure_defender.ResourceGraphClient", return_value=mock_arg):
        findings = collect(mode="scheduled")
    assert findings == []

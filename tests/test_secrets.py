import json
import os
import pytest
from unittest.mock import patch, MagicMock

from byob_core.models import Credentials


def test_aws_loads_from_secrets_manager(monkeypatch):
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "byob-scanner")
    monkeypatch.setenv("CORTEX_SECRET_NAME", "byob/cortex")
    secret_val = json.dumps({
        "cortex_api_key": "k1",
        "cortex_auth_id": "5",
        "cortex_fqdn": "api-t.xdr.us.paloaltonetworks.com",
    })
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {"SecretString": secret_val}
    with patch("boto3.client", return_value=mock_client):
        from byob_core import secrets
        creds = secrets.load_credentials()
    assert isinstance(creds, Credentials)
    assert creds.cortex_api_key == "k1"
    assert creds.cortex_auth_id == "5"
    assert creds.cortex_fqdn == "api-t.xdr.us.paloaltonetworks.com"
    mock_client.get_secret_value.assert_called_once_with(SecretId="byob/cortex")


def test_azure_loads_from_key_vault(monkeypatch):
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    monkeypatch.setenv("CORTEX_KEYVAULT_URL", "https://myvault.vault.azure.net")
    monkeypatch.setenv("CORTEX_SECRET_NAME", "byob-cortex")
    secret_val = json.dumps({
        "cortex_api_key": "k2",
        "cortex_auth_id": "9",
        "cortex_fqdn": "api-t.xdr.eu.paloaltonetworks.com",
    })
    mock_secret = MagicMock()
    mock_secret.value = secret_val
    mock_kv = MagicMock()
    mock_kv.get_secret.return_value = mock_secret
    with patch("azure.keyvault.secrets.SecretClient", return_value=mock_kv), \
         patch("azure.identity.DefaultAzureCredential"):
        from byob_core import secrets
        creds = secrets.load_credentials()
    assert isinstance(creds, Credentials)
    assert creds.cortex_api_key == "k2"
    assert creds.cortex_auth_id == "9"
    assert creds.cortex_fqdn == "api-t.xdr.eu.paloaltonetworks.com"
    mock_kv.get_secret.assert_called_once_with("byob-cortex")


def test_missing_secret_name_raises(monkeypatch):
    monkeypatch.delenv("CORTEX_SECRET_NAME", raising=False)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "byob-scanner")
    from byob_core import secrets
    with pytest.raises(KeyError):
        secrets.load_credentials()

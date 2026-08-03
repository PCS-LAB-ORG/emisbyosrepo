from __future__ import annotations
import json
import logging
import os

from byob_core.models import Credentials

logger = logging.getLogger(__name__)


def load_credentials() -> Credentials:
    # Direct env vars — works locally without any secrets backend.
    if all(os.environ.get(k) for k in ("CORTEX_API_KEY", "CORTEX_AUTH_ID", "CORTEX_FQDN")):
        logger.info("Loading Cortex credentials from environment variables")
        return Credentials(
            cortex_api_key=os.environ["CORTEX_API_KEY"],
            cortex_auth_id=os.environ["CORTEX_AUTH_ID"],
            cortex_fqdn=os.environ["CORTEX_FQDN"],
        )
    secret_name = os.environ["CORTEX_SECRET_NAME"]
    # Use Key Vault only when explicitly configured; otherwise use Secrets Manager.
    if os.environ.get("CORTEX_KEYVAULT_URL"):
        return _from_key_vault(secret_name)
    return _from_secrets_manager(secret_name)


def _from_secrets_manager(secret_name: str) -> Credentials:
    import boto3
    region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    logger.info("Loading Cortex credentials from Secrets Manager (region=%s)", region)
    client = boto3.client("secretsmanager", region_name=region)
    resp = client.get_secret_value(SecretId=secret_name)
    data = json.loads(resp["SecretString"])
    return Credentials(
        cortex_api_key=data["cortex_api_key"],
        cortex_auth_id=data["cortex_auth_id"],
        cortex_fqdn=data["cortex_fqdn"],
    )


def _from_key_vault(secret_name: str) -> Credentials:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
    logger.info("Loading Cortex credentials from Azure Key Vault")
    vault_url = os.environ["CORTEX_KEYVAULT_URL"]
    client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
    secret = client.get_secret(secret_name)
    data = json.loads(secret.value)
    return Credentials(
        cortex_api_key=data["cortex_api_key"],
        cortex_auth_id=data["cortex_auth_id"],
        cortex_fqdn=data["cortex_fqdn"],
    )

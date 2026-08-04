from __future__ import annotations
import json
import logging
import os
import sys

from byob_core.models import Credentials

logger = logging.getLogger(__name__)


def verify_credentials() -> None:
    """Verify Cortex credentials are accessible before spending time on collection.

    Checks in order:
      1. Individual env vars  CORTEX_API_KEY + CORTEX_AUTH_ID + CORTEX_FQDN
      2. AWS Secrets Manager  CORTEX_SECRET_NAME  (+ optional AWS_DEFAULT_REGION)
      3. Azure Key Vault       CORTEX_SECRET_NAME + CORTEX_KEYVAULT_URL

    Exits with a clear error message if credentials cannot be resolved.
    """
    # Option 1 — individual env vars already set (or applied from --cortex-* flags)
    if all(os.environ.get(k) for k in ("CORTEX_API_KEY", "CORTEX_AUTH_ID", "CORTEX_FQDN")):
        logger.info(
            "Cortex credentials: using individual env vars "
            "(CORTEX_API_KEY / CORTEX_AUTH_ID / CORTEX_FQDN)"
        )
        return

    # Option 2 / 3 — secret name must be set
    secret_name = os.environ.get("CORTEX_SECRET_NAME", "").strip()
    if not secret_name:
        logger.error(
            "No Cortex credentials found.\n\n"
            "  Provide them in one of these ways:\n\n"
            "  A) Individual env vars:\n"
            "       CORTEX_API_KEY=<key>\n"
            "       CORTEX_AUTH_ID=<id>\n"
            "       CORTEX_FQDN=<fqdn>\n\n"
            "  B) CLI flags:\n"
            "       --cortex-api-key <key>\n"
            "       --cortex-auth-id <id>\n"
            "       --cortex-fqdn   <fqdn>\n\n"
            "  C) AWS Secrets Manager secret:\n"
            "       CORTEX_SECRET_NAME=<secret-name>\n"
            "       (optional: AWS_DEFAULT_REGION=<region>)\n\n"
            "  D) Azure Key Vault secret:\n"
            "       CORTEX_SECRET_NAME=<secret-name>\n"
            "       CORTEX_KEYVAULT_URL=https://<vault-name>.vault.azure.net/"
        )
        sys.exit(1)

    # Option 3 — Azure Key Vault
    if os.environ.get("CORTEX_KEYVAULT_URL"):
        vault_url = os.environ["CORTEX_KEYVAULT_URL"]
        logger.info(
            "Cortex credentials: verifying secret '%s' in Azure Key Vault (%s) ...",
            secret_name, vault_url,
        )
        try:
            from azure.identity import DefaultAzureCredential  # noqa: PLC0415
            from azure.keyvault.secrets import SecretClient    # noqa: PLC0415
            client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
            client.get_secret(secret_name)
            logger.info(
                "Cortex credentials: Key Vault secret '%s' found and readable.", secret_name
            )
        except Exception as exc:
            logger.error(
                "Cortex credentials: failed to read secret '%s' from Key Vault '%s'.\n"
                "  Error: %s\n\n"
                "  Check that:\n"
                "    - The secret name is correct\n"
                "    - Your Azure identity has 'Get' permission on the Key Vault\n"
                "    - CORTEX_KEYVAULT_URL is set correctly",
                secret_name, vault_url, exc,
            )
            sys.exit(1)
        return

    # Option 2 — AWS Secrets Manager
    region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    logger.info(
        "Cortex credentials: verifying secret '%s' in Secrets Manager (region=%s) ...",
        secret_name, region,
    )
    try:
        import boto3  # noqa: PLC0415
        client = boto3.client("secretsmanager", region_name=region)
        resp = client.get_secret_value(SecretId=secret_name)
        data = json.loads(resp["SecretString"])
        missing = [k for k in ("cortex_api_key", "cortex_auth_id", "cortex_fqdn") if not data.get(k)]
        if missing:
            logger.error(
                "Cortex credentials: secret '%s' exists but is missing required keys: %s\n"
                "  The secret must contain: cortex_api_key, cortex_auth_id, cortex_fqdn",
                secret_name, missing,
            )
            sys.exit(1)
        logger.info(
            "Cortex credentials: secret '%s' found and contains all required keys.", secret_name
        )
    except Exception as exc:
        logger.error(
            "Cortex credentials: failed to read secret '%s' from Secrets Manager (region=%s).\n"
            "  Error: %s\n\n"
            "  Check that:\n"
            "    - The secret name is correct (CORTEX_SECRET_NAME=%s)\n"
            "    - AWS_DEFAULT_REGION is set correctly (current: %s)\n"
            "    - Your IAM user/role has secretsmanager:GetSecretValue on this secret\n"
            "    - AWS credentials are configured (aws configure / SSO / instance profile)",
            secret_name, region, exc, secret_name, region,
        )
        sys.exit(1)


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

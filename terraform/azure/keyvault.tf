resource "azurerm_key_vault" "kv" {
  name                = var.key_vault_name
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"
}

# Placeholder secret — value must be populated out-of-band before invoking the function
resource "azurerm_key_vault_secret" "cortex_credentials" {
  name         = var.cortex_secret_name
  value        = "REPLACE_ME"
  key_vault_id = azurerm_key_vault.kv.id

  lifecycle {
    ignore_changes = [value]
  }

  depends_on = [azurerm_key_vault_access_policy.deployer_policy]
}

# Allow the deploying principal to manage secrets (required to create the placeholder)
resource "azurerm_key_vault_access_policy" "deployer_policy" {
  key_vault_id = azurerm_key_vault.kv.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  secret_permissions = ["Get", "Set", "Delete", "Purge", "List"]
}

# Allow the Function App managed identity to read secrets
resource "azurerm_key_vault_access_policy" "func_policy" {
  key_vault_id = azurerm_key_vault.kv.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_linux_function_app.func.identity[0].principal_id

  secret_permissions = ["Get"]
}

# Security Reader so the Function App can pull Defender findings
resource "azurerm_role_assignment" "security_reader" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Security Reader"
  principal_id         = azurerm_linux_function_app.func.identity[0].principal_id
}

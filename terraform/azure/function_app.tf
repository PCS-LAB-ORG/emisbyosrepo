resource "azurerm_linux_function_app" "func" {
  name                       = var.function_app_name
  resource_group_name        = azurerm_resource_group.rg.name
  location                   = azurerm_resource_group.rg.location
  storage_account_name       = azurerm_storage_account.sa.name
  storage_account_access_key = azurerm_storage_account.sa.primary_access_key
  service_plan_id            = azurerm_service_plan.plan.id

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      python_version = "3.12"
    }
  }

  app_settings = {
    FUNCTIONS_EXTENSION_VERSION = "~4"
    FUNCTIONS_WORKER_RUNTIME    = "python"
    CORTEX_KEYVAULT_URL         = azurerm_key_vault.kv.vault_uri
    CORTEX_SECRET_NAME          = var.cortex_secret_name
    AZURE_SUBSCRIPTION_ID       = var.subscription_id
  }
}

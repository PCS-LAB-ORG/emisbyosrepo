output "function_app_id" {
  value       = azurerm_linux_function_app.func.id
  description = "Resource ID of the Linux Function App"
}

output "function_app_name" {
  value       = azurerm_linux_function_app.func.name
  description = "Name of the Linux Function App"
}

output "function_app_default_hostname" {
  value       = azurerm_linux_function_app.func.default_hostname
  description = "Default hostname of the Function App"
}

output "keyvault_id" {
  value       = azurerm_key_vault.kv.id
  description = "Resource ID of the Key Vault"
}

output "keyvault_uri" {
  value       = azurerm_key_vault.kv.vault_uri
  description = "URI of the Key Vault (used in CORTEX_KEYVAULT_URL app setting)"
}

output "event_grid_topic_id" {
  value       = azurerm_eventgrid_system_topic.security.id
  description = "Resource ID of the Event Grid system topic"
}

output "managed_identity_principal_id" {
  value       = azurerm_linux_function_app.func.identity[0].principal_id
  description = "Principal ID of the Function App system-assigned managed identity"
}

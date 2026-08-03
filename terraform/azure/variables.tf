variable "location" {
  type        = string
  default     = "eastus"
  description = "Azure region for all resources"
}

variable "resource_group_name" {
  type        = string
  default     = "byob-scanner-rg"
  description = "Name of the resource group"
}

variable "storage_account_name" {
  type        = string
  description = "Globally unique storage account name for the Function App"
}

variable "subscription_id" {
  type        = string
  description = "Azure subscription ID"
}

variable "function_app_name" {
  type        = string
  default     = "byob-scanner-func"
  description = "Name of the Linux Function App"
}

variable "key_vault_name" {
  type        = string
  default     = "byob-scanner-kv"
  description = "Name of the Key Vault (must be globally unique)"
}

variable "cortex_secret_name" {
  type        = string
  default     = "cortex-credentials"
  description = "Name of the Key Vault secret holding Cortex XDR credentials"
}

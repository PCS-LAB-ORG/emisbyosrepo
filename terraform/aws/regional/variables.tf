variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "lambda_zip_path" {
  type    = string
  default = "../../../dist/byob_lambda.zip"
}

variable "cortex_secret_name" {
  type    = string
  default = "byob/cortex"
}

variable "lambda_role_arn" {
  type        = string
  description = "ARN of the IAM role created by the global module"
}

variable "schedule_expression" {
  type    = string
  default = "rate(6 hours)"
}

variable "inspector2_statuses" {
  type        = string
  default     = "ACTIVE"
  description = "Comma-separated Inspector2 finding statuses to collect. Valid: ACTIVE, SUPPRESSED, CLOSED"
}

variable "inspector2_severities" {
  type        = string
  default     = "LOW,MEDIUM,HIGH,CRITICAL"
  description = "Comma-separated Inspector2 severities to collect. Valid: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL, UNTRIAGED"
}

variable "inspector2_lookback_hours" {
  type        = number
  default     = 12
  description = "Only return findings updated in the last N hours. 0 = disabled (full scan). Set to 12 for the scheduled Lambda so each 6-hour run pulls a delta with overlap."
}

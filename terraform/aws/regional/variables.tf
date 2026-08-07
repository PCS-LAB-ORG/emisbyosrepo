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

variable "inspector2_statuses" {
  type        = string
  default     = "ACTIVE"
  description = "Comma-separated Inspector2 finding statuses applied to all severity rules. Valid: ACTIVE, SUPPRESSED, CLOSED"
}

variable "inspector2_severities" {
  type        = string
  default     = "LOW,MEDIUM,HIGH,CRITICAL"
  description = "Comma-separated Inspector2 severities to collect. Valid: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL, UNTRIAGED"
}

variable "inspector2_lookback_hours" {
  type        = number
  default     = 6
  description = "Only return findings updated in the last N hours. Each severity rule runs every 4 hours — 6 gives a 2-hour overlap safety buffer. 0 = no time filter."
}

variable "inspector2_coverage_hours" {
  type        = number
  default     = 720
  description = "The lastScannedAt window (hours) used by the list-coverage pre-filter. Only resources scanned within this window are included. Default 720 = 30 days. Set to 72 for a 3-day window."
}

variable "inspector2_coverage_filter" {
  type        = string
  default     = "true"
  description = "Set to 'false' to disable the list-coverage pre-filter (e.g. if the IAM role lacks inspector2:ListCoverage)."
}

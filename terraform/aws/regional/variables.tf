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

variable "inspector2_lookback_hours" {
  type        = number
  default     = 6
  description = "Only return findings updated in the last N hours. Each severity rule runs every 4 hours — 6 gives a 2-hour overlap safety buffer. 0 = no time filter."
}

resource "aws_lambda_function" "byob_scanner" {
  function_name                  = "byob-scanner"
  filename                       = var.lambda_zip_path
  handler                        = "handler.lambda_handler"
  runtime                        = "python3.12"
  role                           = var.lambda_role_arn
  timeout                        = 900
  memory_size                    = 1024
  reserved_concurrent_executions = 1

  ephemeral_storage {
    size = 2048
  }

  source_code_hash = try(filebase64sha256(var.lambda_zip_path), null)

  environment {
    variables = {
      CORTEX_SECRET_NAME          = var.cortex_secret_name
      INSPECTOR2_STATUSES         = var.inspector2_statuses
      INSPECTOR2_SEVERITIES       = var.inspector2_severities
      INSPECTOR2_LOOKBACK_HOURS   = tostring(var.inspector2_lookback_hours)
    }
  }
}

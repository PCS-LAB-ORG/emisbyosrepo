output "lambda_function_name" {
  value = aws_lambda_function.byob_scanner.function_name
}

output "lambda_function_arn" {
  value = aws_lambda_function.byob_scanner.arn
}

output "eventbridge_rule_arn" {
  value = aws_cloudwatch_event_rule.scheduled.arn
}

output "secret_arn" {
  value       = aws_secretsmanager_secret.cortex_creds.arn
  description = "Populate with Cortex credentials JSON before invoking"
}

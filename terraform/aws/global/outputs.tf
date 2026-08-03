output "lambda_role_arn" {
  value       = aws_iam_role.lambda_role.arn
  description = "ARN of the shared IAM role — pass to each regional deployment"
}

output "lambda_role_name" {
  value = aws_iam_role.lambda_role.name
}

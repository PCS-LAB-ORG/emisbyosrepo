resource "aws_cloudwatch_event_rule" "scheduled" {
  name                = "byob-scanner-schedule"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "scheduled_target" {
  rule      = aws_cloudwatch_event_rule.scheduled.name
  target_id = "byob-scanner-scheduled"
  arn       = aws_lambda_function.byob_scanner.arn
}

resource "aws_lambda_permission" "allow_scheduled" {
  statement_id  = "AllowScheduled"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.byob_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scheduled.arn
}

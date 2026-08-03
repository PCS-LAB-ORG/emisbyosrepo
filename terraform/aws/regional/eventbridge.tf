locals {
  # Each severity gets its own rule running every 4 hours, staggered by 30 minutes
  # so only one Lambda invocation is active at a time — avoids Cortex rate limits.
  # 6-hour lookback window (var.inspector2_lookback_hours) gives a 2-hour overlap
  # and keeps each run well within the 15-minute Lambda timeout.
  #
  # Timeline (UTC):
  #   00:00 / 04:00 / 08:00 / 12:00 / 16:00 / 20:00 → CRITICAL
  #   00:30 / 04:30 / 08:30 / 12:30 / 16:30 / 20:30 → HIGH
  #   01:00 / 05:00 / 09:00 / 13:00 / 17:00 / 21:00 → MEDIUM
  #   01:30 / 05:30 / 09:30 / 13:30 / 17:30 / 21:30 → LOW
  severity_schedules = {
    CRITICAL = "cron(0 0,4,8,12,16,20 * * ? *)"
    HIGH     = "cron(30 0,4,8,12,16,20 * * ? *)"
    MEDIUM   = "cron(0 1,5,9,13,17,21 * * ? *)"
    LOW      = "cron(30 1,5,9,13,17,21 * * ? *)"
  }
}

resource "aws_cloudwatch_event_rule" "severity" {
  for_each            = local.severity_schedules
  name                = "byob-scanner-${lower(each.key)}"
  schedule_expression = each.value
}

resource "aws_cloudwatch_event_target" "severity" {
  for_each  = local.severity_schedules
  rule      = aws_cloudwatch_event_rule.severity[each.key].name
  target_id = "byob-scanner-${lower(each.key)}"
  arn       = aws_lambda_function.byob_scanner.arn

  input = jsonencode({
    inspector2_statuses       = var.inspector2_statuses
    inspector2_severities     = each.key
    inspector2_lookback_hours = var.inspector2_lookback_hours
  })
}

resource "aws_lambda_permission" "severity" {
  for_each      = local.severity_schedules
  statement_id  = "AllowScheduled${title(lower(each.key))}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.byob_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.severity[each.key].arn
}

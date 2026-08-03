# System topic scoped to the subscription for Microsoft.Security.Assessments events.
# topic_type must match the event types in the subscription below.
# "Microsoft.Security.Assessments" publishes AssessmentStatusChanged events (Defender
# for Cloud vulnerability/sub-assessment findings). The previous value
# "Microsoft.Security.SecurityAlerts" only publishes "Microsoft.Security.Alert" events,
# so AssessmentStatusChanged would have been silently dropped.
resource "azurerm_eventgrid_system_topic" "security" {
  name                   = "byob-security-events"
  resource_group_name    = azurerm_resource_group.rg.name
  location               = "Global"
  source_arm_resource_id = "/subscriptions/${var.subscription_id}"
  topic_type             = "Microsoft.Security.Assessments"
}

# Subscription that forwards Defender for Cloud assessment events to the Function App.
# included_event_types must be published by the topic_type above.
resource "azurerm_eventgrid_system_topic_event_subscription" "defender_alerts" {
  name                = "byob-defender-alerts"
  system_topic        = azurerm_eventgrid_system_topic.security.name
  resource_group_name = azurerm_resource_group.rg.name

  azure_function_endpoint {
    function_id = "${azurerm_linux_function_app.func.id}/functions/EventDrivenSync"
  }

  included_event_types = [
    "Microsoft.Security.AssessmentStatusChanged",
  ]
}

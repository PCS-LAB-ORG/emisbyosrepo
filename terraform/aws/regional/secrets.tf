resource "aws_secretsmanager_secret" "cortex_creds" {
  name                    = var.cortex_secret_name
  description             = "Cortex XDR BYOS credentials"
  recovery_window_in_days = 0
}

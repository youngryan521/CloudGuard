# ============================================================
# Security Hub + GuardDuty
#
# NOTE: Security Hub and GuardDuty require manual activation
# on new/free-tier AWS accounts before Terraform can manage them.
#
# TO ENABLE:
#   1. Go to AWS Console -> GuardDuty -> Get Started -> Enable GuardDuty
#   2. Go to AWS Console -> Security Hub -> Go to Security Hub -> Enable
#   3. After enabling both, run: terraform apply
#      Terraform will import and manage them on the next run.
# ============================================================

# GuardDuty EventBridge alert rule (works without GuardDuty enabled -- 
# will simply never fire until GuardDuty is activated)
resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "cloudguard-guardduty-high-severity"
  description = "Triggers on GuardDuty HIGH or CRITICAL findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
    }
  })

  tags = { Name = "cloudguard-guardduty-high-rule" }
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  count = var.alert_email != "" ? 1 : 0

  rule      = aws_cloudwatch_event_rule.guardduty_high.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      title       = "$.detail.title"
      description = "$.detail.description"
      region      = "$.region"
      account     = "$.account"
    }
    input_template = "\"GuardDuty ALERT | Severity: <severity> | <title> | <description> | Account: <account> | Region: <region>\""
  }
}

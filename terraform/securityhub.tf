# ============================================================
# Security Hub + GuardDuty
# Security Hub aggregates findings from: GuardDuty, Config,
# Inspector, Macie into one normalized view.
# CIS AWS Foundations Benchmark v1.4 enabled as standard.
# ============================================================

resource "aws_securityhub_account" "main" {}

# CIS AWS Foundations Benchmark v1.4
resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.main]
}

# AWS Foundational Security Best Practices v1.0
resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

# ============================================================
# GuardDuty
# ============================================================

resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes { enable = true }
      }
    }
  }

  tags = { Name = "cloudguard-guardduty" }
}

# EventBridge rule: HIGH severity GuardDuty finding -> SNS alert
resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "cloudguard-guardduty-high-severity"
  description = "Triggers on GuardDuty HIGH or CRITICAL findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }] # HIGH (7-8.9) and CRITICAL (9-10)
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

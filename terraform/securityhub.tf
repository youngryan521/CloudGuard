# ============================================================
# Security Hub + GuardDuty
# ============================================================

resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

# ============================================================
# GuardDuty -- nested blocks must each be on their own line
# ============================================================

resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = { Name = "cloudguard-guardduty" }
}

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

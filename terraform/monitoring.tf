# ============================================================
# CloudWatch: metric filters, alarms, dashboard
# CIS 3.x requires specific metric filters on CloudTrail logs
# for security-critical API calls.
# ============================================================

# -- SNS topic for all security alerts --
resource "aws_sns_topic" "security_alerts" {
  name              = "cloudguard-security-alerts"
  kms_master_key_id = aws_kms_key.cloudwatch.arn
  tags              = { Name = "cloudguard-security-alerts" }
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ============================================================
# CIS 3.x -- CloudWatch metric filters on CloudTrail log group
# Each filter looks for a specific API pattern in CloudTrail logs
# and triggers an alarm when the pattern is detected.
# ============================================================

locals {
  # Map of: filter_name -> { pattern, description, alarm_description }
  cis_metric_filters = {
    unauthorized_api_calls = {
      pattern           = "{ ($.errorCode = \"*UnauthorizedAccess*\") || ($.errorCode = \"AccessDenied\") }"
      description       = "CIS 3.1 -- Unauthorized API calls"
      alarm_description = "One or more unauthorized API calls detected"
    }
    console_no_mfa = {
      pattern           = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
      description       = "CIS 3.2 -- Console login without MFA"
      alarm_description = "Console login without MFA detected"
    }
    root_usage = {
      pattern           = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      description       = "CIS 3.3 -- Root account usage"
      alarm_description = "Root account activity detected"
    }
    iam_policy_changes = {
      pattern           = "{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=SetDefaultPolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy) }"
      description       = "CIS 3.4 -- IAM policy changes"
      alarm_description = "IAM policy change detected"
    }
    cloudtrail_config_changes = {
      pattern           = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
      description       = "CIS 3.5 -- CloudTrail configuration changes"
      alarm_description = "CloudTrail configuration change detected"
    }
    console_auth_failures = {
      pattern           = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
      description       = "CIS 3.6 -- Console auth failures"
      alarm_description = "Multiple console authentication failures detected"
    }
    cmk_disable_delete = {
      pattern           = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
      description       = "CIS 3.7 -- KMS CMK disable/delete"
      alarm_description = "KMS CMK disabled or scheduled for deletion"
    }
    s3_bucket_policy_changes = {
      pattern           = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
      description       = "CIS 3.8 -- S3 bucket policy changes"
      alarm_description = "S3 bucket policy/ACL change detected"
    }
    config_changes = {
      pattern           = "{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }"
      description       = "CIS 3.9 -- AWS Config changes"
      alarm_description = "AWS Config configuration change detected"
    }
    security_group_changes = {
      pattern           = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
      description       = "CIS 3.10 -- Security group changes"
      alarm_description = "Security group modification detected"
    }
    nacl_changes = {
      pattern           = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
      description       = "CIS 3.11 -- NACL changes"
      alarm_description = "Network ACL change detected"
    }
    network_gateway_changes = {
      pattern           = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
      description       = "CIS 3.12 -- Network gateway changes"
      alarm_description = "Network gateway change detected"
    }
    route_table_changes = {
      pattern           = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
      description       = "CIS 3.13 -- Route table changes"
      alarm_description = "Route table change detected"
    }
    vpc_changes = {
      pattern           = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
      description       = "CIS 3.14 -- VPC changes"
      alarm_description = "VPC change detected"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "cis" {
  for_each = local.cis_metric_filters

  name           = "cloudguard-${each.key}"
  pattern        = each.value.pattern
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name          = "cloudguard-${each.key}"
    namespace     = "CloudGuard/CIS"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis" {
  for_each = local.cis_metric_filters

  alarm_name          = "cloudguard-${each.key}"
  alarm_description   = each.value.alarm_description
  namespace           = "CloudGuard/CIS"
  metric_name         = "cloudguard-${each.key}"
  statistic           = "Sum"
  period              = 300  # 5 minutes
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]

  tags = { Name = "cloudguard-alarm-${each.key}" }
}

# ============================================================
# CloudWatch Dashboard
# ============================================================

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "CloudGuard-Security"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0; y = 0; width = 24; height = 2
        properties = {
          markdown = "## CloudGuard Security Dashboard\nCompliance status across CIS AWS Foundations Benchmark v1.4 and NIST SP 800-53 controls."
        }
      },
      {
        type   = "metric"
        x      = 0; y = 2; width = 12; height = 6
        properties = {
          title  = "Unauthorized API Calls (CIS 3.1)"
          metrics = [["CloudGuard/CIS", "cloudguard-unauthorized_api_calls"]]
          period = 300; stat = "Sum"; view = "timeSeries"
          annotations = { horizontal = [{ value = 1; color = "#ff0000"; label = "Threshold" }] }
        }
      },
      {
        type   = "metric"
        x      = 12; y = 2; width = 12; height = 6
        properties = {
          title  = "Root Account Usage (CIS 3.3)"
          metrics = [["CloudGuard/CIS", "cloudguard-root_usage"]]
          period = 300; stat = "Sum"; view = "timeSeries"
          annotations = { horizontal = [{ value = 1; color = "#ff0000"; label = "Threshold" }] }
        }
      },
      {
        type   = "metric"
        x      = 0; y = 8; width = 12; height = 6
        properties = {
          title  = "Console Logins Without MFA (CIS 3.2)"
          metrics = [["CloudGuard/CIS", "cloudguard-console_no_mfa"]]
          period = 300; stat = "Sum"; view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12; y = 8; width = 12; height = 6
        properties = {
          title   = "IAM Policy Changes (CIS 3.4)"
          metrics = [["CloudGuard/CIS", "cloudguard-iam_policy_changes"]]
          period  = 300; stat = "Sum"; view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 0; y = 14; width = 8; height = 6
        properties = {
          title   = "ALB 5xx Errors"
          metrics = [["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", aws_lb.main.arn_suffix]]
          period  = 60; stat = "Sum"; view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 8; y = 14; width = 8; height = 6
        properties = {
          title   = "RDS CPU Utilization"
          metrics = [["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.main.id]]
          period  = 60; stat = "Average"; view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 16; y = 14; width = 8; height = 6
        properties = {
          title   = "ASG Instance Count"
          metrics = [["AWS/AutoScaling", "GroupInServiceInstances", "AutoScalingGroupName", aws_autoscaling_group.app.name]]
          period  = 60; stat = "Average"; view = "timeSeries"
        }
      }
    ]
  })
}

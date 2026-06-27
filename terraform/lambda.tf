# ============================================================
# Lambda: auto-remediation + compliance report generator
# All functions run in VPC private subnet, no public IPs
# ============================================================

# Compliance reports bucket
resource "aws_s3_bucket" "compliance_reports" {
  bucket = "cloudguard-compliance-reports-${data.aws_caller_identity.current.account_id}"
  tags   = { Name = "cloudguard-compliance-reports" }
}

resource "aws_s3_bucket_versioning" "compliance_reports" {
  bucket = aws_s3_bucket.compliance_reports.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliance_reports" {
  bucket = aws_s3_bucket.compliance_reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "compliance_reports" {
  bucket                  = aws_s3_bucket.compliance_reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# -- Package Lambda source files --
data "archive_file" "remediate_s3" {
  type        = "zip"
  source_file = "${path.module}/../lambda/remediate_s3.py"
  output_path = "${path.module}/../lambda/dist/remediate_s3.zip"
}

data "archive_file" "remediate_sg" {
  type        = "zip"
  source_file = "${path.module}/../lambda/remediate_sg.py"
  output_path = "${path.module}/../lambda/dist/remediate_sg.zip"
}

data "archive_file" "compliance_report" {
  type        = "zip"
  source_file = "${path.module}/../lambda/compliance_report.py"
  output_path = "${path.module}/../lambda/dist/compliance_report.zip"
}

# ============================================================
# Lambda 1: Remediate S3 public access
# Triggered by EventBridge when Config flags an S3 bucket
# ============================================================

resource "aws_lambda_function" "remediate_s3" {
  function_name    = "cloudguard-remediate-s3-public-access"
  role             = aws_iam_role.lambda_remediation.arn
  handler          = "remediate_s3.handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.remediate_s3.output_path
  source_code_hash = data.archive_file.remediate_s3.output_base64sha256

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }

  tracing_config { mode = "Active" } # X-Ray tracing

  tags = { Name = "cloudguard-remediate-s3" }
}

# EventBridge: Config compliance change on S3 -> trigger Lambda
resource "aws_cloudwatch_event_rule" "config_s3_noncompliant" {
  name        = "cloudguard-config-s3-noncompliant"
  description = "Triggers Lambda when Config flags S3 bucket as non-compliant"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      messageType    = ["ComplianceChangeNotification"]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
      configRuleName = [
        "s3-bucket-public-read-prohibited",
        "s3-bucket-public-write-prohibited"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "remediate_s3" {
  rule      = aws_cloudwatch_event_rule.config_s3_noncompliant.name
  target_id = "RemediateS3"
  arn       = aws_lambda_function.remediate_s3.arn
}

resource "aws_lambda_permission" "allow_eventbridge_s3" {
  statement_id  = "AllowEventBridgeS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate_s3.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_s3_noncompliant.arn
}

# ============================================================
# Lambda 2: Remediate overly permissive security groups
# ============================================================

resource "aws_lambda_function" "remediate_sg" {
  function_name    = "cloudguard-remediate-sg"
  role             = aws_iam_role.lambda_remediation.arn
  handler          = "remediate_sg.handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.remediate_sg.output_path
  source_code_hash = data.archive_file.remediate_sg.output_base64sha256

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      LOG_LEVEL         = "INFO"
      SNS_TOPIC_ARN     = aws_sns_topic.security_alerts.arn
    }
  }

  tracing_config { mode = "Active" }

  tags = { Name = "cloudguard-remediate-sg" }
}

resource "aws_cloudwatch_event_rule" "config_sg_noncompliant" {
  name        = "cloudguard-config-sg-noncompliant"
  description = "Triggers Lambda when Config flags unrestricted SSH/RDP"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      messageType = ["ComplianceChangeNotification"]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
      configRuleName = [
        "restricted-ssh",
        "restricted-common-ports"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "remediate_sg" {
  rule      = aws_cloudwatch_event_rule.config_sg_noncompliant.name
  target_id = "RemediateSG"
  arn       = aws_lambda_function.remediate_sg.arn
}

resource "aws_lambda_permission" "allow_eventbridge_sg" {
  statement_id  = "AllowEventBridgeSG"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate_sg.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_sg_noncompliant.arn
}

# ============================================================
# Lambda 3: Compliance report generator (Bedrock/Claude)
# Runs on schedule, queries Security Hub, generates narrative
# ============================================================

resource "aws_lambda_function" "compliance_report" {
  function_name    = "cloudguard-compliance-report"
  role             = aws_iam_role.lambda_remediation.arn
  handler          = "compliance_report.handler"
  runtime          = "python3.12"
  timeout          = 300 # 5 min -- Bedrock calls can be slow
  memory_size      = 512
  filename         = data.archive_file.compliance_report.output_path
  source_code_hash = data.archive_file.compliance_report.output_base64sha256

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      REPORT_BUCKET     = aws_s3_bucket.compliance_reports.id
      BEDROCK_MODEL_ID  = "anthropic.claude-3-haiku-20240307-v1:0"
      AWS_REGION_NAME   = var.aws_region
      LOG_LEVEL         = "INFO"
    }
  }

  tracing_config { mode = "Active" }

  tags = { Name = "cloudguard-compliance-report" }
}

resource "aws_cloudwatch_event_rule" "compliance_report_schedule" {
  name                = "cloudguard-compliance-report-schedule"
  description         = "Triggers daily compliance report generation"
  schedule_expression = var.compliance_report_schedule
}

resource "aws_cloudwatch_event_target" "compliance_report" {
  rule      = aws_cloudwatch_event_rule.compliance_report_schedule.name
  target_id = "ComplianceReport"
  arn       = aws_lambda_function.compliance_report.arn
}

resource "aws_lambda_permission" "allow_eventbridge_report" {
  statement_id  = "AllowEventBridgeReport"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_report.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.compliance_report_schedule.arn
}

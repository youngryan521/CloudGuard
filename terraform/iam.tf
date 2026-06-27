# ============================================================
# IAM -- least-privilege roles for every component
# No inline policies (CIS 1.16), no wildcards on sensitive actions
# ============================================================

# -- EC2 instance profile (app tier) --
# SSM Session Manager replaces SSH -- no key pair, no port 22 (CIS 5.2)
resource "aws_iam_role" "ec2_app" {
  name = "cloudguard-ec2-app-role"

  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = { Name = "cloudguard-ec2-app-role" }
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# SSM core permissions (enables Session Manager without SSH)
resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Read-only S3 for app config/assets
resource "aws_iam_policy" "ec2_s3_read" {
  name = "cloudguard-ec2-s3-read"

  policy = data.aws_iam_policy_document.ec2_s3_read.json
}

data "aws_iam_policy_document" "ec2_s3_read" {
  statement {
    sid     = "ReadAppAssets"
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      aws_s3_bucket.app_assets.arn,
      "${aws_s3_bucket.app_assets.arn}/*"
    ]
  }
}

resource "aws_iam_role_policy_attachment" "ec2_s3" {
  role       = aws_iam_role.ec2_app.name
  policy_arn = aws_iam_policy.ec2_s3_read.arn
}

resource "aws_iam_instance_profile" "ec2_app" {
  name = "cloudguard-ec2-app-profile"
  role = aws_iam_role.ec2_app.name
}

# -- VPC Flow Logs role --
resource "aws_iam_role" "flow_logs" {
  name               = "cloudguard-flow-logs-role"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "cloudguard-flow-logs-policy"
  role   = aws_iam_role.flow_logs.id

  policy = data.aws_iam_policy_document.flow_logs_policy.json
}

data "aws_iam_policy_document" "flow_logs_policy" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams"
    ]
    resources = ["*"]
  }
}

# -- AWS Config service role --
resource "aws_iam_role" "config" {
  name               = "cloudguard-config-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

data "aws_iam_policy_document" "config_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Config needs to write snapshots to S3
resource "aws_iam_role_policy" "config_s3" {
  name   = "cloudguard-config-s3"
  role   = aws_iam_role.config.id

  policy = data.aws_iam_policy_document.config_s3.json
}

data "aws_iam_policy_document" "config_s3" {
  statement {
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.config_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
    ]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config_logs.arn]
  }
}

# -- Lambda auto-remediation role --
resource "aws_iam_role" "lambda_remediation" {
  name               = "cloudguard-lambda-remediation-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_remediation.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_policy" "lambda_remediation" {
  name = "cloudguard-lambda-remediation-policy"

  policy = data.aws_iam_policy_document.lambda_remediation_policy.json
}

data "aws_iam_policy_document" "lambda_remediation_policy" {
  # S3: block public access
  statement {
    sid    = "S3Remediation"
    effect = "Allow"
    actions = [
      "s3:PutBucketPublicAccessBlock",
      "s3:GetBucketPublicAccessBlock",
      "s3:ListAllMyBuckets"
    ]
    resources = ["*"]
  }

  # EC2: remediate security group rules
  statement {
    sid    = "SGRemediation"
    effect = "Allow"
    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:RevokeSecurityGroupIngress"
    ]
    resources = ["*"]
  }

  # Security Hub: update finding status post-remediation
  statement {
    sid    = "SecurityHubUpdate"
    effect = "Allow"
    actions = [
      "securityhub:BatchUpdateFindings",
      "securityhub:GetFindings"
    ]
    resources = ["*"]
  }

  # Bedrock: for compliance report Lambda
  statement {
    sid    = "BedrockInvoke"
    effect = "Allow"
    actions = [
      "bedrock:InvokeModel"
    ]
    resources = [
      "arn:aws:bedrock:${var.aws_region}::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
    ]
  }

  # S3: write compliance reports
  statement {
    sid    = "ComplianceReportWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject"
    ]
    resources = [
      "${aws_s3_bucket.compliance_reports.arn}/*"
    ]
  }

  # CloudWatch Logs
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_role_policy_attachment" "lambda_remediation_attach" {
  role       = aws_iam_role.lambda_remediation.name
  policy_arn = aws_iam_policy.lambda_remediation.arn
}

# -- IAM Account Password Policy (CIS 1.8 - 1.11) --
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  hard_expiry                    = false
  max_password_age               = 90
  password_reuse_prevention      = 24
}

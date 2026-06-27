# ============================================================
# KMS Customer Managed Keys (CMKs)
# Separate keys per service -- limits blast radius if one key
# is compromised. Rotation enabled on all (CIS 2.8).
# ============================================================

# -- S3 (CloudTrail logs, Config snapshots, compliance reports) --
resource "aws_kms_key" "s3" {
  description             = "CloudGuard: S3 encryption (CloudTrail, Config, reports)"
  deletion_window_in_days = 30
  enable_key_rotation     = true # CIS 2.8

  policy = data.aws_iam_policy_document.kms_s3.json

  tags = { Name = "cloudguard-kms-s3" }
}

resource "aws_kms_alias" "s3" {
  name          = "alias/cloudguard-s3"
  target_key_id = aws_kms_key.s3.key_id
}

# -- RDS --
resource "aws_kms_key" "rds" {
  description             = "CloudGuard: RDS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = { Name = "cloudguard-kms-rds" }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/cloudguard-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# -- EBS (EC2 root and data volumes) --
resource "aws_kms_key" "ebs" {
  description             = "CloudGuard: EBS volume encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = { Name = "cloudguard-kms-ebs" }
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/cloudguard-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

# -- CloudWatch Logs --
resource "aws_kms_key" "cloudwatch" {
  description             = "CloudGuard: CloudWatch Logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = data.aws_iam_policy_document.kms_cloudwatch.json

  tags = { Name = "cloudguard-kms-cloudwatch" }
}

resource "aws_kms_alias" "cloudwatch" {
  name          = "alias/cloudguard-cloudwatch"
  target_key_id = aws_kms_key.cloudwatch.key_id
}

# -- Secrets Manager (DB credentials) --
resource "aws_kms_key" "secrets" {
  description             = "CloudGuard: Secrets Manager encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = { Name = "cloudguard-kms-secrets" }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/cloudguard-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# -- KMS key policies --

data "aws_iam_policy_document" "kms_s3" {
  statement {
    sid     = "EnableRootAccess"
    effect  = "Allow"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
  }

  # CloudTrail needs to use this key for log encryption
  statement {
    sid    = "AllowCloudTrail"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
    }
  }
}

data "aws_iam_policy_document" "kms_cloudwatch" {
  statement {
    sid     = "EnableRootAccess"
    effect  = "Allow"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
  }

  # CloudWatch Logs service needs decrypt/encrypt for the log group
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*"
    ]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }
}

# ============================================================
# CloudTrail -- multi-region, log file validation, KMS encrypted
# Covers: CIS 2.1, 2.2, 2.3, 2.4, 2.6, 2.7
# ============================================================

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "cloudguard-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy = false # Never auto-delete audit logs
  tags          = { Name = "cloudguard-cloudtrail-logs" }
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration { status = "Enabled" }
}

# Block all public access (CIS 2.3)
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Encrypt with CMK (CIS 2.7)
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

# Access logging on the CloudTrail bucket itself (CIS 2.6)
resource "aws_s3_bucket" "cloudtrail_access_logs" {
  bucket        = "cloudguard-cloudtrail-access-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = { Name = "cloudguard-cloudtrail-access-logs" }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_access_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "cloudtrail_logs" {
  bucket        = aws_s3_bucket.cloudtrail_logs.id
  target_bucket = aws_s3_bucket.cloudtrail_access_logs.id
  target_prefix = "log/"
}

# CloudTrail needs specific bucket policy
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = data.aws_iam_policy_document.cloudtrail_s3.json
}

data "aws_iam_policy_document" "cloudtrail_s3" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/cloudguard-trail"]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/cloudguard-trail"]
    }
  }
}

# CloudWatch Log Group for CloudTrail (CIS 2.4)
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/cloudguard/cloudtrail"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.cloudwatch.arn
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name               = "cloudguard-cloudtrail-cw-role"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
}

data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name   = "cloudguard-cloudtrail-cw-policy"
  role   = aws_iam_role.cloudtrail_cloudwatch.id

  policy = data.aws_iam_policy_document.cloudtrail_cw_policy.json
}

data "aws_iam_policy_document" "cloudtrail_cw_policy" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
  }
}

# -- The trail itself (CIS 2.1, 2.2) --
resource "aws_cloudtrail" "main" {
  name                          = "cloudguard-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true  # IAM, STS events
  is_multi_region_trail         = true  # CIS 2.1
  enable_log_file_validation    = true  # CIS 2.2
  kms_key_id                    = aws_kms_key.s3.arn # CIS 2.7

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*" # CIS 2.4
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  # S3 data events: log all GetObject and PutObject (CIS 2.1.5)
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
  tags       = { Name = "cloudguard-trail" }
}

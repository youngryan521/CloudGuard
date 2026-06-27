# ============================================================
# AWS Config -- records all resource changes, 23 managed rules
# covering CIS AWS Foundations Benchmark v1.4 and NIST SP 800-53
# ============================================================

resource "aws_s3_bucket" "config_logs" {
  bucket        = "cloudguard-config-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = { Name = "cloudguard-config-logs" }
}

resource "aws_s3_bucket_versioning" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_public_access_block" "config_logs" {
  bucket                  = aws_s3_bucket.config_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
  }
}

# Config recorder -- records ALL resource types
resource "aws_config_configuration_recorder" "main" {
  name     = "cloudguard-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "cloudguard-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config_logs.id

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# ============================================================
# Config Rules -- grouped by domain
# ============================================================

# --- S3 Security (CIS 2.1.1, 2.1.2, 2.1.5) ---

resource "aws_config_config_rule" "s3_no_public_read" {
  name        = "s3-bucket-public-read-prohibited"
  description = "CIS 2.1.1 | NIST SC-7 -- S3 buckets must not allow public read"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "s3_no_public_write" {
  name        = "s3-bucket-public-write-prohibited"
  description = "CIS 2.1.2 | NIST SC-7 -- S3 buckets must not allow public write"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "s3_encryption" {
  name        = "s3-bucket-server-side-encryption-enabled"
  description = "CIS 2.1.5 | NIST SC-28 -- S3 buckets must use SSE"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "s3_logging" {
  name        = "s3-bucket-logging-enabled"
  description = "CIS 2.6 | NIST AU-2 -- S3 buckets must have access logging"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LOGGING_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# --- IAM (CIS 1.4, 1.5, 1.8-1.11, 1.14, 1.16) ---

resource "aws_config_config_rule" "iam_password_policy" {
  name        = "iam-password-policy"
  description = "CIS 1.8-1.11 | NIST IA-5 -- IAM password policy requirements"
  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }
  input_parameters = jsonencode({
    RequireUppercaseCharacters = "true"
    RequireLowercaseCharacters = "true"
    RequireSymbols             = "true"
    RequireNumbers             = "true"
    MinimumPasswordLength      = "14"
    PasswordReusePrevention    = "24"
    MaxPasswordAge             = "90"
  })
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "iam_root_access_key" {
  name        = "iam-root-access-key-check"
  description = "CIS 1.4 | NIST AC-6 -- Root account must not have active access keys"
  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "iam_mfa_console" {
  name        = "mfa-enabled-for-iam-console-access"
  description = "CIS 1.10 | NIST IA-2 -- MFA required for all console users"
  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "iam_root_mfa" {
  name        = "root-account-mfa-enabled"
  description = "CIS 1.5 | NIST IA-2 -- Root account must have MFA enabled"
  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "access_keys_rotated" {
  name        = "access-keys-rotated"
  description = "CIS 1.14 | NIST IA-5 -- IAM access keys must be rotated every 90 days"
  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }
  input_parameters = jsonencode({
    maxAccessKeyAge = tostring(var.access_key_max_age_days)
  })
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "iam_no_inline_policies" {
  name        = "iam-no-inline-policy-check"
  description = "CIS 1.16 | NIST AC-6 -- IAM users/roles must not have inline policies"
  source {
    owner             = "AWS"
    source_identifier = "IAM_NO_INLINE_POLICY_CHECK"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "iam_no_admin_policy" {
  name        = "iam-policy-no-statements-with-admin-access"
  description = "CIS 1.16 | NIST AC-6 -- No IAM policy should allow full '*:*' admin access"
  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# --- CloudTrail (CIS 2.1, 2.2, 2.7) ---

resource "aws_config_config_rule" "cloudtrail_enabled" {
  name        = "cloud-trail-enabled"
  description = "CIS 2.1 | NIST AU-2 -- CloudTrail must be enabled"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "cloudtrail_log_validation" {
  name        = "cloud-trail-log-file-validation-enabled"
  description = "CIS 2.2 | NIST AU-9 -- CloudTrail log file validation must be enabled"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "cloudtrail_encryption" {
  name        = "cloud-trail-encryption-enabled"
  description = "CIS 2.7 | NIST AU-9, SC-28 -- CloudTrail logs must be encrypted at rest"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# --- KMS (CIS 2.8) ---

resource "aws_config_config_rule" "kms_rotation" {
  name        = "cmk-backing-key-rotation-enabled"
  description = "CIS 2.8 | NIST SC-12 -- CMK key rotation must be enabled"
  source {
    owner             = "AWS"
    source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# --- Networking (CIS 5.2, 5.3, 5.4) ---

resource "aws_config_config_rule" "no_unrestricted_ssh" {
  name        = "restricted-ssh"
  description = "CIS 5.2 | NIST SC-7 -- No security group allows unrestricted SSH (port 22)"
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "no_unrestricted_rdp" {
  name        = "restricted-common-ports"
  description = "CIS 5.3 | NIST SC-7 -- No security group allows unrestricted RDP/admin ports"
  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }
  input_parameters = jsonencode({ blockedPort1 = "3389", blockedPort2 = "22" })
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "default_sg_closed" {
  name        = "vpc-default-security-group-closed"
  description = "CIS 5.4 | NIST SC-7 -- Default VPC SG must have no inbound or outbound rules"
  source {
    owner             = "AWS"
    source_identifier = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# --- Encryption at rest (CIS N/A | NIST SC-28) ---

resource "aws_config_config_rule" "ebs_encrypted" {
  name        = "encrypted-volumes"
  description = "NIST SC-28 | Well-Architected -- EBS volumes must be encrypted"
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "rds_encrypted" {
  name        = "rds-storage-encrypted"
  description = "NIST SC-28 | Well-Architected -- RDS storage must be encrypted"
  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "rds_no_public" {
  name        = "rds-instance-public-access-check"
  description = "CIS N/A | NIST SC-7 -- RDS instances must not be publicly accessible"
  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# --- Security services (NIST CA-7) ---

resource "aws_config_config_rule" "guardduty_enabled" {
  name        = "guardduty-enabled-centralized"
  description = "NIST CA-7, IR-4 -- GuardDuty must be enabled"
  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

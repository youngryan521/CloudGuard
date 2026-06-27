# CloudGuard Compliance Matrix

Mapping of CIS AWS Foundations Benchmark v1.4 and NIST SP 800-53 Rev 5 controls
to AWS services, Terraform resources, and automated enforcement mechanisms in this project.

**Legend:**
- `[Auto]` — AWS Config rule evaluates and triggers Lambda auto-remediation
- `[Monitor]` — AWS Config evaluates; CloudWatch alarm fires on violation
- `[Enforce]` — Control enforced at infrastructure level (cannot be violated without changing IaC)
- `[Detective]` — Logging or detection in place; manual review required

---

## Section 1 — Identity and Access Management

| CIS v1.4 | CIS Control Description | NIST SP 800-53 Rev 5 | AWS Config Rule | Terraform Resource | Status |
|---|---|---|---|---|---|
| 1.4 | Ensure no root account access key exists | AC-6, IA-5 | `iam-root-access-key-check` | `aws_config_config_rule.iam_root_access_key` | [Monitor] |
| 1.5 | Ensure MFA is enabled for root account | IA-2, IA-5 | `root-account-mfa-enabled` | `aws_config_config_rule.iam_root_mfa` | [Monitor] |
| 1.8 | Ensure IAM password policy requires min length 14 | IA-5 | `iam-password-policy` | `aws_iam_account_password_policy.strict` | [Enforce + Monitor] |
| 1.9 | Ensure IAM password policy prevents reuse (24) | IA-5 | `iam-password-policy` | `aws_iam_account_password_policy.strict` | [Enforce + Monitor] |
| 1.10 | Ensure MFA is enabled for all console users | IA-2 | `mfa-enabled-for-iam-console-access` | `aws_config_config_rule.iam_mfa_console` | [Monitor] |
| 1.11 | Ensure single-use credentials are disabled at creation | AC-2 | IAM Access Advisor (manual review) | — | [Detective] |
| 1.14 | Ensure access keys are rotated every 90 days | IA-5 | `access-keys-rotated` | `aws_config_config_rule.access_keys_rotated` | [Monitor] |
| 1.16 | Ensure IAM policies are attached to groups or roles only | AC-6, AC-2 | `iam-no-inline-policy-check` | `aws_config_config_rule.iam_no_inline_policies` | [Monitor] |
| 1.16 | Ensure no IAM policy allows full "\*:\*" admin | AC-6 | `iam-policy-no-statements-with-admin-access` | `aws_config_config_rule.iam_no_admin_policy` | [Monitor] |

**Architecture-level IAM controls (Enforce):**
- All EC2 instances use IAM instance profiles — no access keys on instances (`aws_iam_instance_profile.ec2_app`)
- SSH replaced by SSM Session Manager — no port 22 open anywhere (`aws_vpc_endpoint.ssm`)
- IMDSv2 enforced on all EC2 instances — prevents SSRF credential theft (`aws_launch_template.app`)
- Least-privilege policies per service component (`aws_iam_policy.*`)

---

## Section 2 — Storage

| CIS v1.4 | CIS Control Description | NIST SP 800-53 Rev 5 | AWS Config Rule | Terraform Resource | Status |
|---|---|---|---|---|---|
| 2.1.1 | Ensure S3 buckets do not allow public read | SC-7, AC-3 | `s3-bucket-public-read-prohibited` | `aws_config_config_rule.s3_no_public_read` + `aws_lambda_function.remediate_s3` | **[Auto]** |
| 2.1.2 | Ensure S3 buckets do not allow public write | SC-7, AC-3 | `s3-bucket-public-write-prohibited` | `aws_config_config_rule.s3_no_public_write` + `aws_lambda_function.remediate_s3` | **[Auto]** |
| 2.1.5 | Ensure S3 buckets use server-side encryption | SC-28 | `s3-bucket-server-side-encryption-enabled` | `aws_config_config_rule.s3_encryption` + all `aws_s3_bucket_server_side_encryption_configuration.*` | [Monitor + Enforce] |
| 2.2 | Ensure CloudTrail log file validation is enabled | AU-9, SI-7 | `cloud-trail-log-file-validation-enabled` | `aws_cloudtrail.main` (`enable_log_file_validation = true`) | [Enforce + Monitor] |
| 2.3 | Ensure CloudTrail S3 bucket is not publicly accessible | SC-7 | `s3-bucket-public-read-prohibited` | `aws_s3_bucket_public_access_block.cloudtrail_logs` | [Enforce] |
| 2.4 | Ensure CloudTrail is integrated with CloudWatch Logs | AU-2, AU-6 | — | `aws_cloudtrail.main` (`cloud_watch_logs_group_arn`) | [Enforce] |
| 2.6 | Ensure S3 bucket access logging is enabled on CloudTrail bucket | AU-2, AU-9 | `s3-bucket-logging-enabled` | `aws_s3_bucket_logging.cloudtrail_logs` | [Enforce + Monitor] |
| 2.7 | Ensure CloudTrail logs are encrypted with KMS CMK | SC-28, AU-9 | `cloud-trail-encryption-enabled` | `aws_cloudtrail.main` (`kms_key_id`) | [Enforce + Monitor] |
| 2.8 | Ensure KMS CMK rotation is enabled | SC-12 | `cmk-backing-key-rotation-enabled` | `aws_kms_key.*` (`enable_key_rotation = true`) | [Enforce + Monitor] |
| 2.9 | Ensure VPC flow logging is enabled | AU-2, SC-7 | — | `aws_flow_log.vpc` | [Enforce] |

---

## Section 3 — Logging (CloudWatch Metric Filters + Alarms)

All 14 CIS 3.x controls are implemented as CloudWatch metric filters on the CloudTrail log group
with corresponding SNS alarms. See `monitoring.tf` — `local.cis_metric_filters`.

| CIS v1.4 | CIS Control Description | NIST SP 800-53 Rev 5 | Metric Filter | Alarm | Status |
|---|---|---|---|---|---|
| 3.1 | Unauthorized API calls | AU-2, IR-5 | `cloudguard-unauthorized_api_calls` | SNS alert | [Monitor] |
| 3.2 | Console login without MFA | IA-2, AC-17 | `cloudguard-console_no_mfa` | SNS alert | [Monitor] |
| 3.3 | Root account usage | AC-6, IA-2 | `cloudguard-root_usage` | SNS alert | [Monitor] |
| 3.4 | IAM policy changes | CM-3, AC-2 | `cloudguard-iam_policy_changes` | SNS alert | [Monitor] |
| 3.5 | CloudTrail configuration changes | AU-9, CM-3 | `cloudguard-cloudtrail_config_changes` | SNS alert | [Monitor] |
| 3.6 | Console authentication failures | AC-7, IR-5 | `cloudguard-console_auth_failures` | SNS alert | [Monitor] |
| 3.7 | KMS CMK disable/delete | SC-12, CM-3 | `cloudguard-cmk_disable_delete` | SNS alert | [Monitor] |
| 3.8 | S3 bucket policy changes | CM-3, SC-7 | `cloudguard-s3_bucket_policy_changes` | SNS alert | [Monitor] |
| 3.9 | AWS Config configuration changes | CM-3, CA-7 | `cloudguard-config_changes` | SNS alert | [Monitor] |
| 3.10 | Security group changes | CM-3, SC-7 | `cloudguard-security_group_changes` | SNS alert | [Monitor] |
| 3.11 | Network ACL changes | CM-3, SC-7 | `cloudguard-nacl_changes` | SNS alert | [Monitor] |
| 3.12 | Network gateway changes | CM-3, SC-7 | `cloudguard-network_gateway_changes` | SNS alert | [Monitor] |
| 3.13 | Route table changes | CM-3, SC-7 | `cloudguard-route_table_changes` | SNS alert | [Monitor] |
| 3.14 | VPC changes | CM-3, SC-7 | `cloudguard-vpc_changes` | SNS alert | [Monitor] |

---

## Section 4 — Monitoring (Covered by Section 3 Alarms Above)

All Section 4 CIS controls (4.1–4.16) are implemented via the metric filters and alarms in
`monitoring.tf`. No additional controls required.

---

## Section 5 — Networking

| CIS v1.4 | CIS Control Description | NIST SP 800-53 Rev 5 | AWS Config Rule | Terraform Resource | Status |
|---|---|---|---|---|---|
| 5.2 | Ensure no security group allows unrestricted SSH (port 22) | SC-7 | `restricted-ssh` | `aws_config_config_rule.no_unrestricted_ssh` + `aws_lambda_function.remediate_sg` | **[Auto]** |
| 5.3 | Ensure no security group allows unrestricted RDP (port 3389) | SC-7 | `restricted-common-ports` | `aws_config_config_rule.no_unrestricted_rdp` + `aws_lambda_function.remediate_sg` | **[Auto]** |
| 5.4 | Ensure default security group restricts all traffic | SC-7 | `vpc-default-security-group-closed` | `aws_default_security_group.default` (empty rules) | [Enforce + Monitor] |

**Additional network security controls (Enforce):**
- 3-tier subnet isolation: public (ALB) / private (EC2) / isolated (RDS) (`vpc.tf`)
- RDS in isolated subnet with no internet route (`aws_route_table.isolated`)
- VPC Endpoints for S3, SSM — AWS API traffic never leaves the VPC (`security_groups.tf`)
- ALB access logs enabled (`aws_lb.main`)

---

## NIST SP 800-53 Rev 5 Control Coverage Summary

| Control Family | Control ID | Control Name | Implementation | Mechanism |
|---|---|---|---|---|
| Access Control | AC-2 | Account Management | IAM password policy, no root keys | `aws_iam_account_password_policy` + Config rules |
| Access Control | AC-3 | Access Enforcement | SG least-privilege, no public S3/RDS | Security groups + S3 public access block |
| Access Control | AC-6 | Least Privilege | Per-component IAM roles, no wildcards | `aws_iam_role.*`, `aws_iam_policy.*` |
| Access Control | AC-17 | Remote Access | SSM Session Manager replaces SSH | `aws_vpc_endpoint.ssm`, no key pairs |
| Audit and Accountability | AU-2 | Event Logging | CloudTrail multi-region, all events | `aws_cloudtrail.main` |
| Audit and Accountability | AU-6 | Audit Review | CloudWatch Logs integration | CloudTrail -> CloudWatch log group |
| Audit and Accountability | AU-9 | Protection of Audit Info | CloudTrail S3 bucket encrypted + private | KMS + bucket policy + public access block |
| Assessment and Authorization | CA-7 | Continuous Monitoring | AWS Config + Security Hub continuous eval | 23 Config rules + Security Hub standards |
| Configuration Management | CM-3 | Configuration Change Control | All 14 CIS 3.x alarms | CloudWatch metric filters on CloudTrail |
| Configuration Management | CM-6 | Configuration Settings | IaC enforced settings, drift detection | Terraform + AWS Config |
| Identification and Authentication | IA-2 | User Identification | MFA required for console + root | Config rules: `mfa-enabled-*`, `root-account-mfa-*` |
| Identification and Authentication | IA-5 | Authenticator Management | Password policy, key rotation | `aws_iam_account_password_policy` + `access-keys-rotated` |
| Incident Response | IR-4 | Incident Handling | GuardDuty with EventBridge -> SNS | `aws_guardduty_detector.main` |
| Incident Response | IR-5 | Incident Monitoring | CloudWatch alarms on auth failures | `cloudguard-console_auth_failures` |
| System and Comm Protection | SC-7 | Boundary Protection | VPC tiering, SGs, NACLs, no public access | `vpc.tf`, `security_groups.tf` |
| System and Comm Protection | SC-12 | Key Management | CMK per service, rotation enabled | `kms.tf` |
| System and Comm Protection | SC-28 | Protection of Info at Rest | KMS encryption on S3, EBS, RDS | All `*_server_side_encryption_configuration.*` |
| System and Info Integrity | SI-2 | Flaw Remediation | Auto-remediation Lambdas | `remediate_s3.py`, `remediate_sg.py` |
| System and Info Integrity | SI-3 | Malicious Code Protection | GuardDuty malware scanning | `aws_guardduty_detector.main` datasources |
| System and Info Integrity | SI-7 | Software and Info Integrity | CloudTrail log file validation | `aws_cloudtrail.main` |

---

## Encryption Coverage

| Data Store | Encryption Key | Key Rotation | Config Rule |
|---|---|---|---|
| CloudTrail S3 logs | `cloudguard-kms-s3` (CMK) | Yes | `cloud-trail-encryption-enabled` |
| AWS Config snapshots | `cloudguard-kms-s3` (CMK) | Yes | — |
| EC2 EBS volumes | `cloudguard-kms-ebs` (CMK) | Yes | `encrypted-volumes` |
| RDS PostgreSQL | `cloudguard-kms-rds` (CMK) | Yes | `rds-storage-encrypted` |
| CloudWatch Logs | `cloudguard-kms-cloudwatch` (CMK) | Yes | — |
| Secrets Manager | `cloudguard-kms-secrets` (CMK) | Yes | — |
| S3 compliance reports | `cloudguard-kms-s3` (CMK) | Yes | `s3-bucket-server-side-encryption-enabled` |
| S3 app assets | `cloudguard-kms-s3` (CMK) | Yes | `s3-bucket-server-side-encryption-enabled` |

---

## Auto-Remediation Coverage

| Finding | Config Rule Trigger | Lambda | Action | Time-to-Remediation |
|---|---|---|---|---|
| S3 bucket public read | `s3-bucket-public-read-prohibited` | `remediate_s3` | `put_public_access_block` (all 4 settings) | < 2 minutes |
| S3 bucket public write | `s3-bucket-public-write-prohibited` | `remediate_s3` | `put_public_access_block` (all 4 settings) | < 2 minutes |
| Unrestricted SSH (port 22) | `restricted-ssh` | `remediate_sg` | `revoke_security_group_ingress` (0.0.0.0/0) | < 2 minutes |
| Unrestricted RDP (port 3389) | `restricted-common-ports` | `remediate_sg` | `revoke_security_group_ingress` (0.0.0.0/0) | < 2 minutes |

---

## Control Gaps and Manual Compensating Controls

The following controls require manual implementation or are outside IaC scope:

| Control | Gap | Compensating Control |
|---|---|---|
| CIS 1.5 — Root MFA | Cannot enforce via Terraform (requires console action) | AWS Config rule alerts if not enabled |
| CIS 1.10 — User MFA | Requires per-user enforcement or identity provider | AWS Config rule monitors compliance |
| CIS 1.14 — Key rotation | Cannot force rotation; only detect overdue keys | Config rule alerts at 90 days |
| CIS 2.5 — AWS Config enabled | Config must already be enabled to detect this | Bootstrapped in `config.tf` |
| GuardDuty threat response | Findings require human triage | EventBridge -> SNS for HIGH/CRITICAL |


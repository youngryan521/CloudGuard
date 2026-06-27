"""
remediate_s3.py
Auto-remediation: block public access on S3 buckets flagged by AWS Config.
Triggered by EventBridge when Config rule s3-bucket-public-read/write-prohibited
transitions to NON_COMPLIANT.

Covers: CIS 2.1.1, 2.1.2 | NIST SC-7, AC-3
"""

import json
import logging
import os
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

s3 = boto3.client("s3")
securityhub = boto3.client("securityhub")


def handler(event, context):
    logger.info("Event received: %s", json.dumps(event))

    detail = event.get("detail", {})
    resource_id = detail.get("resourceId", "")

    # Config events pass the bucket name as resourceId
    bucket_name = resource_id
    if not bucket_name:
        logger.warning("No resourceId in event -- skipping")
        return {"status": "skipped", "reason": "no_resource_id"}

    logger.info("Remediating S3 public access on bucket: %s", bucket_name)

    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        logger.info("Successfully blocked public access on %s", bucket_name)

        # Verify the remediation took effect
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]
        all_blocked = all(config.values())

        if all_blocked:
            logger.info("Verification passed for %s", bucket_name)
            _update_securityhub_finding(detail, bucket_name, "RESOLVED")
            return {"status": "remediated", "bucket": bucket_name}
        else:
            logger.error("Verification failed for %s -- config: %s", bucket_name, config)
            return {"status": "verification_failed", "bucket": bucket_name, "config": config}

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchBucket":
            logger.warning("Bucket %s no longer exists -- skipping", bucket_name)
            return {"status": "skipped", "reason": "bucket_deleted"}
        logger.exception("Failed to remediate bucket %s: %s", bucket_name, e)
        raise


def _update_securityhub_finding(detail, bucket_name, resolution_status):
    """Mark the related Security Hub finding as RESOLVED post-remediation."""
    try:
        finding_id = detail.get("configRuleARN", "")
        if not finding_id:
            return

        account_id = boto3.client("sts").get_caller_identity()["Account"]
        region = os.environ.get("AWS_REGION", "us-east-1")

        securityhub.batch_update_findings(
            FindingIdentifiers=[{
                "Id": f"arn:aws:securityhub:{region}:{account_id}:finding/{bucket_name}-public-access",
                "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default"
            }],
            Note={
                "Text": f"Auto-remediated by CloudGuard: public access blocked on {bucket_name}",
                "UpdatedBy": "cloudguard-lambda"
            },
            Workflow={"Status": resolution_status}
        )
    except ClientError:
        # Non-fatal -- finding update failure should not block remediation success
        logger.warning("Could not update Security Hub finding for %s", bucket_name)

"""
remediate_sg.py
Auto-remediation: remove unrestricted SSH/RDP ingress rules from security groups
flagged by AWS Config rules restricted-ssh and restricted-common-ports.

Covers: CIS 5.2, 5.3 | NIST SC-7
"""

import json
import logging
import os
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

ec2 = boto3.client("ec2")
sns = boto3.client("sns")

# Ports considered admin/sensitive -- remove any 0.0.0.0/0 or ::/0 rules
RESTRICTED_PORTS = {22, 3389, 21, 23, 5900}
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")


def handler(event, context):
    logger.info("Event received: %s", json.dumps(event))

    detail = event.get("detail", {})
    sg_id = detail.get("resourceId", "")

    if not sg_id or not sg_id.startswith("sg-"):
        logger.warning("No valid security group ID in event -- skipping")
        return {"status": "skipped", "reason": "invalid_resource_id"}

    logger.info("Inspecting security group: %s", sg_id)

    try:
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        sg = response["SecurityGroups"][0]
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidGroup.NotFound":
            logger.warning("Security group %s not found -- skipping", sg_id)
            return {"status": "skipped", "reason": "sg_not_found"}
        raise

    rules_removed = []

    for rule in sg.get("IpPermissions", []):
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)

        # Check if any restricted port falls in this rule's range
        port_is_restricted = any(
            from_port <= p <= to_port for p in RESTRICTED_PORTS
        ) or (from_port == -1 and to_port == -1)  # ICMP all

        # Check for world-open CIDRs
        open_ipv4 = [r for r in rule.get("IpRanges", []) if r["CidrIp"] == "0.0.0.0/0"]
        open_ipv6 = [r for r in rule.get("Ipv6Ranges", []) if r["CidrIpv6"] == "::/0"]

        if port_is_restricted and (open_ipv4 or open_ipv6):
            logger.warning(
                "Removing unrestricted rule on port %s-%s in SG %s",
                from_port, to_port, sg_id
            )
            # Build minimal rule to revoke -- only the offending CIDRs
            revoke_rule = {
                "IpProtocol": rule["IpProtocol"],
                "FromPort": from_port,
                "ToPort": to_port,
                "IpRanges": open_ipv4,
                "Ipv6Ranges": open_ipv6,
            }
            try:
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[revoke_rule]
                )
                rules_removed.append(f"port {from_port}-{to_port} 0.0.0.0/0")
            except ClientError as e:
                logger.error("Failed to revoke rule in %s: %s", sg_id, e)

    if rules_removed:
        msg = (
            f"CloudGuard auto-remediated security group {sg_id}.\n"
            f"Removed rules: {', '.join(rules_removed)}\n"
            f"These rules allowed unrestricted access to sensitive ports.\n"
            f"Review and re-add with specific CIDR ranges if access is needed."
        )
        logger.info(msg)
        _notify(f"[CloudGuard] SG Remediation: {sg_id}", msg)
        return {"status": "remediated", "sg_id": sg_id, "rules_removed": rules_removed}

    logger.info("No unrestricted rules found in %s -- may have been already fixed", sg_id)
    return {"status": "no_action_needed", "sg_id": sg_id}


def _notify(subject, message):
    if not SNS_TOPIC_ARN:
        return
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    except ClientError:
        logger.warning("Failed to publish SNS notification")

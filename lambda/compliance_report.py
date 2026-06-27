"""
compliance_report.py
Daily compliance report generator.
Queries Security Hub for findings, summarizes by CIS/NIST control,
calls Amazon Bedrock (Claude 3 Haiku) to generate a human-readable
executive narrative, and saves the report to S3.

Covers: NIST CA-7 (Continuous Monitoring), SI-2 (Flaw Remediation)
"""

import json
import logging
import os
import datetime
import boto3
from collections import defaultdict
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

securityhub = boto3.client("securityhub")
bedrock = boto3.client("bedrock-runtime", region_name=os.environ.get("AWS_REGION_NAME", "us-east-1"))
s3 = boto3.client("s3")

REPORT_BUCKET = os.environ["REPORT_BUCKET"]
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")

# Only report on ACTIVE findings (not suppressed/resolved)
FINDING_FILTERS = {
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
}


def handler(event, context):
    logger.info("Starting compliance report generation")

    findings = _get_all_findings()
    logger.info("Retrieved %d active findings", len(findings))

    summary = _summarize_findings(findings)
    narrative = _generate_narrative(summary, findings)
    report = _build_report(summary, narrative, findings)

    report_key = _save_report(report)
    logger.info("Report saved to s3://%s/%s", REPORT_BUCKET, report_key)

    return {
        "status": "success",
        "report_key": report_key,
        "finding_count": len(findings),
        "critical_count": summary["by_severity"].get("CRITICAL", 0),
        "high_count": summary["by_severity"].get("HIGH", 0),
    }


def _get_all_findings():
    """Page through all active Security Hub findings."""
    findings = []
    paginator = securityhub.get_paginator("get_findings")

    for page in paginator.paginate(Filters=FINDING_FILTERS, MaxResults=100):
        findings.extend(page["Findings"])

    return findings


def _summarize_findings(findings):
    """Build structured summary: counts by severity, by control, by resource type."""
    by_severity = defaultdict(int)
    by_control = defaultdict(list)
    by_resource_type = defaultdict(int)
    auto_remediated = 0

    for f in findings:
        severity = f.get("Severity", {}).get("Label", "UNKNOWN")
        by_severity[severity] += 1

        for resource in f.get("Resources", []):
            by_resource_type[resource.get("Type", "Unknown")] += 1

        # Extract control IDs from finding metadata
        for compliance in f.get("Compliance", {}).get("RelatedRequirements", []):
            by_control[compliance].append({
                "title": f.get("Title", ""),
                "severity": severity,
                "resource": f.get("Resources", [{}])[0].get("Id", ""),
            })

        if "cloudguard-lambda" in f.get("Note", {}).get("UpdatedBy", ""):
            auto_remediated += 1

    return {
        "total": len(findings),
        "by_severity": dict(by_severity),
        "by_control": dict(by_control),
        "by_resource_type": dict(by_resource_type),
        "auto_remediated": auto_remediated,
    }


def _generate_narrative(summary, findings):
    """Call Bedrock/Claude to write an executive compliance summary."""
    # Build a compact findings digest for the prompt (token-efficient)
    top_findings = []
    for f in sorted(findings, key=lambda x: _severity_rank(x), reverse=True)[:15]:
        top_findings.append({
            "title": f.get("Title", ""),
            "severity": f.get("Severity", {}).get("Label", ""),
            "description": f.get("Description", "")[:200],
            "resource_type": f.get("Resources", [{}])[0].get("Type", ""),
        })

    prompt = f"""You are a cloud security compliance analyst. Based on the following AWS Security Hub findings summary, write a concise executive compliance report.

FINDINGS SUMMARY:
- Total active findings: {summary['total']}
- By severity: {json.dumps(summary['by_severity'])}
- Auto-remediated by automation: {summary['auto_remediated']}
- Resource types affected: {json.dumps(dict(list(summary['by_resource_type'].items())[:5]))}

TOP FINDINGS (by severity):
{json.dumps(top_findings, indent=2)}

Write a 3-paragraph executive summary:
1. Overall compliance posture (1-2 sentences with key metrics)
2. Top risks and affected resources (specific, actionable)
3. Remediation status and recommended next steps

Be direct and specific. Avoid filler language. Target audience: CISO and engineering leads."""

    try:
        response = bedrock.converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 600, "temperature": 0.2},
        )
        return response["output"]["message"]["content"][0]["text"]
    except ClientError as e:
        logger.warning("Bedrock call failed: %s -- using fallback narrative", e)
        return _fallback_narrative(summary)


def _fallback_narrative(summary):
    """Fallback if Bedrock is unavailable or not yet enabled."""
    sev = summary["by_severity"]
    critical = sev.get("CRITICAL", 0)
    high = sev.get("HIGH", 0)
    return (
        f"CloudGuard detected {summary['total']} active security findings. "
        f"{critical} CRITICAL and {high} HIGH severity findings require immediate attention. "
        f"{summary['auto_remediated']} findings were automatically remediated. "
        f"Review the detailed findings table below and prioritize CRITICAL items first."
    )


def _build_report(summary, narrative, findings):
    """Assemble the full JSON report object saved to S3."""
    now = datetime.datetime.utcnow()
    return {
        "report_metadata": {
            "generated_at": now.isoformat() + "Z",
            "report_date": now.strftime("%Y-%m-%d"),
            "generator": "CloudGuard Compliance Report v1.0",
            "frameworks": ["CIS AWS Foundations Benchmark v1.4", "NIST SP 800-53 Rev 5", "AWS FSBP v1.0"],
        },
        "executive_summary": narrative,
        "finding_counts": summary["by_severity"],
        "auto_remediated_count": summary["auto_remediated"],
        "top_findings": [
            {
                "title": f.get("Title"),
                "severity": f.get("Severity", {}).get("Label"),
                "resource_id": f.get("Resources", [{}])[0].get("Id", ""),
                "resource_type": f.get("Resources", [{}])[0].get("Type", ""),
                "remediation": f.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
            }
            for f in sorted(findings, key=_severity_rank, reverse=True)[:50]
        ],
        "control_coverage": {
            "cis_14_controls_monitored": 23,
            "nist_80053_controls_monitored": 12,
        },
    }


def _save_report(report):
    now = datetime.datetime.utcnow()
    key = f"reports/{now.strftime('%Y/%m/%d')}/cloudguard-compliance-report-{now.strftime('%H%M%S')}.json"

    s3.put_object(
        Bucket=REPORT_BUCKET,
        Key=key,
        Body=json.dumps(report, indent=2).encode("utf-8"),
        ContentType="application/json",
        ServerSideEncryption="aws:kms",
    )
    return key


def _severity_rank(finding):
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}
    return order.get(finding.get("Severity", {}).get("Label", ""), 0)

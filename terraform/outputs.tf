output "vpc_id" {
  value = aws_vpc.main.id
}

output "alb_dns_name" {
  description = "Public DNS of the ALB -- access the app here"
  value       = aws_lb.main.dns_name
}

output "cloudtrail_bucket" {
  value = aws_s3_bucket.cloudtrail_logs.id
}

output "config_bucket" {
  value = aws_s3_bucket.config_logs.id
}

output "compliance_reports_bucket" {
  value = aws_s3_bucket.compliance_reports.id
}

output "cloudwatch_dashboard_url" {
  description = "Direct URL to the CloudGuard security dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=CloudGuard-Security"
}

output "security_hub_url" {
  description = "Direct URL to Security Hub findings"
  value       = "https://${var.aws_region}.console.aws.amazon.com/securityhub/home?region=${var.aws_region}#/summary"
}

output "rds_endpoint" {
  description = "RDS endpoint (private -- accessible from app tier only)"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}

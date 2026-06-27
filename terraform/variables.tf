variable "aws_region" {
  description = "AWS region to deploy all resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "owner_tag" {
  description = "Owner tag applied to all resources"
  type        = string
  default     = "cloudguard"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

# 3 AZs, 3 subnet tiers: public (ALB), private (EC2), isolated (RDS)
variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
}

variable "isolated_subnet_cidrs" {
  description = "Isolated subnets for RDS -- no route to internet"
  type        = list(string)
  default     = ["10.0.21.0/24", "10.0.22.0/24", "10.0.23.0/24"]
}

variable "app_instance_type" {
  description = "EC2 instance type for app tier"
  type        = string
  default     = "t3.micro" # Free tier eligible
}

variable "asg_min_size" {
  type    = number
  default = 1
}

variable "asg_max_size" {
  type    = number
  default = 3
}

variable "asg_desired_capacity" {
  type    = number
  default = 1
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro" # Free tier eligible
}

variable "db_name" {
  type    = string
  default = "cloudguarddb"
}

variable "db_username" {
  description = "RDS master username -- store real value in SSM or tfvars (never commit)"
  type        = string
  default     = "cgadmin"
  sensitive   = true
}

variable "db_password" {
  description = "RDS master password -- store in SSM Parameter Store, not here"
  type        = string
  sensitive   = true
}

variable "db_multi_az" {
  description = "Enable Multi-AZ for RDS (set true in prod)"
  type        = bool
  default     = false
}

variable "alert_email" {
  description = "Email address for security finding notifications"
  type        = string
  default     = ""
}

variable "access_key_max_age_days" {
  description = "Max allowed age (days) for IAM access keys before Config flags them"
  type        = number
  default     = 90
}

variable "compliance_report_schedule" {
  description = "EventBridge cron for compliance report Lambda (UTC)"
  type        = string
  default     = "cron(0 8 * * ? *)" # 8am UTC daily
}

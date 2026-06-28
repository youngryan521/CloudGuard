# ============================================================
# Compute: ALB + EC2 Auto Scaling Group
# No SSH key pair -- use SSM Session Manager for shell access
# IMDSv2 enforced on all instances
# EBS volumes encrypted with CMK
# ============================================================

resource "aws_s3_bucket" "app_assets" {
  bucket = "cloudguard-app-assets-${data.aws_caller_identity.current.account_id}"
  tags   = { Name = "cloudguard-app-assets" }
}

resource "aws_s3_bucket_versioning" "app_assets" {
  bucket = aws_s3_bucket.app_assets.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_assets" {
  bucket = aws_s3_bucket.app_assets.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "app_assets" {
  bucket                  = aws_s3_bucket.app_assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# -- ALB --
resource "aws_lb" "main" {
  name               = "cloudguard-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = "alb"
    enabled = true
  }

  drop_invalid_header_fields = true

  tags = { Name = "cloudguard-alb" }
}

resource "aws_s3_bucket" "alb_logs" {
  bucket        = "cloudguard-alb-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags          = { Name = "cloudguard-alb-logs" }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_elb_service_account" "main" {}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = data.aws_elb_service_account.main.arn }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.alb_logs.arn}/alb/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    }]
  })
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_target_group" "app" {
  name     = "cloudguard-app-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
  }

  tags = { Name = "cloudguard-app-tg" }
}

# -- Launch Template --
# user_data uses printf to avoid nested heredoc syntax issues in HCL
locals {
  user_data_script = <<-SCRIPT
    #!/bin/bash
    set -euo pipefail
    dnf update -y
    dnf install -y nginx

    printf '{"status": "healthy", "service": "cloudguard-app"}\n' \
      > /usr/share/nginx/html/health

    printf 'server {\n  listen 8080;\n  location /health {\n    root /usr/share/nginx/html;\n    default_type application/json;\n  }\n  location / {\n    root /usr/share/nginx/html;\n  }\n}\n' \
      > /etc/nginx/conf.d/app.conf

    systemctl enable nginx
    systemctl start nginx
  SCRIPT
}

resource "aws_launch_template" "app" {
  name_prefix   = "cloudguard-app-"
  image_id      = data.aws_ssm_parameter.al2023_ami.value
  instance_type = var.app_instance_type

  key_name = null

  vpc_security_group_ids = [aws_security_group.app.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_app.name
  }

  # IMDSv2 required -- prevents SSRF-based metadata theft
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 20
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.ebs.arn
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  user_data = base64encode(local.user_data_script)

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "cloudguard-launch-template" }
}

# -- Auto Scaling Group --
resource "aws_autoscaling_group" "app" {
  name                = "cloudguard-app-asg"
  desired_capacity    = var.asg_desired_capacity
  min_size            = var.asg_min_size
  max_size            = var.asg_max_size
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.app.arn]
  health_check_type   = "ELB"

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "Name"
    value               = "cloudguard-app"
    propagate_at_launch = true
  }
}

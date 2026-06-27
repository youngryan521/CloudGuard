# ============================================================
# Security Groups -- least-privilege, explicit deny by default
# No SG allows 0.0.0.0/0 SSH or RDP (CIS 5.2, 5.3)
# ============================================================

# -- ALB: accepts HTTPS from internet, HTTP only for redirect --
resource "aws_security_group" "alb" {
  name        = "cloudguard-alb-sg"
  description = "ALB: inbound HTTPS/HTTP from internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP redirect only"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Outbound to app tier only"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.private_subnet_cidrs
  }

  tags = { Name = "cloudguard-alb-sg" }
}

# -- App tier: accepts traffic from ALB only, no direct internet --
resource "aws_security_group" "app" {
  name        = "cloudguard-app-sg"
  description = "App tier EC2: inbound from ALB only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "App port from ALB only"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Outbound: HTTPS for AWS API calls (SSM, S3, etc.) and DB access
  egress {
    description = "HTTPS to AWS APIs and internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description     = "PostgreSQL to RDS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.rds.id]
  }

  tags = { Name = "cloudguard-app-sg" }
}

# -- RDS: accepts PostgreSQL from app tier only --
resource "aws_security_group" "rds" {
  name        = "cloudguard-rds-sg"
  description = "RDS: inbound from app tier only, no public access"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from app tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  # No egress needed -- RDS doesn't initiate outbound connections
  tags = { Name = "cloudguard-rds-sg" }
}

# -- Lambda: outbound HTTPS only (for AWS API calls and Bedrock) --
resource "aws_security_group" "lambda" {
  name        = "cloudguard-lambda-sg"
  description = "Lambda functions: outbound HTTPS only"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS to AWS APIs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "cloudguard-lambda-sg" }
}

# -- VPC Endpoints: keep AWS API traffic off the public internet --
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.app.id]
  private_dns_enabled = true
  tags                = { Name = "cloudguard-ep-ssm" }
}

resource "aws_vpc_endpoint" "ssm_messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.app.id]
  private_dns_enabled = true
  tags                = { Name = "cloudguard-ep-ssmmessages" }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id, aws_route_table.isolated.id]
  tags              = { Name = "cloudguard-ep-s3" }
}

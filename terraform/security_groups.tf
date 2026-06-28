# ============================================================
# Security Groups
# Cross-SG references (app <-> rds) are broken out into
# separate aws_security_group_rule resources to avoid the
# circular dependency that occurs when both SGs reference
# each other inline.
# ============================================================

# -- ALB: accepts HTTPS/HTTP from internet --
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

# -- App tier: accepts traffic from ALB only --
# RDS egress rule is defined separately below to break the cycle
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

  egress {
    description = "HTTPS to AWS APIs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "cloudguard-app-sg" }
}

# -- RDS: no inline rules referencing app SG (defined separately below) --
resource "aws_security_group" "rds" {
  name        = "cloudguard-rds-sg"
  description = "RDS: inbound from app tier only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "cloudguard-rds-sg" }
}

# -- Lambda: outbound HTTPS only --
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

# -- Cross-SG rules (added after both SGs exist, breaking the cycle) --

resource "aws_security_group_rule" "app_to_rds" {
  type                     = "egress"
  description              = "PostgreSQL from app tier to RDS"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.rds.id
}

resource "aws_security_group_rule" "rds_from_app" {
  type                     = "ingress"
  description              = "PostgreSQL from app tier"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.rds.id
  source_security_group_id = aws_security_group.app.id
}

# -- VPC Endpoints --
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

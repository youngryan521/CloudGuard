# ============================================================
# VPC + Networking
# 3-tier subnet layout:
#   public    -> ALB (internet-facing)
#   private   -> EC2 app tier (outbound via NAT)
#   isolated  -> RDS (no internet route at all)
# ============================================================

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "cloudguard-vpc" }
}

# -- Public subnets (ALB) --
resource "aws_subnet" "public" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.public_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  # ALB requires public IPs -- EC2 instances themselves do NOT get public IPs
  map_public_ip_on_launch = false

  tags = { Name = "cloudguard-public-${count.index + 1}", Tier = "public" }
}

# -- Private subnets (EC2 app tier) --
resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  map_public_ip_on_launch = false

  tags = { Name = "cloudguard-private-${count.index + 1}", Tier = "private" }
}

# -- Isolated subnets (RDS) -- no route table entry pointing outbound --
resource "aws_subnet" "isolated" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.isolated_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  map_public_ip_on_launch = false

  tags = { Name = "cloudguard-isolated-${count.index + 1}", Tier = "isolated" }
}

# -- Internet Gateway --
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "cloudguard-igw" }
}

# -- Elastic IP + NAT Gateway (single AZ for dev cost; use count=3 in prod) --
resource "aws_eip" "nat" {
  domain     = "vpc"
  depends_on = [aws_internet_gateway.main]
  tags       = { Name = "cloudguard-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id # Place NAT in first public subnet
  depends_on    = [aws_internet_gateway.main]
  tags          = { Name = "cloudguard-nat" }
}

# -- Route tables --
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "cloudguard-rt-public" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = { Name = "cloudguard-rt-private" }
}

resource "aws_route_table" "isolated" {
  vpc_id = aws_vpc.main.id
  # No outbound route -- isolated subnets have no internet access
  tags = { Name = "cloudguard-rt-isolated" }
}

# -- Route table associations --
resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "isolated" {
  count          = 3
  subnet_id      = aws_subnet.isolated[count.index].id
  route_table_id = aws_route_table.isolated.id
}

# -- VPC Flow Logs -> CloudWatch (CIS 2.9) --
resource "aws_flow_log" "vpc" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn

  tags = { Name = "cloudguard-vpc-flow-logs" }
}

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/cloudguard/vpc/flow-logs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.cloudwatch.arn
}

# -- Default VPC security group: deny all (CIS 5.4) --
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  # No ingress/egress rules -- effectively blocks all traffic on the default SG
  tags = { Name = "cloudguard-default-sg-deny-all" }
}

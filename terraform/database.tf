# ============================================================
# RDS PostgreSQL -- isolated subnet, encrypted, no public access
# ============================================================

resource "aws_db_subnet_group" "main" {
  name       = "cloudguard-db-subnet-group"
  subnet_ids = aws_subnet.isolated[*].id
  tags       = { Name = "cloudguard-db-subnet-group" }
}

# Store credentials in Secrets Manager, not plaintext
resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "cloudguard/rds/master-credentials"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = 7
  tags                    = { Name = "cloudguard-db-secret" }
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = var.db_username
    password = var.db_password
  })
}

resource "aws_db_instance" "main" {
  identifier = "cloudguard-postgres"

  engine               = "postgres"
  engine_version       = "15.7"
  instance_class       = var.db_instance_class
  allocated_storage    = 20
  max_allocated_storage = 100 # Auto-scaling up to 100 GB
  storage_type         = "gp3"

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  multi_az            = var.db_multi_az
  publicly_accessible = false # CIS -- no public RDS

  # Encryption at rest with CMK
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  # Automated backups (7-day retention)
  backup_retention_period    = 7
  backup_window              = "03:00-04:00"
  maintenance_window         = "sun:04:00-sun:05:00"
  copy_tags_to_snapshot      = true
  delete_automated_backups   = false

  # Enhanced monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  # Performance Insights
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.rds.arn
  performance_insights_retention_period = 7

  # Audit logging to CloudWatch
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  auto_minor_version_upgrade  = true
  deletion_protection         = false # Set true in prod
  skip_final_snapshot         = true  # Set false in prod
  apply_immediately           = false

  tags = { Name = "cloudguard-postgres" }
}

# RDS Enhanced Monitoring role
resource "aws_iam_role" "rds_monitoring" {
  name               = "cloudguard-rds-monitoring-role"
  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_assume.json
}

data "aws_iam_policy_document" "rds_monitoring_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

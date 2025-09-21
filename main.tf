# -------------------------------------------
# 1. KMS Key for RDS & Secrets Manager
# -------------------------------------------
resource "aws_kms_key" "rds_kms" {
  description             = "Customer managed KMS key for RDS and Secrets Manager"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "rds_kms_alias" {
  name          = "alias/rds-db-key"
  target_key_id = aws_kms_key.rds_kms.key_id
}

# -------------------------------------------
# 2. Generate random master password
# -------------------------------------------
resource "random_password" "db_master" {
  length  = 16
  special = true
}

# -------------------------------------------
# 3. Store DB password in Secrets Manager
# -------------------------------------------
resource "aws_secretsmanager_secret" "db_password" {
  name        = "devsecopstest-db-master-password"
  description = "Master password for devsecopstest RDS"
  kms_key_id  = aws_kms_key.rds_kms.arn
}

resource "aws_secretsmanager_secret_version" "db_password_value" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_master.result
}

# -------------------------------------------
# 4. RDS Security Group
# -------------------------------------------
resource "aws_security_group" "rds_sg" {
  name        = "devsecopstest-db-sg"
  description = "Allow access to RDS from app or bastion"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.app_sg_id] # app SG or bastion SG
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# -------------------------------------------
# 5. RDS Instance (PostgreSQL)
# -------------------------------------------
resource "aws_db_instance" "mydb" {
  identifier                      = "devsecopstest-db"
  engine                          = "postgres"
  engine_version                  = "15.3"
  instance_class                  = "db.t3.medium"
  allocated_storage               = 20
  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.rds_kms.arn
  username                        = "masteruser"
  password                        = random_password.db_master.result
  db_subnet_group_name            = aws_db_subnet_group.example.name
  vpc_security_group_ids          = [aws_security_group.rds_sg.id]
  skip_final_snapshot             = true

  # Security best practices
  iam_database_authentication_enabled = true
  publicly_accessible                 = false
  apply_immediately                   = true
}

# -------------------------------------------
# 6. Application IAM role permissions for KMS & Secrets Manager
# -------------------------------------------
resource "aws_iam_role_policy" "devsecopstest_role_policy" {
  role = "devsecopstest-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowSecretsManagerRead"
        Effect   = "Allow"
        Action   = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.db_password.arn
      },
      {
        Sid      = "AllowKMSDecrypt"
        Effect   = "Allow"
        Action   = [
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.rds_kms.arn
      },
      {
        Sid      = "AllowRDSConnect"
        Effect   = "Allow"
        Action   = [
          "rds-db:connect"
        ]
        Resource = "arn:aws:rds-db:${var.region}:${data.aws_caller_identity.current.account_id}:dbuser:*/appuser"
      }
    ]
  })
}

# -------------------------------------------
# 7. Optional: DB subnet group
# -------------------------------------------
resource "aws_db_subnet_group" "example" {
  name       = "devsecopstest-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "devsecopstest-subnet-group"
  }
}

# -------------------------------------------
# 8. Get current AWS account ID
# -------------------------------------------
data "aws_caller_identity" "current" {}

# Terraform_RDS_Security_Best_Practice

This Terraform project provisions a secure PostgreSQL RDS instance for the devsecopstest application with best-practice security configurations.

Security Highlights: 
RDS encrypted at rest with a customer-managed KMS key.
Master password stored in AWS Secrets Manager — the application reads it securely, and AWS KMS decrypts it automatically.
IAM database authentication enabled — application users can connect to the database without static passwords.
Restricted security group — the database is not publicly accessible, only accessible from approved application or bastion hosts.
KMS key rotation enabled — annual rotation to maintain key security.
Least-privilege IAM policy applied to the application role: the role can only access necessary secrets, decrypt the KMS key, and connect to the RDS database.
SSL-only connections can be enforced via the rds.force_ssl parameter group if desired


Notes
Secure Terraform state (S3 + KMS) for sensitive info.
Restrict Security Group to trusted hosts only.
Keep master credentials in Secrets Manager, not in code.
Monitor KMS usage and rotation for compliance.

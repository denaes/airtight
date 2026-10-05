resource "aws_iam_policy" "read_only_iam" {
  name = "ReadOnlyIAM"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:GetRole", "iam:ListRoles", "iam:GetUser"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "s3_access" {
  name = "S3Access"
  role = "app-role"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::my-bucket/*"
  }]
}
POLICY
}

resource "aws_iam_policy" "explicit_deny_version" {
  name = "DenyPolicyEscalation"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = ["iam:CreatePolicyVersion"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_policy" "describe_ec2" {
  name = "DescribeEC2"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"]
      Resource = "*"
    }]
  })
}

resource "aws_s3_bucket_policy" "bucket_policy" {
  bucket = "my-bucket"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*"
  }]
}
EOF
}

resource "aws_iam_role_policy" "sqs_send" {
  name = "SQSSendMessage"
  role = "worker-role"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = "*"
    }]
  })
}

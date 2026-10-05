resource "aws_iam_policy" "create_policy_version" {
  name = "EscalateViaPolicyVersion"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:CreatePolicyVersion"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "set_default_version" {
  name = "EscalateViaSetDefault"
  role = "my-role"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:SetDefaultPolicyVersion",
    "Resource": "*"
  }]
}
POLICY
}

resource "aws_iam_policy" "pass_role_lambda" {
  name = "EscalateViaLambdaPassRole"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "lambda:CreateFunction"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "attach_role_policy" {
  name = "EscalateViaAttachPolicy"
  role = "dev-role"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:AttachRolePolicy"],
    "Resource": "*"
  }]
}
EOF
}

resource "aws_iam_policy" "pass_role_ec2" {
  name = "EscalateViaEC2PassRole"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:RunInstances", "iam:PassRole"]
      Resource = "*"
    }]
  })
}

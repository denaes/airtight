resource "aws_iam_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":["*"]}]}
POLICY
}

resource "aws_iam_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}
POLICY
}

resource "aws_iam_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Action":"logs:PutLogEvents","Resource":"*"}]}
POLICY
}

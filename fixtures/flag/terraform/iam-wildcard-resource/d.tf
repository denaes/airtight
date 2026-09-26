resource "aws_iam_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}
POLICY
}

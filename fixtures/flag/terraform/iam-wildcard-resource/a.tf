resource "aws_iam_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}
POLICY
}

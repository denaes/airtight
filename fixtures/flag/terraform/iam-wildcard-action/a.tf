resource "aws_iam_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::b/*"}]}
POLICY
}

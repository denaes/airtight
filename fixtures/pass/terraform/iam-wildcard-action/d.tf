resource "aws_iam_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::1:role/r"}]}
POLICY
}

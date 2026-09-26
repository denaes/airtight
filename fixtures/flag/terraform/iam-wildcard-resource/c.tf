resource "aws_iam_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource" : "*"}]}
POLICY
}

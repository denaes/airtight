resource "aws_iam_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}
POLICY
}

resource "aws_s3_bucket_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}
POLICY
}

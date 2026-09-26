resource "aws_s3_bucket_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Principal":{"Service":"cloudfront.amazonaws.com"},"Action":"s3:GetObject"}]}
POLICY
}

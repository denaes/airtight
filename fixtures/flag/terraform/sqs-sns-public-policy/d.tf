resource "aws_sqs_queue_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Principal":{"AWS": "*"},"Action":"sqs:*"}]}
POLICY
}

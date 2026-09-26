resource "aws_sqs_queue_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::2:role/r"},"Action":"sqs:*"}]}
POLICY
}

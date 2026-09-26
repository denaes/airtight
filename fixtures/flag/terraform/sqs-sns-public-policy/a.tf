resource "aws_sqs_queue_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage"}]}
POLICY
}

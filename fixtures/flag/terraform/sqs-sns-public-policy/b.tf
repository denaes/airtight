resource "aws_sns_topic_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sns:Publish"}]}
POLICY
}

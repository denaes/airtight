resource "aws_sns_topic_policy" "p" {
  policy = <<POLICY
{"Statement":[{"Effect":"Deny","Principal":"*","Action":"sns:Publish"}]}
POLICY
}

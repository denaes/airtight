resource "aws_sqs_queue" "aws_managed_kms" {
  name              = "encrypted-aws-kms-queue"
  kms_master_key_id = "alias/aws/sqs"
}

resource "aws_sqs_queue" "custom_kms_arn" {
  name              = "encrypted-custom-kms-queue"
  kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
}

resource "aws_sqs_queue" "sse_sqs_enabled" {
  name                    = "encrypted-sse-sqs-queue"
  sqs_managed_sse_enabled = true
}

resource "aws_sqs_queue" "both_configured" {
  name                    = "encrypted-both-queue"
  kms_master_key_id       = "alias/my-company-sqs"
  sqs_managed_sse_enabled = true
}

resource "aws_sns_topic" "unencrypted_topic" {
  name = "notification-topic"
}

resource "aws_sqs_queue" "kms_reference" {
  name              = "encrypted-ref-queue"
  kms_master_key_id = "var.kms_key_id"
}

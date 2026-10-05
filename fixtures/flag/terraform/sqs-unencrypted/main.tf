resource "aws_sqs_queue" "default_queue" {
  name = "unencrypted-default-queue"
}

resource "aws_sqs_queue" "explicitly_disabled" {
  name                    = "explicitly-unencrypted-queue"
  sqs_managed_sse_enabled = false
}

resource "aws_sqs_queue" "fifo_unencrypted" {
  name                        = "orders.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
}

resource "aws_sqs_queue" "dead_letter_queue" {
  name                      = "unencrypted-dlq"
  message_retention_seconds = 86400
}

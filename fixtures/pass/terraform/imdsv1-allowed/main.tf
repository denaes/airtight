resource "aws_instance" "a" {
  metadata_options {
    http_tokens = "required"
    http_put_response_hop_limit = 1
  }
}
resource "aws_instance" "b" {
  metadata_options {
    http_tokens = "required"
    http_put_response_hop_limit = 1
  }
}
resource "aws_instance" "c" {
  metadata_options {
    http_tokens = "required"
    http_put_response_hop_limit = 1
  }
}
resource "aws_instance" "d" {
  metadata_options {
    http_tokens = var.tokens
  }
}
resource "aws_instance" "e" {
  ami = "ami-123"
}

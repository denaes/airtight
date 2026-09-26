resource "aws_s3_bucket" "a" {
  acl = "private"
}
resource "aws_s3_bucket_acl" "b" {
  acl = "log-delivery-write"
}
resource "aws_s3_bucket" "c" {
  acl = var.acl
}
resource "aws_s3_bucket" "d" {
  bucket = "no-acl-at-all"
}
resource "aws_cloudfront_distribution" "e" {
  acl = "public-read"
}

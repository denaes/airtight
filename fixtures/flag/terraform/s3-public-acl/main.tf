resource "aws_s3_bucket" "a" {
  acl = "public-read"
}
resource "aws_s3_bucket" "b" {
  acl = "public-read-write"
}
resource "aws_s3_bucket_acl" "c" {
  acl = "public-read"
}
resource "aws_s3_bucket_acl" "d" {
  acl = "public-read-write"
}

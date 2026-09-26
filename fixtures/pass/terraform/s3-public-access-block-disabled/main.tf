resource "aws_s3_bucket_public_access_block" "a" {
  block_public_acls = true
  block_public_policy = true
}
resource "aws_s3_bucket_public_access_block" "b" {
  block_public_acls = true
  block_public_policy = true
}
resource "aws_s3_bucket_public_access_block" "c" {
  block_public_acls = true
  block_public_policy = true
}
resource "aws_s3_bucket_public_access_block" "d" {
  block_public_acls = true
  block_public_policy = true
}
resource "aws_s3_bucket_public_access_block" "e" {
  block_public_acls = var.block
}

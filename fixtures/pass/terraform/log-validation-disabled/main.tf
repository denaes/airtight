resource "aws_cloudtrail" "a" {
  enable_log_file_validation = true
}
resource "aws_cloudtrail" "b" {
  enable_log_file_validation = true
}
resource "aws_cloudtrail" "c" {
  enable_log_file_validation = true
}
resource "aws_cloudtrail" "d" {
  enable_log_file_validation = var.validate
}
resource "aws_cloudtrail" "e" {
  name = "trail"
}

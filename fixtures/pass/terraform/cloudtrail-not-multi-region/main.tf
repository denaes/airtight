resource "aws_cloudtrail" "a" {
  is_multi_region_trail = true
  enable_log_file_validation = true
}
resource "aws_cloudtrail" "b" {
  is_multi_region_trail = true
  enable_log_file_validation = true
}
resource "aws_cloudtrail" "c" {
  is_multi_region_trail = true
  enable_log_file_validation = true
}
resource "aws_cloudtrail" "d" {
  is_multi_region_trail = var.multi
}
resource "aws_cloudtrail" "e" {
  name = "trail"
}

resource "aws_kms_key" "a" {
  description = "a"
}
resource "aws_kms_key" "b" {
  enable_key_rotation = false
}
resource "aws_kms_key" "c" {
  description = "c"
  deletion_window_in_days = 7
}
resource "aws_kms_key" "d" {
  enable_key_rotation = false
  description = "d"
}

resource "aws_ebs_volume" "a" {
  encrypted = true
  size = 10
}
resource "aws_ebs_volume" "b" {
  encrypted = true
  size = 10
}
resource "aws_ebs_volume" "c" {
  encrypted = true
  size = 10
}
resource "aws_ebs_volume" "d" {
  encrypted = var.enc
}
resource "aws_ebs_volume" "e" {
  size = 10
}

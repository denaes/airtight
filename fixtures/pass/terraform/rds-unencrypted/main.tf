resource "aws_db_instance" "a" {
  storage_encrypted = true
}
resource "aws_rds_cluster" "b" {
  storage_encrypted = true
}
resource "aws_db_instance" "c" {
  storage_encrypted = var.encrypt
}
resource "aws_db_instance" "d" {
  engine = "postgres"
}
resource "aws_ebs_volume" "e" {
  storage_encrypted = false
}

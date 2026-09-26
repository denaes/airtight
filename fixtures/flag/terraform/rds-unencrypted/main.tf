resource "aws_db_instance" "a" {
  storage_encrypted = false
}
resource "aws_rds_cluster" "b" {
  storage_encrypted = false
}
resource "aws_db_instance" "c" {
  storage_encrypted = false
  engine = "mysql"
}
resource "aws_rds_cluster" "d" {
  storage_encrypted = false
  engine = "aurora"
}

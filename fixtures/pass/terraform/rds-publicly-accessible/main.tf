resource "aws_db_instance" "a" {
  publicly_accessible = false
}
resource "aws_rds_cluster" "b" {
  publicly_accessible = false
}
resource "aws_db_instance" "c" {
  publicly_accessible = var.public
}
resource "aws_db_instance" "d" {
  engine = "postgres"
}
resource "aws_instance" "e" {
  publicly_accessible = true
}

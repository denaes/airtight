resource "aws_db_instance" "a" {
  publicly_accessible = true
}
resource "aws_rds_cluster" "b" {
  publicly_accessible = true
}
resource "aws_redshift_cluster" "c" {
  publicly_accessible = true
}
resource "aws_db_instance" "d" {
  publicly_accessible = true
  storage_encrypted = true
}

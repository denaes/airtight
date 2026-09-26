resource "aws_db_instance" "a" {
  password = "SuperSecret123!"
}
resource "aws_rds_cluster" "b" {
  master_password = "hunter2hunter2"
  api_key = "k3y-abc-def-ghi"
}
resource "helm_release" "c" {
  client_secret = "cs-9f8e7d6c5b4a3210"
}
resource "kubernetes_secret" "d" {
  token = "tok_ab12cd34ef56gh78"
}

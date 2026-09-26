resource "aws_db_instance" "a" {
  password = var.db_password
}
resource "aws_rds_cluster" "b" {
  master_password = random_password.db.result
}
resource "helm_release" "c" {
  client_secret = data.aws_secretsmanager_secret_version.s.secret_string
}
resource "kubernetes_secret" "d" {
  token = local.token
}
resource "aws_instance" "e" {
  user_data = "echo ${var.password}"
}
resource "aws_db_instance" "f" {
  username = "appuser"
}
resource "aws_db_instance" "g" {
  password = aws_secretsmanager_secret_version.db.secret_string
}
resource "helm_release" "h" {
  api_key = module.secrets.api_key
}

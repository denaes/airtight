resource "aws_lb_listener" "a" {
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}
resource "aws_lb_listener" "b" {
  ssl_policy = "ELBSecurityPolicy-TLS-1-2-2017-01"
}
resource "aws_lb_listener" "c" {
  ssl_policy = "ELBSecurityPolicy-FS-1-2-Res-2020-10"
}
resource "aws_lb_listener" "d" {
  ssl_policy = var.ssl_policy
}
resource "aws_lb_listener" "e" {
  protocol = "HTTPS"
}

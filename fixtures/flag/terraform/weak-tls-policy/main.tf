resource "aws_lb_listener" "a" {
  ssl_policy = "ELBSecurityPolicy-TLS-1-0-2015-04"
}
resource "aws_lb_listener" "b" {
  ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
}
resource "aws_lb_listener" "c" {
  ssl_policy = "ELBSecurityPolicy-2015-05"
}
resource "aws_lb_listener" "d" {
  ssl_policy = "ELBSecurityPolicy-2016-08"
}

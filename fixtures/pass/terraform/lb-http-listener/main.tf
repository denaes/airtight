resource "aws_lb_listener" "a" {
  port = 443
  protocol = "HTTPS"
}
resource "aws_lb_listener" "b" {
  port = 80
  protocol = "HTTP"
  default_action = "redirect-to-https"
}
resource "aws_lb_listener" "c" {
  protocol = var.protocol
}
resource "aws_lb_listener" "d" {
  protocol = "TLS"
}
resource "aws_lb_listener" "e" {
  protocol = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

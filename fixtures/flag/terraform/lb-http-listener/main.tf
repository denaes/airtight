resource "aws_lb_listener" "a" {
  port = 80
  protocol = "HTTP"
  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.a.arn
  }
}
resource "aws_lb_listener" "b" {
  port = 80
  protocol = "HTTP"
  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.b.arn
  }
}
resource "aws_lb_listener" "c" {
  port = 80
  protocol = "HTTP"
  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.c.arn
  }
}
resource "aws_lb_listener" "d" {
  port = 80
  protocol = "HTTP"
  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.d.arn
  }
}

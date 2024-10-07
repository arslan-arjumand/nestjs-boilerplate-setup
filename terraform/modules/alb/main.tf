# Application Load Balancer
resource "aws_lb" "main" {
  name               = "${var.app_name}-${var.environment}-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = var.security_group_ids
  subnets            = var.subnet_ids

  tags = {
    Name = "${var.app_name}-${var.environment}-alb"
  }
}

# Target Group for the ALB
resource "aws_lb_target_group" "main" {
  name        = "${var.app_name}-${var.environment}-tg"
  port        = var.target_group_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"  
  
  health_check {
    path                = var.health_check_path
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = {
    Name = "${var.app_name}-${var.environment}-tg"
  }
}

# HTTP Listener for the ALB
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}

# HTTPS Listener for the ALB 
resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }

  depends_on = [aws_lb.main]
}

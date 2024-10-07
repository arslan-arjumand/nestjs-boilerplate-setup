# Target tracking configuration for ECS service autoscaling
resource "aws_appautoscaling_target" "ecs_autoscaling_target" {
  max_capacity       = var.max_capacity
  min_capacity       = var.min_capacity
  resource_id        = "service/${var.ecs_cluster_name}/${var.ecs_service_name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

# Scaling policy based on CPU utilization or Memory utilization
resource "aws_appautoscaling_policy" "ecs_scaling_policy" {
  name               = "${var.app_name}-${var.environment}-scaling-policy"
  scalable_dimension = aws_appautoscaling_target.ecs_autoscaling_target.scalable_dimension
  service_namespace  = "ecs"
  resource_id        = aws_appautoscaling_target.ecs_autoscaling_target.resource_id
  policy_type        = "TargetTrackingScaling"

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = var.predefined_metric_type
    }

    target_value = var.target_value

    scale_in_cooldown  = 300
    scale_out_cooldown = 300
  }
}

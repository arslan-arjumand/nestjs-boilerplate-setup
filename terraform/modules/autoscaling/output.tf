output "autoscaling_policy_arn" {
  description = "The ARN of the autoscaling policy"
  value       = aws_appautoscaling_policy.ecs_scaling_policy.arn
}

output "autoscaling_target_id" {
  description = "The ID of the ECS autoscaling target"
  value       = aws_appautoscaling_target.ecs_autoscaling_target.id
}

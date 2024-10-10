variable "app_name" {
    description = "Name of the application"
    type        = string
}

variable "environment" {
    description = "Environment in which the application is deployed"
    type        = string
}

variable "container_port" {
    description = "Port on which the container listens"
    type        = number
}

variable "region" {
  description = "AWS region for ECS resources"
  type        = string
}

variable "subnet_ids" {
  description = "List of private subnets to place ECS service in"
  type        = list(string)
}

variable "security_group_ids" {
    description = "List of security group IDs"
    type = list(string)
}

variable "alb_target_group_arn" {
  description = "The ARN of the ALB target group to associate with ECS service"
  type        = string
}

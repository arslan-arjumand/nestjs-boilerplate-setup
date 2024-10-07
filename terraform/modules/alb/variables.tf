variable "app_name" {
  description = "Application name"
  type        = string
}

variable "environment" {
  description = "Deployment environment (e.g., staging, production)"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs where ALB should be deployed"
  type        = list(string)
}

variable "security_group_ids" {
  description = "List of security group IDs to associate with ALB"
  type        = list(string)
}

variable "certificate_arn" {
  description = "ARN of the SSL certificate for HTTPS listener"
  type        = string
}

variable "target_group_port" {
  description = "The port on which the target group is listening (ECS container port)"
  type        = number
  default     = 80
}

variable "health_check_path" {
  description = "Path for health check on the target group"
  type        = string
}

variable "region" {
  description = "AWS region for all resources."
  type        = string
}

variable "app_name" {
  description = "Name of the application"
  type    = string
  default = "app_name"
}

variable "environment" {
  description = "Environment in which the application is deployed"
  type    = string
  default = "staging"
}

variable "container_port" {
  description = "Port on which the container listens"
  type    = number
  default = 3001
}

variable "min_capacity" {
  description = "Minimum number of tasks to run"
  type    = number
  default = 1
}

variable "max_capacity" {
  description = "Maximum number of tasks to run"
  type    = number
  default = 1
}

variable "certificate_arn" {
  description = "Certificate ARN for the ALB"
  type    = string
}
variable "health_check_path" {
  description = "Path for health check on the target group"
  type        = string
  default     = "/api/health-check"
}
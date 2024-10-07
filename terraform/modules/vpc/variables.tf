variable "app_name" {
  description = "Name of the application"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "region" {
  description = "AWS region for deploying the infrastructure"
  type        = string
}

variable "container_port" {
  description = "Port for container (e.g., for ECS service)"
  type        = number
}

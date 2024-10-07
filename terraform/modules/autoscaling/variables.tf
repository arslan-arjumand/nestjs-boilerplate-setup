variable "app_name" {
    description = "Name of the application"
    type        = string
}

variable "environment" {
    description = "Environment in which the application is deployed"
    type        = string
}

variable "min_capacity" {
    description = "Minimum number of tasks to run"
    type        = number
}

variable "max_capacity" {
    description = "Maximum number of tasks to run"
    type        = number
}

variable "ecs_cluster_name" {
    description = "Name of the ECS cluster"
    type        = string
}

variable "ecs_service_name" {
    description = "Name of the ECS service"
    type        = string
}

variable "predefined_metric_type" {
    description = "Predefined metric for scaling"
    type        = string
    default     = "ECSServiceAverageCPUUtilization"
}

variable "target_value" {
    description = "The target value for the metric"
    type        = number
    default     = 75
}

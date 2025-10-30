# AWS Complete Example Variables

# General
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

# EKS Configuration
variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "inferadb-prod"
}

variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.28"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones_count" {
  description = "Number of availability zones"
  type        = number
  default     = 3
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "CIDR blocks allowed to access EKS API"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # CHANGE THIS in production!
}

# Node Configuration
variable "node_instance_types" {
  description = "EC2 instance types for nodes"
  type        = list(string)
  default     = ["m5.xlarge"]
}

variable "node_desired_size" {
  description = "Desired number of nodes"
  type        = number
  default     = 3
}

variable "node_min_size" {
  description = "Minimum number of nodes"
  type        = number
  default     = 3
}

variable "node_max_size" {
  description = "Maximum number of nodes"
  type        = number
  default     = 10
}

# Redis Configuration
variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.r7g.large"
}

variable "redis_number_of_nodes" {
  description = "Number of Redis cache nodes"
  type        = number
  default     = 2
}

# InferaDB Configuration
variable "helm_chart_path" {
  description = "Path to InferaDB Helm chart"
  type        = string
  default     = "../../../helm"
}

variable "inferadb_image_repository" {
  description = "InferaDB container image repository"
  type        = string
  default     = "inferadb"
}

variable "inferadb_image_tag" {
  description = "InferaDB container image tag"
  type        = string
  default     = "latest"
}

variable "inferadb_replica_count" {
  description = "Initial number of InferaDB replicas"
  type        = number
  default     = 3
}

variable "inferadb_min_replicas" {
  description = "Minimum replicas for autoscaling"
  type        = number
  default     = 3
}

variable "inferadb_max_replicas" {
  description = "Maximum replicas for autoscaling"
  type        = number
  default     = 20
}

variable "inferadb_cpu_request" {
  description = "CPU request for InferaDB pods"
  type        = string
  default     = "500m"
}

variable "inferadb_memory_request" {
  description = "Memory request for InferaDB pods"
  type        = string
  default     = "512Mi"
}

variable "inferadb_cpu_limit" {
  description = "CPU limit for InferaDB pods"
  type        = string
  default     = "2000m"
}

variable "inferadb_memory_limit" {
  description = "Memory limit for InferaDB pods"
  type        = string
  default     = "2Gi"
}

variable "inferadb_auth_enabled" {
  description = "Enable authentication"
  type        = bool
  default     = true
}

variable "inferadb_tracing_enabled" {
  description = "Enable distributed tracing"
  type        = bool
  default     = false
}

variable "inferadb_internal_lb" {
  description = "Use internal load balancer"
  type        = bool
  default     = false
}

# Monitoring
variable "enable_cloudwatch_logs" {
  description = "Enable CloudWatch logs"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 7
}

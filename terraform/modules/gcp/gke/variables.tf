# GCP GKE Module Variables

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "cluster_name" {
  description = "Name of the GKE cluster"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zonal_cluster" {
  description = "Create a zonal cluster (cheaper) instead of regional (HA)"
  type        = bool
  default     = false
}

# Networking
variable "subnet_cidr" {
  description = "CIDR range for the subnet"
  type        = string
  default     = "10.0.0.0/24"
}

variable "pods_cidr" {
  description = "CIDR range for pods"
  type        = string
  default     = "10.1.0.0/16"
}

variable "services_cidr" {
  description = "CIDR range for services"
  type        = string
  default     = "10.2.0.0/16"
}

variable "master_ipv4_cidr_block" {
  description = "CIDR range for GKE master"
  type        = string
  default     = "172.16.0.0/28"
}

variable "enable_private_endpoint" {
  description = "Enable private GKE endpoint (requires VPN/interconnect)"
  type        = bool
  default     = false
}

variable "master_authorized_networks" {
  description = "List of CIDR blocks allowed to access the master"
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  default = []
}

# Node configuration
variable "machine_type" {
  description = "Machine type for nodes"
  type        = string
  default     = "n2-standard-4"
}

variable "disk_size_gb" {
  description = "Disk size for nodes in GB"
  type        = number
  default     = 100
}

variable "disk_type" {
  description = "Disk type for nodes"
  type        = string
  default     = "pd-standard"
}

variable "node_count_per_zone" {
  description = "Number of nodes per zone"
  type        = number
  default     = 1
}

variable "min_node_count_per_zone" {
  description = "Minimum nodes per zone for autoscaling"
  type        = number
  default     = 1
}

variable "max_node_count_per_zone" {
  description = "Maximum nodes per zone for autoscaling"
  type        = number
  default     = 3
}

variable "use_spot_vms" {
  description = "Use spot VMs for cost savings (not for production)"
  type        = bool
  default     = false
}

variable "node_tags" {
  description = "Network tags for nodes"
  type        = list(string)
  default     = []
}

# Cluster features
variable "release_channel" {
  description = "GKE release channel (RAPID, REGULAR, STABLE)"
  type        = string
  default     = "REGULAR"
}

variable "enable_network_policy" {
  description = "Enable network policy"
  type        = bool
  default     = true
}

variable "enable_binary_authorization" {
  description = "Enable binary authorization"
  type        = bool
  default     = false
}

variable "enable_managed_prometheus" {
  description = "Enable managed Prometheus"
  type        = bool
  default     = true
}

variable "logging_components" {
  description = "GKE logging components"
  type        = list(string)
  default     = ["SYSTEM_COMPONENTS", "WORKLOADS"]
}

variable "monitoring_components" {
  description = "GKE monitoring components"
  type        = list(string)
  default     = ["SYSTEM_COMPONENTS"]
}

variable "maintenance_start_time" {
  description = "Maintenance window start time (HH:MM)"
  type        = string
  default     = "03:00"
}

variable "enable_artifact_registry_reader" {
  description = "Grant Artifact Registry reader role to node pool SA"
  type        = bool
  default     = false
}

variable "labels" {
  description = "Labels to apply to resources"
  type        = map(string)
  default     = {}
}

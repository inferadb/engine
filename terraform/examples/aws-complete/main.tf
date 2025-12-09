# Complete AWS Deployment for InferaDB Engine
# This example deploys the InferaDB Engine on EKS.
#
# Note: The Redis module is included for deployments that also include
# the Control service (which uses Redis for session/replay protection).
# For Engine-only deployments, Redis is optional.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  # Recommended: Use S3 backend for state storage
  # backend "s3" {
  #   bucket = "your-terraform-state-bucket"
  #   key    = "inferadb/terraform.tfstate"
  #   region = "us-west-2"
  #   encrypt = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "InferaDB"
      ManagedBy   = "Terraform"
      Environment = var.environment
    }
  }
}

# Get current AWS region
data "aws_region" "current" {}

# EKS Cluster
module "eks" {
  source = "../../modules/aws/eks"

  cluster_name       = var.cluster_name
  kubernetes_version = var.kubernetes_version

  # Networking
  vpc_cidr                 = var.vpc_cidr
  availability_zones_count = var.availability_zones_count

  # Node Configuration
  node_instance_types = var.node_instance_types
  node_desired_size   = var.node_desired_size
  node_min_size       = var.node_min_size
  node_max_size       = var.node_max_size

  # Security
  cluster_endpoint_public_access_cidrs = var.cluster_endpoint_public_access_cidrs

  # EBS CSI for persistent volumes
  enable_ebs_csi_driver = true

  tags = {
    Environment = var.environment
    Application = "inferadb"
  }
}

# Configure Kubernetes provider
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      module.eks.cluster_name,
      "--region",
      data.aws_region.current.name
    ]
  }
}

# Configure Helm provider
provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = [
        "eks",
        "get-token",
        "--cluster-name",
        module.eks.cluster_name,
        "--region",
        data.aws_region.current.name
      ]
    }
  }
}

# Generate secure Redis auth token (used by Control service)
resource "random_password" "redis_auth_token" {
  length  = 32
  special = false
}

# ElastiCache Redis (for Control service - optional for Engine-only deployments)
# The Control service uses Redis for:
# - Session management and replay protection
# - Distributed rate limiting
# - Cache for organization/vault data
module "redis" {
  source = "../../modules/aws/redis"

  name_prefix          = var.cluster_name
  replication_group_id = "${var.cluster_name}-redis"

  # Networking
  vpc_id                  = module.eks.vpc_id
  subnet_ids              = module.eks.private_subnet_ids
  allowed_security_groups = [module.eks.cluster_security_group_id]

  # Configuration
  engine_version         = "7.0"
  node_type              = var.redis_node_type
  number_cache_clusters  = var.redis_number_of_nodes

  # Security
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token_enabled        = true
  auth_token                = random_password.redis_auth_token.result

  # High Availability
  automatic_failover_enabled = true
  multi_az_enabled          = true

  # Monitoring
  enable_cloudwatch_alarms = true

  tags = {
    Environment = var.environment
    Application = "inferadb"
  }

  depends_on = [module.eks]
}

# Kubernetes Namespace
resource "kubernetes_namespace" "inferadb" {
  metadata {
    name = "inferadb"
    labels = {
      name        = "inferadb"
      environment = var.environment
    }
  }

  depends_on = [module.eks]
}

# Kubernetes Secret for Redis (used by Control service, not Engine)
resource "kubernetes_secret" "redis" {
  metadata {
    name      = "redis-credentials"
    namespace = kubernetes_namespace.inferadb.metadata[0].name
  }

  data = {
    redis-url      = module.redis.connection_string
    redis-password = random_password.redis_auth_token.result
  }

  type = "Opaque"
}

# Deploy InferaDB via Helm
resource "helm_release" "inferadb" {
  name       = "inferadb"
  namespace  = kubernetes_namespace.inferadb.metadata[0].name
  chart      = var.helm_chart_path
  timeout    = 600
  wait       = true

  values = [
    yamlencode({
      replicaCount = var.inferadb_replica_count

      image = {
        repository = var.inferadb_image_repository
        tag        = var.inferadb_image_tag
        pullPolicy = "IfNotPresent"
      }

      resources = {
        requests = {
          cpu    = var.inferadb_cpu_request
          memory = var.inferadb_memory_request
        }
        limits = {
          cpu    = var.inferadb_cpu_limit
          memory = var.inferadb_memory_limit
        }
      }

      autoscaling = {
        enabled                        = true
        minReplicas                    = var.inferadb_min_replicas
        maxReplicas                    = var.inferadb_max_replicas
        targetCPUUtilizationPercentage = 70
      }

      config = {
        # Storage backend: "memory" or "foundationdb"
        storage = "memory"  # Change to "foundationdb" for production
        logging = "info"

        # Cache configuration
        cache = {
          enabled  = true
          capacity = 100000
          ttl      = 600
        }

        # Token validation settings
        token = {
          cacheTtl  = 300
          clockSkew = 60
          maxAge    = 86400
        }

        # Mesh configuration for Control service communication
        mesh = {
          timeout     = 5000
          cacheTtl    = 300
          certCacheTtl = 900
        }
      }

      # Discovery configuration
      discovery = {
        mode = "kubernetes"
        control = {
          serviceName = "inferadb-control"
          namespace   = "inferadb"
          port        = 9092
        }
      }

      secrets = {
        pem = ""  # Set from external secret manager in production
      }

      service = {
        type = "LoadBalancer"
        annotations = {
          "service.beta.kubernetes.io/aws-load-balancer-type"     = "nlb"
          "service.beta.kubernetes.io/aws-load-balancer-internal" = tostring(var.inferadb_internal_lb)
        }
      }

      serviceMonitor = {
        enabled = true
      }
    })
  ]

  depends_on = [
    module.eks
  ]
}

# CloudWatch Log Group for application logs (optional)
resource "aws_cloudwatch_log_group" "inferadb" {
  count = var.enable_cloudwatch_logs ? 1 : 0

  name              = "/aws/eks/${var.cluster_name}/inferadb"
  retention_in_days = var.log_retention_days

  tags = {
    Environment = var.environment
    Application = "inferadb"
  }
}

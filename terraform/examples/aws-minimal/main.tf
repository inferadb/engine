# Minimal AWS Deployment for InferaDB
# For development and testing - not recommended for production

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
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_region" "current" {}

# Minimal EKS Cluster
module "eks" {
  source = "../../modules/aws/eks"

  cluster_name       = var.cluster_name
  kubernetes_version = "1.28"

  # Minimal networking - single AZ for cost savings
  vpc_cidr                 = "10.0.0.0/16"
  availability_zones_count = 1

  # Small node pool
  node_instance_types = ["t3.medium"]
  node_desired_size   = 1
  node_min_size       = 1
  node_max_size       = 3

  # Public access for simplicity
  cluster_endpoint_public_access       = true
  cluster_endpoint_public_access_cidrs = ["0.0.0.0/0"]

  # Disable expensive features
  enable_ebs_csi_driver = false

  tags = {
    Environment = "development"
    Purpose     = "testing"
  }
}

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

# Kubernetes Namespace
resource "kubernetes_namespace" "inferadb" {
  metadata {
    name = "inferadb"
  }
}

# Deploy InferaDB with minimal configuration
resource "helm_release" "inferadb" {
  name      = "inferadb"
  namespace = kubernetes_namespace.inferadb.metadata[0].name
  chart     = var.helm_chart_path
  timeout   = 600

  values = [
    yamlencode({
      replicaCount = 1

      image = {
        repository = "inferadb"
        tag        = "latest"
        pullPolicy = "IfNotPresent"
      }

      resources = {
        requests = {
          cpu    = "100m"
          memory = "128Mi"
        }
        limits = {
          cpu    = "500m"
          memory = "512Mi"
        }
      }

      # Disable autoscaling
      autoscaling = {
        enabled = false
      }

      # Use memory storage (no external dependencies)
      config = {
        store = {
          backend = "memory"
        }

        cache = {
          enabled     = true
          maxCapacity = 10000
        }

        # Disable auth for testing
        auth = {
          enabled = false
        }

        observability = {
          logLevel       = "debug"
          logFormat      = "pretty"
          metricsEnabled = true
        }
      }

      # Use NodePort for easy access
      service = {
        type = "NodePort"
      }
    })
  ]

  depends_on = [module.eks]
}

# InferaDB Terraform Modules

Infrastructure as Code for deploying InferaDB on major cloud providers.

## Overview

This directory contains Terraform modules and examples for deploying InferaDB on:
- **AWS** - Amazon Web Services (EKS)
- **GCP** - Google Cloud Platform (GKE)

Each provider includes:
- Reusable modules for core infrastructure
- Complete deployment examples
- Minimal development/testing configurations
- Production-ready best practices

## Quick Start

### AWS

**Complete Production Deployment:**
```bash
cd examples/aws-complete
terraform init
terraform apply
```

**Minimal Development Setup:**
```bash
cd examples/aws-minimal
terraform init
terraform apply
```

### GCP

**Complete Production Deployment:**
```bash
cd examples/gcp-complete
terraform init
terraform apply
```

**Minimal Development Setup:**
```bash
cd examples/gcp-minimal
terraform init
terraform apply
```

## Directory Structure

```
terraform/
├── README.md                    # This file
├── modules/                     # Reusable Terraform modules
│   ├── aws/                     # AWS-specific modules
│   │   ├── eks/                 # Amazon EKS cluster
│   │   ├── redis/               # ElastiCache Redis
│   │   └── foundationdb/        # FDB on EKS
│   ├── gcp/                     # GCP-specific modules
│   │   ├── gke/                 # Google Kubernetes Engine
│   │   ├── redis/               # Memorystore Redis
│   │   └── foundationdb/        # FDB on GKE
│   └── common/                  # Cloud-agnostic modules
│       └── monitoring/          # Observability stack
└── examples/                    # Complete deployment examples
    ├── aws-complete/            # Production AWS deployment
    ├── aws-minimal/             # Development AWS setup
    ├── gcp-complete/            # Production GCP deployment
    └── gcp-minimal/             # Development GCP setup
```

## Modules

### AWS Modules

#### `modules/aws/eks`
Creates a production-ready EKS cluster with:
- Multi-AZ deployment
- Private worker nodes
- IRSA (IAM Roles for Service Accounts)
- EBS CSI driver for persistent volumes
- Security best practices

[Documentation](modules/aws/eks/README.md)

#### `modules/aws/redis`
Deploys ElastiCache Redis for replay protection:
- Multi-AZ with automatic failover
- Encryption at rest and in transit
- CloudWatch alarms
- Parameter tuning for InferaDB

[Documentation](modules/aws/redis/)

### GCP Modules

#### `modules/gcp/gke`
Creates a production-ready GKE cluster with:
- Regional or zonal deployment
- Private nodes
- Workload Identity
- Managed Prometheus
- Security best practices

[Documentation](modules/gcp/gke/)

#### `modules/gcp/redis`
Deploys Memorystore Redis for replay protection:
- High availability
- In-transit encryption
- Monitoring integration
- Optimized for InferaDB workloads

[Documentation](modules/gcp/redis/)

## Examples

### AWS Complete

Full production deployment on AWS including:
- EKS cluster (3 nodes, m5.xlarge)
- ElastiCache Redis (Multi-AZ)
- Network Load Balancer
- Auto-scaling (3-20 pods)
- CloudWatch monitoring

**Estimated cost:** ~$695/month

[Documentation](examples/aws-complete/README.md)

### AWS Minimal

Development deployment on AWS:
- Single-AZ EKS cluster
- 1 small node (t3.medium)
- In-memory storage only
- No external dependencies

**Estimated cost:** ~$60/month

[Documentation](examples/aws-minimal/README.md)

### GCP Complete

Full production deployment on GCP including:
- GKE cluster (regional)
- Memorystore Redis (HA)
- Load Balancer
- Auto-scaling
- Cloud Monitoring

**Estimated cost:** ~$650/month

[Documentation](examples/gcp-complete/)

### GCP Minimal

Development deployment on GCP:
- Zonal GKE cluster
- 1 small node (n2-standard-2)
- In-memory storage only

**Estimated cost:** ~$75/month

[Documentation](examples/gcp-minimal/)

## Prerequisites

### General Requirements

1. **Terraform** >= 1.5
   ```bash
   # Install via Homebrew (macOS)
   brew install terraform

   # Or download from https://www.terraform.io/downloads
   ```

2. **kubectl** for cluster management
   ```bash
   brew install kubectl
   ```

3. **Helm** >= 3.8
   ```bash
   brew install helm
   ```

### AWS-Specific

1. **AWS CLI** configured with credentials
   ```bash
   brew install awscli
   aws configure
   ```

2. **IAM Permissions**: Your AWS user/role needs:
   - EKS full access
   - EC2 full access
   - VPC management
   - ElastiCache management
   - IAM role creation

### GCP-Specific

1. **gcloud CLI** configured
   ```bash
   brew install --cask google-cloud-sdk
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```

2. **GCP APIs**: Enable required APIs
   ```bash
   gcloud services enable container.googleapis.com
   gcloud services enable compute.googleapis.com
   gcloud services enable redis.googleapis.com
   ```

3. **IAM Permissions**: Your user needs:
   - Kubernetes Engine Admin
   - Compute Admin
   - Service Account Admin
   - Memorystore Redis Admin

## Usage Patterns

### Development Workflow

1. **Start with minimal deployment**
   ```bash
   cd examples/aws-minimal  # or gcp-minimal
   terraform init
   terraform apply
   ```

2. **Configure kubectl**
   ```bash
   # AWS
   aws eks update-kubeconfig --region us-west-2 --name inferadb-dev

   # GCP
   gcloud container clusters get-credentials inferadb-dev --region us-central1
   ```

3. **Verify deployment**
   ```bash
   kubectl get nodes
   kubectl get pods -n inferadb
   ```

4. **Test InferaDB**
   ```bash
   kubectl port-forward -n inferadb svc/inferadb 8080:8080
   curl http://localhost:8080/health
   ```

5. **Cleanup**
   ```bash
   terraform destroy
   ```

### Production Deployment

1. **Review and customize variables**
   ```bash
   cd examples/aws-complete  # or gcp-complete
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your settings
   ```

2. **Configure state backend** (recommended)
   ```hcl
   # AWS S3
   terraform {
     backend "s3" {
       bucket = "your-terraform-state"
       key    = "inferadb/prod/terraform.tfstate"
       region = "us-west-2"
       encrypt = true
     }
   }

   # GCP Cloud Storage
   terraform {
     backend "gcs" {
       bucket = "your-terraform-state"
       prefix = "inferadb/prod"
     }
   }
   ```

3. **Plan and apply**
   ```bash
   terraform init
   terraform plan -out=tfplan
   terraform apply tfplan
   ```

4. **Configure monitoring**
   - Set up alerts in CloudWatch (AWS) or Cloud Monitoring (GCP)
   - Configure log aggregation
   - Set up Grafana dashboards

## Best Practices

### Security

1. **Restrict API access**
   ```hcl
   cluster_endpoint_public_access_cidrs = ["YOUR_OFFICE_IP/32"]
   ```

2. **Use private endpoints** for production
   ```hcl
   # AWS
   cluster_endpoint_public_access = false

   # GCP
   enable_private_endpoint = true
   ```

3. **Enable encryption**
   - All modules enable encryption by default
   - Use KMS/Cloud KMS for key management

4. **Use service accounts, not user credentials**
   - AWS: Use IRSA (IAM Roles for Service Accounts)
   - GCP: Use Workload Identity

### Cost Optimization

1. **Right-size resources**
   - Start small, scale up based on metrics
   - Use autoscaling to match demand

2. **Use reserved/committed instances**
   - AWS: Reserved Instances for predictable workloads
   - GCP: Committed Use Discounts

3. **Spot/Preemptible VMs for non-critical workloads**
   ```hcl
   # AWS (add to node group)
   capacity_type = "SPOT"

   # GCP
   use_spot_vms = true
   ```

4. **Clean up unused resources**
   ```bash
   # Find orphaned resources
   terraform state list
   terraform plan
   ```

### High Availability

1. **Multi-AZ/Regional deployment**
   ```hcl
   # AWS
   availability_zones_count = 3

   # GCP
   zonal_cluster = false  # Creates regional cluster
   ```

2. **Pod Disruption Budgets**
   ```yaml
   # Included in Helm chart
   podDisruptionBudget:
     enabled: true
     minAvailable: 2
   ```

3. **Regular backups**
   - Redis: Automatic snapshots enabled
   - FoundationDB: Continuous backups
   - State: Use remote state with locking

### Monitoring

1. **Enable all logging**
   ```hcl
   # AWS
   cluster_enabled_log_types = ["api", "audit", "authenticator"]

   # GCP
   logging_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
   ```

2. **Set up alerts**
   - CPU/memory utilization
   - Pod failure rates
   - API errors
   - Database connection issues

3. **Use managed Prometheus**
   - AWS: Amazon Managed Service for Prometheus
   - GCP: Managed Prometheus (enabled by default)

## Troubleshooting

### Common Issues

#### Terraform State Lock

```bash
# AWS S3 backend
aws dynamodb delete-item \
  --table-name terraform-locks \
  --key '{"LockID":{"S":"your-lock-id"}}'

# GCP Cloud Storage
# Locks expire automatically after 30 minutes
```

#### kubectl Access Denied

```bash
# AWS - Update kubeconfig
aws eks update-kubeconfig --region us-west-2 --name cluster-name

# GCP - Get credentials
gcloud container clusters get-credentials cluster-name --region us-central1
```

#### Pods Not Starting

```bash
# Check pod status
kubectl describe pod -n inferadb <pod-name>

# Check events
kubectl get events -n inferadb --sort-by='.lastTimestamp'

# Check logs
kubectl logs -n inferadb <pod-name>
```

#### Out of Quota/Capacity

```bash
# AWS - Request service quota increase
aws service-quotas request-service-quota-increase \
  --service-code eks \
  --quota-code L-1194D53C \
  --desired-value 50

# GCP - Request quota increase
gcloud compute project-info describe --project=PROJECT_ID
# Then request increase via console
```

## Migration Between Providers

To migrate from AWS to GCP (or vice versa):

1. **Deploy new infrastructure**
   ```bash
   cd examples/gcp-complete
   terraform apply
   ```

2. **Replicate data**
   - Export from source FoundationDB
   - Import to destination FoundationDB

3. **Update DNS**
   - Point to new load balancer
   - Use weighted routing for gradual migration

4. **Cleanup old infrastructure**
   ```bash
   cd examples/aws-complete
   terraform destroy
   ```

## Support

- **Documentation**: [InferaDB Docs](../docs/)
- **Issues**: [GitHub Issues](https://github.com/inferadb/server/issues)
- **Terraform Docs**:
  - [AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
  - [GCP Provider](https://registry.terraform.io/providers/hashicorp/google/latest/docs)
  - [Kubernetes Provider](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs)
  - [Helm Provider](https://registry.terraform.io/providers/hashicorp/helm/latest/docs)

## Contributing

When adding new modules or examples:

1. Follow existing directory structure
2. Include comprehensive README
3. Add examples for common use cases
4. Document all variables and outputs
5. Test deployment and cleanup
6. Update this README

## License

Same as InferaDB - Business Source License 1.1

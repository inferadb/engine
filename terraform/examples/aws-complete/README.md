# Complete AWS Deployment for InferaDB

This example deploys a production-ready InferaDB installation on AWS using:

- **Amazon EKS** for Kubernetes
- **ElastiCache Redis** for replay protection
- **Network Load Balancer** for external access
- **Auto-scaling** for high availability

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         AWS Account                          │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              VPC (10.0.0.0/16)                         │ │
│  │                                                        │ │
│  │  ┌──────────────────────────────────────────────────┐ │ │
│  │  │              EKS Cluster                         │ │ │
│  │  │                                                  │ │ │
│  │  │  ┌────────────────────────────────────────────┐ │ │ │
│  │  │  │     InferaDB Pods (3-20 replicas)         │ │ │ │
│  │  │  │     - Auto-scaling based on CPU/memory    │ │ │ │
│  │  │  │     - Health checks                        │ │ │ │
│  │  │  │     - Prometheus metrics                   │ │ │ │
│  │  │  └────────────────────────────────────────────┘ │ │ │
│  │  │                                                  │ │ │
│  │  └──────────────────────────────────────────────────┘ │ │
│  │                                                        │ │
│  │  ┌──────────────────────────────────────────────────┐ │ │
│  │  │     ElastiCache Redis Cluster                    │ │ │
│  │  │     - Multi-AZ with automatic failover           │ │ │
│  │  │     - Encrypted at rest and in transit           │ │ │
│  │  │     - Used for replay protection                 │ │ │
│  │  └──────────────────────────────────────────────────┘ │ │
│  │                                                        │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │     Network Load Balancer                              │ │
│  │     - HTTP/gRPC traffic routing                        │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

1. **AWS CLI** configured with appropriate credentials
2. **Terraform** >= 1.5
3. **kubectl** for cluster management
4. **Helm** >= 3.8 (optional, for manual deployments)

## Quick Start

### 1. Configure Variables

Create a `terraform.tfvars` file:

```hcl
aws_region      = "us-west-2"
cluster_name    = "inferadb-prod"
environment     = "production"

# Restrict API access to your IP
cluster_endpoint_public_access_cidrs = ["YOUR_IP/32"]

# Node configuration
node_instance_types = ["m5.xlarge"]
node_desired_size   = 3
node_min_size       = 3
node_max_size       = 10

# InferaDB configuration
inferadb_replica_count = 3
inferadb_min_replicas  = 3
inferadb_max_replicas  = 20
inferadb_auth_enabled  = true

# Use internal LB for private deployments
inferadb_internal_lb = false
```

### 2. Initialize Terraform

```bash
terraform init
```

### 3. Review Plan

```bash
terraform plan
```

### 4. Deploy

```bash
terraform apply
```

This will take approximately 15-20 minutes to:

- Create VPC with public/private subnets across 3 AZs
- Deploy EKS cluster with managed node group
- Create ElastiCache Redis cluster
- Deploy InferaDB via Helm

### 5. Configure kubectl

```bash
aws eks update-kubeconfig --region us-west-2 --name inferadb-prod
```

### 6. Verify Deployment

```bash
# Check nodes
kubectl get nodes

# Check InferaDB pods
kubectl get pods -n inferadb

# Check services
kubectl get svc -n inferadb

# Get LoadBalancer URL
export LB_URL=$(kubectl get svc -n inferadb inferadb -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
echo $LB_URL
```

### 7. Test InferaDB

```bash
# Health check
curl http://$LB_URL:8080/health

# Authorization check
curl -X POST http://$LB_URL:8080/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "tuple": {
      "object": "doc:readme",
      "relation": "viewer",
      "subject": "user:alice"
    }
  }'
```

## Configuration Options

### Instance Sizing

| Workload    | Node Type  | Node Count | Redis Type       |
| ----------- | ---------- | ---------- | ---------------- |
| Development | t3.large   | 2          | cache.t4g.medium |
| Staging     | m5.large   | 2-3        | cache.r7g.large  |
| Production  | m5.xlarge  | 3-10       | cache.r7g.large  |
| High-Scale  | m5.2xlarge | 5-20       | cache.r7g.xlarge |

### Cost Optimization

1. **Use Spot Instances**: Add spot instances to node group for cost savings
2. **Right-size Redis**: Start with smaller instance, scale up if needed
3. **Enable Cluster Autoscaler**: Automatically adjust node count
4. **Use Reserved Instances**: For predictable production workloads

### Security Hardening

```hcl
# Restrict API access
cluster_endpoint_public_access_cidrs = ["YOUR_OFFICE_IP/32"]

# Use private load balancer
inferadb_internal_lb = true

# Enable VPC endpoints (add to main.tf)
# This keeps traffic within AWS network
```

## Monitoring

### CloudWatch Metrics

The deployment automatically creates CloudWatch alarms for:

- Redis CPU utilization (> 75%)
- Redis memory usage (> 80%)
- Redis evictions (> 100/5min)

### Prometheus Metrics

InferaDB exports metrics on `/metrics`:

```bash
# Port-forward to access metrics
kubectl port-forward -n inferadb svc/inferadb 9090:9090

# Access metrics
curl http://localhost:9090/metrics
```

### Logs

View InferaDB logs:

```bash
# All pods
kubectl logs -n inferadb -l app.kubernetes.io/name=inferadb --tail=100 -f

# Specific pod
kubectl logs -n inferadb inferadb-<pod-id> -f
```

## Scaling

### Manual Scaling

```bash
# Scale pods
kubectl scale deployment -n inferadb inferadb --replicas=10

# Scale nodes (if not using cluster autoscaler)
aws eks update-nodegroup-config \
  --cluster-name inferadb-prod \
  --nodegroup-name inferadb-prod-node-group \
  --scaling-config minSize=5,maxSize=20,desiredSize=10
```

### Auto-Scaling

The deployment includes:

- **Horizontal Pod Autoscaler (HPA)**: Scales pods based on CPU/memory
- **Cluster Autoscaler**: Can be added to scale nodes automatically

To enable Cluster Autoscaler:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/autoscaler/master/cluster-autoscaler/cloudprovider/aws/examples/cluster-autoscaler-autodiscover.yaml
```

## Disaster Recovery

### Backup

```bash
# Backup Helm values
helm get values -n inferadb inferadb > backup-values.yaml

# Backup Kubernetes resources
kubectl get all -n inferadb -o yaml > backup-k8s.yaml
```

### Restore

```bash
# Restore from backup
helm upgrade -n inferadb inferadb ../../../helm -f backup-values.yaml
```

## Upgrading

### InferaDB Version

```bash
terraform apply -var="inferadb_image_tag=v2.0.0"
```

### Kubernetes Version

```bash
terraform apply -var="kubernetes_version=1.29"
```

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

**Warning**: This will delete:

- EKS cluster and all workloads
- ElastiCache Redis cluster
- VPC and all networking resources
- Load balancers

## Troubleshooting

### Pods not starting

```bash
# Check pod status
kubectl describe pod -n inferadb <pod-name>

# Check logs
kubectl logs -n inferadb <pod-name>
```

### Cannot connect to Redis

```bash
# Verify Redis endpoint
terraform output redis_endpoint

# Check security groups
aws elasticache describe-cache-clusters \
  --cache-cluster-id inferadb-prod-redis-001 \
  --show-cache-node-info
```

### LoadBalancer not provisioned

```bash
# Check service
kubectl describe svc -n inferadb inferadb

# Check AWS Load Balancer Controller logs
kubectl logs -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

## Cost Estimate

Approximate monthly costs for production deployment (us-west-2):

| Resource              | Configuration      | Monthly Cost    |
| --------------------- | ------------------ | --------------- |
| EKS Cluster           | Control plane      | $73             |
| EC2 Nodes             | 3x m5.xlarge       | ~$367           |
| ElastiCache           | 2x cache.r7g.large | ~$224           |
| Network Load Balancer | 1 NLB              | ~$22            |
| Data Transfer         | 100GB/month        | ~$9             |
| **Total**             |                    | **~$695/month** |

_Prices are approximate and vary by region. Use AWS Cost Calculator for accurate estimates._

## Support

- [InferaDB Documentation](../../README.md)
- [Terraform AWS Provider Docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [EKS Best Practices](https://aws.github.io/aws-eks-best-practices/)

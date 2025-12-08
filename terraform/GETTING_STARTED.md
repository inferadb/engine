# Getting Started with InferaDB on Cloud Platforms

This guide helps you choose the right deployment method and get InferaDB running on AWS or GCP.

## Quick Decision Tree

```text
Need production deployment?
├─ Yes
│  ├─ On AWS? → Use terraform/examples/aws-complete
│  └─ On GCP? → Use terraform/examples/gcp-complete
└─ No (development/testing)
   ├─ On AWS? → Use terraform/examples/aws-minimal
   └─ On GCP? → Use terraform/examples/gcp-minimal
```

## Deployment Comparison

| Feature               | Docker    | Kubernetes       | Helm     | Terraform AWS   | Terraform GCP   |
| --------------------- | --------- | ---------------- | -------- | --------------- | --------------- |
| **Setup Time**        | 5 min     | 15 min           | 10 min   | 20 min          | 20 min          |
| **Production Ready**  | No        | Yes              | Yes      | Yes             | Yes             |
| **Auto-scaling**      | No        | Manual           | Yes      | Yes             | Yes             |
| **High Availability** | No        | Manual           | Yes      | Yes             | Yes             |
| **Infrastructure**    | Manual    | Manual           | Manual   | Automated       | Automated       |
| **Cost**              | Minimal   | Variable         | Variable | ~$60-695/mo     | ~$75-650/mo     |
| **Best For**          | Local dev | Self-managed K8s | Any K8s  | AWS deployments | GCP deployments |

## AWS Deployment

### Prerequisites

```bash
# Install required tools
brew install terraform awscli kubectl

# Configure AWS credentials
aws configure
```

### Production Deployment (~20 minutes)

```bash
# 1. Navigate to example
cd terraform/examples/aws-complete

# 2. Create configuration
cat > terraform.tfvars <<EOF
cluster_name    = "inferadb-prod"
aws_region      = "us-west-2"
environment     = "production"

# IMPORTANT: Replace with your IP
cluster_endpoint_public_access_cidrs = ["1.2.3.4/32"]

# Node configuration
node_instance_types = ["m5.xlarge"]
node_desired_size   = 3
node_max_size       = 10

# InferaDB configuration
inferadb_engine_replica_count = 3
inferadb_engine_auth_enabled  = true
EOF

# 3. Initialize and apply
terraform init
terraform apply

# 4. Configure kubectl (from terraform output)
aws eks update-kubeconfig --region us-west-2 --name inferadb-prod

# 5. Verify deployment
kubectl get nodes
kubectl get pods -n inferadb

# 6. Get LoadBalancer URL
kubectl get svc -n inferadb inferadb
```

**What You Get:**

- EKS cluster with 3 nodes (m5.xlarge)
- ElastiCache Redis for replay protection
- Network Load Balancer
- Auto-scaling 3-20 pods
- CloudWatch monitoring
- **Cost:** ~$695/month

### Development Deployment (~10 minutes)

```bash
cd terraform/examples/aws-minimal
terraform init
terraform apply -auto-approve

# Configure kubectl
aws eks update-kubeconfig --region us-west-2 --name inferadb-dev
```

**What You Get:**

- Minimal EKS cluster (1 node, t3.medium)
- In-memory storage only
- NodePort service
- **Cost:** ~$60/month

## GCP Deployment

### Prerequisites

```bash
# Install required tools
brew install terraform google-cloud-sdk kubectl

# Configure GCP
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable container.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable redis.googleapis.com
```

### Production Deployment (~20 minutes)

```bash
# 1. Navigate to example
cd terraform/examples/gcp-complete

# 2. Create configuration
cat > terraform.tfvars <<EOF
project_id      = "your-gcp-project-id"
cluster_name    = "inferadb-prod"
region          = "us-central1"
environment     = "production"

# Node configuration
machine_type           = "n2-standard-4"
node_count_per_zone    = 1
max_node_count_per_zone = 3

# InferaDB configuration
inferadb_engine_replica_count = 3
inferadb_engine_auth_enabled  = true
EOF

# 3. Initialize and apply
terraform init
terraform apply

# 4. Configure kubectl (from terraform output)
gcloud container clusters get-credentials inferadb-prod \
  --region us-central1 --project YOUR_PROJECT_ID

# 5. Verify deployment
kubectl get nodes
kubectl get pods -n inferadb

# 6. Get LoadBalancer URL
kubectl get svc -n inferadb inferadb
```

**What You Get:**

- Regional GKE cluster (3 zones)
- Memorystore Redis for replay protection
- Load Balancer
- Auto-scaling
- Cloud Monitoring
- **Cost:** ~$650/month

### Development Deployment (~10 minutes)

```bash
cd terraform/examples/gcp-minimal
terraform init
terraform apply -auto-approve

# Configure kubectl
gcloud container clusters get-credentials inferadb-dev \
  --region us-central1
```

**What You Get:**

- Zonal GKE cluster (1 node)
- In-memory storage only
- NodePort service
- **Cost:** ~$75/month

## Testing Your Deployment

### Health Check

```bash
# Get LoadBalancer URL
export LB_URL=$(kubectl get svc -n inferadb inferadb -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')  # AWS
export LB_URL=$(kubectl get svc -n inferadb inferadb -o jsonpath='{.status.loadBalancer.ingress[0].ip}')        # GCP

# Test health endpoint
curl http://$LB_URL:8080/health
```

### Authorization Check

```bash
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

Expected response:

```json
{ "allowed": true }
```

## Monitoring

### View Logs

```bash
# All InferaDB pods
kubectl logs -n inferadb -l app.kubernetes.io/name=inferadb --tail=100 -f

# Specific pod
kubectl logs -n inferadb inferadb-<pod-id> -f
```

### View Metrics

```bash
# Port-forward to metrics endpoint
kubectl port-forward -n inferadb svc/inferadb 9090:9090

# Access metrics
curl http://localhost:9090/metrics
```

### Cloud Monitoring

**AWS:**

```bash
# View CloudWatch logs
aws logs tail /aws/eks/inferadb-prod/cluster --follow

# View Redis metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/ElastiCache \
  --metric-name CPUUtilization \
  --dimensions Name=ReplicationGroupId,Value=inferadb-prod-redis \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average
```

**GCP:**

```bash
# View logs
gcloud logging read "resource.type=k8s_container AND resource.labels.namespace_name=inferadb" --limit 100

# View Redis metrics
gcloud redis instances describe inferadb-prod-redis --region us-central1
```

## Scaling

### Scale Pods

```bash
# Manual scaling
kubectl scale deployment -n inferadb inferadb --replicas=10

# Via Terraform
terraform apply -var="inferadb_engine_replica_count=10"
```

### Scale Nodes

**AWS:**

```bash
# Update node group
aws eks update-nodegroup-config \
  --cluster-name inferadb-prod \
  --nodegroup-name inferadb-prod-node-group \
  --scaling-config minSize=5,maxSize=20,desiredSize=10
```

**GCP:**

```bash
# Update node pool
gcloud container clusters resize inferadb-prod \
  --node-pool inferadb-prod-primary-pool \
  --num-nodes 5 \
  --region us-central1
```

## Cleanup

### Destroy Everything

```bash
# This will delete ALL resources created by Terraform
terraform destroy

# Confirm deletion
# Type "yes" when prompted
```

**Warning:** This deletes:

- Kubernetes cluster and all workloads
- Redis/Memorystore instances
- Load balancers
- VPC and networking (if created by Terraform)
- All data (not recoverable)

## Troubleshooting

### Pods Not Starting

```bash
# Describe pod
kubectl describe pod -n inferadb <pod-name>

# Check events
kubectl get events -n inferadb --sort-by='.lastTimestamp'

# Check resource limits
kubectl top nodes
kubectl top pods -n inferadb
```

### Cannot Access LoadBalancer

```bash
# Check service
kubectl get svc -n inferadb inferadb

# Check security groups (AWS)
aws ec2 describe-security-groups \
  --filters "Name=tag:kubernetes.io/cluster/inferadb-prod,Values=owned"

# Check firewall rules (GCP)
gcloud compute firewall-rules list \
  --filter="targetTags:gke-inferadb-prod"
```

### Redis Connection Issues

**AWS:**

```bash
# Check Redis status
aws elasticache describe-replication-groups \
  --replication-group-id inferadb-prod-redis

# Test connectivity from pod
kubectl run -it --rm debug --image=redis:7 --restart=Never -- \
  redis-cli -h <redis-endpoint> ping
```

**GCP:**

```bash
# Check Redis instance
gcloud redis instances describe inferadb-prod-redis --region us-central1

# Test connectivity from pod
kubectl run -it --rm debug --image=redis:7 --restart=Never -- \
  redis-cli -h <redis-ip> ping
```

## Cost Optimization

### Development

- Use minimal examples (~$60-75/month)
- Use spot/preemptible instances
- Delete when not in use

### Production

- Right-size based on metrics
- Use reserved/committed instances
- Enable autoscaling
- Set up budget alerts

**AWS Budget Alert:**

```bash
aws budgets create-budget \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --budget file://budget.json \
  --notifications-with-subscribers file://notifications.json
```

**GCP Budget Alert:**

```bash
gcloud billing budgets create \
  --billing-account=YOUR_BILLING_ACCOUNT \
  --display-name="InferaDB Monthly Budget" \
  --budget-amount=1000
```

## Next Steps

1. **Configure Authentication**: See [Authentication Guide](../docs/security/authentication.md)
2. **Set Up Monitoring**: See [Observability Guide](../docs/operations/observability.md)
3. **Enable FoundationDB**: For production persistence
4. **Configure Backups**: For disaster recovery
5. **Set Up CI/CD**: Automate deployments

## Support

- [Full Terraform Documentation](README.md)
- [Deployment Guide](../docs/guides/deployment.md)
- [Configuration Reference](../docs/guides/configuration.md)
- [GitHub Issues](https://github.com/inferadb/server/issues)

# Minimal AWS Deployment for InferaDB

**For development and testing only - NOT for production use**

This example deploys InferaDB with minimal resources for development and testing:

- Single-AZ EKS cluster
- 1 small node (t3.medium)
- Memory-only storage (no FoundationDB)
- No Redis (no replay protection)
- No authentication
- NodePort service

## Cost

Approximately **$50-70/month** for:

- EKS control plane: $73/month
- 1x t3.medium EC2: ~$30/month
- Minimal data transfer

## Quick Start

```bash
# Initialize
terraform init

# Deploy (takes ~10 minutes)
terraform apply -auto-approve

# Configure kubectl
aws eks update-kubeconfig --region us-west-2 --name inferadb-dev

# Get NodePort
export NODE_PORT=$(kubectl get svc -n inferadb inferadb -o jsonpath='{.spec.ports[0].nodePort}')
export NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}')

# Test
curl -X POST http://$NODE_IP:$NODE_PORT/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tuple": {"object": "doc:test", "relation": "viewer", "subject": "user:test"}}'
```

## Limitations

- **Single node**: No high availability
- **Memory storage**: Data lost on restart
- **No authentication**: Insecure
- **No replay protection**: Can't prevent token reuse
- **NodePort**: Not suitable for production traffic

## Cleanup

```bash
terraform destroy -auto-approve
```

## Upgrading to Production

See [aws-complete](../aws-complete/) example for production deployment with:

- Multi-AZ for HA
- ElastiCache Redis
- Authentication enabled
- Load balancer
- Auto-scaling

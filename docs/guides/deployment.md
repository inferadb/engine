# InferaDB Deployment Guide

This guide covers deploying InferaDB to production environments.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Deployment Options](#deployment-options)
- [Docker Deployment](#1-docker-deployment)
- [Kubernetes Deployment](#2-kubernetes-deployment)
- [Helm Deployment](#3-helm-deployment)
- [Cloud Deployment with Terraform](#4-cloud-deployment-with-terraform)
- [Configuration](#configuration)
- [Security](#security)
- [Monitoring](#monitoring)
- [Upgrading](#upgrading)
- [Troubleshooting](#troubleshooting)

## Overview

InferaDB is a high-performance authorization database designed for cloud-native deployments. It supports multiple deployment models:

- **Standalone**: Single instance for development/testing
- **Replicated**: Multiple instances with load balancing
- **Distributed**: FoundationDB backend for production scale

### Architecture

```mermaid
flowchart LR
    CLIENT["Client"] --> LB["Load Balancer"]
    LB --> CLUSTER["InferaDB<br/>Cluster"]

    CLUSTER --> REDIS["Redis<br/>(Replay)"]
    CLUSTER --> FDB["FDB<br/>(Storage)"]
    CLUSTER --> CONTROL["Control<br/>(JWKS)"]

    style CLIENT fill:#E3F2FD,stroke:#42A5F5
    style LB fill:#1E88E5,stroke:#1565C0,color:#fff
    style CLUSTER fill:#4CAF50,stroke:#2E7D32,color:#fff
    style REDIS fill:#FF9800,stroke:#F57C00,color:#fff
    style FDB fill:#FF9800,stroke:#F57C00,color:#fff
    style CONTROL fill:#9C27B0,stroke:#7B1FA2,color:#fff
```

## Prerequisites

### General Requirements

- Linux/macOS/Windows with x86_64 or ARM64
- 2+ CPU cores
- 512MB+ RAM (2GB+ for production)
- Network connectivity for dependencies

### Storage Backend Requirements

#### Memory Backend (Development)

- No additional requirements
- Data lost on restart
- Fast performance for testing

#### FoundationDB Backend (Production)

- FoundationDB 7.1+ cluster
- Network access to FDB cluster
- Cluster file (`fdb.cluster`)

### Authentication Requirements

- JWKS endpoint URL (for JWT validation)
- Redis instance (for replay protection)
- OAuth/OIDC provider (optional)

## Deployment Options

### 1. Docker Deployment

Best for: Development, testing, single-node production

**Quick Start:**

```bash
# Pull the image
docker pull inferadb-engine:latest

# Run with memory backend
docker run -d \
  --name inferadb \
  -p 8080:8080 \
  -p 8081:8081 \
  -e INFERADB__ENGINE__STORAGE=memory \
  inferadb-engine:latest

# Verify health
curl http://localhost:8080/health
```

**Production Configuration:**

```bash
# Create secrets directory
mkdir -p /var/run/secrets/inferadb

# Create environment file
cat > inferadb.env <<EOF
INFERADB__ENGINE__THREADS=4
INFERADB__ENGINE__STORAGE=foundationdb
INFERADB__ENGINE__FOUNDATIONDB__CLUSTER_FILE=/etc/foundationdb/fdb.cluster
INFERADB__ENGINE__CACHE__ENABLED=true
INFERADB__ENGINE__CACHE__CAPACITY=100000
INFERADB__ENGINE__TOKEN__CACHE_TTL=300
EOF

# Run with configuration
docker run -d \
  --name inferadb \
  -p 8080:8080 \
  -p 8081:8081 \
  --env-file inferadb.env \
  -v /etc/foundationdb:/etc/foundationdb:ro \
  -v /var/run/secrets/inferadb:/var/run/secrets:ro \
  --restart unless-stopped \
  inferadb-engine:latest
```

**Docker Compose:**

```yaml
version: "3.8"

services:
  inferadb:
    image: inferadb-engine:latest
    ports:
      - "8080:8080"
      - "8081:8081"
      - "9090:9090" # Metrics
    environment:
      INFERADB__ENGINE__THREADS: "4"
      INFERADB__ENGINE__STORAGE: "memory"
      INFERADB__ENGINE__CACHE__ENABLED: "true"
      INFERADB__ENGINE__LOGGING: "info"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 10s
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

### 2. Kubernetes Deployment

Best for: Production, high availability, cloud deployments

See [Kubernetes README](../k8s/README.md) for detailed instructions.

**Quick Start:**

```bash
# Create namespace
kubectl create namespace inferadb

# Create secrets
kubectl create secret generic inferadb-secrets \
  --from-literal=INFERADB__ENGINE__TOKEN__JWKS_URL="https://auth.example.com/.well-known/jwks.json" \
  -n inferadb

# Deploy
kubectl apply -k k8s/ -n inferadb

# Verify
kubectl get pods -n inferadb
kubectl logs -n inferadb -l app=inferadb --tail=100
```

### 3. Helm Deployment

Best for: Kubernetes with parameterized configuration

See [Helm README](../../helm/README.md) for detailed instructions.

**Quick Start:**

```bash
# Install with defaults
helm install inferadb ./helm --namespace inferadb --create-namespace

# Install with custom values
cat > values-prod.yaml <<EOF
replicaCount: 5

config:
  store:
    backend: foundationdb
  auth:
    enabled: true
    replayProtection: true

autoscaling:
  enabled: true
  minReplicas: 5
  maxReplicas: 50
EOF

helm install inferadb ./helm \
  -f values-prod.yaml \
  --namespace inferadb \
  --create-namespace
```

### 4. Cloud Deployment with Terraform

Best for: Automated infrastructure provisioning on AWS or GCP

InferaDB provides Terraform modules for one-command cloud deployments. See [Terraform README](../../terraform/README.md) for full documentation.

**AWS Quick Start:**

```bash
cd terraform/examples/aws-complete

# Configure variables
cat > terraform.tfvars <<EOF
cluster_name    = "inferadb-prod"
aws_region      = "us-west-2"
environment     = "production"

# Restrict API access
cluster_endpoint_public_access_cidrs = ["YOUR_IP/32"]

# Node configuration
node_instance_types = ["m5.xlarge"]
node_desired_size   = 3
node_max_size       = 10

# InferaDB configuration
inferadb_engine_replica_count = 3
inferadb_engine_auth_enabled  = true
EOF

# Deploy everything (EKS + Redis + InferaDB)
terraform init
terraform apply

# Configure kubectl
aws eks update-kubeconfig --region us-west-2 --name inferadb-prod
```

**GCP Quick Start:**

```bash
cd terraform/examples/gcp-complete

# Configure variables
cat > terraform.tfvars <<EOF
project_id      = "your-gcp-project"
cluster_name    = "inferadb-prod"
region          = "us-central1"
environment     = "production"

# Node configuration
machine_type    = "n2-standard-4"

# InferaDB configuration
inferadb_engine_replica_count = 3
EOF

# Deploy everything (GKE + Redis + InferaDB)
terraform init
terraform apply

# Configure kubectl
gcloud container clusters get-credentials inferadb-prod --region us-central1
```

**What Terraform Creates:**

- **AWS**: EKS cluster, VPC, subnets, NAT gateways, ElastiCache Redis, Load Balancer, InferaDB deployment
- **GCP**: GKE cluster, VPC, Cloud NAT, Memorystore Redis, Load Balancer, InferaDB deployment

**Cost Estimates:**

- AWS Complete: ~$695/month
- AWS Minimal (dev): ~$60/month
- GCP Complete: ~$650/month
- GCP Minimal (dev): ~$75/month

See [terraform/README.md](../../terraform/README.md) for detailed documentation.

## Configuration

### Environment Variables

All configuration can be provided via environment variables using the `INFERADB__ENGINE__` prefix:

| Environment Variable               | Description                                  | Default        |
| ---------------------------------- | -------------------------------------------- | -------------- |
| `INFERADB__ENGINE__LISTEN__HTTP`   | Public REST API address (host:port)          | `0.0.0.0:8080` |
| `INFERADB__ENGINE__LISTEN__GRPC`   | Public gRPC API address (host:port)          | `0.0.0.0:8081` |
| `INFERADB__ENGINE__LISTEN__MESH`   | Service mesh address (host:port)             | `0.0.0.0:8082` |
| `INFERADB__ENGINE__THREADS`        | Tokio worker threads                         | CPU count      |
| `INFERADB__ENGINE__STORAGE`        | Storage backend (`memory` or `foundationdb`) | `memory`       |
| `INFERADB__ENGINE__CACHE__ENABLED` | Enable caching                               | `true`         |

See [Configuration Guide](configuration.md) for complete list.

### Configuration File

Alternatively, use a YAML configuration file:

```yaml
engine:
  threads: 4
  logging: "info"

  listen:
    http: "0.0.0.0:8080"
    grpc: "0.0.0.0:8081"
    mesh: "0.0.0.0:8082"

  storage: foundationdb
  foundationdb:
    cluster_file: /etc/foundationdb/fdb.cluster

  cache:
    enabled: true
    capacity: 100000
    ttl: 600

  token:
    cache_ttl: 300

  mesh:
    url: "http://inferadb-control:9092"
```

Load with:

```bash
inferadb-engine --config /etc/inferadb/config.yaml
```

### Secrets Management

**Never** commit secrets to version control. Use one of these approaches:

#### 1. Environment Variables

```bash
export INFERADB__ENGINE__PEM="-----BEGIN PRIVATE KEY-----\n..."
inferadb-engine
```

#### 2. Kubernetes Secrets

```bash
kubectl create secret generic inferadb-secrets \
  --from-literal=INFERADB__ENGINE__PEM="-----BEGIN PRIVATE KEY-----..."
```

#### 3. External Secrets Operator

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: inferadb-secrets
spec:
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: inferadb-secrets
  data:
    - secretKey: INFERADB__ENGINE__TOKEN__JWKS_URL
      remoteRef:
        key: inferadb/prod/auth
        property: jwks_url
```

#### 4. Docker Secrets

```bash
echo "https://auth.example.com/.well-known/jwks.json" | \
  docker secret create jwks_url -

docker service create \
  --secret jwks_url \
  --env INFERADB__ENGINE__TOKEN__JWKS_URL=/run/secrets/jwks_url \
  inferadb:latest
```

## Security

### Network Security

1. **TLS Termination**: Use a reverse proxy (nginx, Envoy) or ingress controller
2. **Service Mesh mTLS**: Use Istio/Linkerd for transparent pod-to-pod encryption
3. **Network Policies**: Restrict pod-to-pod communication
4. **Firewall Rules**: Limit external access

**Example nginx TLS termination:**

```nginx
upstream inferadb {
    server inferadb-1:8080;
    server inferadb-2:8080;
    server inferadb-3:8080;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/ssl/certs/api.example.com.crt;
    ssl_certificate_key /etc/ssl/private/api.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://inferadb;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Container Security

Our Docker image follows security best practices:

- **Non-root user**: Runs as UID 65532 (nonroot)
- **Read-only filesystem**: No write access to container filesystem
- **Distroless base**: Minimal attack surface
- **No shell**: Prevents shell-based attacks
- **Dropped capabilities**: All Linux capabilities dropped

### Authentication Security

1. **Token validation**: Configure `INFERADB__ENGINE__TOKEN__CACHE_TTL` appropriately
2. **Clock skew**: Adjust `INFERADB__ENGINE__TOKEN__CLOCK_SKEW` as needed (default: 60 seconds)
3. **Token age**: Set `INFERADB__ENGINE__TOKEN__MAX_AGE` for maximum token lifetime
4. **Identity**: Provide `INFERADB__ENGINE__PEM` with Ed25519 private key in production

## Monitoring

### Health Checks

InferaDB exposes multiple health endpoints:

- **`/health`**: Legacy health check (backward compatible)
- **`/health/live`**: Liveness probe (for Kubernetes)
- **`/health/ready`**: Readiness probe (for load balancers)
- **`/health/startup`**: Startup probe (initialization status)

**Example responses:**

```bash
# Liveness - is the process alive?
curl http://localhost:8080/health/live
{"status":"healthy","service":"inferadb-engine","version":"0.1.0"}

# Readiness - can it serve traffic?
curl http://localhost:8080/health/ready
{"status":"healthy","service":"inferadb-engine","version":"0.1.0","details":{...}}

# Startup - is initialization complete?
curl http://localhost:8080/health/startup
{"status":"healthy","service":"inferadb-engine","version":"0.1.0"}
```

### Prometheus Metrics

Metrics are exposed at `/metrics` in Prometheus format:

```bash
curl http://localhost:8080/metrics
```

**Key metrics:**

- `inferadb_requests_total` - Total requests
- `inferadb_request_duration_seconds` - Request latency
- `inferadb_engine_cache_hits_total` - Cache hit count
- `inferadb_engine_cache_misses_total` - Cache miss count
- `inferadb_engine_auth_validations_total` - Authentication attempts
- `inferadb_tuples_stored` - Number of stored tuples

### Distributed Tracing

Enable OpenTelemetry tracing:

```yaml
observability:
  tracing_enabled: true
  tracing_endpoint: http://jaeger:4317
  tracing_sample_rate: 0.1
```

### Logging

Configure logging format and level:

```yaml
observability:
  log_level: info # trace, debug, info, warn, error
  log_format: json # or "text"
```

**Structured JSON logs:**

```json
{
  "timestamp": "2025-10-30T12:00:00Z",
  "level": "INFO",
  "message": "Request processed",
  "duration_ms": 15,
  "path": "/v1/check",
  "status": 200
}
```

## Upgrading

### Docker Upgrade

```bash
# Pull new version
docker pull inferadb-engine:v2.0.0

# Stop old container
docker stop inferadb

# Remove old container
docker rm inferadb

# Start new version
docker run -d \
  --name inferadb \
  --env-file inferadb.env \
  -p 8080:8080 \
  inferadb-engine:v2.0.0
```

### Kubernetes Rolling Update

```bash
# Update image
kubectl set image deployment/inferadb inferadb=inferadb-engine:v2.0.0 -n inferadb

# Monitor rollout
kubectl rollout status deployment/inferadb -n inferadb

# Rollback if needed
kubectl rollout undo deployment/inferadb -n inferadb
```

### Helm Upgrade

```bash
# Upgrade to new version
helm upgrade inferadb ./helm \
  --set image.tag=v2.0.0 \
  --namespace inferadb

# Monitor
helm status inferadb --namespace inferadb

# Rollback if needed
helm rollback inferadb --namespace inferadb
```

### Zero-Downtime Upgrades

For zero-downtime upgrades:

1. **Use rolling updates**: Update one replica at a time
2. **Set PodDisruptionBudget**: Ensure minimum replicas available
3. **Health checks**: Configure readiness probes
4. **Graceful shutdown**: 30-second termination grace period

Example Kubernetes configuration:

```yaml
spec:
  replicas: 5
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0 # Zero downtime

  template:
    spec:
      terminationGracePeriodSeconds: 30
      containers:
        - name: inferadb
          readinessProbe:
            httpGet:
              path: /health/ready
              port: 8080
            periodSeconds: 5
```

## Troubleshooting

### Pods Not Starting

**Check pod status:**

```bash
kubectl describe pod -n inferadb -l app=inferadb
kubectl logs -n inferadb -l app=inferadb --tail=100
```

**Common issues:**

1. **Image pull errors**: Verify image name and credentials
2. **Configuration errors**: Check ConfigMap and Secrets
3. **Resource limits**: Increase CPU/memory requests
4. **Dependencies**: Ensure FDB/Redis are accessible

### Connection Issues

**Test connectivity:**

```bash
# From within cluster
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://inferadb:8080/health

# Port forward from local
kubectl port-forward -n inferadb svc/inferadb 8080:8080
curl http://localhost:8080/health
```

**Check endpoints:**

```bash
kubectl get endpoints inferadb -n inferadb
```

### Performance Issues

**Check resource usage:**

```bash
kubectl top pods -n inferadb -l app=inferadb
```

**Check metrics:**

```bash
kubectl port-forward -n inferadb svc/inferadb 8080:8080
curl http://localhost:8080/metrics | grep inferadb_request_duration
```

**Common fixes:**

1. **Increase replicas**: Scale horizontally
2. **Increase resources**: More CPU/memory
3. **Enable caching**: Ensure `INFERADB__ENGINE__CACHE__CAPACITY` is set appropriately
4. **Optimize queries**: Review application logic
5. **Check backend**: FDB performance, Redis latency

### Authentication Failures

**Check JWKS connectivity:**

```bash
# From pod
kubectl exec -it -n inferadb deployment/inferadb -- \
  curl https://auth.example.com/.well-known/jwks.json
```

**Common issues:**

1. **Wrong JWKS URL**: Verify `INFERADB__ENGINE__TOKEN__JWKS_URL`
2. **Network restrictions**: Check firewall/egress rules
3. **Clock skew**: Increase `INFERADB__ENGINE__TOKEN__CLOCK_SKEW_SECONDS`
4. **Token format**: Verify JWT structure and claims

### Storage Issues

**FoundationDB connectivity:**

```bash
# Check cluster file
kubectl exec -it -n inferadb deployment/inferadb -- \
  cat /etc/foundationdb/fdb.cluster

# Test FDB connection
kubectl run -it --rm fdb-test --image=foundationdb/foundationdb:7.1.38 -- \
  fdbcli -C /etc/foundationdb/fdb.cluster status
```

## Best Practices

### Production Checklist

- [ ] Use FoundationDB backend (not memory)
- [ ] Enable authentication
- [ ] Enable replay protection
- [ ] Use external secret manager
- [ ] Configure resource limits
- [ ] Enable autoscaling (HPA)
- [ ] Set PodDisruptionBudget
- [ ] Configure health checks
- [ ] Enable monitoring (Prometheus)
- [ ] Enable distributed tracing
- [ ] Use structured logging (JSON)
- [ ] Configure TLS termination
- [ ] Set up backup/restore procedures
- [ ] Document runbooks
- [ ] Test disaster recovery

### Scaling Guidelines

| Workload    | Replicas | CPU/Replica | Memory/Replica | Backend      |
| ----------- | -------- | ----------- | -------------- | ------------ |
| Development | 1        | 100m        | 128Mi          | Memory       |
| Testing     | 1-3      | 250m        | 256Mi          | Memory       |
| Staging     | 3-5      | 500m        | 512Mi          | FoundationDB |
| Production  | 5-50     | 1000m       | 2Gi            | FoundationDB |

### Resource Allocation

**CPU:**

- Worker threads = CPU cores
- Over-provision for burst traffic
- Monitor CPU throttling

**Memory:**

- Cache size ≈ 50% of memory
- Account for request buffers
- Monitor OOM kills

**Storage:**

- FoundationDB for persistence
- Size based on tuple count
- Plan for growth

## Support

- **Documentation**: [https://docs.inferadb.com](https://docs.inferadb.com)
- **Issues**: [https://github.com/inferadb/inferadb/issues](https://github.com/inferadb/inferadb/issues)
- **Community**: [https://community.inferadb.com](https://community.inferadb.com)

## See Also

- [Kubernetes Deployment](../../k8s/README.md)
- [Helm Chart](../../helm/README.md)
- [Configuration Reference](configuration.md)
- [Observability Guide](../operations/observability/README.md)
- [Operational Runbooks](../runbooks/)

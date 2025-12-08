# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying InferaDB to a Kubernetes cluster.

## Prerequisites

- Kubernetes 1.24+
- kubectl configured to access your cluster
- FoundationDB operator (optional, for FDB storage backend)
- Redis (for replay protection)
- Metrics server (for HPA)
- Prometheus (for monitoring)

## Quick Start

### 1. Customize Configuration

**IMPORTANT:** Before deploying, update these files with your environment-specific values:

1. **configmap.yaml**:
   - Update any configuration values as needed

2. **secret.yaml**:
   - Replace all placeholder values marked with `change-me-in-production`
   - **DO NOT** commit real secrets to version control
   - Use Kubernetes secrets, External Secrets Operator, or sealed-secrets instead

3. **kustomization.yaml** (line 37):
   - Replace `v1.0.0` with your desired InferaDB version

### 2. Create Namespace

```bash
kubectl create namespace inferadb
```

### 3. Update Secrets (Production Recommended)

Create secrets using kubectl (not checked into git):

```bash
kubectl create secret generic inferadb-secrets \
  --from-literal=INFERADB__AUTH__JWKS_URL="https://your-auth.example.com/.well-known/jwks.json" \
  --from-literal=INFERADB__AUTH__REDIS_URL="redis://redis-master:6379" \
  --from-literal=INFERADB__AUTH__OIDC_CLIENT_SECRET="your-secret-here" \
  -n inferadb
```

### 4. Deploy

```bash
kubectl apply -f rbac.yaml -n inferadb
kubectl apply -f configmap.yaml -n inferadb
kubectl apply -f secret.yaml -n inferadb
kubectl apply -f deployment.yaml -n inferadb
kubectl apply -f service.yaml -n inferadb
kubectl apply -f hpa.yaml -n inferadb
kubectl apply -f pdb.yaml -n inferadb
```

Or use kustomize:

```bash
kubectl apply -k .
```

### 4. Verify Deployment

```bash
# Check pods
kubectl get pods -n inferadb -l app=inferadb

# Check services
kubectl get svc -n inferadb

# Check logs
kubectl logs -n inferadb -l app=inferadb --tail=100
```

## Configuration

### Environment Variables

Configuration is managed through ConfigMap (`configmap.yaml`). Key settings:

- `INFERADB__SERVER__WORKER_THREADS`: Number of Tokio worker threads (default: 4)
- `INFERADB__CACHE__MAX_CAPACITY`: Maximum cache entries (default: 100000)
- `INFERADB__AUTH__ENABLED`: Enable authentication (default: true)

See [docs/configuration-reference.md](../docs/configuration-reference.md) for all options.

### Secrets

Sensitive configuration is stored in Secret (`secret.yaml`):

- JWKS URL for JWT validation
- Redis connection URL for replay protection
- OAuth client secrets

**Production:** Use external secret managers (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) via External Secrets Operator.

## Scaling

### Manual Scaling

```bash
kubectl scale deployment inferadb --replicas=5 -n inferadb
```

### Autoscaling

HPA is configured to scale based on:

- CPU utilization (target: 70%)
- Memory utilization (target: 80%)
- Request rate (target: 1000 RPS)

Limits:

- Min replicas: 3
- Max replicas: 20

## Health Checks

The deployment includes three health probes:

### Liveness Probe

- Path: `/health/live`
- Initial delay: 10s
- Period: 10s
- Indicates if the pod is alive

### Readiness Probe

- Path: `/health/ready`
- Initial delay: 5s
- Period: 5s
- Indicates if the pod can serve traffic

### Startup Probe

- Path: `/health/startup`
- Initial delay: 0s
- Period: 5s
- Max failures: 30 (150s total)
- Indicates if initialization is complete

## Storage Backend

### In-Memory (Development)

```yaml
env:
  - name: INFERADB__STORE__BACKEND
    value: "memory"
```

### FoundationDB (Production)

1. Install FoundationDB Operator:

```bash
kubectl apply -f https://raw.githubusercontent.com/FoundationDB/fdb-kubernetes-operator/main/config/crd/bases/apps.foundationdb.org_foundationdbclusters.yaml
kubectl apply -f https://raw.githubusercontent.com/FoundationDB/fdb-kubernetes-operator/main/config/samples/deployment.yaml
```

1. Create FDB cluster:

```yaml
apiVersion: apps.foundationdb.org/v1beta2
kind: FoundationDBCluster
metadata:
  name: inferadb-fdb
spec:
  version: 7.1.38
  processCounts:
    storage: 3
    log: 3
    stateless: 3
```

1. Update ConfigMap with cluster file location:

```yaml
INFERADB__STORE__CONNECTION_STRING: "/etc/foundationdb/fdb.cluster"
```

## Monitoring

### Prometheus Scraping

The deployment includes Prometheus annotations:

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8080"
  prometheus.io/path: "/metrics"
```

### ServiceMonitor

For Prometheus Operator:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: inferadb
spec:
  selector:
    matchLabels:
      app: inferadb
  endpoints:
    - port: metrics
      interval: 30s
```

### Grafana Dashboards

Import dashboards from `../grafana/`:

- Overview dashboard
- Performance dashboard
- Errors dashboard
- Cache dashboard
- Replication dashboard

## Security

### Pod Security

- Runs as non-root user (UID 65532)
- Read-only root filesystem
- No privilege escalation
- Drops all capabilities
- Uses seccomp RuntimeDefault profile

### Network Policies

Create NetworkPolicy to restrict traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: inferadb
spec:
  podSelector:
    matchLabels:
      app: inferadb
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector: {}
      ports:
        - port: 8080
        - port: 8081
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: foundationdb
      ports:
        - port: 4500
    - to:
        - podSelector:
            matchLabels:
              app: redis
      ports:
        - port: 6379
```

## Troubleshooting

### Pods Not Starting

```bash
# Check pod status
kubectl describe pod -n inferadb -l app=inferadb

# Check events
kubectl get events -n inferadb --sort-by='.lastTimestamp'

# Check logs
kubectl logs -n inferadb -l app=inferadb --previous
```

### Connection Issues

```bash
# Test service connectivity
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://inferadb:8080/health

# Check endpoints
kubectl get endpoints inferadb -n inferadb
```

### Performance Issues

```bash
# Check resource usage
kubectl top pods -n inferadb -l app=inferadb

# Check HPA status
kubectl get hpa inferadb -n inferadb

# Check metrics
kubectl port-forward -n inferadb svc/inferadb 8080:8080
curl http://localhost:8080/metrics
```

## Upgrading

### Rolling Update

```bash
# Update image
kubectl set image deployment/inferadb inferadb=inferadb:v2.0.0 -n inferadb

# Monitor rollout
kubectl rollout status deployment/inferadb -n inferadb

# Rollback if needed
kubectl rollout undo deployment/inferadb -n inferadb
```

### Zero-Downtime Deployment

The deployment is configured for zero-downtime updates:

- `maxUnavailable: 0` ensures at least one pod is always running
- `maxSurge: 1` allows one extra pod during rollout
- PodDisruptionBudget ensures minimum 2 pods available
- Graceful shutdown with 30s termination grace period

## Disaster Recovery

### Backup

FoundationDB backups are handled by FDB operator. For configuration:

```bash
# Backup ConfigMap
kubectl get configmap inferadb-engine-config -n inferadb -o yaml > backup-configmap.yaml

# Backup Secrets (encrypted)
kubectl get secret inferadb-secrets -n inferadb -o yaml > backup-secrets.yaml
```

### Restore

```bash
kubectl apply -f backup-configmap.yaml
kubectl apply -f backup-secrets.yaml
kubectl rollout restart deployment/inferadb -n inferadb
```

## See Also

- [Deployment Documentation](../docs/guides/deployment.md)
- [Configuration Reference](../docs/guides/configuration.md)
- [Operational Runbooks](../docs/runbooks/)
- [Helm Chart](../helm/)

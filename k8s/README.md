# Kubernetes Deployment

Kubernetes manifests for deploying InferaDB Engine.

## Prerequisites

- Kubernetes 1.24+
- kubectl configured to access your cluster
- FoundationDB operator (optional, for FDB storage backend)
- Metrics server (for HPA)
- Prometheus (for monitoring)

## Quick Start

### 1. Customize Configuration

**IMPORTANT:** Before deploying, update these files:

1. **configmap.yaml**: Update configuration values as needed
2. **secret.yaml**: Replace placeholder values (use External Secrets Operator in production)
3. **kustomization.yaml**: Replace `v1.0.0` with your desired version

### 2. Create Namespace

```bash
kubectl create namespace inferadb
```

### 3. Deploy

```bash
kubectl apply -k . -n inferadb
```

Or apply individually:

```bash
kubectl apply -f rbac.yaml -n inferadb
kubectl apply -f configmap.yaml -n inferadb
kubectl apply -f secret.yaml -n inferadb
kubectl apply -f deployment.yaml -n inferadb
kubectl apply -f service.yaml -n inferadb
kubectl apply -f hpa.yaml -n inferadb
kubectl apply -f pdb.yaml -n inferadb
```

### 4. Verify

```bash
kubectl get pods -n inferadb -l app=inferadb-engine
kubectl get svc -n inferadb
kubectl logs -n inferadb -l app=inferadb-engine --tail=100
```

## Configuration

### Environment Variables

Configuration uses the `INFERADB__ENGINE__` prefix:

| Variable | Description | Default |
|----------|-------------|---------|
| `INFERADB__ENGINE__THREADS` | Worker threads | `4` |
| `INFERADB__ENGINE__LOGGING` | Log level | `info` |
| `INFERADB__ENGINE__LISTEN__HTTP` | HTTP listen address | `0.0.0.0:8080` |
| `INFERADB__ENGINE__LISTEN__GRPC` | gRPC listen address | `0.0.0.0:8081` |
| `INFERADB__ENGINE__LISTEN__MESH` | Mesh listen address | `0.0.0.0:8082` |
| `INFERADB__ENGINE__STORAGE` | Storage backend | `memory` |
| `INFERADB__ENGINE__CACHE__ENABLED` | Enable caching | `true` |
| `INFERADB__ENGINE__CACHE__CAPACITY` | Max cache entries | `100000` |
| `INFERADB__ENGINE__TOKEN__CACHE_TTL` | JWKS cache TTL (seconds) | `300` |
| `INFERADB__ENGINE__MESH__URL` | Control service URL | `""` |

See [Configuration Guide](../docs/guides/configuration.md) for complete reference.

### Secrets

For production, use External Secrets Operator:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: inferadb-engine-secrets
spec:
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: inferadb-engine-secrets
  data:
    - secretKey: INFERADB__ENGINE__PEM
      remoteRef:
        key: inferadb/prod/engine
        property: pem
```

## Ports

| Port | Name | Description |
|------|------|-------------|
| 8080 | http | REST API (client-facing) |
| 8081 | grpc | gRPC API (client-facing) |
| 8082 | mesh | Mesh API (JWKS, metrics, inter-service) |

## Health Checks

| Endpoint | Purpose |
|----------|---------|
| `/livez` | Liveness probe |
| `/readyz` | Readiness probe |
| `/startupz` | Startup probe |

## Storage Backend

### In-Memory (Development)

```yaml
# In configmap.yaml
INFERADB__ENGINE__STORAGE: "memory"
```

### FoundationDB (Production)

1. Install FoundationDB Operator
2. Create FDB cluster
3. Configure:

```yaml
# In configmap.yaml
INFERADB__ENGINE__STORAGE: "foundationdb"
INFERADB__ENGINE__FOUNDATIONDB__CLUSTER_FILE: "/etc/foundationdb/fdb.cluster"
```

## Scaling

### Manual

```bash
kubectl scale deployment inferadb-engine --replicas=5 -n inferadb
```

### Autoscaling

HPA scales on CPU (70%) and memory (80%). Limits: 3-20 replicas.

## Monitoring

Prometheus scrapes metrics from port 8082 at `/metrics`.

For ServiceMonitor:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: inferadb-engine
spec:
  selector:
    matchLabels:
      app: inferadb-engine
  endpoints:
    - port: mesh
      interval: 30s
      path: /metrics
```

## Security

- Non-root user (UID 65532)
- Read-only root filesystem
- No privilege escalation
- Dropped capabilities
- Seccomp RuntimeDefault profile

## Troubleshooting

```bash
# Check pod status
kubectl describe pod -n inferadb -l app=inferadb-engine

# Check events
kubectl get events -n inferadb --sort-by='.lastTimestamp'

# Check logs
kubectl logs -n inferadb -l app=inferadb-engine --previous

# Test connectivity
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://inferadb-engine:8080/health
```

## See Also

- [Configuration Guide](../docs/guides/configuration.md)
- [Deployment Guide](../docs/guides/deployment.md)
- [Helm Chart](../helm/)

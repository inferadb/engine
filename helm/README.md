# InferaDB Helm Chart

Official Helm chart for deploying InferaDB to Kubernetes.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.8+
- PV provisioner support in the underlying infrastructure (for persistent storage)

## Installation

### Add Helm Repository

```bash
helm repo add inferadb https://charts.inferadb.com
helm repo update
```

### Install Chart

```bash
# Install with default values
helm install inferadb inferadb/inferadb

# Install with custom values
helm install inferadb inferadb/inferadb -f custom-values.yaml

# Install in specific namespace
helm install inferadb inferadb/inferadb --namespace inferadb --create-namespace
```

### Install from Source

```bash
helm install inferadb ./helm --namespace inferadb --create-namespace
```

## Configuration

See [values.yaml](values.yaml) for all configuration options.

### Common Configurations

#### Production with FoundationDB

```yaml
replicaCount: 5

resources:
  requests:
    cpu: 1000m
    memory: 2Gi
  limits:
    cpu: 4000m
    memory: 8Gi

config:
  store:
    backend: "foundationdb"
    connectionString: "/etc/foundationdb/fdb.cluster"

  auth:
    enabled: true
    replayProtection: true

autoscaling:
  enabled: true
  minReplicas: 5
  maxReplicas: 50

foundationdb:
  enabled: true
  clusterName: "prod-fdb"

redis:
  enabled: true
  auth:
    enabled: true
    password: "secure-password"
```

#### Development with In-Memory Storage

```yaml
replicaCount: 1

resources:
  requests:
    cpu: 100m
    memory: 128Mi

config:
  store:
    backend: "memory"

  auth:
    enabled: false

autoscaling:
  enabled: false
```

## Upgrading

### Upgrade Release

```bash
helm upgrade inferadb inferadb/inferadb --namespace inferadb
```

### Upgrade with New Values

```bash
helm upgrade inferadb inferadb/inferadb -f new-values.yaml --namespace inferadb
```

### Rollback

```bash
helm rollback inferadb --namespace inferadb
```

## Uninstallation

```bash
helm uninstall inferadb --namespace inferadb
```

## Parameters

### Global Parameters

| Name               | Description                            | Value          |
| ------------------ | -------------------------------------- | -------------- |
| `image.repository` | InferaDB image repository              | `inferadb`     |
| `image.tag`        | Image tag (overrides Chart appVersion) | `""`           |
| `image.pullPolicy` | Image pull policy                      | `IfNotPresent` |
| `replicaCount`     | Number of replicas                     | `3`            |

### Service Parameters

| Name               | Description             | Value       |
| ------------------ | ----------------------- | ----------- |
| `service.type`     | Kubernetes service type | `ClusterIP` |
| `service.port`     | HTTP service port       | `8080`      |
| `service.grpcPort` | gRPC service port       | `8081`      |

### Autoscaling Parameters

| Name                                         | Description      | Value  |
| -------------------------------------------- | ---------------- | ------ |
| `autoscaling.enabled`                        | Enable HPA       | `true` |
| `autoscaling.minReplicas`                    | Minimum replicas | `3`    |
| `autoscaling.maxReplicas`                    | Maximum replicas | `20`   |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU %     | `70`   |

### InferaDB Configuration

| Name                          | Description           | Value    |
| ----------------------------- | --------------------- | -------- |
| `config.server.workerThreads` | Tokio worker threads  | `4`      |
| `config.store.backend`        | Storage backend       | `memory` |
| `config.cache.enabled`        | Enable caching        | `true`   |
| `config.auth.enabled`         | Enable authentication | `true`   |

See [values.yaml](values.yaml) for complete list.

## Monitoring

### Prometheus Integration

The chart includes ServiceMonitor support for Prometheus Operator:

```yaml
serviceMonitor:
  enabled: true
  interval: 30s
```

### Grafana Dashboards

Import dashboards from the repository:

- [grafana/overview-dashboard.json](../grafana/overview-dashboard.json)
- [grafana/performance-dashboard.json](../grafana/performance-dashboard.json)

## Security

### Pod Security

The chart enforces security best practices:

- Non-root user (UID 65532)
- Read-only root filesystem
- No privilege escalation
- Dropped capabilities
- Seccomp profile

### Secrets Management

For production, use external secret managers:

```yaml
# Use External Secrets Operator
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
    - secretKey: jwksUrl
      remoteRef:
        key: inferadb/prod/auth
        property: jwks_url
```

## Examples

### Minimal Installation

```bash
helm install inferadb ./helm --set config.auth.enabled=false
```

### High Availability

```bash
helm install inferadb ./helm \
  --set replicaCount=5 \
  --set autoscaling.minReplicas=5 \
  --set autoscaling.maxReplicas=50 \
  --set podDisruptionBudget.minAvailable=3
```

### Custom Configuration File

```bash
cat > prod-values.yaml <<EOF
replicaCount: 5
config:
  store:
    backend: foundationdb
  auth:
    enabled: true
    replayProtection: true
EOF

helm install inferadb ./helm -f prod-values.yaml
```

## Troubleshooting

### Check Release Status

```bash
helm status inferadb --namespace inferadb
```

### View Values

```bash
helm get values inferadb --namespace inferadb
```

### Debug Templates

```bash
helm template inferadb ./helm --debug
```

## Support

- Documentation: https://docs.inferadb.com
- Issues: https://github.com/inferadb/inferadb/issues
- Community: https://community.inferadb.com

# FoundationDB Multi-Region Kubernetes Manifests

This directory contains Kubernetes manifests for deploying FoundationDB clusters in a multi-region Fearless DR configuration.

## Overview

These manifests deploy FoundationDB clusters that:

- Use the FDB Kubernetes Operator for management
- Configure Fearless DR for cross-region replication
- Include Tailscale sidecars for cross-region networking
- Support automatic failover between regions

## Prerequisites

1. **FDB Kubernetes Operator**: Install the operator in each region:

   ```bash
   # Using Helm
   helm repo add fdb https://foundationdb.github.io/fdb-kubernetes-operator/
   helm install fdb-operator fdb/fdb-kubernetes-operator -n fdb-system --create-namespace
   ```

2. **Tailscale**: Create a reusable, tagged auth key:

   ```bash
   # Create secret in each region
   kubectl create secret generic tailscale-auth \
     --from-literal=authkey=tskey-auth-xxx \
     -n inferadb
   ```

3. **Network Connectivity**: Ensure Tailscale ACLs allow FDB traffic:

   ```json
   {
     "acls": [
       {
         "action": "accept",
         "src": ["tag:fdb"],
         "dst": ["tag:fdb:4500,4501"]
       }
     ]
   }
   ```

## Deployment Order

### 1. Deploy Primary Region

```bash
# Switch to primary cluster context
kubectl config use-context aws-us-west-1

# Create namespace
kubectl create namespace inferadb

# Deploy Tailscale secret
kubectl create secret generic tailscale-auth \
  --from-literal=authkey=$TAILSCALE_AUTH_KEY \
  -n inferadb

# Deploy FDB cluster
kubectl apply -f fdb-cluster-primary.yaml

# Wait for cluster to be ready
kubectl wait --for=condition=Ready foundationdbcluster/inferadb-fdb -n inferadb --timeout=600s
```

### 2. Deploy Secondary Region

```bash
# Switch to secondary cluster context
kubectl config use-context aws-eu-central-1

# Create namespace
kubectl create namespace inferadb

# Deploy Tailscale secret
kubectl create secret generic tailscale-auth \
  --from-literal=authkey=$TAILSCALE_AUTH_KEY \
  -n inferadb

# Deploy FDB cluster
kubectl apply -f fdb-cluster-secondary.yaml

# Wait for cluster to be ready
kubectl wait --for=condition=Ready foundationdbcluster/inferadb-fdb -n inferadb --timeout=600s
```

### 3. Verify Replication

```bash
# In primary region, check cluster status
kubectl exec -it inferadb-fdb-storage-0 -n inferadb -c foundationdb -- fdbcli --exec "status"

# Expected output should show both regions
# Data distribution should indicate cross-region replication
```

## Configuration

### Process Counts

Adjust `processCounts` in the manifests based on your workload:

| Workload | Storage | Log | Stateless |
| -------- | ------- | --- | --------- |
| Dev/Test | 1       | 1   | 1         |
| Small    | 3       | 3   | 3         |
| Medium   | 5       | 5   | 5         |
| Large    | 9+      | 9+  | 9+        |

### Redundancy Mode

Choose based on your fault tolerance requirements:

| Mode     | Copies | Tolerates  | Use Case          |
| -------- | ------ | ---------- | ----------------- |
| `single` | 1      | 0 failures | Dev only          |
| `double` | 2      | 1 machine  | Production        |
| `triple` | 3      | 2 machines | High availability |

### Multi-Region Configuration

The `regions` configuration must be **identical** in both primary and secondary:

```yaml
regions:
  - datacenters:
      - id: us-west-1 # Primary region
        priority: 1 # Lower = higher priority
  - datacenters:
      - id: eu-central-1 # Secondary region
        priority: 2
```

## Files

| File                         | Description                           |
| ---------------------------- | ------------------------------------- |
| `fdb-cluster-primary.yaml`   | Primary region FDB cluster            |
| `fdb-cluster-secondary.yaml` | Secondary (DR) region FDB cluster     |
| `fdb-configmap.yaml`         | Configuration reference and templates |
| `README.md`                  | This file                             |

## Monitoring

### FDB CLI Commands

```bash
# Connect to FDB CLI
kubectl exec -it inferadb-fdb-storage-0 -n inferadb -c foundationdb -- fdbcli

# Useful commands:
status                    # Overall cluster status
status details            # Detailed status
status json               # JSON format for parsing
configure double          # Change redundancy mode
coordinators auto         # Auto-select coordinators
```

### Key Metrics

Monitor these FDB metrics in your observability stack:

- `fdb_database_available`: Is the database available?
- `fdb_replication_lag_seconds`: Replication lag to DR region
- `fdb_coordinators_connected`: Number of connected coordinators
- `fdb_storage_used_bytes`: Storage utilization

### Alerts

Recommended alert thresholds:

```yaml
# Prometheus alerting rules
groups:
  - name: fdb
    rules:
      - alert: FDBClusterUnavailable
        expr: fdb_database_available == 0
        for: 1m
        labels:
          severity: critical

      - alert: FDBHighReplicationLag
        expr: fdb_replication_lag_seconds > 5
        for: 5m
        labels:
          severity: warning

      - alert: FDBLowCoordinators
        expr: fdb_coordinators_connected < 3
        for: 2m
        labels:
          severity: warning
```

## Failover Procedure

### Automatic Failover

FDB Fearless DR handles most failover scenarios automatically:

1. Primary region becomes unavailable
2. FDB detects loss of quorum in primary
3. Secondary region is promoted to primary
4. Writes resume in the new primary

### Manual Failover (Testing)

```bash
# 1. In secondary region, force failover
kubectl exec -it inferadb-fdb-storage-0 -n inferadb -c foundationdb -- fdbcli --exec "force_recovery_with_data_loss"

# 2. Verify secondary is now primary
kubectl exec -it inferadb-fdb-storage-0 -n inferadb -c foundationdb -- fdbcli --exec "status"

# 3. When primary is restored, it will sync from new primary
```

### Failback

After the original primary recovers:

1. It automatically re-syncs data from the current primary
2. Optionally, manually failback by running `force_recovery_with_data_loss` in the original primary

## Troubleshooting

### Common Issues

**Cluster not forming:**

- Check FDB operator logs: `kubectl logs -n fdb-system deploy/fdb-operator`
- Verify coordinator connectivity
- Check network policies allow FDB ports (4500, 4501)

**Replication not working:**

- Verify Tailscale connectivity between regions
- Check both clusters have identical multi-region configuration
- Verify coordinators can reach each other

**High replication lag:**

- Check cross-region network latency
- Verify `satellite_logs` is appropriately configured
- Consider increasing log processes

### Useful Commands

```bash
# Check FDB operator status
kubectl get foundationdbcluster -A

# View FDB pod logs
kubectl logs -n inferadb inferadb-fdb-storage-0 -c foundationdb

# Check Tailscale connectivity
kubectl exec -it inferadb-fdb-storage-0 -n inferadb -c tailscale -- tailscale status

# Test FDB connectivity from Engine pod
kubectl exec -it deploy/inferadb-engine -n inferadb -- fdbcli --exec "status"
```

## References

- [FDB Kubernetes Operator Documentation](https://github.com/FoundationDB/fdb-kubernetes-operator/tree/main/docs)
- [FoundationDB Configuration Guide](https://apple.github.io/foundationdb/configuration.html)
- [Fearless DR Documentation](https://apple.github.io/foundationdb/configuration.html#fearless-dr)
- [Tailscale Kubernetes Guide](https://tailscale.com/kb/1185/kubernetes)

# Backup and Restore Runbook

## Overview

This runbook covers backup and restoration procedures for InferaDB data and configuration.

## Storage Backend Considerations

### Memory Backend

**Important**: Memory backend does **not persist data**. All data is lost on pod restart.

- **Use case**: Development/testing only
- **Backup**: Not applicable
- **Restore**: Reload from source of truth

### Ledger Backend

**Recommended**: Production deployments use Ledger for persistence.

- **Use case**: Production
- **Backup**: Automated backups via Ledger snapshot API
- **Restore**: Point-in-time recovery available

## Configuration Backup

### Backup ConfigMaps

```bash
# Export current configuration
kubectl get configmap inferadb-engine-config -n inferadb -o yaml > backup-configmap-$(date +%Y%m%d).yaml

# With labels
kubectl get configmap -n inferadb -l app=inferadb -o yaml > backup-all-configmaps-$(date +%Y%m%d).yaml
```

### Backup Secrets

**Important**: Secrets should be encrypted before storage.

```bash
# Export secrets (CAREFUL: contains sensitive data)
kubectl get secret inferadb-secrets -n inferadb -o yaml > backup-secrets-$(date +%Y%m%d).yaml

# Encrypt backup
gpg --encrypt --recipient your-ops-team@example.com backup-secrets-$(date +%Y%m%d).yaml

# Store encrypted file securely
aws s3 cp backup-secrets-$(date +%Y%m%d).yaml.gpg s3://YOUR_BUCKET_NAME/inferadb/secrets/
```

### Backup Helm Values

```bash
# Get current values
helm get values inferadb -n inferadb > backup-helm-values-$(date +%Y%m%d).yaml

# Get all resources
helm get all inferadb -n inferadb > backup-helm-full-$(date +%Y%m%d).yaml
```

## Data Backup (Ledger)

### Prerequisites

- Ledger cluster running
- Backup storage available (S3, GCS, Azure Blob)
- gRPC connectivity to Ledger

### Configure Ledger Backup

#### 1. Verify Ledger Health

```bash
# Check Ledger cluster health
kubectl exec -it inferadb-ledger-0 -n inferadb -- grpcurl -plaintext localhost:50051 grpc.health.v1.Health/Check

# Check cluster status
kubectl exec -it inferadb-ledger-0 -n inferadb -- grpcurl -plaintext localhost:50051 ledger.v1.Admin/ClusterStatus
```

#### 2. Configure Backup Destination

```yaml
# backup-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ledger-backup-config
  namespace: inferadb
data:
  backup.yaml: |
    storage:
      type: s3
      bucket: YOUR_BUCKET_NAME
      prefix: ledger-backups/
      region: us-east-1
    schedule:
      full: "0 2 * * 0"    # Weekly full backup
      incremental: "0 2 * * *"  # Daily incremental
    retention:
      daily: 7
      weekly: 4
      monthly: 12
```

### Manual Snapshot

```bash
# Create a manual snapshot
kubectl exec -it inferadb-ledger-0 -n inferadb -- \
  grpcurl -plaintext -d '{"name": "manual-'$(date +%Y%m%d-%H%M%S)'"}' \
  localhost:50051 ledger.v1.Admin/CreateSnapshot

# List available snapshots
kubectl exec -it inferadb-ledger-0 -n inferadb -- \
  grpcurl -plaintext localhost:50051 ledger.v1.Admin/ListSnapshots
```

### Automated Backups

#### CronJob for Regular Backups

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ledger-backup
  namespace: inferadb
spec:
  schedule: "0 2 * * *" # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: inferadb/ledger-tools:latest
              command:
                - /bin/bash
                - -c
                - |
                  DATE=$(date +%Y%m%d-%H%M%S)
                  SNAPSHOT_NAME="backup-${DATE}"

                  echo "Starting backup: ${SNAPSHOT_NAME}"
                  grpcurl -plaintext -d "{\"name\": \"${SNAPSHOT_NAME}\"}" \
                    inferadb-ledger:50051 ledger.v1.Admin/CreateSnapshot

                  echo "Uploading to S3..."
                  grpcurl -plaintext -d "{\"snapshot\": \"${SNAPSHOT_NAME}\", \"destination\": \"s3://YOUR_BUCKET_NAME/ledger-backups/${SNAPSHOT_NAME}\"}" \
                    inferadb-ledger:50051 ledger.v1.Admin/ExportSnapshot

                  echo "Backup completed: ${SNAPSHOT_NAME}"
              env:
                - name: AWS_ACCESS_KEY_ID
                  valueFrom:
                    secretKeyRef:
                      name: aws-credentials
                      key: access_key_id
                - name: AWS_SECRET_ACCESS_KEY
                  valueFrom:
                    secretKeyRef:
                      name: aws-credentials
                      key: secret_access_key
          restartPolicy: OnFailure
```

### Backup Verification

```bash
# List backups
kubectl exec -it inferadb-ledger-0 -n inferadb -- \
  grpcurl -plaintext localhost:50051 ledger.v1.Admin/ListSnapshots

# Verify backup integrity
kubectl exec -it inferadb-ledger-0 -n inferadb -- \
  grpcurl -plaintext -d '{"snapshot": "backup-20251030"}' \
  localhost:50051 ledger.v1.Admin/VerifySnapshot
```

## Restore Procedures

### Restore Configuration

#### Restore ConfigMap

```bash
# Apply saved ConfigMap
kubectl apply -f backup-configmap-20251030.yaml

# Restart deployment to pick up changes
kubectl rollout restart deployment/inferadb -n inferadb
```

#### Restore Secrets

```bash
# Decrypt backup
gpg --decrypt backup-secrets-20251030.yaml.gpg > backup-secrets-20251030.yaml

# Apply secrets
kubectl apply -f backup-secrets-20251030.yaml

# Restart deployment
kubectl rollout restart deployment/inferadb -n inferadb

# Clean up decrypted file
shred -u backup-secrets-20251030.yaml
```

### Restore Data (Ledger)

**⚠️ WARNING**: Restoration overwrites existing data. Ensure you have current backups before proceeding.

#### Full Restore

```bash
# 1. Stop InferaDB to prevent writes
kubectl scale deployment inferadb --replicas=0 -n inferadb

# 2. Check Ledger cluster health
kubectl exec -it inferadb-ledger-0 -n inferadb -- \
  grpcurl -plaintext localhost:50051 grpc.health.v1.Health/Check

# 3. Import snapshot from S3
kubectl exec -it inferadb-ledger-0 -n inferadb -- \
  grpcurl -plaintext -d '{"source": "s3://YOUR_BUCKET_NAME/ledger-backups/backup-20251030", "name": "restore-20251030"}' \
  localhost:50051 ledger.v1.Admin/ImportSnapshot

# 4. Restore from snapshot
kubectl exec -it inferadb-ledger-0 -n inferadb -- \
  grpcurl -plaintext -d '{"snapshot": "restore-20251030"}' \
  localhost:50051 ledger.v1.Admin/RestoreSnapshot

# 5. Verify restore
kubectl exec -it inferadb-ledger-0 -n inferadb -- \
  grpcurl -plaintext localhost:50051 ledger.v1.Admin/ClusterStatus

# 6. Restart InferaDB
kubectl scale deployment inferadb --replicas=5 -n inferadb

# 7. Verify functionality
kubectl exec -it -n inferadb deployment/inferadb -- \
  curl http://localhost:8080/health/ready
```

#### Point-in-Time Restore

```bash
# List available restore points
kubectl exec -it inferadb-ledger-0 -n inferadb -- \
  grpcurl -plaintext localhost:50051 ledger.v1.Admin/ListSnapshots

# Restore to specific revision
kubectl exec -it inferadb-ledger-0 -n inferadb -- \
  grpcurl -plaintext -d '{"snapshot": "backup-20251030", "target_revision": 12345}' \
  localhost:50051 ledger.v1.Admin/RestoreSnapshot
```

### Emergency Restore

For critical outages requiring immediate recovery:

```bash
#!/bin/bash
# emergency-restore.sh

set -e

BACKUP_URL="$1"
NAMESPACE="inferadb"

if [ -z "$BACKUP_URL" ]; then
  echo "Usage: $0 <backup-url>"
  exit 1
fi

echo "=== EMERGENCY RESTORE ==="
echo "Backup: $BACKUP_URL"
echo "Namespace: $NAMESPACE"
echo ""

read -p "This will OVERWRITE all data. Continue? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
  echo "Aborted"
  exit 1
fi

# Stop writes
echo "1. Stopping InferaDB..."
kubectl scale deployment inferadb --replicas=0 -n $NAMESPACE

# Wait for pods to terminate
kubectl wait --for=delete pod -l app=inferadb -n $NAMESPACE --timeout=60s

# Import and restore
echo "2. Importing snapshot from backup..."
kubectl exec -it inferadb-ledger-0 -n $NAMESPACE -- \
  grpcurl -plaintext -d "{\"source\": \"$BACKUP_URL\", \"name\": \"emergency-restore\"}" \
  localhost:50051 ledger.v1.Admin/ImportSnapshot

echo "3. Restoring from snapshot..."
kubectl exec -it inferadb-ledger-0 -n $NAMESPACE -- \
  grpcurl -plaintext -d '{"snapshot": "emergency-restore"}' \
  localhost:50051 ledger.v1.Admin/RestoreSnapshot

# Verify
echo "4. Verifying restore..."
kubectl exec -it inferadb-ledger-0 -n $NAMESPACE -- \
  grpcurl -plaintext localhost:50051 ledger.v1.Admin/ClusterStatus

# Restart service
echo "5. Restarting InferaDB..."
kubectl scale deployment inferadb --replicas=5 -n $NAMESPACE

# Wait for readiness
kubectl wait --for=condition=ready pod -l app=inferadb -n $NAMESPACE --timeout=120s

echo "=== RESTORE COMPLETE ==="
echo "Verify functionality and monitor logs"
```

## Disaster Recovery

### DR Checklist

Before disaster strikes:

- [ ] Regular automated backups configured
- [ ] Backups stored in separate region/zone
- [ ] Backup encryption enabled
- [ ] Restore procedures tested quarterly
- [ ] Recovery Time Objective (RTO) defined
- [ ] Recovery Point Objective (RPO) defined
- [ ] Runbooks accessible offline
- [ ] Contact information current

### DR Scenarios

#### Scenario 1: Accidental Data Deletion

**RTO**: 1 hour
**RPO**: Last backup (typically < 24 hours)

**Steps**:

1. Identify last good backup before deletion
2. Stop writes to prevent further changes
3. Restore from backup
4. Verify data integrity
5. Resume operations

#### Scenario 2: Cluster Failure

**RTO**: 30 minutes
**RPO**: Continuous Raft replication

**Steps**:

1. Provision new Ledger cluster
2. Restore latest snapshot
3. Update InferaDB connection strings
4. Resume operations

#### Scenario 3: Region Outage

**RTO**: 2 hours
**RPO**: Continuous backup with cross-region replication

**Steps**:

1. Failover to secondary region
2. Restore latest cross-region backup
3. Update DNS/load balancer
4. Verify functionality
5. Communicate status to stakeholders

## Backup Retention Policy

### Recommended Retention

| Backup Type         | Retention Period | Frequency       |
| ------------------- | ---------------- | --------------- |
| Continuous          | 7 days           | Real-time       |
| Daily Snapshots     | 30 days          | Daily 2 AM      |
| Weekly Snapshots    | 90 days          | Sunday 2 AM     |
| Monthly Snapshots   | 1 year           | 1st of month    |
| Quarterly Snapshots | 7 years          | Jan/Apr/Jul/Oct |

### Cleanup Old Backups

```bash
# List backups older than 30 days
aws s3 ls s3://YOUR_BUCKET_NAME/ledger-backups/ --recursive | \
  awk '{if (NR>30) print $4}' | \
  xargs -I {} aws s3 rm s3://YOUR_BUCKET_NAME/ledger-backups/{}

# Automated cleanup with lifecycle policy
aws s3api put-bucket-lifecycle-configuration \
  --bucket YOUR_BUCKET_NAME \
  --lifecycle-configuration file://lifecycle.json
```

lifecycle.json:

```json
{
  "Rules": [
    {
      "Id": "DeleteOldBackups",
      "Status": "Enabled",
      "Prefix": "ledger-backups/daily/",
      "Expiration": {
        "Days": 30
      }
    },
    {
      "Id": "DeleteOldSnapshots",
      "Status": "Enabled",
      "Prefix": "ledger-backups/monthly/",
      "Expiration": {
        "Days": 365
      }
    }
  ]
}
```

## Testing Restore Procedures

### Monthly Restore Test

```bash
#!/bin/bash
# monthly-restore-test.sh

NAMESPACE="inferadb-test"
BACKUP_URL="s3://YOUR_BUCKET_NAME/ledger-backups/latest"

# Create test namespace
kubectl create namespace $NAMESPACE

# Deploy test Ledger cluster
kubectl apply -f test-ledger-cluster.yaml -n $NAMESPACE

# Import and restore backup
kubectl exec -it -n $NAMESPACE inferadb-ledger-0 -- \
  grpcurl -plaintext -d "{\"source\": \"$BACKUP_URL\", \"name\": \"test-restore\"}" \
  localhost:50051 ledger.v1.Admin/ImportSnapshot

kubectl exec -it -n $NAMESPACE inferadb-ledger-0 -- \
  grpcurl -plaintext -d '{"snapshot": "test-restore"}' \
  localhost:50051 ledger.v1.Admin/RestoreSnapshot

# Deploy InferaDB
helm install inferadb-test ./helm \
  --namespace $NAMESPACE \
  --set config.store.backend=ledger

# Run validation tests
kubectl run -it --rm test --image=curlimages/curl --restart=Never -n $NAMESPACE -- \
  curl http://inferadb-test:8080/health

# Cleanup
kubectl delete namespace $NAMESPACE
```

## Monitoring Backups

### Prometheus Metrics

```yaml
# Alert on backup failures
groups:
  - name: ledger-backup
    rules:
      - alert: LedgerBackupFailed
        expr: ledger_backup_status != 1
        for: 15m
        labels:
          severity: critical
        annotations:
          summary: "Ledger backup failed"
          description: "Backup has been failing for 15 minutes"

      - alert: LedgerBackupStale
        expr: time() - ledger_backup_last_success_timestamp > 86400
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Ledger backup is stale"
          description: "No successful backup in 24 hours"
```

### Backup Status Dashboard

Track in monitoring dashboard:

- Last successful backup timestamp
- Backup size
- Backup duration
- Restore test results
- Storage usage

## Troubleshooting

### Backup Fails to Start

**Problem**: Backup agent can't connect to Ledger

**Investigation**:

```bash
kubectl logs -n inferadb statefulset/inferadb-ledger
kubectl exec -it -n inferadb inferadb-ledger-0 -- \
  grpcurl -plaintext localhost:50051 grpc.health.v1.Health/Check
```

**Resolution**:

- Verify Ledger cluster is healthy
- Check network connectivity
- Ensure backup service has proper permissions

### Restore Hangs

**Problem**: Restore operation stuck

**Investigation**:

```bash
kubectl exec -it -n inferadb inferadb-ledger-0 -- \
  grpcurl -plaintext localhost:50051 ledger.v1.Admin/ClusterStatus
```

**Resolution**:

- Check Ledger cluster health
- Verify backup files are accessible
- Check storage credentials
- Increase restore timeout

### Backup Storage Full

**Problem**: Backup destination running out of space

**Investigation**:

```bash
aws s3 ls s3://YOUR_BUCKET_NAME/ledger-backups/ --recursive --summarize --human-readable
```

**Resolution**:

- Implement retention policy
- Delete old backups
- Increase storage quota
- Archive old backups to glacier

## Related Runbooks

- [Service Outage](service-outage.md) - Recovery procedures
- [Storage Backend](storage-backend.md) - Ledger troubleshooting
- [Upgrades](upgrades.md) - Backup before upgrades

# Backup and Restore Runbook

## Overview

This runbook covers backup and restoration procedures for InferaDB data and configuration.

## Storage Backend Considerations

### Memory Backend

**Important**: Memory backend does **not persist data**. All data is lost on pod restart.

- **Use case**: Development/testing only
- **Backup**: Not applicable
- **Restore**: Reload from source of truth

### FoundationDB Backend

**Recommended**: Production deployments use FoundationDB for persistence.

- **Use case**: Production
- **Backup**: Automated backups via FDB tools
- **Restore**: Point-in-time recovery available

## Configuration Backup

### Backup ConfigMaps

```bash
# Export current configuration
kubectl get configmap inferadb-config -n inferadb -o yaml > backup-configmap-$(date +%Y%m%d).yaml

# With labels
kubectl get configmap -n inferadb -l app=inferadb -o yaml > backup-all-configmaps-$(date +%Y%m%d).yaml
```

### Backup Secrets

**Important**: Secrets should be encrypted before storage.

```bash
# Export secrets (CAREFUL: contains sensitive data)
kubectl get secret inferadb-secrets -n inferadb -o yaml > backup-secrets-$(date +%Y%m%d).yaml

# Encrypt backup
gpg --encrypt --recipient ops@example.com backup-secrets-$(date +%Y%m%d).yaml

# Store encrypted file securely
aws s3 cp backup-secrets-$(date +%Y%m%d).yaml.gpg s3://backups/inferadb/secrets/
```

### Backup Helm Values

```bash
# Get current values
helm get values inferadb -n inferadb > backup-helm-values-$(date +%Y%m%d).yaml

# Get all resources
helm get all inferadb -n inferadb > backup-helm-full-$(date +%Y%m%d).yaml
```

## Data Backup (FoundationDB)

### Prerequisites

- FoundationDB cluster running
- Backup agent configured
- Blob storage available (S3, GCS, Azure Blob)

### Configure FDB Backup

#### 1. Start Backup Agent

```bash
# Deploy FDB backup agent
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fdb-backup-agent
  namespace: inferadb
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fdb-backup-agent
  template:
    metadata:
      labels:
        app: fdb-backup-agent
    spec:
      containers:
      - name: backup-agent
        image: foundationdb/foundationdb:7.1.38
        command:
        - /usr/bin/backup_agent
        args:
        - -C
        - /etc/foundationdb/fdb.cluster
        volumeMounts:
        - name: fdb-cluster-file
          mountPath: /etc/foundationdb
          readOnly: true
      volumes:
      - name: fdb-cluster-file
        secret:
          secretName: fdb-cluster-file
EOF
```

#### 2. Configure Backup Destination

```bash
# Connect to FDB
kubectl exec -it -n inferadb deployment/fdb-backup-agent -- fdbcli -C /etc/foundationdb/fdb.cluster

# Start continuous backup (in fdbcli)
fdb> backup start -d blobstore://s3.amazonaws.com/my-bucket/fdb-backups?bucket=my-bucket&region=us-east-1

# Check backup status
fdb> backup status
```

### Manual Snapshot

```bash
# Connect to fdbcli
kubectl exec -it -n inferadb deployment/fdb-backup-agent -- fdbcli -C /etc/foundationdb/fdb.cluster

# Take snapshot
fdb> backup start -d blobstore://s3.amazonaws.com/my-bucket/snapshots/$(date +%Y%m%d) -s

# Wait for completion
fdb> backup status
```

### Automated Backups

#### CronJob for Regular Backups

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: fdb-backup
  namespace: inferadb
spec:
  schedule: "0 2 * * *" # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: foundationdb/foundationdb:7.1.38
              command:
                - /bin/bash
                - -c
                - |
                  DATE=$(date +%Y%m%d-%H%M%S)
                  DEST="blobstore://s3.amazonaws.com/my-bucket/fdb-backups/${DATE}"

                  echo "Starting backup to ${DEST}"
                  fdbcli -C /etc/foundationdb/fdb.cluster --exec "backup start -d ${DEST} -s"

                  echo "Waiting for backup to complete"
                  while true; do
                    STATUS=$(fdbcli -C /etc/foundationdb/fdb.cluster --exec "backup status")
                    if echo "$STATUS" | grep -q "Backup complete"; then
                      echo "Backup completed successfully"
                      break
                    fi
                    sleep 30
                  done
              volumeMounts:
                - name: fdb-cluster-file
                  mountPath: /etc/foundationdb
                  readOnly: true
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
          volumes:
            - name: fdb-cluster-file
              secret:
                secretName: fdb-cluster-file
          restartPolicy: OnFailure
```

### Backup Verification

```bash
# List backups
kubectl exec -it -n inferadb deployment/fdb-backup-agent -- \
  fdbcli -C /etc/foundationdb/fdb.cluster --exec "backup list"

# Describe backup
kubectl exec -it -n inferadb deployment/fdb-backup-agent -- \
  fdbcli -C /etc/foundationdb/fdb.cluster --exec "backup describe -d blobstore://..."

# Verify backup integrity
kubectl exec -it -n inferadb deployment/fdb-backup-agent -- \
  fdbcli -C /etc/foundationdb/fdb.cluster --exec "backup verify -d blobstore://..."
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

### Restore Data (FoundationDB)

**⚠️ WARNING**: Restoration overwrites existing data. Ensure you have current backups before proceeding.

#### Full Restore

```bash
# 1. Stop InferaDB to prevent writes
kubectl scale deployment inferadb --replicas=0 -n inferadb

# 2. Connect to FDB
kubectl exec -it -n inferadb deployment/fdb-backup-agent -- \
  fdbcli -C /etc/foundationdb/fdb.cluster

# 3. Start restore (in fdbcli)
fdb> restore start -r blobstore://s3.amazonaws.com/my-bucket/fdb-backups/20251030-020000

# 4. Monitor restore progress
fdb> restore status

# 5. Wait for completion
# This may take several hours for large databases

# 6. Verify restore
fdb> status details

# 7. Restart InferaDB
kubectl scale deployment inferadb --replicas=5 -n inferadb

# 8. Verify functionality
kubectl exec -it -n inferadb deployment/inferadb -- \
  curl http://localhost:8080/health/ready
```

#### Point-in-Time Restore

```bash
# Restore to specific timestamp
kubectl exec -it -n inferadb deployment/fdb-backup-agent -- \
  fdbcli -C /etc/foundationdb/fdb.cluster

# Find available timestamps
fdb> backup describe -d blobstore://s3.amazonaws.com/my-bucket/fdb-backups/20251030-020000

# Restore to specific time (e.g., 2025-10-30 12:00:00)
fdb> restore start -r blobstore://s3.amazonaws.com/my-bucket/fdb-backups/20251030-020000 -t "2025-10-30 12:00:00"

# Monitor
fdb> restore status
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

# Start restore
echo "2. Starting FDB restore..."
kubectl exec -it -n $NAMESPACE deployment/fdb-backup-agent -- \
  fdbcli -C /etc/foundationdb/fdb.cluster --exec "restore start -r $BACKUP_URL -w"

# Verify
echo "3. Verifying restore..."
kubectl exec -it -n $NAMESPACE deployment/fdb-backup-agent -- \
  fdbcli -C /etc/foundationdb/fdb.cluster --exec "status details"

# Restart service
echo "4. Restarting InferaDB..."
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
**RPO**: Continuous backup

**Steps**:

1. Provision new FDB cluster
2. Configure backup agents
3. Restore latest backup
4. Update InferaDB connection strings
5. Resume operations

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
aws s3 ls s3://my-bucket/fdb-backups/ --recursive | \
  awk '{if (NR>30) print $4}' | \
  xargs -I {} aws s3 rm s3://my-bucket/fdb-backups/{}

# Automated cleanup with lifecycle policy
aws s3api put-bucket-lifecycle-configuration \
  --bucket my-bucket \
  --lifecycle-configuration file://lifecycle.json
```

lifecycle.json:

```json
{
  "Rules": [
    {
      "Id": "DeleteOldBackups",
      "Status": "Enabled",
      "Prefix": "fdb-backups/daily/",
      "Expiration": {
        "Days": 30
      }
    },
    {
      "Id": "DeleteOldSnapshots",
      "Status": "Enabled",
      "Prefix": "fdb-backups/monthly/",
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
BACKUP_URL="blobstore://s3.amazonaws.com/my-bucket/fdb-backups/latest"

# Create test namespace
kubectl create namespace $NAMESPACE

# Deploy test FDB cluster
kubectl apply -f test-fdb-cluster.yaml -n $NAMESPACE

# Restore backup
kubectl exec -it -n $NAMESPACE deployment/fdb-backup-agent -- \
  fdbcli -C /etc/foundationdb/fdb.cluster --exec "restore start -r $BACKUP_URL -w"

# Deploy InferaDB
helm install inferadb-test ./helm/infera \
  --namespace $NAMESPACE \
  --set config.store.backend=foundationdb

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
  - name: fdb-backup
    rules:
      - alert: FDBBackupFailed
        expr: fdb_backup_status != 1
        for: 15m
        labels:
          severity: critical
        annotations:
          summary: "FDB backup failed"
          description: "Backup has been failing for 15 minutes"

      - alert: FDBBackupStale
        expr: time() - fdb_backup_last_success_timestamp > 86400
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "FDB backup is stale"
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

**Problem**: Backup agent can't connect to FDB

**Investigation**:

```bash
kubectl logs -n inferadb deployment/fdb-backup-agent
kubectl exec -it -n inferadb deployment/fdb-backup-agent -- \
  fdbcli -C /etc/foundationdb/fdb.cluster --exec "status"
```

**Resolution**:

- Verify cluster file is correct
- Check network connectivity
- Ensure backup agent has proper permissions

### Restore Hangs

**Problem**: Restore operation stuck

**Investigation**:

```bash
kubectl exec -it -n inferadb deployment/fdb-backup-agent -- \
  fdbcli -C /etc/foundationdb/fdb.cluster --exec "restore status"
```

**Resolution**:

- Check FDB cluster health
- Verify backup files are accessible
- Check storage credentials
- Increase restore timeout

### Backup Storage Full

**Problem**: Backup destination running out of space

**Investigation**:

```bash
aws s3 ls s3://my-bucket/fdb-backups/ --recursive --summarize --human-readable
```

**Resolution**:

- Implement retention policy
- Delete old backups
- Increase storage quota
- Archive old backups to glacier

## Related Runbooks

- [Service Outage](service-outage.md) - Recovery procedures
- [Storage Backend](storage-backend.md) - FDB troubleshooting
- [Upgrades](upgrades.md) - Backup before upgrades

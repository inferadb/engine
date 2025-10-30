# Operational Runbooks

This directory contains operational runbooks for managing InferaDB in production.

## Available Runbooks

### Incident Response

- [High Latency](high-latency.md) - Diagnosing and resolving slow requests
- [Service Outage](service-outage.md) - Handling complete service failures
- [Authentication Failures](auth-failures.md) - Resolving authentication issues

### Maintenance

- [Scaling](scaling.md) - Horizontal and vertical scaling procedures
- [Backup and Restore](backup-restore.md) - Data backup and recovery
- [Upgrades](upgrades.md) - Version upgrade procedures
- [Configuration Changes](config-changes.md) - Safe configuration updates

### Monitoring and Diagnostics

- [Health Check Failures](health-check-failures.md) - Investigating failed health probes
- [Memory Issues](memory-issues.md) - OOM kills and memory leaks
- [Storage Backend](storage-backend.md) - FoundationDB troubleshooting

## Runbook Structure

Each runbook follows this structure:

1. **Overview** - Brief description of the issue
2. **Symptoms** - How to identify the problem
3. **Investigation** - Diagnostic steps
4. **Resolution** - Fix procedures
5. **Prevention** - Avoiding future occurrences
6. **Escalation** - When to escalate

## Quick Reference

### Emergency Contacts

| Role               | Contact     | Escalation Time |
| ------------------ | ----------- | --------------- |
| On-call Engineer   | Pagerduty   | Immediate       |
| Platform Team Lead | Email/Slack | 15 minutes      |
| Database Team      | Email/Slack | 30 minutes      |
| Security Team      | Email/Slack | 1 hour          |

### Common Commands

```bash
# Check pod status
kubectl get pods -n inferadb -l app=inferadb

# View logs
kubectl logs -n inferadb -l app=inferadb --tail=100 -f

# Check health
curl http://inferadb:8080/health/ready

# View metrics
kubectl port-forward -n inferadb svc/inferadb 8080:8080
curl http://localhost:8080/metrics

# Scale deployment
kubectl scale deployment inferadb --replicas=10 -n inferadb

# Restart deployment
kubectl rollout restart deployment/inferadb -n inferadb
```

### Service Level Objectives (SLOs)

| Metric                | Target  | Measured Over |
| --------------------- | ------- | ------------- |
| Availability          | 99.9%   | 30 days       |
| Request Latency (p50) | < 10ms  | 5 minutes     |
| Request Latency (p99) | < 100ms | 5 minutes     |
| Error Rate            | < 0.1%  | 5 minutes     |

### Critical Thresholds

| Metric                | Warning | Critical |
| --------------------- | ------- | -------- |
| CPU Usage             | 70%     | 85%      |
| Memory Usage          | 80%     | 90%      |
| Request Latency (p99) | 100ms   | 500ms    |
| Error Rate            | 0.5%    | 1%       |
| Pod Restart Count     | 3/hour  | 10/hour  |

## Contributing

When adding new runbooks:

1. Use the template in `runbook-template.md`
2. Include real commands and examples
3. Test procedures in staging first
4. Get peer review before merging
5. Update this README

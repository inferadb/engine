# Incident Response Runbook

## Overview

This runbook provides a framework for responding to production incidents affecting InferaDB.

## Incident Severity Levels

### SEV-1: Critical

**Impact**: Complete service outage or data loss
**Response Time**: Immediate
**Examples**:

- All pods down
- Authentication system failure
- Data corruption
- Security breach

### SEV-2: High

**Impact**: Significant degradation affecting multiple users
**Response Time**: 15 minutes
**Examples**:

- High error rate (>5%)
- Severe latency (p99 >1s)
- Partial outage (some regions/features down)
- Critical dependencies down

### SEV-3: Medium

**Impact**: Moderate degradation affecting some users
**Response Time**: 1 hour
**Examples**:

- Elevated error rate (1-5%)
- Moderate latency (p99 >500ms)
- Non-critical feature degradation
- Resource exhaustion warnings

### SEV-4: Low

**Impact**: Minor issues with workarounds available
**Response Time**: 4 hours
**Examples**:

- Isolated errors
- Minor performance degradation
- Non-user-facing issues

## Incident Response Process

### 1. Detection

**Automated Alerts**:

```bash
# Example alert channels
- PagerDuty (SEV-1, SEV-2)
- Slack #incidents (all severities)
- Email (SEV-3, SEV-4)
```

**Manual Detection**:

- User reports
- Monitoring dashboard review
- Health check failures

### 2. Initial Response (First 5 minutes)

#### Acknowledge Alert

```bash
# Acknowledge in PagerDuty
# Post in #incidents Slack channel
echo "Incident detected: <brief description>"
echo "Severity: SEV-X"
echo "Responder: @your-name"
```

#### Quick Assessment

```bash
# Check service health
kubectl get pods -n inferadb -l app=inferadb

# Check recent events
kubectl get events -n inferadb --sort-by='.lastTimestamp' | head -20

# Check logs for errors
kubectl logs -n inferadb -l app=inferadb --tail=100 | grep -i error

# Check metrics
curl http://inferadb:8080/metrics | grep -E "(error|latency|requests)"
```

#### Determine Severity

- Is service completely down? → SEV-1
- Are users significantly impacted? → SEV-2
- Is it a degradation with workarounds? → SEV-3
- Is it minor/isolated? → SEV-4

### 3. Escalation (if needed)

#### SEV-1 Escalation

```bash
# Immediate escalation
1. Page on-call manager
2. Notify platform team lead
3. Open bridge call
4. Post in #incidents-critical
```

#### SEV-2 Escalation

```bash
# Escalate if not resolved in 15 minutes
1. Notify platform team lead
2. Request additional responders
3. Open bridge call (optional)
```

### 4. Investigation

#### Gather Information

**System State**:

```bash
# Pod status
kubectl get pods -n inferadb -l app=inferadb -o wide

# Recent changes
kubectl rollout history deployment/inferadb -n inferadb

# Resource usage
kubectl top pods -n inferadb -l app=inferadb

# Service health
for pod in $(kubectl get pods -n inferadb -l app=inferadb -o name); do
  kubectl exec -n inferadb $pod -- curl -s http://localhost:8080/health/ready
done
```

**Recent Deployments**:

```bash
# Check recent deployments
kubectl rollout history deployment/inferadb -n inferadb

# Check recent config changes
kubectl get configmap inferadb-config -n inferadb -o yaml | grep "creationTimestamp"

# Check Helm releases
helm history inferadb -n inferadb
```

**External Dependencies**:

```bash
# Check FoundationDB
kubectl exec -it -n inferadb deployment/inferadb -- \
  fdbcli -C /etc/foundationdb/fdb.cluster --exec "status"

# Check Redis
kubectl exec -it -n inferadb deployment/inferadb -- \
  redis-cli -h redis ping

# Check auth service
curl -I https://auth.example.com/.well-known/jwks.json
```

**Metrics Analysis**:

```bash
# Request rate
curl http://inferadb:8080/metrics | grep inferadb_requests_total

# Error rate
curl http://inferadb:8080/metrics | grep inferadb_errors_total

# Latency
curl http://inferadb:8080/metrics | grep inferadb_request_duration
```

#### Common Investigation Queries

**Find crash loops**:

```bash
kubectl get pods -n inferadb -l app=inferadb --field-selector=status.phase!=Running
```

**Find OOM kills**:

```bash
kubectl get pods -n inferadb -l app=inferadb -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.containerStatuses[0].lastState.terminated.reason}{"\n"}{end}' | grep OOM
```

**Find recent errors**:

```bash
kubectl logs -n inferadb -l app=inferadb --since=10m | grep -i "error\|fatal\|panic"
```

### 5. Mitigation

#### Quick Wins

**Restart Pods** (if healthy infrastructure):

```bash
kubectl rollout restart deployment/inferadb -n inferadb
```

**Scale Up** (if resource constrained):

```bash
kubectl scale deployment inferadb --replicas=10 -n inferadb
```

**Rollback** (if recent deployment):

```bash
# Kubernetes
kubectl rollout undo deployment/inferadb -n inferadb

# Helm
helm rollback inferadb -n inferadb
```

**Disable Problem Feature**:

```bash
# Example: disable authentication temporarily
kubectl set env deployment/inferadb INFERA__AUTH__ENABLED=false -n inferadb
```

#### Advanced Mitigation

**Route Around Problem**:

```bash
# Remove unhealthy pods from service
kubectl label pod <pod-name> -n inferadb app-

# Or delete problem pods
kubectl delete pod <pod-name> -n inferadb
```

**Increase Resources**:

```bash
kubectl set resources deployment inferadb \
  --limits=cpu=8000m,memory=16Gi \
  --requests=cpu=4000m,memory=8Gi \
  -n inferadb
```

**Circuit Breaker**:

```bash
# Reduce load on struggling backend
kubectl set env deployment/inferadb \
  INFERA__CACHE__ENABLED=true \
  INFERA__CACHE__TTL_SECONDS=3600 \
  -n inferadb
```

### 6. Communication

#### Status Page Update

```markdown
**Issue**: InferaDB experiencing [brief description]
**Impact**: [user-facing impact]
**Status**: Investigating / Identified / Monitoring / Resolved
**Next Update**: [time]
```

#### Stakeholder Communication

**SEV-1/SEV-2**:

- Update every 15-30 minutes
- Use #incidents channel
- Email stakeholders
- Update status page

**SEV-3/SEV-4**:

- Update every 1-2 hours
- Use #incidents channel
- Update status page

### 7. Resolution

#### Verify Fix

```bash
# Check pod health
kubectl get pods -n inferadb -l app=inferadb

# Check error rate
# Should be <0.1%
kubectl logs -n inferadb -l app=inferadb --since=10m | grep -i error | wc -l

# Check latency
# p99 should be <100ms
curl http://inferadb:8080/metrics | grep inferadb_request_duration_seconds

# Run smoke tests
kubectl run -it --rm test --image=curlimages/curl --restart=Never -- \
  curl -X POST http://inferadb:8080/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tuple":{"object":"doc:1","relation":"viewer","subject":"user:alice"}}'
```

#### Declare Resolution

```bash
# Post in #incidents
echo "RESOLVED: [incident title]"
echo "Duration: [start time] - [end time]"
echo "Root Cause: [brief description]"
echo "Next Steps: Post-mortem scheduled for [date]"
```

### 8. Post-Incident

#### Incident Timeline

Document in post-mortem:

```
00:00 - Incident detected by [alert/person]
00:02 - Initial investigation started
00:05 - Severity determined: SEV-X
00:10 - Root cause identified: [cause]
00:15 - Mitigation deployed: [action]
00:30 - Service restored
00:45 - Monitoring confirmed stable
01:00 - Incident resolved
```

#### Post-Mortem Template

```markdown
# Post-Mortem: [Incident Title]

## Incident Summary

- **Date**: 2025-10-30
- **Duration**: 45 minutes
- **Severity**: SEV-2
- **Impacted Users**: ~10,000

## Root Cause

[Detailed explanation of what went wrong]

## Detection

- **How detected**: Automated alert / User report
- **Time to detect**: 2 minutes

## Response

- **Time to acknowledge**: 1 minute
- **Time to mitigate**: 15 minutes
- **Time to resolve**: 45 minutes

## What Went Well

- Quick detection via monitoring
- Effective escalation
- Clear communication

## What Went Wrong

- Inadequate testing before deployment
- Missing alert for [metric]
- Unclear runbook steps

## Action Items

1. [ ] Add [specific test] to CI/CD (@owner, due date)
2. [ ] Create alert for [metric] (@owner, due date)
3. [ ] Update runbook with [clarification] (@owner, due date)
4. [ ] Conduct tabletop exercise (@owner, due date)

## Timeline

[Detailed timeline from above]
```

## Incident Response Checklist

### Detection & Initial Response (0-5 min)

- [ ] Acknowledge alert
- [ ] Post in #incidents channel
- [ ] Determine severity
- [ ] Begin investigation

### Investigation (5-15 min)

- [ ] Check pod status
- [ ] Review logs
- [ ] Check metrics
- [ ] Identify recent changes
- [ ] Check dependencies

### Mitigation (15-30 min)

- [ ] Deploy fix or workaround
- [ ] Verify mitigation working
- [ ] Update stakeholders
- [ ] Monitor for improvement

### Resolution (30+ min)

- [ ] Verify service restored
- [ ] Run smoke tests
- [ ] Declare resolution
- [ ] Update status page

### Post-Incident (24-48 hours)

- [ ] Schedule post-mortem
- [ ] Write incident report
- [ ] Create action items
- [ ] Update runbooks

## Common Incident Scenarios

### All Pods Failing

**Symptoms**:

```bash
kubectl get pods -n inferadb
# All pods in CrashLoopBackOff or Error
```

**Likely Causes**:

- Recent deployment breaking change
- Configuration error
- Resource exhaustion
- Dependency failure

**Quick Fix**:

```bash
# Rollback recent deployment
kubectl rollout undo deployment/inferadb -n inferadb
```

**See**: [Service Outage Runbook](service-outage.md)

### High Error Rate

**Symptoms**:

```bash
# Error rate >1%
curl http://inferadb:8080/metrics | grep inferadb_errors_total
```

**Likely Causes**:

- Authentication failures
- Storage backend issues
- Invalid requests
- Bug in recent deployment

**Quick Fix**:

```bash
# Check error types in logs
kubectl logs -n inferadb -l app=inferadb | grep ERROR | tail -100

# If auth errors, check JWKS
curl https://auth.example.com/.well-known/jwks.json
```

**See**: [Authentication Failures Runbook](auth-failures.md)

### High Latency

**Symptoms**:

```bash
# p99 latency >500ms
curl http://inferadb:8080/metrics | grep inferadb_request_duration_seconds
```

**Likely Causes**:

- Resource saturation
- Storage backend slow
- Cache disabled
- High request volume

**Quick Fix**:

```bash
# Scale up
kubectl scale deployment inferadb --replicas=10 -n inferadb

# Check resources
kubectl top pods -n inferadb
```

**See**: [High Latency Runbook](high-latency.md)

## On-Call Handoff

When handing off incident to next responder:

```markdown
**Incident**: [title]
**Severity**: SEV-X
**Status**: [Investigating/Mitigating/Monitoring]
**Current State**: [brief description]
**Actions Taken**: [list of actions]
**Next Steps**: [what needs to happen]
**Contact**: [your name/contact]
```

## Related Runbooks

- [High Latency](high-latency.md)
- [Service Outage](service-outage.md)
- [Authentication Failures](auth-failures.md)
- [Memory Issues](memory-issues.md)
- [Scaling](scaling.md)

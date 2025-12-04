# Scaling Runbook

## Overview

This runbook covers scaling InferaDB horizontally (more replicas) and vertically (more resources per replica).

## When to Scale

### Indicators for Horizontal Scaling (More Replicas)

- **High CPU usage** across all pods (>70% sustained)
- **High request rate** with acceptable per-pod latency
- **Geographic distribution** needs
- **High availability** requirements

### Indicators for Vertical Scaling (More Resources)

- **Memory pressure** or OOM kills
- **Single-request latency** issues
- **Cache thrashing** due to insufficient memory
- **Thread pool saturation**

## Horizontal Scaling

### Manual Scaling

#### Kubernetes Deployment

```bash
# Scale to 10 replicas
kubectl scale deployment inferadb --replicas=10 -n inferadb

# Verify scaling
kubectl get pods -n inferadb -l app=inferadb -w

# Check rollout status
kubectl rollout status deployment/inferadb -n inferadb
```

#### Helm

```bash
# Update values
helm upgrade inferadb ./helm \
  --set replicaCount=10 \
  --namespace inferadb

# Monitor
kubectl get pods -n inferadb -l app=inferadb -w
```

### Autoscaling (HPA)

#### Enable HPA

```bash
# Create HPA
kubectl autoscale deployment inferadb \
  --min=3 \
  --max=20 \
  --cpu-percent=70 \
  -n inferadb

# Check HPA status
kubectl get hpa inferadb -n inferadb

# Describe HPA
kubectl describe hpa inferadb -n inferadb
```

#### Custom Metrics

For scaling based on custom metrics (request rate, queue depth):

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: inferadb
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: inferadb
  minReplicas: 5
  maxReplicas: 50
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Pods
      pods:
        metric:
          name: inferadb_requests_per_second
        target:
          type: AverageValue
          averageValue: "1000"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 50
          periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Percent
          value: 100
          periodSeconds: 30
```

### Scaling Best Practices

1. **Scale gradually**: Don't jump from 3 to 50 replicas instantly
2. **Monitor during scaling**: Watch for errors or latency spikes
3. **PodDisruptionBudget**: Ensure `minAvailable: 2` to prevent outages
4. **Resource availability**: Verify cluster has capacity
5. **Load balancer limits**: Check if load balancer can handle increased traffic

### Scaling Timeline

| Action            | Time to Complete | Notes                         |
| ----------------- | ---------------- | ----------------------------- |
| kubectl scale     | 30-60 seconds    | New pods start                |
| Health check pass | 10-30 seconds    | Pods become ready             |
| Full rollout      | 1-3 minutes      | All replicas healthy          |
| HPA decision      | 30-60 seconds    | Metric aggregation + decision |

## Vertical Scaling

### Increase Resources

#### Kubernetes

```bash
# Update deployment resources
kubectl set resources deployment inferadb \
  --limits=cpu=4000m,memory=8Gi \
  --requests=cpu=2000m,memory=4Gi \
  -n inferadb

# Monitor rollout
kubectl rollout status deployment/inferadb -n inferadb

# Check resource usage
kubectl top pods -n inferadb -l app=inferadb
```

#### Helm

```yaml
# values-prod.yaml
resources:
  requests:
    cpu: 2000m
    memory: 4Gi
  limits:
    cpu: 4000m
    memory: 8Gi
```

```bash
helm upgrade inferadb ./helm \
  -f values-prod.yaml \
  --namespace inferadb
```

### Adjust Worker Threads

Match worker threads to CPU allocation:

```bash
# For 4 CPU cores, set 4 worker threads
kubectl set env deployment/inferadb \
  INFERADB__SERVER__WORKER_THREADS=4 \
  -n inferadb
```

### Adjust Cache Size

Scale cache with available memory:

```bash
# For 4Gi memory, use ~2M cache capacity
kubectl set env deployment/inferadb \
  INFERADB__CACHE__MAX_CAPACITY=2000000 \
  -n inferadb
```

## Scaling Down

### Gradual Scale Down

```bash
# Scale down slowly
kubectl scale deployment inferadb --replicas=5 -n inferadb

# Wait for connections to drain
sleep 60

# Continue scaling
kubectl scale deployment inferadb --replicas=3 -n inferadb
```

### HPA Behavior

Configure conservative scale-down:

```yaml
behavior:
  scaleDown:
    stabilizationWindowSeconds: 300 # Wait 5 minutes
    policies:
      - type: Percent
        value: 50 # Max 50% reduction per step
        periodSeconds: 60
```

## Emergency Scaling

### Rapid Scale Up (Traffic Spike)

```bash
# Immediate scale to handle spike
kubectl scale deployment inferadb --replicas=30 -n inferadb

# Monitor
watch kubectl get pods -n inferadb -l app=inferadb

# Check HPA
kubectl patch hpa inferadb -n inferadb --patch '{"spec":{"minReplicas":30}}'
```

### Scale to Zero (Maintenance)

```bash
# Not recommended for production, but useful for development

# Disable HPA
kubectl patch hpa inferadb -n inferadb --patch '{"spec":{"minReplicas":0}}'

# Scale down
kubectl scale deployment inferadb --replicas=0 -n inferadb

# Resume
kubectl scale deployment inferadb --replicas=3 -n inferadb
kubectl patch hpa inferadb -n inferadb --patch '{"spec":{"minReplicas":3}}'
```

## Verification

### Check Scaling Success

```bash
# 1. Pod count
kubectl get pods -n inferadb -l app=inferadb --no-headers | wc -l

# 2. All pods ready
kubectl get pods -n inferadb -l app=inferadb

# 3. Service endpoints
kubectl get endpoints inferadb -n inferadb

# 4. Health checks
for pod in $(kubectl get pods -n inferadb -l app=inferadb -o name); do
  echo "Checking $pod"
  kubectl exec -n inferadb $pod -- curl -s http://localhost:8080/health/ready
done

# 5. Metrics
kubectl port-forward -n inferadb svc/inferadb 8080:8080 &
curl http://localhost:8080/metrics | grep inferadb_requests_total
```

### Monitor Impact

```bash
# CPU usage across pods
kubectl top pods -n inferadb -l app=inferadb

# Request distribution (from Prometheus)
sum(rate(inferadb_requests_total[5m])) by (pod)

# Latency impact
histogram_quantile(0.99, sum(rate(inferadb_request_duration_seconds_bucket[5m])) by (le))
```

## Troubleshooting

### Pods Not Starting

**Problem**: New pods stuck in Pending state

**Investigation**:

```bash
kubectl describe pod -n inferadb <pod-name>
kubectl get events -n inferadb --sort-by='.lastTimestamp'
```

**Common causes**:

- Insufficient cluster resources
- Image pull errors
- PVC provisioning failures

**Resolution**:

- Scale down replicas or add cluster nodes
- Check image availability
- Verify storage provisioner

### Pods Crashing After Scale

**Problem**: OOM kills or crash loops

**Investigation**:

```bash
kubectl logs -n inferadb <pod-name> --previous
kubectl top pods -n inferadb -l app=inferadb
```

**Resolution**:

- Increase memory limits
- Reduce cache size
- Check for memory leaks

### HPA Not Scaling

**Problem**: HPA not triggering autoscaling

**Investigation**:

```bash
kubectl get hpa inferadb -n inferadb
kubectl describe hpa inferadb -n inferadb
kubectl top pods -n inferadb -l app=inferadb
```

**Common causes**:

- Metrics server not installed
- Metric not available
- Thresholds not met

**Resolution**:

```bash
# Check metrics server
kubectl get deployment metrics-server -n kube-system

# Install if missing
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# Verify metrics
kubectl top pods -n inferadb
```

### Uneven Load Distribution

**Problem**: Some pods handling more requests than others

**Investigation**:

```bash
# Check request distribution (Prometheus)
sum(rate(inferadb_requests_total[5m])) by (pod)

# Check service endpoints
kubectl get endpoints inferadb -n inferadb
```

**Resolution**:

- Verify service selector labels
- Check pod readiness probes
- Review load balancer configuration
- Consider session affinity settings

## Capacity Planning

### Calculate Required Replicas

```text
Required Replicas = (Target RPS / RPS per Pod) × Safety Margin

Example:
- Target: 100,000 RPS
- Per Pod: 5,000 RPS
- Safety Margin: 1.5x

Required = (100,000 / 5,000) × 1.5 = 30 replicas
```

### Resource Requirements

| Workload | RPS/Pod | CPU/Pod | Memory/Pod | Replicas |
| -------- | ------- | ------- | ---------- | -------- |
| Light    | 1,000   | 500m    | 512Mi      | 3-10     |
| Medium   | 5,000   | 1000m   | 2Gi        | 5-20     |
| Heavy    | 10,000  | 2000m   | 4Gi        | 10-50    |

### Cost Optimization

```bash
# Right-size based on actual usage
kubectl top pods -n inferadb -l app=inferadb

# Review HPA metrics
kubectl get hpa inferadb -n inferadb -o yaml

# Adjust resource requests to match usage
# Request = P95 usage, Limit = P99 usage
```

## Rollback

If scaling causes issues:

```bash
# Revert to previous replica count
kubectl scale deployment inferadb --replicas=3 -n inferadb

# Revert resource changes (Helm)
helm rollback inferadb --namespace inferadb

# Revert resource changes (kubectl)
kubectl rollout undo deployment/inferadb -n inferadb
```

## Prevention

1. **Load testing**: Test scaling before production
2. **Gradual rollout**: Use canary deployments
3. **Monitor**: Track metrics during scaling
4. **Automation**: Use HPA for predictable patterns
5. **Capacity planning**: Project future needs

## Related Runbooks

- [High Latency](high-latency.md) - Performance issues requiring scaling
- [Memory Issues](memory-issues.md) - OOM kills during scaling
- [Upgrades](upgrades.md) - Scaling during version upgrades

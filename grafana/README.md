# InferaDB Grafana Dashboards

This directory contains pre-built Grafana dashboards for monitoring InferaDB in production.

## Available Dashboards

### 1. Overview Dashboard (`overview-dashboard.json`)

**Purpose**: High-level view of system health and SLO compliance

**Key Metrics**:

- SLO compliance summary (availability, latency, error rate, cache hit rate)
- Request rate and error rate trends
- Latency percentiles (p50, p90, p99, p99.9)
- Error budget remaining
- Cache performance
- Active connections
- Top operations by volume
- Top errors by type

**Best For**: Operations team daily monitoring, executive dashboards, war room displays

**Refresh Rate**: 30 seconds

---

### 2. Performance Dashboard (`performance-dashboard.json`)

**Purpose**: Deep dive into performance characteristics and bottlenecks

**Key Metrics**:

- Request latency heatmap
- Latency by percentile with SLO targets
- Storage read/write latency
- WASM execution latency
- Evaluation depth distribution
- Cache hit/miss/eviction rates
- Throughput by operation
- Resource utilization (CPU, memory, goroutines)
- GC performance

**Best For**: Performance optimization, capacity planning, latency debugging

**Refresh Rate**: 30 seconds

---

### 3. Replication Dashboard (`replication-dashboard.json`)

**Purpose**: Monitor multi-region replication health and performance

**Key Metrics**:

- Replication lag by region
- Replication target health
- Changes replicated per second
- Replication batch size distribution
- Replication errors and retries
- Conflict rate and resolution distribution
- Queue depth by region
- Bytes replicated per second
- Topology view (regions, targets, lag)
- Replication strategy info

**Best For**: Multi-region deployments, replication troubleshooting, consistency monitoring

**Refresh Rate**: 30 seconds

---

### 4. Errors Dashboard (`errors-dashboard.json`)

**Purpose**: Track errors, debug issues, and monitor error budget

**Key Metrics**:

- Error rate overview (5xx, 4xx)
- Error budget burn rate (1h, 24h)
- Errors by type and HTTP status code
- Storage, evaluation, auth, and replication errors
- Top error sources
- Error rate by endpoint
- Request success rate
- JWKS stale serves

**Best For**: Incident response, debugging, SLO tracking, postmortems

**Refresh Rate**: 30 seconds

---

### 5. Cache Dashboard (`cache-dashboard.json`)

**Purpose**: Monitor cache performance and optimize hit rates

**Key Metrics**:

- Cache hit rate
- Cache operations (hits, misses, evictions)
- Cache size and entry count
- Cache memory usage percentage
- Eviction rate
- Cache TTL distribution
- Hit rate by key type
- Most cached keys
- Cache latency impact (hit vs miss)
- Saved storage operations

**Best For**: Cache tuning, performance optimization, memory management

**Refresh Rate**: 30 seconds

---

## Installation

### Prerequisites

- Grafana 9.x or later
- Prometheus data source configured in Grafana
- InferaDB exporting metrics to Prometheus

### Option 1: Import via UI

1. Open Grafana web interface
2. Navigate to **Dashboards** → **Import**
3. Click **Upload JSON file**
4. Select one of the dashboard files from this directory
5. Select your Prometheus data source
6. Click **Import**

### Option 2: Import via API

```bash
# Set your Grafana credentials
GRAFANA_URL="http://localhost:3000"
GRAFANA_API_KEY="your-api-key"

# Import all dashboards
for dashboard in grafana/*.json; do
  curl -X POST \
    -H "Authorization: Bearer ${GRAFANA_API_KEY}" \
    -H "Content-Type: application/json" \
    -d @"${dashboard}" \
    "${GRAFANA_URL}/api/dashboards/db"
done
```

### Option 3: Provisioning (Recommended for Production)

Create a provisioning file:

```yaml
# /etc/grafana/provisioning/dashboards/inferadb.yaml
apiVersion: 1

providers:
  - name: "InferaDB"
    orgId: 1
    folder: "InferaDB"
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards/inferadb
```

Copy dashboard files to the provisioning directory:

```bash
cp grafana/*.json /var/lib/grafana/dashboards/inferadb/
```

Restart Grafana:

```bash
systemctl restart grafana-server
```

### Option 4: Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: inferadb-dashboards
  namespace: monitoring
data:
  overview-dashboard.json: |
    # Paste overview-dashboard.json contents here
  performance-dashboard.json: |
    # Paste performance-dashboard.json contents here
  # ... repeat for other dashboards
```

Mount the ConfigMap in Grafana deployment:

```yaml
volumeMounts:
  - name: dashboards
    mountPath: /var/lib/grafana/dashboards/inferadb
volumes:
  - name: dashboards
    configMap:
      name: inferadb-dashboards
```

---

## Configuration

### Data Source

All dashboards expect a Prometheus data source. Update the data source UID if needed:

1. Open dashboard settings
2. Go to **JSON Model**
3. Find and replace `"datasource": "Prometheus"` with your data source name

### Variables (Optional)

You can add template variables to filter by environment, region, or instance:

```json
"templating": {
  "list": [
    {
      "name": "environment",
      "type": "query",
      "query": "label_values(inferadb_checks_total, environment)",
      "multi": true,
      "includeAll": true
    },
    {
      "name": "region",
      "type": "query",
      "query": "label_values(inferadb_checks_total, region)",
      "multi": true,
      "includeAll": true
    }
  ]
}
```

Then update queries to filter by variables:

```promql
inferadb_checks_total{environment=~"$environment", region=~"$region"}
```

### Alerts

Some panels include embedded alerts that will fire when SLOs are violated. To enable:

1. Ensure Grafana alerting is configured
2. Configure notification channels (Slack, PagerDuty, etc.)
3. Alert conditions are pre-configured in the dashboards

**Panels with alerts**:

- **Overview**: p99 Latency SLO
- **Performance**: (no embedded alerts, use Prometheus alerting)
- **Replication**: Replication Lag SLO
- **Errors**: Error Rate SLO
- **Cache**: Cache Hit Rate SLO

**Note**: We recommend using Prometheus AlertManager for production alerting (see [../prometheus/README.md](../prometheus/README.md)) and Grafana alerts for development/testing.

---

## Customization

### Adding Panels

1. Open dashboard in edit mode
2. Click **Add panel**
3. Select visualization type
4. Add Prometheus query
5. Configure display options
6. Save dashboard

### Modifying Queries

All queries use standard PromQL. Common modifications:

**Change time range**:

```promql
# Change from 5m to 1m
rate(inferadb_checks_total[1m])
```

**Add filters**:

```promql
# Filter by region
rate(inferadb_checks_total{region="us-west-1"}[5m])
```

**Aggregate differently**:

```promql
# Sum by different label
sum by (method) (rate(inferadb_checks_total[5m]))
```

### Changing Thresholds

Update thresholds in panel field config:

```json
"thresholds": {
  "mode": "absolute",
  "steps": [
    { "value": null, "color": "green" },
    { "value": 80, "color": "yellow" },
    { "value": 90, "color": "red" }
  ]
}
```

---

## Dashboard Organization

We recommend organizing dashboards in folders:

- **Folder**: `InferaDB - Production`

  - Overview Dashboard
  - Errors Dashboard
  - Replication Dashboard (if multi-region)

- **Folder**: `InferaDB - Performance`

  - Performance Dashboard
  - Cache Dashboard

- **Folder**: `InferaDB - Development`
  - Custom/experimental dashboards

---

## Best Practices

### 1. Use Time Range Picker

Set appropriate time ranges for different use cases:

- **Real-time monitoring**: Last 15 minutes
- **Incident investigation**: Last 1-6 hours
- **Performance analysis**: Last 24 hours
- **Capacity planning**: Last 30 days

### 2. Refresh Rates

Adjust refresh rates based on use case:

- **War room display**: 10-30 seconds
- **Daily monitoring**: 1-5 minutes
- **Historical analysis**: No auto-refresh

### 3. Annotations

Add annotations for deployments, incidents, and maintenance:

```bash
# Add deployment annotation via API
curl -X POST \
  -H "Authorization: Bearer ${GRAFANA_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "dashboardId": 1,
    "time": 1234567890000,
    "tags": ["deployment", "v1.2.3"],
    "text": "Deployed v1.2.3 to production"
  }' \
  "${GRAFANA_URL}/api/annotations"
```

### 4. Snapshot Sharing

Share dashboard snapshots during incidents:

1. Open dashboard
2. Click **Share** → **Snapshot**
3. Set expiration time
4. Click **Publish to snapshot**
5. Share link with team

### 5. Dashboard Variables

Use variables for multi-environment deployments:

```json
"templating": {
  "list": [
    {
      "name": "env",
      "query": "label_values(inferadb_checks_total, environment)",
      "current": { "text": "production", "value": "production" }
    }
  ]
}
```

### 6. Panel Linking

Link panels to related dashboards:

```json
"links": [
  {
    "title": "View Performance Details",
    "url": "/d/performance-dashboard",
    "type": "dashboard"
  }
]
```

---

## Troubleshooting

### Dashboard shows "No data"

**Cause**: Prometheus not scraping InferaDB metrics

**Fix**:

1. Check Prometheus targets: `http://prometheus:9090/targets`
2. Verify InferaDB is exporting metrics: `curl http://localhost:9090/metrics`
3. Check Prometheus scrape config includes InferaDB

### Queries are slow

**Cause**: High cardinality metrics or long time ranges

**Fix**:

1. Reduce time range
2. Increase evaluation interval in panel settings
3. Use recording rules for expensive queries
4. Add metric retention policies in Prometheus

### Alerts not firing

**Cause**: Grafana alerting not configured

**Fix**:

1. Enable alerting in `grafana.ini`:
   ```ini
   [alerting]
   enabled = true
   ```
2. Configure notification channels
3. Check alert rules are enabled on panels

### Dashboards out of sync with metrics

**Cause**: Metric names changed or new metrics added

**Fix**:

1. Check latest metric names: `curl http://localhost:9090/metrics | grep inferadb`
2. Update dashboard queries to match
3. Re-export and re-import dashboard

---

## Maintenance

### Regular Updates

Update dashboards when:

- New metrics are added
- SLO targets change
- New features are released
- Metric names change

### Version Control

Store dashboard JSON files in version control:

```bash
# Export dashboard from Grafana
curl -H "Authorization: Bearer ${GRAFANA_API_KEY}" \
  "${GRAFANA_URL}/api/dashboards/uid/${DASHBOARD_UID}" | \
  jq '.dashboard' > overview-dashboard.json

# Commit to git
git add grafana/overview-dashboard.json
git commit -m "Update overview dashboard with new metrics"
```

### Testing Changes

Test dashboard changes before deploying to production:

1. Import to development Grafana instance
2. Verify queries return data
3. Check thresholds are appropriate
4. Test alerts fire correctly
5. Export and commit to version control

---

## References

- [Grafana Documentation](https://grafana.com/docs/)
- [PromQL Documentation](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- [InferaDB SLO Documentation](../docs/slos.md)
- [InferaDB Observability Guide](../docs/observability.md)
- [InferaDB Alerting Guide](../prometheus/README.md)

---

## Support

For questions or issues with dashboards:

1. Check [docs/observability.md](../docs/observability.md) for metric definitions
2. Review [docs/slos.md](../docs/slos.md) for SLO rationale
3. Consult [prometheus/README.md](../prometheus/README.md) for alerting configuration
4. Open an issue in the InferaDB repository

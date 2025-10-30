//! # Replication Agent
//!
//! Handles replication of changes from local region to remote regions.
//! Subscribes to the local change feed and forwards changes to configured remote nodes,
//! with retry logic, partition handling, and conflict resolution.

use crate::{
    conflict::{ConflictResolver, ConflictStats},
    topology::{NodeId, RegionId, Topology},
    Change, ChangeFeed, Operation, ReplError, Result,
};
use infera_api::grpc::proto::{
    infera_service_client::InferaServiceClient, DeleteRequest, Tuple as ProtoTuple, WriteRequest,
};
use infera_observe::metrics::{
    record_replication_batch, record_replication_changes, record_replication_failure,
    update_replication_targets,
};
use infera_store::TupleStore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::time::sleep;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

/// Configuration for the replication agent
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    /// Maximum number of retries for failed replications
    pub max_retries: u32,
    /// Base delay between retries (exponential backoff)
    pub retry_delay: Duration,
    /// Maximum batch size for replication
    pub batch_size: usize,
    /// Timeout for replication requests
    pub request_timeout: Duration,
    /// Buffer size for pending changes
    pub buffer_size: usize,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            retry_delay: Duration::from_millis(100),
            batch_size: 100,
            request_timeout: Duration::from_secs(10),
            buffer_size: 10000,
        }
    }
}

/// Represents a replication target (remote node)
struct ReplicationTarget {
    #[allow(dead_code)] // Used for future replication routing logic
    region_id: RegionId,
    node_id: NodeId,
    endpoint: String,
    client: Option<InferaServiceClient<Channel>>,
    last_successful_replication: Option<Instant>,
    consecutive_failures: u32,
}

impl ReplicationTarget {
    fn new(region_id: RegionId, node_id: NodeId, endpoint: String) -> Self {
        Self {
            region_id,
            node_id,
            endpoint,
            client: None,
            last_successful_replication: None,
            consecutive_failures: 0,
        }
    }

    async fn connect(&mut self) -> Result<()> {
        if self.client.is_some() {
            return Ok(());
        }

        match InferaServiceClient::connect(self.endpoint.clone()).await {
            Ok(client) => {
                self.client = Some(client);
                info!(
                    "Connected to replication target: {} ({})",
                    self.node_id, self.endpoint
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    "Failed to connect to replication target {} ({}): {}",
                    self.node_id, self.endpoint, e
                );
                Err(ReplError::Replication(format!("Connection failed: {}", e)))
            }
        }
    }

    fn is_connected(&self) -> bool {
        self.client.is_some()
    }

    fn mark_success(&mut self) {
        self.last_successful_replication = Some(Instant::now());
        self.consecutive_failures = 0;
    }

    fn mark_failure(&mut self) {
        self.consecutive_failures += 1;
    }

    fn should_retry(&self, max_failures: u32) -> bool {
        self.consecutive_failures < max_failures
    }
}

/// Statistics for replication agent
#[derive(Debug, Clone, Default)]
pub struct ReplicationStats {
    /// Total changes replicated
    pub changes_replicated: u64,
    /// Total changes failed to replicate
    pub replication_failures: u64,
    /// Current replication lag (milliseconds)
    pub replication_lag_ms: u64,
    /// Conflict statistics
    pub conflict_stats: ConflictStats,
}

/// Replication agent that handles multi-region replication
pub struct ReplicationAgent {
    /// Topology configuration
    topology: Arc<RwLock<Topology>>,
    /// Local change feed to subscribe to
    change_feed: Arc<ChangeFeed>,
    /// Tuple store for conflict resolution
    #[allow(dead_code)] // Used in future conflict resolution logic
    store: Arc<dyn TupleStore>,
    /// Conflict resolver
    #[allow(dead_code)] // Used in future conflict resolution logic
    conflict_resolver: Arc<ConflictResolver>,
    /// Replication configuration
    config: ReplicationConfig,
    /// Replication targets
    targets: Arc<RwLock<HashMap<NodeId, ReplicationTarget>>>,
    /// Statistics
    stats: Arc<RwLock<ReplicationStats>>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl ReplicationAgent {
    /// Create a new replication agent
    pub fn new(
        topology: Arc<RwLock<Topology>>,
        change_feed: Arc<ChangeFeed>,
        store: Arc<dyn TupleStore>,
        conflict_resolver: Arc<ConflictResolver>,
        config: ReplicationConfig,
    ) -> Self {
        Self {
            topology,
            change_feed,
            store,
            conflict_resolver,
            config,
            targets: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ReplicationStats::default())),
            shutdown_tx: None,
        }
    }

    /// Start the replication agent
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting replication agent");

        // Initialize replication targets from topology
        self.initialize_targets().await?;

        // Start the replication loop
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        let change_feed = Arc::clone(&self.change_feed);
        let targets = Arc::clone(&self.targets);
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut stream = match change_feed.subscribe().await {
                Ok(stream) => stream,
                Err(e) => {
                    error!("Failed to subscribe to change feed: {}", e);
                    return;
                }
            };

            let mut batch = Vec::new();
            let mut batch_timer = Instant::now();

            loop {
                tokio::select! {
                    Some(change) = stream.recv() => {
                        batch.push(change);

                        // Flush batch if it's full or timer expired
                        if batch.len() >= config.batch_size
                            || batch_timer.elapsed() > Duration::from_millis(100)
                        {
                            Self::replicate_batch(
                                &batch,
                                &targets,
                                &stats,
                                &config,
                            )
                            .await;
                            batch.clear();
                            batch_timer = Instant::now();
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Replication agent shutting down");
                        // Flush remaining batch
                        if !batch.is_empty() {
                            Self::replicate_batch(
                                &batch,
                                &targets,
                                &stats,
                                &config,
                            )
                            .await;
                        }
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the replication agent
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    /// Initialize replication targets from topology
    async fn initialize_targets(&self) -> Result<()> {
        let topology = self.topology.read().await;
        let local_region = &topology.local_region;

        // Get replication targets for local region
        let target_regions = topology.get_replication_targets(local_region);

        let mut targets = self.targets.write().await;

        for region_id in target_regions {
            // Get healthy nodes in target region
            let nodes = topology.get_healthy_nodes(region_id);

            for node in nodes {
                let target = ReplicationTarget::new(
                    region_id.clone(),
                    node.id.clone(),
                    node.endpoint.clone(),
                );
                targets.insert(node.id.clone(), target);
            }
        }

        info!("Initialized {} replication targets", targets.len());
        Ok(())
    }

    /// Replicate a batch of changes to all targets
    async fn replicate_batch(
        batch: &[Change],
        targets: &Arc<RwLock<HashMap<NodeId, ReplicationTarget>>>,
        stats: &Arc<RwLock<ReplicationStats>>,
        config: &ReplicationConfig,
    ) {
        if batch.is_empty() {
            return;
        }

        // Record batch size metric
        record_replication_batch(batch.len());

        let start = Instant::now();
        let mut targets_guard = targets.write().await;

        for (node_id, target) in targets_guard.iter_mut() {
            if !target.should_retry(config.max_retries) {
                debug!("Skipping target {} due to excessive failures", node_id);
                continue;
            }

            // Ensure connected
            if !target.is_connected() {
                if let Err(e) = target.connect().await {
                    error!("Failed to connect to target {}: {}", node_id, e);
                    target.mark_failure();
                    continue;
                }
            }

            // Replicate batch with retries
            let mut retries = 0;
            let mut success = false;

            while retries < config.max_retries && !success {
                match Self::send_batch_to_target(target, batch, config).await {
                    Ok(_) => {
                        target.mark_success();
                        success = true;

                        // Update stats and metrics
                        let mut stats_guard = stats.write().await;
                        stats_guard.changes_replicated += batch.len() as u64;
                        drop(stats_guard);

                        // Record metrics
                        let duration = start.elapsed().as_secs_f64();
                        record_replication_changes(batch.len() as u64, duration);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to replicate to {} (attempt {}/{}): {}",
                            node_id,
                            retries + 1,
                            config.max_retries,
                            e
                        );
                        target.mark_failure();

                        // Exponential backoff
                        let delay = config.retry_delay * 2_u32.pow(retries);
                        sleep(delay).await;

                        retries += 1;

                        // Clear client on failure to force reconnect
                        target.client = None;
                    }
                }
            }

            if !success {
                error!(
                    "Failed to replicate batch to {} after {} retries",
                    node_id, config.max_retries
                );
                let mut stats_guard = stats.write().await;
                stats_guard.replication_failures += batch.len() as u64;
                drop(stats_guard);

                // Record failure metrics
                record_replication_failure(batch.len() as u64);
            }
        }

        // Update replication targets metric
        let connected = targets_guard.values().filter(|t| t.is_connected()).count();
        let total = targets_guard.len();
        drop(targets_guard);
        update_replication_targets(connected, total);
    }

    /// Send a batch of changes to a specific target
    async fn send_batch_to_target(
        target: &mut ReplicationTarget,
        batch: &[Change],
        config: &ReplicationConfig,
    ) -> Result<()> {
        let client = target
            .client
            .as_mut()
            .ok_or_else(|| ReplError::Replication("Not connected".to_string()))?;

        // Separate inserts and deletes
        let inserts: Vec<_> = batch
            .iter()
            .filter(|c| c.operation == Operation::Insert)
            .collect();

        let deletes: Vec<_> = batch
            .iter()
            .filter(|c| c.operation == Operation::Delete)
            .collect();

        // Send inserts
        if !inserts.is_empty() {
            let tuples: Vec<ProtoTuple> = inserts
                .iter()
                .map(|c| ProtoTuple {
                    object: c.tuple.object.clone(),
                    relation: c.tuple.relation.clone(),
                    user: c.tuple.user.clone(),
                })
                .collect();

            let mut request = tonic::Request::new(WriteRequest { tuples });
            request.set_timeout(config.request_timeout);

            client
                .write(request)
                .await
                .map_err(|e| ReplError::Replication(format!("Write request failed: {}", e)))?;
        }

        // Send deletes
        if !deletes.is_empty() {
            let tuples: Vec<ProtoTuple> = deletes
                .iter()
                .map(|c| ProtoTuple {
                    object: c.tuple.object.clone(),
                    relation: c.tuple.relation.clone(),
                    user: c.tuple.user.clone(),
                })
                .collect();

            let mut request = tonic::Request::new(DeleteRequest { tuples });
            request.set_timeout(config.request_timeout);

            client
                .delete(request)
                .await
                .map_err(|e| ReplError::Replication(format!("Delete request failed: {}", e)))?;
        }

        Ok(())
    }

    /// Get current replication statistics
    pub async fn stats(&self) -> ReplicationStats {
        self.stats.read().await.clone()
    }

    /// Get number of connected targets
    pub async fn connected_targets(&self) -> usize {
        self.targets
            .read()
            .await
            .values()
            .filter(|t| t.is_connected())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conflict::ConflictResolutionStrategy;
    use crate::topology::{ReplicationStrategy, TopologyBuilder, ZoneId};
    use infera_store::MemoryBackend;

    #[tokio::test]
    async fn test_replication_target() {
        let mut target = ReplicationTarget::new(
            RegionId::new("us-west-1"),
            NodeId::new("node1"),
            "http://invalid:50051".to_string(),
        );

        assert!(!target.is_connected());
        assert!(target.should_retry(5));

        // Simulate failures
        target.mark_failure();
        target.mark_failure();
        target.mark_failure();

        assert_eq!(target.consecutive_failures, 3);
        assert!(target.should_retry(5));
        assert!(!target.should_retry(3));

        // Simulate success
        target.mark_success();
        assert_eq!(target.consecutive_failures, 0);
        assert!(target.last_successful_replication.is_some());
    }

    #[tokio::test]
    async fn test_replication_agent_creation() {
        let topology = Arc::new(RwLock::new(
            TopologyBuilder::new(
                ReplicationStrategy::ActiveActive,
                RegionId::new("us-west-1"),
            )
            .add_region(RegionId::new("us-west-1"), "US West".to_string(), false)
            .add_zone(
                RegionId::new("us-west-1"),
                ZoneId::new("us-west-1a"),
                "Zone A".to_string(),
            )
            .build()
            .unwrap(),
        ));

        let store: Arc<dyn TupleStore> = Arc::new(MemoryBackend::new());
        let change_feed = Arc::new(ChangeFeed::new());
        let conflict_resolver = Arc::new(ConflictResolver::new(
            ConflictResolutionStrategy::LastWriteWins,
        ));

        let agent = ReplicationAgent::new(
            topology,
            change_feed,
            store,
            conflict_resolver,
            ReplicationConfig::default(),
        );

        assert_eq!(agent.connected_targets().await, 0);
    }

    #[test]
    fn test_replication_config_defaults() {
        let config = ReplicationConfig::default();
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.buffer_size, 10000);
    }
}

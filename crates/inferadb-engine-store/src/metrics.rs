//! Storage backend metrics

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

/// Storage operation metrics
#[derive(Debug)]
pub struct StoreMetrics {
    // Read metrics
    read_count: AtomicU64,
    read_latency_us: AtomicU64,
    read_errors: AtomicU64,

    // Write metrics
    write_count: AtomicU64,
    write_latency_us: AtomicU64,
    write_errors: AtomicU64,

    // Delete metrics
    delete_count: AtomicU64,
    delete_latency_us: AtomicU64,
    delete_errors: AtomicU64,

    // Retry metrics (for transactional backends)
    retry_count: AtomicU64,

    // Key space metrics
    total_keys: AtomicU64,
    total_bytes: AtomicU64,
}

impl StoreMetrics {
    pub fn new() -> Self {
        Self {
            read_count: AtomicU64::new(0),
            read_latency_us: AtomicU64::new(0),
            read_errors: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
            write_latency_us: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            delete_count: AtomicU64::new(0),
            delete_latency_us: AtomicU64::new(0),
            delete_errors: AtomicU64::new(0),
            retry_count: AtomicU64::new(0),
            total_keys: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
        }
    }

    /// Record a read operation
    pub fn record_read(&self, duration: Duration, error: bool) {
        self.read_count.fetch_add(1, Ordering::Relaxed);
        self.read_latency_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        if error {
            self.read_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a write operation
    pub fn record_write(&self, duration: Duration, error: bool) {
        self.write_count.fetch_add(1, Ordering::Relaxed);
        self.write_latency_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        if error {
            self.write_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a delete operation
    pub fn record_delete(&self, duration: Duration, error: bool) {
        self.delete_count.fetch_add(1, Ordering::Relaxed);
        self.delete_latency_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        if error {
            self.delete_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a retry
    pub fn record_retry(&self) {
        self.retry_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Update key space metrics
    pub fn update_key_space(&self, keys: u64, bytes: u64) {
        self.total_keys.store(keys, Ordering::Relaxed);
        self.total_bytes.store(bytes, Ordering::Relaxed);
    }

    /// Get metrics snapshot
    pub fn snapshot(&self) -> MetricsSnapshot {
        let read_count = self.read_count.load(Ordering::Relaxed);
        let write_count = self.write_count.load(Ordering::Relaxed);
        let delete_count = self.delete_count.load(Ordering::Relaxed);

        let read_latency_us = self.read_latency_us.load(Ordering::Relaxed);
        let write_latency_us = self.write_latency_us.load(Ordering::Relaxed);
        let delete_latency_us = self.delete_latency_us.load(Ordering::Relaxed);

        MetricsSnapshot {
            read_count,
            read_avg_latency_us: if read_count > 0 { read_latency_us / read_count } else { 0 },
            read_errors: self.read_errors.load(Ordering::Relaxed),
            write_count,
            write_avg_latency_us: if write_count > 0 { write_latency_us / write_count } else { 0 },
            write_errors: self.write_errors.load(Ordering::Relaxed),
            delete_count,
            delete_avg_latency_us: if delete_count > 0 {
                delete_latency_us / delete_count
            } else {
                0
            },
            delete_errors: self.delete_errors.load(Ordering::Relaxed),
            retry_count: self.retry_count.load(Ordering::Relaxed),
            total_keys: self.total_keys.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.read_count.store(0, Ordering::Relaxed);
        self.read_latency_us.store(0, Ordering::Relaxed);
        self.read_errors.store(0, Ordering::Relaxed);
        self.write_count.store(0, Ordering::Relaxed);
        self.write_latency_us.store(0, Ordering::Relaxed);
        self.write_errors.store(0, Ordering::Relaxed);
        self.delete_count.store(0, Ordering::Relaxed);
        self.delete_latency_us.store(0, Ordering::Relaxed);
        self.delete_errors.store(0, Ordering::Relaxed);
        self.retry_count.store(0, Ordering::Relaxed);
    }
}

impl Default for StoreMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of metrics at a point in time
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub read_count: u64,
    pub read_avg_latency_us: u64,
    pub read_errors: u64,
    pub write_count: u64,
    pub write_avg_latency_us: u64,
    pub write_errors: u64,
    pub delete_count: u64,
    pub delete_avg_latency_us: u64,
    pub delete_errors: u64,
    pub retry_count: u64,
    pub total_keys: u64,
    pub total_bytes: u64,
}

/// Helper to measure operation duration
pub struct OpTimer {
    start: Instant,
}

impl OpTimer {
    pub fn new() -> Self {
        Self { start: Instant::now() }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

impl Default for OpTimer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn test_metrics_recording() {
        let metrics = StoreMetrics::new();

        // Record some reads
        metrics.record_read(Duration::from_micros(100), false);
        metrics.record_read(Duration::from_micros(200), false);
        metrics.record_read(Duration::from_micros(300), true); // with error

        // Record some writes
        metrics.record_write(Duration::from_micros(500), false);
        metrics.record_write(Duration::from_micros(600), false);

        // Record retries
        metrics.record_retry();
        metrics.record_retry();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.read_count, 3);
        assert_eq!(snapshot.read_avg_latency_us, 200); // (100+200+300)/3
        assert_eq!(snapshot.read_errors, 1);
        assert_eq!(snapshot.write_count, 2);
        assert_eq!(snapshot.write_avg_latency_us, 550); // (500+600)/2
        assert_eq!(snapshot.retry_count, 2);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = StoreMetrics::new();

        metrics.record_read(Duration::from_micros(100), false);
        metrics.record_write(Duration::from_micros(200), false);
        metrics.record_retry();

        assert_eq!(metrics.snapshot().read_count, 1);
        assert_eq!(metrics.snapshot().write_count, 1);
        assert_eq!(metrics.snapshot().retry_count, 1);

        metrics.reset();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.read_count, 0);
        assert_eq!(snapshot.write_count, 0);
        assert_eq!(snapshot.retry_count, 0);
    }

    #[test]
    fn test_key_space_tracking() {
        let metrics = StoreMetrics::new();

        metrics.update_key_space(1000, 50000);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_keys, 1000);
        assert_eq!(snapshot.total_bytes, 50000);
    }

    #[test]
    fn test_op_timer() {
        let timer = OpTimer::new();
        thread::sleep(Duration::from_millis(10));
        let elapsed = timer.elapsed();
        assert!(elapsed.as_millis() >= 10);
    }
}

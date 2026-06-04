//! 运行时核心方法与各类运行参数读取

use super::*;

impl AppState {
    pub async fn push_event(&self, topic: &str, source: &str, payload: serde_json::Value) {
        let _ = self.events.send(RuntimeEvent {
            topic: topic.to_string(),
            source: source.to_string(),
            timestamp: Utc::now(),
            payload,
        });
    }

    pub fn record_request_activity(&self) {
        self.last_request_activity_at
            .store(Utc::now().timestamp(), Ordering::Relaxed);
    }

    pub(crate) fn maybe_trim_memory(&self) {
        if !Self::memory_trim_enabled() {
            return;
        }

        let now_ts = Utc::now().timestamp();
        let last_request_at = self.last_request_activity_at.load(Ordering::Relaxed);
        let last_trim_at = self.last_memory_trim_at.load(Ordering::Relaxed);
        let current_rss_bytes = current_process_rss_bytes();

        if Self::should_trim_memory(
            last_request_at,
            last_trim_at,
            now_ts,
            Self::memory_trim_idle_threshold(),
        ) && self.trim_memory("idle", current_rss_bytes, now_ts)
        {
            return;
        }

        if Self::should_periodic_trim_memory(
            last_trim_at,
            now_ts,
            Self::memory_trim_periodic_interval(),
        ) && self.trim_memory("periodic", current_rss_bytes, now_ts)
        {
            return;
        }

        let Some(rss_bytes) = current_rss_bytes else {
            return;
        };
        let threshold_bytes = Self::memory_trim_rss_threshold_bytes();
        if Self::should_force_trim_memory(
            last_trim_at,
            now_ts,
            rss_bytes,
            threshold_bytes,
            Self::memory_trim_force_interval(),
        ) {
            let _ = self.trim_memory("pressure", Some(rss_bytes), now_ts);
        }
    }

    pub(crate) fn trim_memory(&self, reason: &str, rss_bytes: Option<u64>, now_ts: i64) -> bool {
        let trimmed = trim_process_memory();
        if trimmed {
            self.last_memory_trim_at.store(now_ts, Ordering::Relaxed);
            if reason != "periodic" {
                let rss_after_bytes = current_process_rss_bytes();
                info!(
                    reason,
                    rss_bytes = rss_bytes.or(rss_after_bytes).unwrap_or_default(),
                    rss_before_bytes = rss_bytes.unwrap_or_default(),
                    rss_after_bytes = rss_after_bytes.unwrap_or_default(),
                    threshold_bytes = Self::memory_trim_rss_threshold_bytes(),
                    "RustIO 已执行内存回收 / RustIO memory trim executed"
                );
            }
        }
        trimmed
    }

    pub(crate) async fn append_audit_event(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        outcome: &str,
        reason: Option<String>,
        details: serde_json::Value,
    ) {
        let event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            actor: actor.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            outcome: outcome.to_string(),
            reason,
            timestamp: Utc::now(),
            details,
        };
        {
            let mut audits = self.audits.write().await;
            audits.push(event.clone());
            prune_audits_locked(&mut audits);
        }
        self.push_event(
            "audit.appended",
            "audit-service",
            json!({
                "action": event.action,
                "resource": event.resource,
                "outcome": event.outcome,
                "timestamp": event.timestamp,
            }),
        )
        .await;
    }

    pub async fn append_audit(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        outcome: &str,
        reason: Option<String>,
        details: serde_json::Value,
    ) {
        self.append_audit_event(actor, action, resource, outcome, reason, details)
            .await;
    }

    pub async fn append_runtime_audit(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        outcome: &str,
        reason: Option<String>,
        details: serde_json::Value,
    ) {
        self.append_audit_event(actor, action, resource, outcome, reason, details)
            .await;
    }

    pub(crate) fn resolve_data_disks(data_dir: &Path) -> Vec<PathBuf> {
        let from_env = std::env::var("RUSTIO_DATA_DISKS")
            .or_else(|_| std::env::var("RUSTIO_EC_DISKS"))
            .unwrap_or_default();
        let mut disks = from_env
            .split(|ch: char| ch == ',' || ch == ';' || ch.is_ascii_whitespace())
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        if disks.len() < 5 {
            disks = (0..5)
                .map(|idx| data_dir.join(".rustio_disks").join(format!("disk-{idx}")))
                .collect();
        }
        disks
    }

    pub(crate) fn metadata_network_enabled() -> bool {
        std::env::var("RUSTIO_METADATA_RAFT_NETWORK_ENABLED")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false)
    }

    pub(crate) fn metadata_heartbeat_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_METADATA_RAFT_HEARTBEAT_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(800)
            .clamp(200, 5_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn metadata_local_peer_id() -> String {
        std::env::var("RUSTIO_METADATA_RAFT_NODE_ID").unwrap_or_else(|_| "meta-1".to_string())
    }

    pub(crate) fn replication_remote_enabled() -> bool {
        std::env::var("RUSTIO_REPLICATION_REMOTE_ENABLED")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false)
    }

    pub(crate) fn replication_worker_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_REPLICATION_WORKER_INTERVAL_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(250)
            .clamp(50, 5_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn replication_lease_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_REPLICATION_LEASE_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or_else(|| {
                let base = Self::replication_worker_interval().as_millis() as u64;
                base.saturating_mul(12).clamp(500, 60_000)
            })
            .clamp(100, 300_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn replication_worker_concurrency() -> usize {
        std::env::var("RUSTIO_REPLICATION_WORKER_CONCURRENCY")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(1)
            .clamp(1, 32)
    }

    pub(crate) fn alert_rule_eval_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_ALERT_RULE_EVAL_INTERVAL_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(15_000)
            .clamp(500, 600_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn alert_delivery_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_ALERT_DELIVERY_INTERVAL_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(500)
            .clamp(100, 10_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn alert_delivery_lease_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_ALERT_DELIVERY_LEASE_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or_else(|| {
                let base = Self::alert_delivery_interval().as_millis() as u64;
                base.saturating_mul(8).clamp(500, 60_000)
            })
            .clamp(100, 300_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn alert_delivery_max_attempts() -> u32 {
        std::env::var("RUSTIO_ALERT_DELIVERY_MAX_ATTEMPTS")
            .ok()
            .and_then(|raw| raw.parse::<u32>().ok())
            .unwrap_or(5)
            .clamp(1, 20)
    }

    pub(crate) fn alert_delivery_retry_base_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_ALERT_DELIVERY_RETRY_BASE_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(500)
            .clamp(100, 60_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn alert_delivery_retry_max_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_ALERT_DELIVERY_RETRY_MAX_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(30_000)
            .clamp(500, 300_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn alert_delivery_http_timeout() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_ALERT_DELIVERY_HTTP_TIMEOUT_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(5_000)
            .clamp(500, 60_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn alert_delivery_smtp_server() -> Option<String> {
        std::env::var("RUSTIO_ALERT_SMTP_SERVER")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    pub(crate) fn alert_delivery_smtp_from() -> String {
        std::env::var("RUSTIO_ALERT_SMTP_FROM")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "rustio-alert@localhost".to_string())
    }

    pub(crate) fn alert_delivery_smtp_username() -> Option<String> {
        std::env::var("RUSTIO_ALERT_SMTP_USERNAME")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    pub(crate) fn alert_delivery_smtp_password() -> Option<String> {
        std::env::var("RUSTIO_ALERT_SMTP_PASSWORD")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    pub(crate) fn alert_delivery_smtp_starttls_default() -> bool {
        std::env::var("RUSTIO_ALERT_SMTP_STARTTLS")
            .ok()
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false)
    }

    pub(crate) fn alert_delivery_smtp_tls_default() -> bool {
        std::env::var("RUSTIO_ALERT_SMTP_TLS")
            .ok()
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false)
    }

    pub(crate) fn alert_delivery_nats_default_subject() -> String {
        std::env::var("RUSTIO_ALERT_NATS_SUBJECT")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "rustio.alerts".to_string())
    }

    pub(crate) fn alert_delivery_nats_username() -> Option<String> {
        std::env::var("RUSTIO_ALERT_NATS_USERNAME")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    pub(crate) fn alert_delivery_nats_password() -> Option<String> {
        std::env::var("RUSTIO_ALERT_NATS_PASSWORD")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    pub(crate) fn alert_delivery_nats_token() -> Option<String> {
        std::env::var("RUSTIO_ALERT_NATS_TOKEN")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    pub(crate) fn alert_delivery_nats_tls_default() -> bool {
        std::env::var("RUSTIO_ALERT_NATS_TLS")
            .ok()
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false)
    }

    pub(crate) fn alert_delivery_redis_default_channel() -> String {
        std::env::var("RUSTIO_ALERT_REDIS_CHANNEL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "rustio.alerts".to_string())
    }

    pub(crate) fn alert_delivery_redis_username() -> Option<String> {
        std::env::var("RUSTIO_ALERT_REDIS_USERNAME")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    pub(crate) fn alert_delivery_redis_password() -> Option<String> {
        std::env::var("RUSTIO_ALERT_REDIS_PASSWORD")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    pub(crate) fn alert_delivery_redis_tls_default() -> bool {
        std::env::var("RUSTIO_ALERT_REDIS_TLS")
            .ok()
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false)
    }

    pub(crate) fn alert_delivery_tls_ca_file() -> Option<String> {
        std::env::var("RUSTIO_ALERT_TLS_CA_FILE")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    pub(crate) fn replication_backlog_alert_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_REPLICATION_BACKLOG_ALERT_INTERVAL_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(1_000)
            .clamp(200, 10_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn replication_backlog_alert_suppress_interval() -> std::time::Duration {
        let secs = std::env::var("RUSTIO_REPLICATION_BACKLOG_ALERT_SUPPRESS_SECONDS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(60)
            .clamp(1, 86_400);
        std::time::Duration::from_secs(secs)
    }

    pub(crate) fn replication_backlog_alert_failed_threshold() -> usize {
        std::env::var("RUSTIO_REPLICATION_BACKLOG_ALERT_FAILED_THRESHOLD")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(50)
            .clamp(0, 1_000_000)
    }

    pub(crate) fn replication_backlog_alert_dead_letter_threshold() -> usize {
        std::env::var("RUSTIO_REPLICATION_BACKLOG_ALERT_DEAD_LETTER_THRESHOLD")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(5)
            .clamp(0, 1_000_000)
    }

    pub(crate) fn replication_backlog_alert_pending_age_threshold() -> std::time::Duration {
        let secs = std::env::var("RUSTIO_REPLICATION_BACKLOG_ALERT_PENDING_AGE_SECONDS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(900)
            .clamp(0, 604_800);
        std::time::Duration::from_secs(secs)
    }

    pub fn replication_backlog_alert_threshold_snapshot() -> (usize, usize, u64) {
        (
            Self::replication_backlog_alert_failed_threshold(),
            Self::replication_backlog_alert_dead_letter_threshold(),
            Self::replication_backlog_alert_pending_age_threshold().as_secs(),
        )
    }

    pub(crate) fn replication_retry_base_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_REPLICATION_RETRY_BASE_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(500)
            .clamp(100, 60_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn replication_retry_max_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_REPLICATION_RETRY_MAX_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(30_000)
            .clamp(500, 600_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn replication_retry_delay(attempts: u32) -> std::time::Duration {
        let base_ms = Self::replication_retry_base_interval().as_millis() as u64;
        let max_ms = Self::replication_retry_max_interval().as_millis() as u64;
        let exp = attempts.saturating_sub(1).min(31);
        let factor = 1u64.checked_shl(exp).unwrap_or(u64::MAX);
        let delay_ms = base_ms.saturating_mul(factor).min(max_ms);
        std::time::Duration::from_millis(delay_ms)
    }

    pub(crate) fn replication_max_attempts() -> u32 {
        std::env::var("RUSTIO_REPLICATION_MAX_ATTEMPTS")
            .ok()
            .and_then(|raw| raw.parse::<u32>().ok())
            .unwrap_or(8)
            .clamp(1, 100)
    }

    pub(crate) fn storage_scan_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_STORAGE_SCAN_INTERVAL_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(1_800_000)
            .clamp(500, 3_600_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn storage_heal_worker_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_STORAGE_HEAL_INTERVAL_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(1_000)
            .clamp(100, 60_000);
        std::time::Duration::from_millis(ms)
    }

    pub(crate) fn memory_trim_enabled() -> bool {
        std::env::var("RUSTIO_MEMORY_TRIM_ENABLED")
            .map(|value| !(value.eq_ignore_ascii_case("false") || value == "0"))
            .unwrap_or(true)
    }

    pub(crate) fn memory_trim_interval() -> std::time::Duration {
        let secs = std::env::var("RUSTIO_MEMORY_TRIM_INTERVAL_SECONDS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(300)
            .clamp(30, 86_400);
        std::time::Duration::from_secs(secs)
    }

    pub(crate) fn memory_trim_idle_threshold() -> std::time::Duration {
        let secs = std::env::var("RUSTIO_MEMORY_TRIM_IDLE_SECONDS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(43_200)
            .clamp(30, 604_800);
        std::time::Duration::from_secs(secs)
    }

    pub(crate) fn memory_trim_force_interval() -> std::time::Duration {
        let secs = std::env::var("RUSTIO_MEMORY_TRIM_FORCE_INTERVAL_SECONDS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(7_200)
            .clamp(300, 604_800);
        std::time::Duration::from_secs(secs)
    }

    pub(crate) fn memory_trim_periodic_interval() -> std::time::Duration {
        let secs = std::env::var("RUSTIO_MEMORY_TRIM_PERIODIC_SECONDS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(600)
            .clamp(300, 604_800);
        std::time::Duration::from_secs(secs)
    }

    pub(crate) fn memory_trim_rss_threshold_bytes() -> u64 {
        let mb = std::env::var("RUSTIO_MEMORY_TRIM_RSS_THRESHOLD_MB")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(128)
            .clamp(32, 65_536);
        mb.saturating_mul(1024 * 1024)
    }

    pub(crate) fn should_trim_memory(
        last_request_at: i64,
        last_trim_at: i64,
        now_ts: i64,
        idle_threshold: std::time::Duration,
    ) -> bool {
        let idle_secs = idle_threshold.as_secs().min(i64::MAX as u64) as i64;
        now_ts.saturating_sub(last_request_at) >= idle_secs && last_trim_at < last_request_at
    }

    pub(crate) fn should_force_trim_memory(
        last_trim_at: i64,
        now_ts: i64,
        rss_bytes: u64,
        threshold_bytes: u64,
        min_interval: std::time::Duration,
    ) -> bool {
        let interval_secs = min_interval.as_secs().min(i64::MAX as u64) as i64;
        rss_bytes >= threshold_bytes && now_ts.saturating_sub(last_trim_at) >= interval_secs
    }

    pub(crate) fn should_periodic_trim_memory(
        last_trim_at: i64,
        now_ts: i64,
        interval: std::time::Duration,
    ) -> bool {
        let interval_secs = interval.as_secs().min(i64::MAX as u64) as i64;
        now_ts.saturating_sub(last_trim_at) >= interval_secs
    }

    const REPLICATION_NON_RETRYABLE_PREFIX: &'static str = "__RUSTIO_NON_RETRYABLE__:";

    pub(crate) fn replication_mark_non_retryable(message: String) -> String {
        format!("{}{}", Self::REPLICATION_NON_RETRYABLE_PREFIX, message)
    }

    pub(crate) fn replication_error_is_non_retryable(err: &str) -> bool {
        err.starts_with(Self::REPLICATION_NON_RETRYABLE_PREFIX)
    }

    pub(crate) fn replication_error_message(err: &str) -> String {
        err.strip_prefix(Self::REPLICATION_NON_RETRYABLE_PREFIX)
            .unwrap_or(err)
            .to_string()
    }

    pub(crate) fn replication_dead_letter_error(
        attempts: u32,
        max_attempts: u32,
        err: &str,
    ) -> String {
        let err = err.replace(" / ", " | ");
        format!(
            "复制任务超过最大重试次数（{attempts}/{max_attempts}），已进入死信队列：{err} / replication item exceeded max retry attempts ({attempts}/{max_attempts}) and moved to dead-letter queue: {err}"
        )
    }

    pub(crate) fn replication_dead_letter_non_retryable_error(err: &str) -> String {
        let err = err.replace(" / ", " | ");
        format!(
            "复制任务遇到不可重试错误，已进入死信队列：{err} / replication item hit a non-retryable error and moved to dead-letter queue: {err}"
        )
    }

    pub(crate) fn replication_retry_ready(
        item: &ReplicationBacklogItem,
        now: &DateTime<Utc>,
    ) -> bool {
        if item.status != "failed" {
            return false;
        }
        let delay = Self::replication_retry_delay(item.attempts.max(1));
        let Ok(retry_after) = Duration::from_std(delay) else {
            return true;
        };
        now.signed_duration_since(item.last_attempt_at) >= retry_after
    }
}

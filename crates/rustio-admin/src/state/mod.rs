mod alerts;
mod jobs;
mod persistence_bootstrap;
mod raft_consensus;
mod raft_core;
mod replication_workers;
mod runtime_config;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicI64, AtomicU64, Ordering},
    sync::Arc,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use rustio_core::{
    AlertChannel, AlertEscalationPolicy, AlertHistoryEntry, AlertRule, AlertSilence, AuditEvent,
    BatchRunScope, BucketAclConfig, BucketCorsRule, BucketEncryptionConfig, BucketLegalHoldConfig,
    BucketLifecycleRule, BucketNotificationRule, BucketObjectLockConfig,
    BucketPublicAccessBlockConfig, BucketRetentionConfig, BucketSpec, BucketTag,
    ClusterConfigSnapshot, ClusterNode, ClusterQuota, ConsoleSession, DiagnosticReport, IamGroup,
    IamPolicy, IamUser, JobStatus, LoginResponse, RemoteTierConfig, ReplicationBacklogItem,
    ReplicationStatus, RuntimeEvent, S3ObjectEncryptionMeta, S3ObjectMeta, SecurityConfig,
    SiteReplicationStatus, StsSession, TenantSpec,
};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::{broadcast, RwLock},
    time::timeout,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tracing::info;
use uuid::Uuid;

use crate::routes::{
    expire_current_object_for_lifecycle, expire_noncurrent_object_version_for_lifecycle,
    process_storage_governance_heal_queue_once, process_storage_governance_scan_once,
    transition_current_object_for_lifecycle, transition_noncurrent_object_version_for_lifecycle,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AlertSmtpTransport {
    Plain,
    StartTls,
    Tls,
}

#[derive(Debug, Clone, Default)]
pub struct StorageGovernanceRuntimeState {
    pub last_scan_at: Option<DateTime<Utc>>,
    pub last_heal_at: Option<DateTime<Utc>>,
    pub last_rebalance_at: Option<DateTime<Utc>>,
    pub last_decommission_at: Option<DateTime<Utc>>,
    pub last_scan_duration_seconds: f64,
    pub last_heal_duration_seconds: f64,
    pub last_scan_result: String,
    pub scan_runs_total: u64,
    pub scan_failures_total: u64,
    pub heal_objects_total: u64,
    pub heal_failures_total: u64,
    pub rebalance_objects_total: u64,
    pub rebalance_failures_total: u64,
    pub decommission_objects_total: u64,
    pub decommission_failures_total: u64,
    pub scan_running: bool,
    pub heal_running: usize,
    pub disk_last_anomaly_at: HashMap<String, DateTime<Utc>>,
    pub draining_disks: HashSet<String>,
    pub decommissioned_disks: HashSet<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct LifecycleJobDraft {
    kind: String,
    bucket: String,
    object_key: String,
    idempotency_key: String,
    payload: Value,
}

#[cfg(test)]
mod tests {
    // 测试持有进程级环境锁（std Mutex）跨 await 以串行化用例，此处为有意为之。
    #![allow(clippy::await_holding_lock)]
    use std::{
        collections::HashMap,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use chrono::{Duration, Utc};
    use rustio_core::{AlertChannel, AuditEvent, ConsoleSession, ReplicationBacklogItem};
    use serde_json::json;

    use super::{AlertSmtpTransport, AppState, LocalCredential};

    use crate::test_env_lock;

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn parse_smtp_endpoint_supports_starttls_scheme() {
        let (server, recipient, transport) = AppState::alert_delivery_parse_smtp_endpoint(
            "smtp+starttls://smtp.example.com:587/ops@example.com",
        )
        .expect("smtp endpoint should parse");
        assert_eq!(server, "smtp.example.com:587");
        assert_eq!(recipient, "ops@example.com");
        assert_eq!(transport, AlertSmtpTransport::StartTls);
    }

    #[test]
    fn audit_pruning_keeps_latest_entries() {
        let _guard = test_env_lock()
            .lock()
            .expect("env lock should be available");
        std::env::set_var("RUSTIO_AUDIT_MAX_EVENTS", "100");

        let mut audits = (0..105)
            .map(|index| AuditEvent {
                id: format!("audit-{index}"),
                actor: "admin".to_string(),
                action: "auth.refresh".to_string(),
                resource: "session".to_string(),
                outcome: "success".to_string(),
                reason: None,
                timestamp: Utc::now(),
                details: json!({ "index": index }),
            })
            .collect::<Vec<_>>();

        super::prune_audits_locked(&mut audits);

        let ids = audits.into_iter().map(|entry| entry.id).collect::<Vec<_>>();
        assert_eq!(ids.len(), 100);
        assert_eq!(ids.first().map(String::as_str), Some("audit-5"));
        assert_eq!(ids.last().map(String::as_str), Some("audit-104"));

        std::env::remove_var("RUSTIO_AUDIT_MAX_EVENTS");
    }

    #[test]
    fn memory_trim_idle_threshold_defaults_to_twelve_hours() {
        let _guard = test_env_lock()
            .lock()
            .expect("env lock should be available");
        std::env::remove_var("RUSTIO_MEMORY_TRIM_IDLE_SECONDS");

        assert_eq!(
            AppState::memory_trim_idle_threshold(),
            std::time::Duration::from_secs(43_200)
        );
    }

    #[test]
    fn memory_trim_periodic_interval_defaults_to_ten_minutes() {
        let _guard = test_env_lock()
            .lock()
            .expect("env lock should be available");
        std::env::remove_var("RUSTIO_MEMORY_TRIM_PERIODIC_SECONDS");

        assert_eq!(
            AppState::memory_trim_periodic_interval(),
            std::time::Duration::from_secs(600)
        );
    }

    #[test]
    fn storage_scan_interval_defaults_to_thirty_minutes() {
        let _guard = test_env_lock()
            .lock()
            .expect("env lock should be available");
        std::env::remove_var("RUSTIO_STORAGE_SCAN_INTERVAL_MS");

        assert_eq!(
            AppState::storage_scan_interval(),
            std::time::Duration::from_secs(1_800)
        );
    }

    #[test]
    fn memory_trim_triggers_after_idle_threshold() {
        assert!(AppState::should_trim_memory(
            100,
            0,
            1_100,
            std::time::Duration::from_secs(900)
        ));
    }

    #[test]
    fn memory_trim_skips_when_already_trimmed_since_last_request() {
        assert!(!AppState::should_trim_memory(
            100,
            150,
            1_100,
            std::time::Duration::from_secs(900)
        ));
    }

    #[test]
    fn memory_trim_force_triggers_when_rss_exceeds_threshold() {
        assert!(AppState::should_force_trim_memory(
            0,
            7_500,
            128 * 1024 * 1024,
            128 * 1024 * 1024,
            std::time::Duration::from_secs(7_200)
        ));
    }

    #[test]
    fn memory_trim_force_skips_when_interval_not_elapsed() {
        assert!(!AppState::should_force_trim_memory(
            5_000,
            7_500,
            256 * 1024 * 1024,
            128 * 1024 * 1024,
            std::time::Duration::from_secs(7_200)
        ));
    }

    #[test]
    fn memory_trim_periodic_triggers_when_interval_elapsed() {
        assert!(AppState::should_periodic_trim_memory(
            0,
            3_700,
            std::time::Duration::from_secs(3_600)
        ));
    }

    #[test]
    fn memory_trim_periodic_skips_when_interval_not_elapsed() {
        assert!(!AppState::should_periodic_trim_memory(
            2_000,
            3_700,
            std::time::Duration::from_secs(3_600)
        ));
    }

    #[test]
    fn expired_replication_lease_does_not_block_same_target_progress() {
        let now = Utc::now();
        let backlog = vec![
            ReplicationBacklogItem {
                id: "expired-in-progress".to_string(),
                source_bucket: "photos".to_string(),
                target_site: "dr-site-a".to_string(),
                object_key: "2026/03/a.jpg".to_string(),
                rule_id: None,
                priority: 100,
                operation: "put".to_string(),
                checkpoint: 10,
                idempotency_key: "expired-in-progress".to_string(),
                version_id: Some("v1".to_string()),
                attempts: 1,
                status: "in_progress".to_string(),
                last_error: String::new(),
                lease_owner: Some("worker-1".to_string()),
                lease_until: Some(now - Duration::seconds(1)),
                queued_at: now - Duration::minutes(2),
                last_attempt_at: now - Duration::minutes(1),
            },
            ReplicationBacklogItem {
                id: "pending-next".to_string(),
                source_bucket: "photos".to_string(),
                target_site: "dr-site-a".to_string(),
                object_key: "2026/03/a.jpg".to_string(),
                rule_id: None,
                priority: 100,
                operation: "put".to_string(),
                checkpoint: 11,
                idempotency_key: "pending-next".to_string(),
                version_id: Some("v2".to_string()),
                attempts: 0,
                status: "pending".to_string(),
                last_error: String::new(),
                lease_owner: None,
                lease_until: None,
                queued_at: now - Duration::minutes(1),
                last_attempt_at: now - Duration::minutes(1),
            },
        ];

        assert!(
            !AppState::replication_target_blocked(&backlog, 1, &now),
            "expired in-progress lease should not block newer task on same target"
        );
    }

    #[test]
    fn parse_smtp_server_auth_supports_inline_credentials() {
        let (server, username, password) =
            AppState::alert_delivery_parse_smtp_server_auth("alice:secret@smtp.example.com:465");
        assert_eq!(server, "smtp.example.com:465");
        assert_eq!(username.as_deref(), Some("alice"));
        assert_eq!(password.as_deref(), Some("secret"));
    }

    #[test]
    fn parse_nats_endpoint_supports_tls_scheme() {
        let (server, subject, tls) =
            AppState::alert_delivery_parse_nats_endpoint("natss://nats.example.com:4222/ops.alert")
                .expect("nats endpoint should parse");
        assert_eq!(server, "nats.example.com:4222");
        assert_eq!(subject.as_deref(), Some("ops.alert"));
        assert!(tls);
    }

    #[test]
    fn parse_nats_server_auth_supports_token() {
        let (server, username, password, token) =
            AppState::alert_delivery_parse_nats_server_auth("apitoken@nats.example.com:4222");
        assert_eq!(server, "nats.example.com:4222");
        assert!(username.is_none());
        assert!(password.is_none());
        assert_eq!(token.as_deref(), Some("apitoken"));
    }

    #[test]
    fn parse_nats_server_auth_supports_user_password() {
        let (server, username, password, token) =
            AppState::alert_delivery_parse_nats_server_auth("alice:secret@nats.example.com:4222");
        assert_eq!(server, "nats.example.com:4222");
        assert_eq!(username.as_deref(), Some("alice"));
        assert_eq!(password.as_deref(), Some("secret"));
        assert!(token.is_none());
    }

    #[test]
    fn parse_redis_endpoint_supports_tls_scheme() {
        let (server, channel, tls) = AppState::alert_delivery_parse_redis_endpoint(
            "rediss://cache.example.com:6380/rustio.alerts",
        )
        .expect("redis endpoint should parse");
        assert_eq!(server, "cache.example.com:6380");
        assert_eq!(channel.as_deref(), Some("rustio.alerts"));
        assert!(tls);
    }

    #[test]
    fn parse_redis_server_auth_supports_password_and_userpass() {
        let (server, username, password) =
            AppState::alert_delivery_parse_redis_server_auth(":secret@redis.example.com:6379");
        assert_eq!(server, "redis.example.com:6379");
        assert!(username.is_none());
        assert_eq!(password.as_deref(), Some("secret"));

        let (server, username, password) =
            AppState::alert_delivery_parse_redis_server_auth("alice:secret@redis.example.com:6379");
        assert_eq!(server, "redis.example.com:6379");
        assert_eq!(username.as_deref(), Some("alice"));
        assert_eq!(password.as_deref(), Some("secret"));
    }

    #[test]
    fn notification_target_kind_supports_redis_scheme() {
        assert_eq!(
            AppState::notification_target_kind("redis://127.0.0.1:6379/rustio.alerts").as_deref(),
            Some("redis")
        );
    }

    #[test]
    fn alert_delivery_template_renders_payload_fields() {
        let rendered = AppState::alert_delivery_render_template(
            r#"{"bucket":"{{bucket}}","version":"{{object.version_id}}"}"#,
            &json!({
                "bucket": "reports",
                "object": { "version_id": "v1" }
            }),
        )
        .expect("template should render");
        assert_eq!(rendered, r#"{"bucket":"reports","version":"v1"}"#);
    }

    #[test]
    fn alert_delivery_http_body_wraps_kafka_and_rabbitmq_payloads() {
        let kafka_channel = AlertChannel {
            id: "channel-kafka".to_string(),
            name: "Kafka".to_string(),
            kind: "kafka".to_string(),
            endpoint: "https://kafka.example.internal/topics/rustio".to_string(),
            headers: HashMap::new(),
            payload_template: Some(r#"{"bucket":"{{bucket}}"}"#.to_string()),
            header_template: HashMap::new(),
            enabled: true,
            status: "healthy".to_string(),
            last_checked_at: Utc::now(),
            error: None,
        };
        let (kafka_content_type, kafka_body) = AppState::alert_delivery_render_http_body(
            &kafka_channel,
            &json!({ "bucket": "archive" }),
        )
        .expect("kafka payload should render");
        assert_eq!(kafka_content_type, "application/vnd.kafka.json.v2+json");
        let kafka_json: serde_json::Value =
            serde_json::from_slice(&kafka_body).expect("kafka payload should be json");
        assert_eq!(
            kafka_json.pointer("/records/0/value/bucket"),
            Some(&json!("archive"))
        );

        let rabbitmq_channel = AlertChannel {
            id: "channel-rabbit".to_string(),
            name: "RabbitMQ".to_string(),
            kind: "rabbitmq".to_string(),
            endpoint: "https://rabbit.example.internal/api/exchanges/%2F/rustio/publish?routing_key=ops.alerts".to_string(),
            headers: HashMap::new(),
            payload_template: Some(r#"bucket={{bucket}}"#.to_string()),
            header_template: HashMap::new(),
            enabled: true,
            status: "healthy".to_string(),
            last_checked_at: Utc::now(),
            error: None,
        };
        let (_, rabbitmq_body) = AppState::alert_delivery_render_http_body(
            &rabbitmq_channel,
            &json!({ "bucket": "archive" }),
        )
        .expect("rabbitmq payload should render");
        let rabbitmq_json: serde_json::Value =
            serde_json::from_slice(&rabbitmq_body).expect("rabbitmq payload should be json");
        assert_eq!(rabbitmq_json.get("routing_key"), Some(&json!("ops.alerts")));
        assert_eq!(rabbitmq_json.get("payload"), Some(&json!("bucket=archive")));
    }

    #[tokio::test]
    async fn metadata_snapshot_replicates_security_config() {
        let _guard = test_env_lock()
            .lock()
            .expect("failed to lock state test env guard");
        let leader_dir = unique_temp_dir("rustio-state-leader");
        let follower_dir = unique_temp_dir("rustio-state-follower");
        std::fs::create_dir_all(&leader_dir).expect("failed to create leader temp dir");
        std::fs::create_dir_all(&follower_dir).expect("failed to create follower temp dir");

        std::env::set_var("RUSTIO_DATA_DIR", &leader_dir);
        let leader = AppState::bootstrap();
        {
            let mut security = leader.security.write().await;
            security.oidc_enabled = true;
            security.ldap_enabled = true;
            security.oidc_discovery_url =
                "https://id.example.internal/.well-known/openid-configuration".to_string();
            security.oidc_client_id = "rustio-console".to_string();
            security.ldap_url = "ldap://ldap.example.internal:389".to_string();
            security.ldap_default_role = "operator".to_string();
            security.kms_endpoint = "https://vault.example.internal".to_string();
            security.sse_mode = "SSE-KMS".to_string();
        }
        let request = leader
            .export_metadata_raft_sync_request("state-test-security")
            .await
            .expect("leader should export metadata snapshot");

        std::env::set_var("RUSTIO_DATA_DIR", &follower_dir);
        let follower = AppState::bootstrap();
        {
            let mut raft = follower.metadata_raft.write().await;
            raft.cluster_id = request.cluster_id.clone();
        }
        follower
            .apply_metadata_raft_snapshot_internal(request, true)
            .await
            .expect("follower should apply metadata snapshot");

        let follower_security = follower.security.read().await.clone();
        assert_eq!(
            follower_security.oidc_discovery_url,
            "https://id.example.internal/.well-known/openid-configuration"
        );
        assert_eq!(follower_security.oidc_client_id, "rustio-console");
        assert_eq!(
            follower_security.ldap_url,
            "ldap://ldap.example.internal:389"
        );
        assert_eq!(follower_security.ldap_default_role, "operator");
        assert_eq!(
            follower_security.kms_endpoint,
            "https://vault.example.internal"
        );

        let persisted_path = follower_dir
            .join(".rustio_meta")
            .join("security-config.json");
        let persisted = std::fs::read_to_string(&persisted_path)
            .expect("follower security config should persist to disk");
        assert!(
            persisted.contains("\"oidc_client_id\": \"rustio-console\""),
            "persisted security config should contain replicated oidc client id"
        );

        let _ = std::fs::remove_dir_all(&leader_dir);
        let _ = std::fs::remove_dir_all(&follower_dir);
    }

    #[tokio::test]
    async fn metadata_snapshot_replicates_console_sessions() {
        let _guard = test_env_lock()
            .lock()
            .expect("failed to lock state test env guard");
        let leader_dir = unique_temp_dir("rustio-state-session-leader");
        let follower_dir = unique_temp_dir("rustio-state-session-follower");
        std::fs::create_dir_all(&leader_dir).expect("failed to create leader temp dir");
        std::fs::create_dir_all(&follower_dir).expect("failed to create follower temp dir");

        std::env::set_var("RUSTIO_DATA_DIR", &leader_dir);
        let leader = AppState::bootstrap();
        let now = Utc::now();
        {
            let mut sessions = leader.admin_sessions.write().await;
            sessions.push(ConsoleSession {
                session_id: "console-session-001".to_string(),
                principal: "admin".to_string(),
                role: "admin".to_string(),
                permissions: vec!["cluster:read".to_string(), "cluster:write".to_string()],
                provider: "local".to_string(),
                status: "active".to_string(),
                issued_at: now,
                access_expires_at: now + Duration::hours(4),
                refresh_expires_at: now + Duration::days(7),
                last_refreshed_at: Some(now + Duration::minutes(5)),
                revoked_at: None,
                revoked_reason: None,
            });
        }
        let request = leader
            .export_metadata_raft_sync_request("state-test-console-session")
            .await
            .expect("leader should export metadata snapshot");

        std::env::set_var("RUSTIO_DATA_DIR", &follower_dir);
        let follower = AppState::bootstrap();
        {
            let mut raft = follower.metadata_raft.write().await;
            raft.cluster_id = request.cluster_id.clone();
        }
        follower
            .apply_metadata_raft_snapshot_internal(request, true)
            .await
            .expect("follower should apply metadata snapshot");

        let sessions = follower.admin_sessions.read().await;
        let session = sessions
            .iter()
            .find(|session| session.session_id == "console-session-001")
            .expect("console session should be replicated");
        assert_eq!(session.principal, "admin");
        assert_eq!(session.provider, "local");
        assert_eq!(session.status, "active");
        assert_eq!(session.last_refreshed_at, Some(now + Duration::minutes(5)));
        drop(sessions);

        let _ = std::fs::remove_dir_all(&leader_dir);
        let _ = std::fs::remove_dir_all(&follower_dir);
    }

    #[tokio::test]
    async fn metadata_snapshot_replicates_local_credentials() {
        let _guard = test_env_lock()
            .lock()
            .expect("failed to lock state test env guard");
        let leader_dir = unique_temp_dir("rustio-state-cred-leader");
        let follower_dir = unique_temp_dir("rustio-state-cred-follower");
        std::fs::create_dir_all(&leader_dir).expect("failed to create leader temp dir");
        std::fs::create_dir_all(&follower_dir).expect("failed to create follower temp dir");

        std::env::set_var("RUSTIO_DATA_DIR", &leader_dir);
        let leader = AppState::bootstrap();
        {
            let mut credentials = leader.credentials.write().await;
            credentials.insert(
                "auditor-1".to_string(),
                LocalCredential {
                    password: "auditor-password".to_string(),
                    role: "auditor".to_string(),
                },
            );
        }
        let request = leader
            .export_metadata_raft_sync_request("state-test-local-credentials")
            .await
            .expect("leader should export metadata snapshot");

        std::env::set_var("RUSTIO_DATA_DIR", &follower_dir);
        let follower = AppState::bootstrap();
        {
            let mut raft = follower.metadata_raft.write().await;
            raft.cluster_id = request.cluster_id.clone();
        }
        follower
            .apply_metadata_raft_snapshot_internal(request, true)
            .await
            .expect("follower should apply metadata snapshot");

        let credentials = follower.credentials.read().await;
        let credential = credentials
            .get("auditor-1")
            .expect("local credential should be replicated");
        assert_eq!(credential.password, "auditor-password");
        assert_eq!(credential.role, "auditor");
        drop(credentials);

        let _ = std::fs::remove_dir_all(&leader_dir);
        let _ = std::fs::remove_dir_all(&follower_dir);
    }

    #[tokio::test]
    async fn delete_console_session_runtime_persists_removal() {
        let _guard = test_env_lock()
            .lock()
            .expect("failed to lock state test env guard");
        let data_dir = unique_temp_dir("rustio-state-session-delete");
        std::fs::create_dir_all(&data_dir).expect("failed to create temp data dir");

        std::env::set_var("RUSTIO_DATA_DIR", &data_dir);
        let state = AppState::bootstrap();
        let now = Utc::now();
        state
            .upsert_console_session_runtime(ConsoleSession {
                session_id: "console-session-delete-001".to_string(),
                principal: "admin".to_string(),
                role: "admin".to_string(),
                permissions: vec!["cluster:read".to_string(), "cluster:write".to_string()],
                provider: "local".to_string(),
                status: "active".to_string(),
                issued_at: now,
                access_expires_at: now + Duration::hours(4),
                refresh_expires_at: now + Duration::days(7),
                last_refreshed_at: None,
                revoked_at: None,
                revoked_reason: None,
            })
            .await
            .expect("console session should be persisted");

        state
            .delete_console_session_runtime("console-session-delete-001")
            .await
            .expect("console session removal should be persisted");

        let sessions = state.admin_sessions.read().await;
        assert!(
            sessions
                .iter()
                .all(|session| session.session_id != "console-session-delete-001"),
            "runtime console session should be removed"
        );
        drop(sessions);

        let persisted_path = data_dir.join(".rustio_meta").join("console-sessions.json");
        let persisted = std::fs::read_to_string(&persisted_path)
            .expect("console sessions snapshot should exist");
        assert!(
            !persisted.contains("console-session-delete-001"),
            "persisted console sessions should not contain removed session"
        );

        let _ = std::fs::remove_dir_all(&data_dir);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCredential {
    pub password: String,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct MultipartPart {
    pub part_number: u32,
    pub etag: String,
    pub size: u64,
    pub path: PathBuf,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct MultipartUpload {
    pub upload_id: String,
    pub bucket: String,
    pub key: String,
    pub initiated_at: DateTime<Utc>,
    pub parts: HashMap<u32, MultipartPart>,
    pub encryption: S3ObjectEncryptionMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaneComponent {
    pub id: String,
    pub responsibility: String,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaneTopology {
    pub id: String,
    pub name: String,
    pub responsibilities: Vec<String>,
    pub components: Vec<PlaneComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureTopology {
    pub version: String,
    pub aligned_at: DateTime<Utc>,
    pub planes: Vec<PlaneTopology>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaneAlignmentStatus {
    pub plane_id: String,
    pub plane_name: String,
    pub status: String,
    pub component_total: usize,
    pub component_ready: usize,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureAlignmentReport {
    pub version: String,
    pub generated_at: DateTime<Utc>,
    pub overall_status: String,
    pub missing_planes: Vec<String>,
    pub planes: Vec<PlaneAlignmentStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataObjectEntry {
    pub bucket: String,
    pub key: String,
    pub meta: S3ObjectMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftSnapshot {
    pub generated_at: DateTime<Utc>,
    pub buckets: Vec<BucketSpec>,
    pub remote_tiers: Vec<(String, RemoteTierConfig)>,
    pub bucket_object_locks: Vec<(String, BucketObjectLockConfig)>,
    pub bucket_retentions: Vec<(String, BucketRetentionConfig)>,
    pub bucket_legal_holds: Vec<(String, BucketLegalHoldConfig)>,
    pub bucket_notifications: Vec<(String, Vec<BucketNotificationRule>)>,
    pub bucket_lifecycle_rules: Vec<(String, Vec<BucketLifecycleRule>)>,
    pub bucket_acls: Vec<(String, BucketAclConfig)>,
    pub bucket_public_access_blocks: Vec<(String, BucketPublicAccessBlockConfig)>,
    pub bucket_policies: Vec<(String, Value)>,
    pub bucket_cors_rules: Vec<(String, Vec<BucketCorsRule>)>,
    pub bucket_tags: Vec<(String, Vec<BucketTag>)>,
    pub bucket_encryptions: Vec<(String, BucketEncryptionConfig)>,
    pub objects: Vec<MetadataObjectEntry>,
    pub credentials: Vec<(String, LocalCredential)>,
    pub iam_users: Vec<IamUser>,
    pub iam_groups: Vec<IamGroup>,
    pub iam_policies: Vec<IamPolicy>,
    pub service_accounts: Vec<rustio_core::ServiceAccount>,
    pub admin_sessions: Vec<ConsoleSession>,
    pub sts_sessions: Vec<StsSession>,
    pub replications: Vec<ReplicationStatus>,
    pub site_replications: Vec<SiteReplicationStatus>,
    pub replication_backlog: Vec<ReplicationBacklogItem>,
    pub replication_checkpoints: Vec<(String, u64)>,
    pub cluster_config_history: Vec<ClusterConfigSnapshot>,
    pub security: SecurityConfig,
    pub jobs: Vec<JobStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftLogEntry {
    pub index: u64,
    pub term: u64,
    pub reason: String,
    pub written_at: DateTime<Utc>,
    pub snapshot_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftPeer {
    pub id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub endpoint: Option<String>,
    pub online: bool,
    #[serde(default)]
    pub match_index: u64,
    #[serde(default = "metadata_peer_next_index_default")]
    pub next_index: u64,
    pub last_index: u64,
}

pub(crate) fn metadata_peer_next_index_default() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftState {
    pub cluster_id: String,
    pub leader_id: String,
    pub term: u64,
    #[serde(default)]
    pub voted_for: Option<String>,
    pub commit_index: u64,
    #[serde(default)]
    pub last_commit_term: u64,
    #[serde(default)]
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_election_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_quorum_at: Option<DateTime<Utc>>,
    #[serde(default = "metadata_membership_phase_default")]
    pub membership_phase: String,
    #[serde(default)]
    pub joint_old_members: Vec<String>,
    #[serde(default)]
    pub joint_new_members: Vec<String>,
    pub last_snapshot_hash: String,
    pub last_error: Option<String>,
    pub last_commit_at: Option<DateTime<Utc>>,
    pub peers: Vec<MetadataRaftPeer>,
}

pub(crate) fn metadata_membership_phase_default() -> String {
    "stable".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftStatus {
    pub cluster_id: String,
    pub leader_id: String,
    pub term: u64,
    pub commit_index: u64,
    pub quorum: usize,
    pub online_peers: usize,
    pub last_error: Option<String>,
    pub last_commit_at: Option<DateTime<Utc>>,
    pub membership_phase: String,
    #[serde(default)]
    pub joint_old_members: Vec<String>,
    #[serde(default)]
    pub joint_new_members: Vec<String>,
    #[serde(default)]
    pub joint_elapsed_seconds: Option<u64>,
    pub joint_timeout_seconds: u64,
    pub peers: Vec<MetadataRaftPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftSyncRequest {
    pub cluster_id: String,
    pub peer_id: String,
    pub entry: MetadataRaftLogEntry,
    #[serde(default)]
    pub prev_log_index: u64,
    #[serde(default)]
    pub prev_log_term: u64,
    #[serde(default)]
    pub install_snapshot: bool,
    #[serde(default)]
    pub leader_commit: u64,
    pub snapshot: MetadataRaftSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftVoteRequest {
    pub cluster_id: String,
    pub candidate_id: String,
    pub term: u64,
    pub last_log_index: u64,
    #[serde(default)]
    pub last_log_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftVoteResponse {
    pub term: u64,
    pub vote_granted: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftPreVoteRequest {
    pub cluster_id: String,
    pub candidate_id: String,
    pub term: u64,
    pub last_log_index: u64,
    #[serde(default)]
    pub last_log_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftPreVoteResponse {
    pub term: u64,
    pub pre_vote_granted: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftReadIndexRequest {
    pub cluster_id: String,
    pub requester_id: String,
    #[serde(default)]
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftReadIndexResponse {
    pub term: u64,
    pub leader_id: String,
    pub read_index: u64,
    pub success: bool,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftSyncResponse {
    pub term: u64,
    pub success: bool,
    pub match_index: u64,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftHeartbeatRequest {
    pub cluster_id: String,
    pub leader_id: String,
    pub term: u64,
    pub leader_commit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftHeartbeatResponse {
    pub term: u64,
    pub accepted: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalReplicationApplyRequest {
    pub source_bucket: String,
    pub target_site: String,
    pub object_key: String,
    pub operation: String,
    pub checkpoint: u64,
    pub idempotency_key: String,
    #[serde(default)]
    pub version_id: Option<String>,
    #[serde(default)]
    pub payload_base64: Option<String>,
    #[serde(default)]
    pub object_meta: Option<S3ObjectMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDeliveryItem {
    pub id: String,
    pub history_id: String,
    pub rule_id: Option<String>,
    pub channel_id: String,
    pub channel_kind: String,
    pub endpoint: String,
    pub status: String,
    pub attempts: u32,
    pub last_error: String,
    pub lease_owner: Option<String>,
    pub lease_until: Option<DateTime<Utc>>,
    pub queued_at: DateTime<Utc>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub next_attempt_at: DateTime<Utc>,
    pub payload: Value,
    pub idempotency_key: String,
}

pub struct AppState {
    pub jwt_secret: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub data_dir: PathBuf,
    pub data_disks: Vec<PathBuf>,
    pub architecture: ArchitectureTopology,
    pub metadata_raft: RwLock<MetadataRaftState>,
    pub credentials: RwLock<HashMap<String, LocalCredential>>,
    pub nodes: RwLock<Vec<ClusterNode>>,
    pub quotas: RwLock<Vec<ClusterQuota>>,
    pub tenants: RwLock<Vec<TenantSpec>>,
    pub diagnostics: RwLock<Vec<DiagnosticReport>>,
    pub cluster_config_history: RwLock<Vec<ClusterConfigSnapshot>>,
    pub users: RwLock<Vec<IamUser>>,
    pub groups: RwLock<Vec<IamGroup>>,
    pub policies: RwLock<Vec<IamPolicy>>,
    pub service_accounts: RwLock<Vec<rustio_core::ServiceAccount>>,
    pub admin_sessions: RwLock<Vec<ConsoleSession>>,
    pub sts_sessions: RwLock<Vec<StsSession>>,
    pub buckets: RwLock<HashMap<String, BucketSpec>>,
    pub remote_tiers: RwLock<HashMap<String, RemoteTierConfig>>,
    pub bucket_object_locks: RwLock<HashMap<String, BucketObjectLockConfig>>,
    pub bucket_retentions: RwLock<HashMap<String, BucketRetentionConfig>>,
    pub bucket_legal_holds: RwLock<HashMap<String, BucketLegalHoldConfig>>,
    pub bucket_notifications: RwLock<HashMap<String, Vec<BucketNotificationRule>>>,
    pub bucket_lifecycle_rules: RwLock<HashMap<String, Vec<BucketLifecycleRule>>>,
    pub bucket_acls: RwLock<HashMap<String, BucketAclConfig>>,
    pub bucket_public_access_blocks: RwLock<HashMap<String, BucketPublicAccessBlockConfig>>,
    pub bucket_policies: RwLock<HashMap<String, Value>>,
    pub bucket_cors_rules: RwLock<HashMap<String, Vec<BucketCorsRule>>>,
    pub bucket_tags: RwLock<HashMap<String, Vec<BucketTag>>>,
    pub bucket_encryptions: RwLock<HashMap<String, BucketEncryptionConfig>>,
    pub replications: RwLock<Vec<ReplicationStatus>>,
    pub site_replications: RwLock<Vec<SiteReplicationStatus>>,
    pub replication_backlog: RwLock<Vec<ReplicationBacklogItem>>,
    pub replication_checkpoints: RwLock<HashMap<String, u64>>,
    pub replication_sequence: AtomicU64,
    pub alert_rules: RwLock<Vec<AlertRule>>,
    pub alert_channels: RwLock<Vec<AlertChannel>>,
    pub alert_silences: RwLock<Vec<AlertSilence>>,
    pub alert_escalations: RwLock<Vec<AlertEscalationPolicy>>,
    pub alert_history: RwLock<Vec<AlertHistoryEntry>>,
    pub alert_delivery_queue: RwLock<Vec<AlertDeliveryItem>>,
    pub security: RwLock<SecurityConfig>,
    pub oidc_auth_requests: RwLock<HashMap<String, PendingOidcAuthorization>>,
    pub oidc_completed_logins: RwLock<HashMap<String, CompletedOidcLogin>>,
    pub audits: RwLock<Vec<AuditEvent>>,
    pub jobs: RwLock<Vec<JobStatus>>,
    pub object_access_heat: RwLock<HashMap<(String, String), u64>>,
    pub storage_governance: RwLock<StorageGovernanceRuntimeState>,
    pub object_store: RwLock<HashMap<(String, String), Vec<u8>>>,
    pub object_meta: RwLock<HashMap<(String, String), S3ObjectMeta>>,
    pub multipart_uploads: RwLock<HashMap<String, MultipartUpload>>,
    pub last_request_activity_at: AtomicI64,
    pub last_memory_trim_at: AtomicI64,
    pub events: broadcast::Sender<RuntimeEvent>,
}

pub(crate) fn bilingual_runtime_error(zh: &str, en: impl AsRef<str>) -> String {
    let en = en.as_ref().trim();
    if en.contains(" / ") {
        return en.to_string();
    }
    if en.is_empty() {
        return format!("{zh} / runtime error");
    }
    format!("{zh} / {en}")
}

#[derive(Debug, Clone)]
pub struct PendingOidcAuthorization {
    pub code_verifier: String,
    pub nonce: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CompletedOidcLogin {
    pub response: LoginResponse,
    pub created_at: DateTime<Utc>,
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(target_os = "linux")]
pub(crate) fn trim_process_memory() -> bool {
    unsafe { libc::malloc_trim(0) != 0 }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn trim_process_memory() -> bool {
    false
}

#[cfg(target_os = "linux")]
pub(crate) fn current_process_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let value = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(value.saturating_mul(1024))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn current_process_rss_bytes() -> Option<u64> {
    None
}

pub(crate) fn audit_max_events() -> usize {
    std::env::var("RUSTIO_AUDIT_MAX_EVENTS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(2_048)
        .clamp(100, 100_000)
}

pub(crate) fn prune_audits_locked(audits: &mut Vec<AuditEvent>) {
    let max_events = audit_max_events();
    if audits.len() <= max_events {
        return;
    }

    let overflow = audits.len().saturating_sub(max_events);
    audits.drain(0..overflow);
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct ReplicationRuntimeState {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    sequence: u64,
    #[serde(default)]
    backlog: Vec<ReplicationBacklogItem>,
    #[serde(default)]
    checkpoints: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct MetadataRaftRuntimePeer {
    #[serde(default)]
    id: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default = "metadata_runtime_peer_online_default")]
    online: bool,
    #[serde(default)]
    last_index: u64,
    #[serde(default)]
    match_index: u64,
    #[serde(default = "metadata_peer_next_index_default")]
    next_index: u64,
}

pub(crate) fn metadata_runtime_peer_online_default() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct MetadataRaftRuntimeState {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    cluster_id: String,
    #[serde(default)]
    leader_id: String,
    #[serde(default)]
    term: u64,
    #[serde(default)]
    voted_for: Option<String>,
    #[serde(default)]
    commit_index: u64,
    #[serde(default)]
    last_commit_term: u64,
    #[serde(default)]
    last_snapshot_hash: String,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    last_commit_at: Option<DateTime<Utc>>,
    #[serde(default)]
    last_heartbeat_at: Option<DateTime<Utc>>,
    #[serde(default)]
    last_election_at: Option<DateTime<Utc>>,
    #[serde(default)]
    last_quorum_at: Option<DateTime<Utc>>,
    #[serde(default = "metadata_membership_phase_default")]
    membership_phase: String,
    #[serde(default)]
    joint_old_members: Vec<String>,
    #[serde(default)]
    joint_new_members: Vec<String>,
    #[serde(default)]
    peers: Vec<MetadataRaftRuntimePeer>,
}

pub(crate) fn default_security_config_from_env() -> SecurityConfig {
    SecurityConfig {
        oidc_enabled: std::env::var("RUSTIO_OIDC_ENABLED")
            .ok()
            .and_then(|value| value.parse::<bool>().ok())
            .unwrap_or(true),
        ldap_enabled: std::env::var("RUSTIO_LDAP_ENABLED")
            .ok()
            .and_then(|value| value.parse::<bool>().ok())
            .unwrap_or(true),
        oidc_discovery_url: std::env::var("RUSTIO_OIDC_DISCOVERY_URL").unwrap_or_default(),
        oidc_issuer: std::env::var("RUSTIO_OIDC_ISSUER").unwrap_or_default(),
        oidc_client_id: std::env::var("RUSTIO_OIDC_CLIENT_ID").unwrap_or_default(),
        oidc_jwks_url: std::env::var("RUSTIO_OIDC_JWKS_URL").unwrap_or_default(),
        oidc_allowed_algs: std::env::var("RUSTIO_OIDC_ALLOWED_ALGS").unwrap_or_default(),
        oidc_username_claim: std::env::var("RUSTIO_OIDC_USERNAME_CLAIM")
            .unwrap_or_else(|_| "preferred_username".to_string()),
        oidc_groups_claim: std::env::var("RUSTIO_OIDC_GROUPS_CLAIM")
            .unwrap_or_else(|_| "groups".to_string()),
        oidc_role_claim: std::env::var("RUSTIO_OIDC_ROLE_CLAIM")
            .unwrap_or_else(|_| "role".to_string()),
        oidc_default_role: std::env::var("RUSTIO_OIDC_DEFAULT_ROLE")
            .unwrap_or_else(|_| "viewer".to_string()),
        oidc_group_role_map: std::env::var("RUSTIO_OIDC_GROUP_ROLE_MAP").unwrap_or_default(),
        ldap_url: std::env::var("RUSTIO_LDAP_URL").unwrap_or_default(),
        ldap_bind_dn: std::env::var("RUSTIO_LDAP_BIND_DN").unwrap_or_default(),
        ldap_user_base_dn: std::env::var("RUSTIO_LDAP_USER_BASE_DN").unwrap_or_default(),
        ldap_user_filter: std::env::var("RUSTIO_LDAP_USER_FILTER")
            .unwrap_or_else(|_| "(uid={username})".to_string()),
        ldap_group_base_dn: std::env::var("RUSTIO_LDAP_GROUP_BASE_DN").unwrap_or_default(),
        ldap_group_filter: std::env::var("RUSTIO_LDAP_GROUP_FILTER")
            .unwrap_or_else(|_| "(member={user_dn})".to_string()),
        ldap_group_attribute: std::env::var("RUSTIO_LDAP_GROUP_ATTRIBUTE")
            .unwrap_or_else(|_| "memberOf".to_string()),
        ldap_group_name_attribute: std::env::var("RUSTIO_LDAP_GROUP_NAME_ATTRIBUTE")
            .unwrap_or_else(|_| "cn".to_string()),
        ldap_default_role: std::env::var("RUSTIO_LDAP_DEFAULT_ROLE")
            .unwrap_or_else(|_| "viewer".to_string()),
        ldap_group_role_map: std::env::var("RUSTIO_LDAP_GROUP_ROLE_MAP").unwrap_or_default(),
        kms_endpoint: std::env::var("RUSTIO_KMS_ENDPOINT")
            .unwrap_or_else(|_| "https://vault.example.internal".to_string()),
        kms_healthy: true,
        kms_last_error: None,
        kms_last_checked_at: None,
        kms_last_success_at: None,
        kms_last_recovered_at: None,
        kms_rotation_status: "idle".to_string(),
        kms_rotation_last_started_at: None,
        kms_rotation_last_completed_at: None,
        kms_rotation_last_success_at: None,
        kms_rotation_last_failure_reason: None,
        kms_rotation_scanned: 0,
        kms_rotation_rotated: 0,
        kms_rotation_skipped: 0,
        kms_rotation_failed: 0,
        kms_rotation_failed_objects: Vec::new(),
        sse_mode: std::env::var("RUSTIO_SSE_MODE").unwrap_or_else(|_| "SSE-KMS".to_string()),
    }
}

pub(crate) fn merge_security_config(
    mut base: SecurityConfig,
    persisted: SecurityConfig,
) -> SecurityConfig {
    base.oidc_enabled = persisted.oidc_enabled;
    base.ldap_enabled = persisted.ldap_enabled;

    if !persisted.oidc_discovery_url.trim().is_empty() {
        base.oidc_discovery_url = persisted.oidc_discovery_url;
    }
    if !persisted.oidc_issuer.trim().is_empty() {
        base.oidc_issuer = persisted.oidc_issuer;
    }
    if !persisted.oidc_client_id.trim().is_empty() {
        base.oidc_client_id = persisted.oidc_client_id;
    }
    if !persisted.oidc_jwks_url.trim().is_empty() {
        base.oidc_jwks_url = persisted.oidc_jwks_url;
    }
    if !persisted.oidc_allowed_algs.trim().is_empty() {
        base.oidc_allowed_algs = persisted.oidc_allowed_algs;
    }
    if !persisted.oidc_username_claim.trim().is_empty() {
        base.oidc_username_claim = persisted.oidc_username_claim;
    }
    if !persisted.oidc_groups_claim.trim().is_empty() {
        base.oidc_groups_claim = persisted.oidc_groups_claim;
    }
    if !persisted.oidc_role_claim.trim().is_empty() {
        base.oidc_role_claim = persisted.oidc_role_claim;
    }
    if !persisted.oidc_default_role.trim().is_empty() {
        base.oidc_default_role = persisted.oidc_default_role;
    }
    if !persisted.oidc_group_role_map.trim().is_empty() {
        base.oidc_group_role_map = persisted.oidc_group_role_map;
    }
    if !persisted.ldap_url.trim().is_empty() {
        base.ldap_url = persisted.ldap_url;
    }
    if !persisted.ldap_bind_dn.trim().is_empty() {
        base.ldap_bind_dn = persisted.ldap_bind_dn;
    }
    if !persisted.ldap_user_base_dn.trim().is_empty() {
        base.ldap_user_base_dn = persisted.ldap_user_base_dn;
    }
    if !persisted.ldap_user_filter.trim().is_empty() {
        base.ldap_user_filter = persisted.ldap_user_filter;
    }
    if !persisted.ldap_group_base_dn.trim().is_empty() {
        base.ldap_group_base_dn = persisted.ldap_group_base_dn;
    }
    if !persisted.ldap_group_filter.trim().is_empty() {
        base.ldap_group_filter = persisted.ldap_group_filter;
    }
    if !persisted.ldap_group_attribute.trim().is_empty() {
        base.ldap_group_attribute = persisted.ldap_group_attribute;
    }
    if !persisted.ldap_group_name_attribute.trim().is_empty() {
        base.ldap_group_name_attribute = persisted.ldap_group_name_attribute;
    }
    if !persisted.ldap_default_role.trim().is_empty() {
        base.ldap_default_role = persisted.ldap_default_role;
    }
    if !persisted.ldap_group_role_map.trim().is_empty() {
        base.ldap_group_role_map = persisted.ldap_group_role_map;
    }
    if !persisted.kms_endpoint.trim().is_empty() {
        base.kms_endpoint = persisted.kms_endpoint;
    }
    base.kms_healthy = persisted.kms_healthy;
    base.kms_last_error = persisted.kms_last_error;
    base.kms_last_checked_at = persisted.kms_last_checked_at;
    base.kms_last_success_at = persisted.kms_last_success_at;
    base.kms_last_recovered_at = persisted.kms_last_recovered_at;
    if !persisted.kms_rotation_status.trim().is_empty() {
        base.kms_rotation_status = persisted.kms_rotation_status;
    }
    base.kms_rotation_last_started_at = persisted.kms_rotation_last_started_at;
    base.kms_rotation_last_completed_at = persisted.kms_rotation_last_completed_at;
    base.kms_rotation_last_success_at = persisted.kms_rotation_last_success_at;
    base.kms_rotation_last_failure_reason = persisted.kms_rotation_last_failure_reason;
    base.kms_rotation_scanned = persisted.kms_rotation_scanned;
    base.kms_rotation_rotated = persisted.kms_rotation_rotated;
    base.kms_rotation_skipped = persisted.kms_rotation_skipped;
    base.kms_rotation_failed = persisted.kms_rotation_failed;
    base.kms_rotation_failed_objects = persisted.kms_rotation_failed_objects;
    if !persisted.sse_mode.trim().is_empty() {
        base.sse_mode = persisted.sse_mode;
    }

    base
}

pub(crate) fn default_cluster_config_payload(security: &SecurityConfig) -> Value {
    json!({
        "cluster": {
            "name": "rustio-cluster",
            "region": "cn-east-1",
            "domain": "localhost:9000"
        },
        "network": {
            "api": {
                "address": "0.0.0.0:9000"
            },
            "console": {
                "embedded": true,
                "address": "0.0.0.0:9000"
            }
        },
        "storage": {
            "erasure_set_size": 4,
            "bitrot": "highwayhash256"
        },
        "security": {
            "oidc_enabled": security.oidc_enabled,
            "ldap_enabled": security.ldap_enabled,
            "oidc_discovery_url": security.oidc_discovery_url,
            "oidc_issuer": security.oidc_issuer,
            "oidc_client_id": security.oidc_client_id,
            "oidc_jwks_url": security.oidc_jwks_url,
            "oidc_allowed_algs": security.oidc_allowed_algs,
            "oidc_username_claim": security.oidc_username_claim,
            "oidc_groups_claim": security.oidc_groups_claim,
            "oidc_role_claim": security.oidc_role_claim,
            "oidc_default_role": security.oidc_default_role,
            "oidc_group_role_map": security.oidc_group_role_map,
            "ldap_url": security.ldap_url,
            "ldap_bind_dn": security.ldap_bind_dn,
            "ldap_user_base_dn": security.ldap_user_base_dn,
            "ldap_user_filter": security.ldap_user_filter,
            "ldap_group_base_dn": security.ldap_group_base_dn,
            "ldap_group_filter": security.ldap_group_filter,
            "ldap_group_attribute": security.ldap_group_attribute,
            "ldap_group_name_attribute": security.ldap_group_name_attribute,
            "ldap_default_role": security.ldap_default_role,
            "ldap_group_role_map": security.ldap_group_role_map,
            "kms_endpoint": security.kms_endpoint,
            "sse_mode": security.sse_mode
        },
        "observability": {
            "audit_enabled": true,
            "metrics_enabled": true
        }
    })
}

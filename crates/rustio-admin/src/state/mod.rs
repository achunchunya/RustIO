mod alerts;
pub(crate) mod cluster;
mod jobs;
mod meta_store;
pub(crate) mod password;
mod persistence_bootstrap;
pub(crate) mod raft;
mod replication_workers;
mod runtime_config;
mod session_sync;

use meta_store::MetaStore;
pub(crate) use password::{hash_password, is_hashed as password_is_hashed, verify_password};
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
    /// 集群 peer 健康探测结果(node_id → 健康态),仅集群模式填充。
    pub peer_health: HashMap<u64, PeerHealthState>,
}

/// 单个 peer 的健康探测状态(由后台 heartbeat worker 维护)。
#[derive(Debug, Clone)]
pub struct PeerHealthState {
    pub online: bool,
    pub last_check_at: DateTime<Utc>,
    pub last_ok_at: Option<DateTime<Utc>>,
    pub consecutive_failures: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct LifecycleJobDraft {
    kind: String,
    bucket: String,
    object_key: String,
    idempotency_key: String,
    payload: Value,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    pub peers: Vec<String>,
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
pub struct MetadataRaftSyncResponse {
    pub term: u64,
    pub success: bool,
    pub match_index: u64,
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
    /// 集群：本节点 ID(0=单机模式) + peer 拓扑。
    pub local_node_id: u64,
    pub cluster_peers: RwLock<HashMap<u64, cluster::ClusterPeerInfo>>,
    pub architecture: ArchitectureTopology,
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
    pub(crate) meta_store: MetaStore,
    pub(crate) login_rate_limiter: crate::routes::rate_limit::LoginRateLimiter,
    pub multipart_uploads: RwLock<HashMap<String, MultipartUpload>>,
    pub last_request_activity_at: AtomicI64,
    pub last_memory_trim_at: AtomicI64,
    pub events: broadcast::Sender<RuntimeEvent>,
    /// openraft 元数据 raft 句柄(集群模式);单机未启时为空,写路径回退本地 apply。
    pub(crate) meta_raft: std::sync::OnceLock<raft::MetadataRaft>,
    /// state machine 的 AppState 弱引用 holder(init_metadata_raft 时回填,打破循环)。
    pub(crate) meta_raft_app: raft::AppStateRef,
}

impl AppState {
    /// 查询对象当前版本元数据(读 redb 真相源,不暖缓存)。供外部查询与测试白盒验证。
    pub fn lookup_object_meta(&self, bucket: &str, key: &str) -> Option<S3ObjectMeta> {
        self.meta_store.get_uncached(bucket, key).ok().flatten()
    }

    /// 直接写入对象当前版本元数据(供测试白盒注入;写 redb 真相源)。
    #[doc(hidden)]
    pub fn put_object_meta_direct(&self, meta: &S3ObjectMeta) {
        let _ = self.meta_store.put(meta);
    }
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

impl AppState {
    /// Raft 状态视图(从 openraft metrics 构建)。
    pub async fn metadata_raft_status(&self) -> MetadataRaftStatus {
        if let Some(raft) = self.meta_raft.get() {
            let metrics_guard = raft.metrics();
            let metrics = metrics_guard.borrow();
            let peer_ids: Vec<String> = metrics
                .membership_config
                .nodes()
                .map(|(id, _node)| id.to_string())
                .collect();
            MetadataRaftStatus {
                cluster_id: "raft-meta-cluster".to_string(),
                leader_id: metrics.current_leader.map(|id| id.to_string()).unwrap_or_default(),
                term: metrics.current_term,
                commit_index: metrics.last_log_index.unwrap_or(0),
                quorum: peer_ids.len().max(1),
                online_peers: peer_ids.len(),
                last_error: None,
                last_commit_at: None,
                membership_phase: "stable".to_string(),
                joint_old_members: vec![],
                joint_new_members: vec![],
                joint_elapsed_seconds: None,
                joint_timeout_seconds: 0,
                peers: peer_ids,
            }
        } else {
            MetadataRaftStatus {
                cluster_id: "rustio-standalone".to_string(),
                leader_id: "standalone".to_string(),
                term: 0,
                commit_index: 0,
                quorum: 1,
                online_peers: 1,
                last_error: None,
                last_commit_at: None,
                membership_phase: "stable".to_string(),
                ..Default::default()
            }
        }
    }

    /// 构建元数据快照（集群备份导出用）。
    pub(crate) async fn build_metadata_snapshot(&self) -> MetadataRaftSnapshot {
        let mut buckets = self.buckets.read().await.values().cloned().collect::<Vec<_>>();
        buckets.sort_by(|left, right| left.name.cmp(&right.name));
        let remote_tiers = Self::sorted_map_entries(&self.remote_tiers.read().await.clone());
        let bucket_object_locks = Self::sorted_map_entries(&self.bucket_object_locks.read().await.clone());
        let bucket_retentions = Self::sorted_map_entries(&self.bucket_retentions.read().await.clone());
        let bucket_legal_holds = Self::sorted_map_entries(&self.bucket_legal_holds.read().await.clone());
        let bucket_notifications = Self::sorted_map_entries(&self.bucket_notifications.read().await.clone());
        let bucket_lifecycle_rules = Self::sorted_map_entries(&self.bucket_lifecycle_rules.read().await.clone());
        let bucket_acls = Self::sorted_map_entries(&self.bucket_acls.read().await.clone());
        let bucket_public_access_blocks = Self::sorted_map_entries(&self.bucket_public_access_blocks.read().await.clone());
        let bucket_policies = Self::sorted_map_entries(&self.bucket_policies.read().await.clone());
        let bucket_cors_rules = Self::sorted_map_entries(&self.bucket_cors_rules.read().await.clone());
        let bucket_tags = Self::sorted_map_entries(&self.bucket_tags.read().await.clone());
        let bucket_encryptions = Self::sorted_map_entries(&self.bucket_encryptions.read().await.clone());
        let mut iam_users = self.users.read().await.clone(); iam_users.sort_by(|l, r| l.username.cmp(&r.username));
        let credentials = Self::sorted_map_entries(&self.credentials.read().await.clone());
        let mut iam_groups = self.groups.read().await.clone(); iam_groups.sort_by(|l, r| l.name.cmp(&r.name));
        let mut iam_policies = self.policies.read().await.clone(); iam_policies.sort_by(|l, r| l.name.cmp(&r.name));
        let mut service_accounts = self.service_accounts.read().await.clone(); service_accounts.sort_by(|l, r| l.access_key.cmp(&r.access_key));
        let mut admin_sessions = self.admin_sessions.read().await.clone(); admin_sessions.sort_by(|l, r| l.session_id.cmp(&r.session_id));
        let mut sts_sessions = self.sts_sessions.read().await.clone(); sts_sessions.sort_by(|l, r| l.session_id.cmp(&r.session_id));
        let mut replications = self.replications.read().await.clone();
        replications.sort_by(|l, r| l.source_bucket.cmp(&r.source_bucket).then_with(|| l.target_site.cmp(&r.target_site)).then_with(|| l.rule_id.cmp(&r.rule_id)));
        let mut site_replications = self.site_replications.read().await.clone(); site_replications.sort_by(|l, r| l.site_id.cmp(&r.site_id));
        let mut replication_backlog = self.replication_backlog.read().await.clone(); replication_backlog.sort_by(|l, r| l.id.cmp(&r.id));
        let replication_checkpoints = Self::sorted_map_entries(&self.replication_checkpoints.read().await.clone());
        let cluster_config_history = self.cluster_config_history.read().await.clone();
        let security = self.security.read().await.clone();
        let mut jobs = self.jobs.read().await.clone(); jobs.sort_by(|l, r| l.id.cmp(&r.id));
        MetadataRaftSnapshot {
            generated_at: Utc::now(), buckets, remote_tiers, bucket_object_locks, bucket_retentions,
            bucket_legal_holds, bucket_notifications, bucket_lifecycle_rules, bucket_acls,
            bucket_public_access_blocks, bucket_policies, bucket_cors_rules, bucket_tags, bucket_encryptions,
            objects: Vec::new(), credentials, iam_users, iam_groups, iam_policies, service_accounts,
            admin_sessions, sts_sessions, replications, site_replications, replication_backlog,
            replication_checkpoints, cluster_config_history, security, jobs,
        }
    }

    /// 导出元数据快照同步请求（集群备份用）。
    pub async fn export_metadata_raft_sync_request(&self, reason: &str) -> Result<MetadataRaftSyncRequest, String> {
        let snapshot = self.build_metadata_snapshot().await;
        let (commit_index, term) = if let Some(raft) = self.meta_raft.get() {
            let metrics_guard = raft.metrics();
            let metrics = metrics_guard.borrow();
            (metrics.last_log_index.unwrap_or(0), metrics.current_term)
        } else {
            (0, 1)
        };
        Ok(MetadataRaftSyncRequest {
            cluster_id: "raft-meta-cluster".to_string(),
            peer_id: std::env::var("RUSTIO_METADATA_RAFT_NODE_ID")
                .unwrap_or_else(|_| "meta-1".to_string()),
            entry: MetadataRaftLogEntry {
                index: commit_index, term, reason: reason.to_string(), written_at: Utc::now(),
                snapshot_hash: String::new(),
            },
            prev_log_index: 0, prev_log_term: 0, install_snapshot: true, leader_commit: commit_index,
            snapshot,
        })
    }

    pub(crate) fn sorted_map_entries<T: Clone>(map: &HashMap<String, T>) -> Vec<(String, T)> {
        let mut entries = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>();
        entries.sort_by(|l, r| l.0.cmp(&r.0));
        entries
    }

    pub async fn persist_replication_runtime_state(&self) {
        let runtime = ReplicationRuntimeState {
            version: 1,
            sequence: self.replication_sequence.load(Ordering::SeqCst),
            backlog: self.replication_backlog.read().await.clone(),
            checkpoints: self.replication_checkpoints.read().await.clone(),
        };
        let path = self.replication_state_path();
        if let Some(parent) = path.parent() { let _ = std::fs::create_dir_all(parent); }
        if let Ok(bytes) = serde_json::to_vec_pretty(&runtime) {
            let temp_path = path.with_extension("tmp");
            if std::fs::write(&temp_path, bytes).is_ok() { let _ = std::fs::rename(temp_path, &path); }
        }
    }

    pub(crate) fn restore_replication_runtime_state(&self) {
        let state_path = self.replication_state_path();
        let bytes = match std::fs::read(&state_path) { Ok(b) => b, Err(_) => return };
        let runtime = match serde_json::from_slice::<ReplicationRuntimeState>(&bytes) { Ok(v) => v, Err(_) => return };
        if let Ok(mut backlog) = self.replication_backlog.try_write() { *backlog = runtime.backlog; }
        if let Ok(mut checkpoints) = self.replication_checkpoints.try_write() { *checkpoints = runtime.checkpoints; }
        let mut next_sequence = runtime.sequence.max(1);
        if let Ok(backlog) = self.replication_backlog.try_read() {
            for item in backlog.iter() { next_sequence = next_sequence.max(item.checkpoint.saturating_add(1)); }
        }
        if let Ok(checkpoints) = self.replication_checkpoints.try_read() {
            for checkpoint in checkpoints.values() { next_sequence = next_sequence.max(checkpoint.saturating_add(1)); }
        }
        self.replication_sequence.store(next_sequence.max(1), Ordering::SeqCst);
    }

    pub(crate) fn replication_state_path(&self) -> PathBuf {
        self.replication_root_dir().join("runtime-state.json")
    }

    pub(crate) fn hash_json(value: &impl Serialize) -> Result<String, String> {
        let bytes = serde_json::to_vec(value).map_err(|err| err.to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(hex::encode(hasher.finalize()))
    }

    /// 应用远程元数据快照（集群备份恢复用）。
    pub async fn apply_remote_metadata_raft_sync(
        &self,
        request: MetadataRaftSyncRequest,
    ) -> Result<MetadataRaftSyncResponse, String> {
        let snapshot = request.snapshot;
        {
            let mut buckets = self.buckets.write().await;
            *buckets = snapshot.buckets.into_iter().map(|s| (s.name.clone(), s)).collect();
        }
        {
            let mut tiers = self.remote_tiers.write().await;
            *tiers = snapshot.remote_tiers.into_iter().collect();
        }
        {
            let mut service_accounts = self.service_accounts.write().await;
            *service_accounts = snapshot.service_accounts;
        }
        {
            let mut replications = self.replications.write().await;
            *replications = snapshot.replications;
        }
        {
            let mut policies = self.policies.write().await;
            *policies = snapshot.iam_policies;
        }
        {
            let mut users = self.users.write().await;
            *users = snapshot.iam_users;
        }
        {
            let mut groups = self.groups.write().await;
            *groups = snapshot.iam_groups;
        }
        {
            let mut credentials = self.credentials.write().await;
            *credentials = snapshot.credentials.into_iter().collect();
        }
        {
            let mut admin_sessions = self.admin_sessions.write().await;
            *admin_sessions = snapshot.admin_sessions;
        }
        {
            let mut sts_sessions = self.sts_sessions.write().await;
            *sts_sessions = snapshot.sts_sessions;
        }
        {
            let mut security = self.security.write().await;
            *security = snapshot.security;
        }
        {
            let mut history = self.cluster_config_history.write().await;
            *history = snapshot.cluster_config_history;
        }
        {
            let mut jobs = self.jobs.write().await;
            *jobs = snapshot.jobs;
        }
        {
            let mut checkpoints = self.replication_checkpoints.write().await;
            *checkpoints = snapshot.replication_checkpoints.into_iter().collect();
        }
        {
            let mut backlog = self.replication_backlog.write().await;
            *backlog = snapshot.replication_backlog;
        }
        Ok(MetadataRaftSyncResponse { term: request.entry.term, success: true, match_index: request.entry.index, reason: None })
    }
}

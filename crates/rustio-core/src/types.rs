use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEnvelope<T> {
    pub data: T,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterHealth {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub nodes_online: u32,
    pub nodes_total: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetricsSummary {
    pub generated_at: DateTime<Utc>,
    pub cluster_status: String,
    pub tenants_total: usize,
    pub nodes: SystemNodeMetricsSummary,
    pub storage: SystemStorageMetricsSummary,
    pub raft: SystemRaftMetricsSummary,
    pub replication: SystemReplicationMetricsSummary,
    pub alerts: SystemAlertMetricsSummary,
    pub iam: SystemIamMetricsSummary,
    pub audit: SystemAuditMetricsSummary,
    pub kms: SystemKmsMetricsSummary,
    pub security: SystemSecurityMetricsSummary,
    pub jobs: SystemJobMetricsSummary,
    pub sessions: SystemSessionMetricsSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemNodeMetricsSummary {
    pub total: usize,
    pub online: usize,
    pub offline: usize,
    pub zones_total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStorageMetricsSummary {
    pub capacity_total_bytes: u64,
    pub capacity_used_bytes: u64,
    pub capacity_free_bytes: u64,
    pub utilization_ratio: f64,
    pub disks_total: usize,
    pub disks_online: usize,
    pub disks_degraded: usize,
    pub ec_data_shards: usize,
    pub ec_parity_shards: usize,
    pub shard_files_total: usize,
    pub shard_bytes_total: u64,
    pub shard_healthy_total: usize,
    pub shard_missing_total: usize,
    pub shard_corrupted_total: usize,
    pub governance: SystemStorageGovernanceMetricsSummary,
    pub disks: Vec<SystemStorageDiskMetricsSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemStorageGovernanceMetricsSummary {
    pub last_scan_at: Option<DateTime<Utc>>,
    pub last_heal_at: Option<DateTime<Utc>>,
    pub last_rebalance_at: Option<DateTime<Utc>>,
    pub last_decommission_at: Option<DateTime<Utc>>,
    pub pending_objects: usize,
    pub running_objects: usize,
    pub failed_objects: usize,
    pub retrying_objects: usize,
    pub last_scan_result: String,
    pub last_heal_duration_seconds: f64,
    pub scan_runs_total: u64,
    pub scan_failures_total: u64,
    pub heal_objects_total: u64,
    pub heal_failures_total: u64,
    pub rebalance_objects_total: u64,
    pub rebalance_failures_total: u64,
    pub decommission_objects_total: u64,
    pub decommission_failures_total: u64,
    pub draining_disks: usize,
    pub decommissioned_disks: usize,
    pub object_lock_buckets: usize,
    pub retention_buckets: usize,
    pub legal_hold_buckets: usize,
    pub retained_objects: usize,
    pub legal_hold_objects: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemStorageDiskMetricsSummary {
    pub disk_id: String,
    pub path: String,
    pub online: bool,
    pub status: String,
    pub placement_state: String,
    pub manifests_total: usize,
    pub shard_files: usize,
    pub shard_bytes: u64,
    pub shard_healthy: usize,
    pub shard_missing: usize,
    pub shard_corrupted: usize,
    pub heal_pressure: usize,
    pub last_anomaly_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemRaftMetricsSummary {
    pub cluster_id: String,
    pub leader_id: String,
    pub leader_present: bool,
    pub term: u64,
    pub commit_index: u64,
    pub quorum: usize,
    pub online_peers: usize,
    pub quorum_available: bool,
    pub membership_phase: String,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemReplicationMetricsSummary {
    pub rules_total: usize,
    pub sites_total: usize,
    pub sites_healthy: usize,
    pub checkpoints_total: usize,
    pub max_lag_seconds: u64,
    pub backlog_total: usize,
    pub backlog_pending: usize,
    pub backlog_in_progress: usize,
    pub backlog_failed: usize,
    pub backlog_dead_letter: usize,
    pub backlog_done: usize,
    pub backlog_retryable: usize,
    pub backlog_sla_firing_sites: usize,
    pub sites: Vec<SystemReplicationSiteMetricsSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemReplicationSiteMetricsSummary {
    pub site_id: String,
    pub endpoint: Option<String>,
    pub state: String,
    pub lag_seconds: u64,
    pub backlog_total: usize,
    pub backlog_pending: usize,
    pub backlog_failed: usize,
    pub backlog_dead_letter: usize,
    pub backlog_sla_status: String,
    pub firing_alerts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemAlertMetricsSummary {
    pub rules_total: usize,
    pub channels_total: usize,
    pub channels_enabled: usize,
    pub channels_healthy: usize,
    pub firing_alerts: usize,
    pub history_total: usize,
    pub delivery_queued: usize,
    pub delivery_in_progress: usize,
    pub delivery_failed: usize,
    pub delivery_done: usize,
    pub last_delivery_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemIamMetricsSummary {
    pub users_total: usize,
    pub users_enabled: usize,
    pub groups_total: usize,
    pub policies_total: usize,
    pub service_accounts_total: usize,
    pub service_accounts_enabled: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemAuditMetricsSummary {
    pub events_total: usize,
    pub auth_events_total: usize,
    pub iam_events_total: usize,
    pub kms_events_total: usize,
    pub alert_events_total: usize,
    pub replication_events_total: usize,
    pub job_events_total: usize,
    pub failed_outcomes_total: usize,
    pub latest_event_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemKmsMetricsSummary {
    pub endpoint_configured: bool,
    pub provider: String,
    pub auth_mode: String,
    pub healthy: bool,
    pub last_error: Option<String>,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_recovered_at: Option<DateTime<Utc>>,
    pub rotation_status: String,
    pub rotation_last_started_at: Option<DateTime<Utc>>,
    pub rotation_last_completed_at: Option<DateTime<Utc>>,
    pub rotation_last_success_at: Option<DateTime<Utc>>,
    pub rotation_last_failure_reason: Option<String>,
    pub rotation_scanned: u64,
    pub rotation_rotated: u64,
    pub rotation_skipped: u64,
    pub rotation_failed: u64,
    pub retry_recommended: bool,
    #[serde(default)]
    pub rotation_failed_objects_preview: Vec<KmsRotationFailedObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSecurityMetricsSummary {
    pub oidc_enabled: bool,
    pub ldap_enabled: bool,
    pub kms_endpoint_configured: bool,
    pub kms_healthy: bool,
    pub sse_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemJobMetricsSummary {
    pub total: usize,
    pub running: usize,
    pub pending: usize,
    pub completed: usize,
    pub failed: usize,
    pub cancelled: usize,
    pub idle: usize,
    pub other: usize,
    pub retrying: usize,
    pub scan: usize,
    pub scrub: usize,
    pub heal: usize,
    pub rebuild: usize,
    pub async_total: usize,
    pub async_pending: usize,
    pub async_in_progress: usize,
    pub async_completed: usize,
    pub async_failed: usize,
    pub async_dead_letter: usize,
    pub async_retryable: usize,
    pub kinds: Vec<SystemJobKindMetricsSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemJobKindMetricsSummary {
    pub kind: String,
    pub total: usize,
    pub pending: usize,
    pub in_progress: usize,
    pub completed: usize,
    pub failed: usize,
    pub dead_letter: usize,
    pub retryable: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSessionMetricsSummary {
    pub service_accounts_total: usize,
    pub service_accounts_enabled: usize,
    pub admin_sessions_total: usize,
    pub admin_sessions_active: usize,
    pub admin_sessions_expiring_24h: usize,
    pub sts_sessions_total: usize,
    pub sts_sessions_active: usize,
    pub sts_sessions_expiring_24h: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    pub id: String,
    pub hostname: String,
    pub zone: String,
    pub online: bool,
    pub capacity_total_bytes: u64,
    pub capacity_used_bytes: u64,
    pub last_heartbeat: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterQuota {
    pub tenant: String,
    pub hard_limit_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSpec {
    pub id: String,
    pub display_name: String,
    pub owner_group: String,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub project_name: Option<String>,
    #[serde(default)]
    pub domain_id: Option<String>,
    #[serde(default)]
    pub domain_name: Option<String>,
    pub enabled: bool,
    pub status: String,
    pub hard_limit_bytes: u64,
    pub used_bytes: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub generated_by: String,
    pub summary: String,
    #[serde(default = "default_diagnostic_report_kind")]
    pub kind: String,
    #[serde(default = "default_diagnostic_report_format")]
    pub format: String,
    #[serde(default)]
    pub redacted: bool,
    #[serde(default)]
    pub sections: Vec<String>,
    #[serde(default)]
    pub download_name: Option<String>,
}

fn default_diagnostic_report_kind() -> String {
    "support-bundle".to_string()
}

fn default_diagnostic_report_format() -> String {
    "support-bundle.v1".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfigSnapshot {
    pub version: String,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
    pub source: String,
    pub reason: Option<String>,
    pub etag: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfigValidateRequest {
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfigValidateResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfigApplyRequest {
    pub payload: Value,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfigRollbackRequest {
    pub version: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamUser {
    pub username: String,
    pub display_name: String,
    pub role: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamGroup {
    pub name: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamPolicy {
    pub name: String,
    pub document: Value,
    pub attached_to: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    pub access_key: String,
    pub secret_key: String,
    pub owner: String,
    pub created_at: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StsSession {
    pub session_id: String,
    pub principal: String,
    pub access_key: String,
    pub secret_key: String,
    pub session_token: String,
    #[serde(default = "default_sts_provider")]
    pub provider: String,
    #[serde(default)]
    pub role_arn: Option<String>,
    #[serde(default)]
    pub session_name: Option<String>,
    #[serde(default)]
    pub session_policy: Option<Value>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default = "default_sts_status")]
    pub status: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

fn default_sts_provider() -> String {
    "manual".to_string()
}

fn default_sts_status() -> String {
    "active".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleSession {
    pub session_id: String,
    pub principal: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub provider: String,
    #[serde(default = "default_console_session_status")]
    pub status: String,
    pub issued_at: DateTime<Utc>,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
    #[serde(default)]
    pub last_refreshed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub revoked_reason: Option<String>,
}

fn default_console_session_status() -> String {
    "active".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProviderInfo {
    pub id: String,
    pub enabled: bool,
    pub configured: bool,
    pub supports_username_password: bool,
    pub supports_browser_redirect: bool,
    pub supports_id_token: bool,
    #[serde(default)]
    pub authorize_url: Option<String>,
    #[serde(default)]
    pub missing_requirements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketSpec {
    pub name: String,
    pub tenant_id: String,
    pub versioning: bool,
    pub object_lock: bool,
    pub ilm_policy: Option<String>,
    pub replication_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketGovernanceUpdate {
    pub versioning: Option<bool>,
    pub object_lock: Option<bool>,
    pub ilm_policy: Option<String>,
    pub replication_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketObjectLockConfig {
    pub enabled: bool,
    pub mode: String,
    pub default_retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketRetentionConfig {
    pub enabled: bool,
    pub mode: String,
    pub duration_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketLegalHoldConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketNotificationRule {
    pub id: String,
    pub event: String,
    pub target: String,
    pub prefix: Option<String>,
    pub suffix: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketLifecycleRule {
    pub id: String,
    pub prefix: Option<String>,
    pub status: String,
    pub expiration_days: Option<u32>,
    pub noncurrent_expiration_days: Option<u32>,
    #[serde(default)]
    pub transition_days: Option<u32>,
    #[serde(default)]
    pub transition_tier: Option<String>,
    #[serde(default)]
    pub noncurrent_transition_days: Option<u32>,
    #[serde(default)]
    pub noncurrent_transition_tier: Option<String>,
}

fn default_remote_tier_enabled() -> bool {
    true
}

fn default_remote_tier_backend() -> String {
    "filesystem".to_string()
}

fn default_remote_tier_health_status() -> String {
    "unknown".to_string()
}

fn default_object_storage_class() -> String {
    "STANDARD".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteTierConfig {
    pub name: String,
    pub endpoint: String,
    #[serde(default = "default_remote_tier_backend")]
    pub backend: String,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default = "default_object_storage_class")]
    pub storage_class: String,
    #[serde(default = "default_remote_tier_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub credential_key: Option<String>,
    #[serde(default)]
    pub credential_secret: Option<String>,
    #[serde(default)]
    pub credential_token: Option<String>,
    #[serde(default)]
    pub extra_headers: HashMap<String, String>,
    #[serde(default)]
    pub secret_version: u64,
    #[serde(default = "default_remote_tier_health_status")]
    pub health_status: String,
    #[serde(default)]
    pub last_checked_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_success_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectRemoteTierStatus {
    pub tier: String,
    pub storage_class: String,
    pub transitioned_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObjectRestoreStatus {
    #[serde(default)]
    pub ongoing_request: bool,
    #[serde(default)]
    pub requested_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub expiry_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketAclConfig {
    pub acl: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketPublicAccessBlockConfig {
    pub block_public_acls: bool,
    pub ignore_public_acls: bool,
    pub block_public_policy: bool,
    pub restrict_public_buckets: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketCorsRule {
    pub id: String,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub max_age_seconds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BucketTag {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketEncryptionConfig {
    pub enabled: bool,
    pub algorithm: String,
    pub kms_key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationStatus {
    pub rule_id: String,
    pub source_bucket: String,
    pub target_site: String,
    #[serde(default)]
    pub rule_name: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub suffix: Option<String>,
    #[serde(default)]
    pub tags: Vec<BucketTag>,
    #[serde(default = "default_replication_priority")]
    pub priority: i32,
    #[serde(default = "default_replication_replicate_existing")]
    pub replicate_existing: bool,
    #[serde(default = "default_replication_sync_deletes")]
    pub sync_deletes: bool,
    pub lag_seconds: u64,
    pub status: String,
}

fn default_replication_priority() -> i32 {
    100
}

fn default_replication_replicate_existing() -> bool {
    true
}

fn default_replication_sync_deletes() -> bool {
    true
}

fn default_site_replication_bootstrap_state() -> String {
    "ready".to_string()
}

fn default_site_replication_topology_version() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteReplicationStatus {
    pub site_id: String,
    pub endpoint: String,
    pub role: String,
    pub preferred_primary: bool,
    pub state: String,
    pub lag_seconds: u64,
    pub managed_buckets: u32,
    pub last_sync_at: DateTime<Utc>,
    #[serde(default = "default_site_replication_bootstrap_state")]
    pub bootstrap_state: String,
    #[serde(default)]
    pub joined_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_resync_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_reconcile_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub pending_resync_items: u64,
    #[serde(default)]
    pub drifted_buckets: u32,
    #[serde(default = "default_site_replication_topology_version")]
    pub topology_version: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationBacklogItem {
    pub id: String,
    pub source_bucket: String,
    pub target_site: String,
    pub object_key: String,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default = "default_replication_backlog_priority")]
    pub priority: i32,
    #[serde(default = "default_replication_operation")]
    pub operation: String,
    #[serde(default)]
    pub checkpoint: u64,
    #[serde(default)]
    pub idempotency_key: String,
    #[serde(default)]
    pub version_id: Option<String>,
    pub attempts: u32,
    pub status: String,
    pub last_error: String,
    #[serde(default)]
    pub lease_owner: Option<String>,
    #[serde(default)]
    pub lease_until: Option<DateTime<Utc>>,
    pub queued_at: DateTime<Utc>,
    pub last_attempt_at: DateTime<Utc>,
}

fn default_replication_operation() -> String {
    "put".to_string()
}

fn default_replication_backlog_priority() -> i32 {
    100
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub oidc_enabled: bool,
    pub ldap_enabled: bool,
    #[serde(default)]
    pub oidc_discovery_url: String,
    #[serde(default)]
    pub oidc_issuer: String,
    #[serde(default)]
    pub oidc_client_id: String,
    #[serde(default)]
    pub oidc_jwks_url: String,
    #[serde(default)]
    pub oidc_allowed_algs: String,
    #[serde(default)]
    pub oidc_username_claim: String,
    #[serde(default)]
    pub oidc_groups_claim: String,
    #[serde(default)]
    pub oidc_role_claim: String,
    #[serde(default)]
    pub oidc_default_role: String,
    #[serde(default)]
    pub oidc_group_role_map: String,
    #[serde(default)]
    pub ldap_url: String,
    #[serde(default)]
    pub ldap_bind_dn: String,
    #[serde(default)]
    pub ldap_user_base_dn: String,
    #[serde(default)]
    pub ldap_user_filter: String,
    #[serde(default)]
    pub ldap_group_base_dn: String,
    #[serde(default)]
    pub ldap_group_filter: String,
    #[serde(default)]
    pub ldap_group_attribute: String,
    #[serde(default)]
    pub ldap_group_name_attribute: String,
    #[serde(default)]
    pub ldap_default_role: String,
    #[serde(default)]
    pub ldap_group_role_map: String,
    pub kms_endpoint: String,
    pub kms_healthy: bool,
    #[serde(default)]
    pub kms_last_error: Option<String>,
    #[serde(default)]
    pub kms_last_checked_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub kms_last_success_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub kms_last_recovered_at: Option<DateTime<Utc>>,
    #[serde(default = "default_kms_rotation_status")]
    pub kms_rotation_status: String,
    #[serde(default)]
    pub kms_rotation_last_started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub kms_rotation_last_completed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub kms_rotation_last_success_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub kms_rotation_last_failure_reason: Option<String>,
    #[serde(default)]
    pub kms_rotation_scanned: u64,
    #[serde(default)]
    pub kms_rotation_rotated: u64,
    #[serde(default)]
    pub kms_rotation_skipped: u64,
    #[serde(default)]
    pub kms_rotation_failed: u64,
    #[serde(default, deserialize_with = "deserialize_kms_rotation_failed_objects")]
    pub kms_rotation_failed_objects: Vec<KmsRotationFailedObject>,
    pub sse_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KmsRotationFailedObject {
    #[serde(default)]
    pub bucket: String,
    #[serde(default)]
    pub object_key: String,
    #[serde(default)]
    pub version_id: Option<String>,
    #[serde(default)]
    pub is_current: bool,
    #[serde(default)]
    pub kms_key_id: Option<String>,
    #[serde(default)]
    pub retry_id: String,
    #[serde(default)]
    pub stage: String,
    #[serde(default)]
    pub message: String,
}

impl KmsRotationFailedObject {
    pub fn from_retry_id(retry_id: impl Into<String>) -> Self {
        let retry_id = retry_id.into().trim().to_string();
        let (identity, version_id) = retry_id
            .split_once("?versionId=")
            .map(|(left, right)| (left.to_string(), Some(right.trim().to_string())))
            .unwrap_or_else(|| (retry_id.clone(), None));
        let (bucket, object_key) = identity
            .split_once('/')
            .map(|(bucket, object_key)| (bucket.trim().to_string(), object_key.trim().to_string()))
            .unwrap_or_else(|| ("".to_string(), identity.trim().to_string()));
        let normalized_version_id = version_id.filter(|value| !value.is_empty());
        let is_current = normalized_version_id.is_none();
        Self {
            bucket,
            object_key,
            version_id: normalized_version_id,
            is_current,
            kms_key_id: None,
            retry_id,
            stage: "unknown".to_string(),
            message: "历史失败对象，缺少结构化原因 / legacy failed object without structured failure reason"
                .to_string(),
        }
        .normalized()
    }

    pub fn normalized_retry_id(&self) -> String {
        let retry_id = self.retry_id.trim();
        if !retry_id.is_empty() {
            return retry_id.to_string();
        }
        let object_key = self.object_key.trim();
        let bucket = self.bucket.trim();
        let base = if !bucket.is_empty() && !object_key.is_empty() {
            format!("{bucket}/{object_key}")
        } else if !object_key.is_empty() {
            object_key.to_string()
        } else {
            bucket.to_string()
        };
        self.version_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|version_id| format!("{base}?versionId={version_id}"))
            .unwrap_or(base)
    }

    pub fn normalized(mut self) -> Self {
        self.bucket = self.bucket.trim().to_string();
        self.object_key = self.object_key.trim().to_string();
        self.version_id = self
            .version_id
            .take()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self.kms_key_id = self
            .kms_key_id
            .take()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self.retry_id = self.normalized_retry_id();
        if self.stage.trim().is_empty() {
            self.stage = "unknown".to_string();
        } else {
            self.stage = self.stage.trim().to_string();
        }
        if self.message.trim().is_empty() {
            self.message = "KMS 轮换失败，缺少错误详情 / KMS rotation failed without error details"
                .to_string();
        } else {
            self.message = self.message.trim().to_string();
        }
        if self.version_id.is_none() {
            self.is_current = true;
        }
        self
    }
}

fn deserialize_kms_rotation_failed_objects<'de, D>(
    deserializer: D,
) -> Result<Vec<KmsRotationFailedObject>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        RetryId(String),
        Detailed(KmsRotationFailedObject),
    }

    let items = Vec::<Repr>::deserialize(deserializer)?;
    Ok(items
        .into_iter()
        .map(|item| match item {
            Repr::RetryId(retry_id) => KmsRotationFailedObject::from_retry_id(retry_id),
            Repr::Detailed(item) => item.normalized(),
        })
        .collect())
}

fn default_kms_rotation_status() -> String {
    "idle".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityUpdate {
    pub oidc_enabled: Option<bool>,
    pub ldap_enabled: Option<bool>,
    pub oidc_discovery_url: Option<String>,
    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_jwks_url: Option<String>,
    pub oidc_allowed_algs: Option<String>,
    pub oidc_username_claim: Option<String>,
    pub oidc_groups_claim: Option<String>,
    pub oidc_role_claim: Option<String>,
    pub oidc_default_role: Option<String>,
    pub oidc_group_role_map: Option<String>,
    pub ldap_url: Option<String>,
    pub ldap_bind_dn: Option<String>,
    pub ldap_user_base_dn: Option<String>,
    pub ldap_user_filter: Option<String>,
    pub ldap_group_base_dn: Option<String>,
    pub ldap_group_filter: Option<String>,
    pub ldap_group_attribute: Option<String>,
    pub ldap_group_name_attribute: Option<String>,
    pub ldap_default_role: Option<String>,
    pub ldap_group_role_map: Option<String>,
    pub kms_endpoint: Option<String>,
    pub sse_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub metric: String,
    pub condition: String,
    pub threshold: f64,
    pub window_minutes: u32,
    pub severity: String,
    pub enabled: bool,
    pub channels: Vec<String>,
    pub last_triggered_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertChannel {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub endpoint: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub payload_template: Option<String>,
    #[serde(default)]
    pub header_template: HashMap<String, String>,
    pub enabled: bool,
    pub status: String,
    pub last_checked_at: DateTime<Utc>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSilence {
    pub id: String,
    pub name: String,
    pub rule_ids: Vec<String>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub reason: String,
    pub created_by: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEscalationPolicy {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub wait_minutes: u32,
    pub channels: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertHistoryEntry {
    pub id: String,
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub severity: String,
    pub status: String,
    pub message: String,
    pub triggered_at: DateTime<Utc>,
    pub source: String,
    pub assignee: Option<String>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub outcome: String,
    pub reason: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsRotationResult {
    pub status: String,
    pub scanned: u64,
    pub rotated: u64,
    pub skipped: u64,
    pub failed: u64,
    #[serde(default)]
    pub failed_objects: Vec<KmsRotationFailedObject>,
    pub failure_reason: Option<String>,
    pub retry_recommended: bool,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStatus {
    pub id: String,
    pub kind: String,
    pub status: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub bucket: Option<String>,
    #[serde(default)]
    pub object_key: Option<String>,
    #[serde(default)]
    pub site_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: String,
    #[serde(default)]
    pub attempt: u32,
    #[serde(default)]
    pub lease_owner: Option<String>,
    #[serde(default)]
    pub lease_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub checkpoint: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub payload: Value,
    pub progress: f32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub version_id: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub affected_disks: Vec<String>,
    #[serde(default)]
    pub missing_shards: usize,
    #[serde(default)]
    pub corrupted_shards: usize,
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub attempts: usize,
    #[serde(default)]
    pub max_attempts: usize,
    #[serde(default)]
    pub next_attempt_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub dedupe_key: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncJobStatus {
    pub job_id: String,
    pub kind: String,
    pub status: String,
    pub priority: u8,
    pub bucket: Option<String>,
    pub object_key: Option<String>,
    pub site_id: Option<String>,
    pub idempotency_key: String,
    pub attempt: u32,
    pub lease_owner: Option<String>,
    pub lease_until: Option<DateTime<Utc>>,
    pub checkpoint: Option<u64>,
    pub last_error: Option<String>,
    pub progress: f32,
    pub retryable: bool,
    pub terminal: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncJobSummary {
    pub generated_at: DateTime<Utc>,
    pub total: usize,
    pub pending: usize,
    pub in_progress: usize,
    pub completed: usize,
    pub failed: usize,
    pub dead_letter: usize,
    pub retryable: usize,
    pub kinds: Vec<AsyncJobKindSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncJobKindSummary {
    pub kind: String,
    pub total: usize,
    pub pending: usize,
    pub in_progress: usize,
    pub completed: usize,
    pub failed: usize,
    pub dead_letter: usize,
    pub retryable: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncJobPage {
    pub items: Vec<AsyncJobStatus>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncJobBulkOperationResult {
    pub matched: usize,
    pub updated: usize,
    pub removed: usize,
    pub skipped: usize,
    pub remaining: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BatchRunScope {
    #[serde(default)]
    pub source_bucket: Option<String>,
    #[serde(default)]
    pub target_site: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub object_prefix: Option<String>,
    #[serde(default)]
    pub object_key: Option<String>,
    #[serde(default)]
    pub version_id: Option<String>,
    #[serde(default)]
    pub kms_key_id: Option<String>,
    #[serde(default)]
    pub statuses: Vec<String>,
    #[serde(default)]
    pub retry_only_failed: bool,
    #[serde(default)]
    pub current_only: bool,
    #[serde(default)]
    pub noncurrent_only: bool,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRunRequest {
    pub kind: String,
    #[serde(default)]
    pub source_bucket: Option<String>,
    #[serde(default)]
    pub target_site: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub object_prefix: Option<String>,
    #[serde(default)]
    pub object_key: Option<String>,
    #[serde(default)]
    pub version_id: Option<String>,
    #[serde(default)]
    pub kms_key_id: Option<String>,
    #[serde(default)]
    pub statuses: Vec<String>,
    #[serde(default)]
    pub retry_only_failed: bool,
    #[serde(default)]
    pub current_only: bool,
    #[serde(default)]
    pub noncurrent_only: bool,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRunStatus {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub scope: BatchRunScope,
    pub matched: usize,
    pub enqueued: usize,
    pub skipped: usize,
    #[serde(default)]
    pub failed: usize,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub failed_objects_preview: Vec<KmsRotationFailedObject>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerActionRequest {
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub topic: String,
    pub source: String,
    pub timestamp: DateTime<Utc>,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3ObjectMeta {
    pub bucket: String,
    pub key: String,
    pub version_id: String,
    pub size: u64,
    pub etag: String,
    pub created_at: DateTime<Utc>,
    #[serde(default = "default_object_storage_class")]
    pub storage_class: String,
    pub retention_mode: Option<String>,
    pub retention_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub legal_hold: bool,
    #[serde(default)]
    pub delete_marker: bool,
    #[serde(default)]
    pub remote_tier: Option<ObjectRemoteTierStatus>,
    #[serde(default)]
    pub restore: Option<ObjectRestoreStatus>,
    #[serde(default)]
    pub tags: Vec<BucketTag>,
    #[serde(default)]
    pub user_metadata: HashMap<String, String>,
    #[serde(default)]
    pub encryption: S3ObjectEncryptionMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct S3ObjectEncryptionMeta {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub algorithm: String,
    #[serde(default)]
    pub customer_key_md5: Option<String>,
    #[serde(default)]
    pub kms_key_id: Option<String>,
    #[serde(default)]
    pub nonce_base64: Option<String>,
    #[serde(default)]
    pub wrapped_key_base64: Option<String>,
}

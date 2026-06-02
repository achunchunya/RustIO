mod alerts;
mod audit;
mod buckets;
mod cluster;
mod console;
mod erasure;
mod health;
mod iam;
mod internal;
mod jobs;
mod kms;
mod kms_rotate;
mod ldap;
mod oidc;
mod replication;
mod s3_bucket_ops;
mod s3_chunked;
mod s3_helpers;
mod s3_meta;
mod s3_object_ops;
mod s3_object_rw;
mod s3_paths;
mod s3_sign;
mod s3_versions;
mod session;
mod storage;
mod sts;

pub(crate) use alerts::*;
pub(crate) use audit::*;
pub(crate) use buckets::*;
pub(crate) use cluster::*;
pub(crate) use console::*;
pub(crate) use erasure::*;
pub(crate) use health::*;
pub(crate) use iam::*;
pub(crate) use internal::*;
pub(crate) use jobs::*;
pub(crate) use kms::*;
pub(crate) use kms_rotate::*;
pub(crate) use ldap::*;
pub(crate) use oidc::*;
pub(crate) use replication::*;
pub(crate) use s3_bucket_ops::*;
pub(crate) use s3_helpers::*;
pub(crate) use s3_meta::*;
pub(crate) use s3_object_ops::*;
pub(crate) use s3_object_rw::*;
pub(crate) use s3_paths::*;
pub(crate) use s3_sign::*;
pub(crate) use s3_versions::*;
pub(crate) use session::*;
pub(crate) use storage::*;
pub(crate) use sts::*;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Component, Path as FsPath, PathBuf},
    sync::Arc,
    time::Instant,
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use axum::{
    body::{to_bytes, Bytes},
    extract::{DefaultBodyLimit, OriginalUri, Path, Query, Request, State},
    http::{
        header::{CONTENT_DISPOSITION, CONTENT_TYPE, HOST},
        HeaderMap, HeaderValue, Method, StatusCode, Uri,
    },
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Redirect, Response,
    },
    routing::{get, patch, post, put},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use crc32fast::Hasher as Crc32Hasher;
use csv::{ReaderBuilder, StringRecord, WriterBuilder};
use hmac::{Hmac, Mac};
use jsonwebtoken::{
    decode as jwt_decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation,
};
use ldap3::{LdapConn, Scope, SearchEntry};
use md5::Md5;
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use quick_xml::de::from_str as from_xml_str;
use reed_solomon_erasure::galois_8::ReedSolomon;
use reqwest::Client;
use rustio_core::{
    AlertChannel, AlertEscalationPolicy, AlertHistoryEntry, AlertRule, AlertSilence, ApiEnvelope,
    AsyncJobBulkOperationResult, AsyncJobKindSummary, AsyncJobPage, AsyncJobStatus,
    AsyncJobSummary, AuthProviderInfo, BatchRunRequest, BatchRunScope, BatchRunStatus,
    BucketAclConfig, BucketCorsRule, BucketEncryptionConfig, BucketGovernanceUpdate,
    BucketLegalHoldConfig, BucketLifecycleRule, BucketNotificationRule, BucketObjectLockConfig,
    BucketPublicAccessBlockConfig, BucketRetentionConfig, BucketSpec, BucketTag,
    ClusterConfigApplyRequest, ClusterConfigRollbackRequest, ClusterConfigSnapshot,
    ClusterConfigValidateRequest, ClusterConfigValidateResult, ClusterHealth, ConsoleSession,
    DangerActionRequest, IamGroup, IamPolicy, IamUser, JobStatus, KmsRotationFailedObject,
    KmsRotationResult, LoginRequest, ObjectRemoteTierStatus, ObjectRestoreStatus, Permission,
    RefreshTokenRequest, RemoteTierConfig, ReplicationBacklogItem, ReplicationStatus,
    S3ObjectEncryptionMeta, S3ObjectMeta, SecurityUpdate, SiteReplicationStatus,
    SystemAlertMetricsSummary, SystemAuditMetricsSummary, SystemIamMetricsSummary,
    SystemJobKindMetricsSummary, SystemJobMetricsSummary, SystemKmsMetricsSummary,
    SystemMetricsSummary, SystemNodeMetricsSummary, SystemRaftMetricsSummary,
    SystemReplicationMetricsSummary, SystemReplicationSiteMetricsSummary,
    SystemSecurityMetricsSummary, SystemSessionMetricsSummary, SystemStorageDiskMetricsSummary,
    SystemStorageGovernanceMetricsSummary, SystemStorageMetricsSummary, TenantSpec,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::{
    auth::{
        create_console_session, issue_tokens, refresh_console_session, validate_access_token,
        validate_refresh_token, AuthContext,
    },
    error::AppError,
    state::{
        AlertDeliveryItem, AppState, ArchitectureAlignmentReport, ArchitectureTopology,
        CompletedOidcLogin, InternalReplicationApplyRequest, LocalCredential,
        MetadataRaftHeartbeatRequest, MetadataRaftPreVoteRequest, MetadataRaftReadIndexRequest,
        MetadataRaftReadIndexResponse, MetadataRaftStatus, MetadataRaftSyncRequest,
        MetadataRaftVoteRequest, MultipartPart, MultipartUpload, PendingOidcAuthorization,
    },
};

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(root_entry).post(root_post))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/health/cluster", get(health_cluster))
        .route("/metrics", get(prometheus_metrics))
        // Backward-compatible health endpoints.
        .route("/minio/health/live", get(health_live))
        .route("/minio/health/ready", get(health_ready))
        .route("/minio/health/cluster", get(health_cluster))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/providers", get(list_auth_providers))
        .route("/api/v1/auth/oidc/authorize", get(begin_oidc_browser_login))
        .route(
            "/api/v1/auth/oidc/callback",
            get(complete_oidc_browser_login),
        )
        .route(
            "/api/v1/auth/oidc/session/{request_id}",
            get(redeem_oidc_browser_login),
        )
        .route("/api/v1/auth/session/current", get(current_console_session))
        .route("/api/v1/auth/sessions", get(list_console_sessions))
        .route(
            "/api/v1/auth/sessions/{session_id}",
            axum::routing::delete(delete_console_session),
        )
        .route("/api/v1/auth/refresh", post(refresh_token))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/system/info", get(index))
        .route("/api/v1/system/topology", get(system_topology))
        .route("/api/v1/system/alignment", get(system_alignment))
        .route(
            "/api/v1/system/metrics/summary",
            get(system_metrics_summary),
        )
        .route("/api/v1/system/storage/disks", get(system_storage_disks))
        .route("/api/v1/system/raft/status", get(system_raft_status))
        .route(
            "/api/v1/system/raft/read-index",
            get(system_raft_read_index),
        )
        .route("/api/v1/system/raft/peers", post(system_raft_peer_add))
        .route("/api/v1/system/raft/elect/{id}", post(system_raft_elect))
        .route(
            "/api/v1/system/raft/peers/{id}/offline",
            post(system_raft_peer_offline),
        )
        .route(
            "/api/v1/system/raft/peers/{id}/online",
            post(system_raft_peer_online),
        )
        .route(
            "/api/v1/system/raft/peers/{id}/remove",
            post(system_raft_peer_remove),
        )
        .route(
            "/api/v1/system/raft/peers/membership/abort",
            post(system_raft_membership_abort),
        )
        .route(
            "/api/v1/system/raft/peers/membership/finalize",
            post(system_raft_membership_finalize),
        )
        .route("/api/v1/cluster/health", get(cluster_health))
        .route("/api/v1/cluster/nodes", get(list_nodes))
        .route("/api/v1/cluster/nodes/{id}/offline", post(set_node_offline))
        .route("/api/v1/cluster/nodes/{id}/online", post(set_node_online))
        .route("/api/v1/cluster/quotas", get(list_quotas))
        .route(
            "/api/v1/cluster/tenants",
            get(list_tenants).post(create_tenant),
        )
        .route("/api/v1/cluster/tenants/{id}", put(update_tenant))
        .route("/api/v1/cluster/tenants/{id}/suspend", post(suspend_tenant))
        .route("/api/v1/cluster/tenants/{id}/resume", post(resume_tenant))
        .route("/api/v1/cluster/tenants/{id}/delete", post(delete_tenant))
        .route(
            "/api/v1/identity/projects",
            get(list_tenants).post(create_tenant),
        )
        .route("/api/v1/identity/projects/{id}", put(update_tenant))
        .route(
            "/api/v1/identity/projects/{id}/suspend",
            post(suspend_tenant),
        )
        .route("/api/v1/identity/projects/{id}/resume", post(resume_tenant))
        .route("/api/v1/identity/projects/{id}/delete", post(delete_tenant))
        .route("/api/v1/identity/domains", get(list_identity_domains))
        .route(
            "/api/v1/cluster/diagnostics",
            get(list_diagnostics).post(create_diagnostic),
        )
        .route("/api/v1/cluster/diagnostics/{id}", get(get_diagnostic))
        .route(
            "/api/v1/cluster/diagnostics/{id}/download",
            get(download_diagnostic),
        )
        .route(
            "/api/v1/cluster/config/current",
            get(get_cluster_config_current),
        )
        .route(
            "/api/v1/cluster/config/history",
            get(list_cluster_config_history),
        )
        .route(
            "/api/v1/cluster/config/validate",
            post(validate_cluster_config),
        )
        .route("/api/v1/cluster/config/apply", post(apply_cluster_config))
        .route(
            "/api/v1/cluster/config/rollback",
            post(rollback_cluster_config),
        )
        .route("/api/v1/cluster/config/export", get(export_cluster_config))
        .route("/api/v1/cluster/backup/export", get(export_cluster_backup))
        .route(
            "/api/v1/cluster/backup/restore",
            post(restore_cluster_backup),
        )
        .route("/api/v1/iam/users", get(list_users).post(create_user))
        .route(
            "/api/v1/iam/users/{username}",
            axum::routing::delete(delete_user),
        )
        .route("/api/v1/iam/users/{username}/enable", post(enable_user))
        .route("/api/v1/iam/users/{username}/disable", post(disable_user))
        .route("/api/v1/iam/groups", get(list_groups).post(create_group))
        .route("/api/v1/iam/groups/{name}/members", post(add_group_member))
        .route(
            "/api/v1/iam/groups/{name}/members/{username}",
            axum::routing::delete(remove_group_member),
        )
        .route(
            "/api/v1/iam/policies",
            get(list_policies).post(create_policy),
        )
        .route(
            "/api/v1/iam/policies/{name}/attach",
            post(attach_policy_principal),
        )
        .route(
            "/api/v1/iam/policies/{name}/detach",
            post(detach_policy_principal),
        )
        .route(
            "/api/v1/iam/service-accounts",
            get(list_service_accounts).post(create_service_account),
        )
        .route(
            "/api/v1/iam/service-accounts/{access_key}",
            axum::routing::delete(delete_service_account),
        )
        .route(
            "/api/v1/iam/sts/sessions",
            get(list_sts_sessions).post(create_sts_session),
        )
        .route(
            "/api/v1/iam/sts/sessions/{session_id}",
            axum::routing::delete(delete_sts_session),
        )
        .route(
            "/api/v1/buckets",
            get(list_buckets).post(create_bucket_spec),
        )
        .route(
            "/api/v1/buckets/{name}",
            axum::routing::delete(delete_bucket_spec),
        )
        .route(
            "/api/v1/buckets/{name}/governance",
            patch(update_bucket_governance),
        )
        .route(
            "/api/v1/buckets/{name}/object-lock",
            get(get_bucket_object_lock).put(update_bucket_object_lock),
        )
        .route(
            "/api/v1/buckets/{name}/retention",
            get(get_bucket_retention).put(update_bucket_retention),
        )
        .route(
            "/api/v1/buckets/{name}/legal-hold",
            get(get_bucket_legal_hold).put(update_bucket_legal_hold),
        )
        .route(
            "/api/v1/buckets/{name}/notifications",
            get(list_bucket_notifications).put(update_bucket_notifications),
        )
        .route(
            "/api/v1/buckets/{name}/acl",
            get(get_bucket_acl).put(update_bucket_acl),
        )
        .route(
            "/api/v1/buckets/{name}/public-access-block",
            get(get_bucket_public_access_block)
                .put(update_bucket_public_access_block)
                .delete(delete_bucket_public_access_block),
        )
        .route(
            "/api/v1/buckets/{name}/lifecycle",
            get(list_bucket_lifecycle_rules)
                .put(update_bucket_lifecycle_rules)
                .delete(delete_bucket_lifecycle_rules),
        )
        .route(
            "/api/v1/buckets/{name}/policy",
            get(get_bucket_policy)
                .put(update_bucket_policy)
                .delete(delete_bucket_policy),
        )
        .route(
            "/api/v1/buckets/{name}/cors",
            get(list_bucket_cors)
                .put(update_bucket_cors)
                .delete(delete_bucket_cors),
        )
        .route(
            "/api/v1/buckets/{name}/tags",
            get(list_bucket_tags)
                .put(update_bucket_tags)
                .delete(delete_bucket_tags),
        )
        .route(
            "/api/v1/buckets/{name}/encryption",
            get(get_bucket_encryption)
                .put(update_bucket_encryption)
                .delete(delete_bucket_encryption),
        )
        .route("/api/v1/buckets/{name}/objects", get(list_bucket_objects))
        .route(
            "/api/v1/buckets/{name}/objects/versions",
            get(list_bucket_object_versions),
        )
        .route(
            "/api/v1/buckets/{name}/objects/{*key}",
            get(get_bucket_object)
                .put(put_bucket_object)
                .delete(delete_bucket_object),
        )
        .route(
            "/api/v1/buckets/{name}/replication",
            post(update_bucket_replication),
        )
        .route(
            "/api/v1/buckets/{name}/replication/{rule_id}",
            axum::routing::delete(delete_bucket_replication),
        )
        .route(
            "/api/v1/storage/tiers",
            get(list_remote_tiers).put(update_remote_tiers),
        )
        .route(
            "/api/v1/storage/tiers/{name}",
            axum::routing::delete(delete_remote_tier),
        )
        .route(
            "/api/v1/storage/tiers/{name}/health-check",
            post(check_remote_tier_health),
        )
        .route(
            "/api/v1/storage/tiers/{name}/rotate-secret",
            post(rotate_remote_tier_secret),
        )
        .route("/api/v1/storage/inventory", get(list_storage_inventory))
        .route(
            "/api/v1/storage/inventory/export",
            get(export_storage_inventory),
        )
        .route(
            "/api/v1/storage/archive/report",
            get(get_storage_archive_report),
        )
        .route(
            "/api/v1/storage/archive/report/export",
            get(export_storage_archive_report),
        )
        .route(
            "/api/v1/storage/archive/prewarm",
            post(prewarm_storage_archive),
        )
        .route(
            "/api/v1/storage/governance",
            get(get_storage_governance_status),
        )
        .route(
            "/api/v1/storage/governance/rebalance",
            post(start_storage_rebalance),
        )
        .route(
            "/api/v1/storage/governance/decommission",
            post(start_storage_decommission),
        )
        .route(
            "/api/v1/buckets/replication/status",
            get(replication_status),
        )
        .route(
            "/api/v1/replication/sites/bootstrap",
            post(bootstrap_site_replication),
        )
        .route("/api/v1/replication/sites", get(list_site_replications))
        .route(
            "/api/v1/replication/sites/{site_id}/join",
            post(join_site_replication),
        )
        .route(
            "/api/v1/replication/sites/{site_id}/failover",
            post(failover_site_replication),
        )
        .route(
            "/api/v1/replication/sites/{site_id}/failback",
            post(failback_site_replication),
        )
        .route(
            "/api/v1/replication/sites/{site_id}/resync",
            post(resync_site_replication),
        )
        .route(
            "/api/v1/replication/sites/{site_id}/reconcile",
            post(reconcile_site_replication),
        )
        .route(
            "/api/v1/replication/sites/{site_id}/reconcile-preview",
            get(preview_site_replication_reconcile),
        )
        .route(
            "/api/v1/replication/sites/{site_id}/drift",
            get(get_site_replication_drift),
        )
        .route(
            "/api/v1/security/config",
            get(get_security).patch(update_security),
        )
        .route("/api/v1/security/kms/status", get(get_kms_status))
        .route("/api/v1/security/kms/rotate", post(rotate_kms_keys))
        .route(
            "/api/v1/security/kms/rotate/retry",
            post(retry_kms_rotation),
        )
        .route(
            "/api/v1/alerts/rules",
            get(list_alert_rules).post(create_alert_rule),
        )
        .route(
            "/api/v1/alerts/rules/{id}",
            put(update_alert_rule).delete(delete_alert_rule),
        )
        .route(
            "/api/v1/alerts/channels",
            get(list_alert_channels).post(create_alert_channel),
        )
        .route(
            "/api/v1/alerts/channels/{id}",
            put(update_alert_channel).delete(delete_alert_channel),
        )
        .route(
            "/api/v1/alerts/channels/{id}/test",
            post(test_alert_channel),
        )
        .route(
            "/api/v1/alerts/rules/{id}/simulate",
            post(simulate_alert_rule_trigger),
        )
        .route(
            "/api/v1/alerts/silences",
            get(list_alert_silences).post(create_alert_silence),
        )
        .route(
            "/api/v1/alerts/silences/{id}",
            axum::routing::delete(delete_alert_silence),
        )
        .route(
            "/api/v1/alerts/escalations",
            get(list_alert_escalations).post(create_alert_escalation),
        )
        .route(
            "/api/v1/alerts/escalations/{id}",
            put(update_alert_escalation).delete(delete_alert_escalation),
        )
        .route(
            "/api/v1/alerts/history/{id}/claim",
            post(claim_alert_history_entry),
        )
        .route(
            "/api/v1/alerts/history/{id}/ack",
            post(ack_alert_history_entry),
        )
        .route(
            "/api/v1/alerts/history/{id}/resolve",
            post(resolve_alert_history_entry),
        )
        .route("/api/v1/alerts/history", get(list_alert_history))
        .route("/api/v1/audit/events", get(list_audit_events))
        .route("/api/v1/audit/export", get(export_audit_events))
        .route("/api/v1/jobs", get(list_jobs))
        .route("/api/v1/jobs/async", get(list_async_jobs))
        .route("/api/v1/jobs/async/page", get(async_jobs_page))
        .route("/api/v1/jobs/async/summary", get(async_jobs_summary))
        .route("/api/v1/jobs/async/export", get(export_async_jobs))
        .route("/api/v1/jobs/async/bulk/retry", post(retry_async_jobs))
        .route("/api/v1/jobs/async/bulk/cleanup", post(cleanup_async_jobs))
        .route("/api/v1/jobs/async/bulk/skip", post(skip_async_jobs))
        .route(
            "/api/v1/jobs/batch",
            get(list_batch_runs).post(create_batch_run),
        )
        .route("/api/v1/jobs/batch/{id}", get(get_batch_run))
        .route("/api/v1/jobs/heal", post(start_heal_job))
        .route("/api/v1/jobs/{id}/retry", post(retry_job))
        .route(
            "/api/v1/jobs/replication-backlog",
            get(list_replication_backlog),
        )
        .route(
            "/api/v1/jobs/replication-backlog/page",
            get(replication_backlog_page),
        )
        .route(
            "/api/v1/jobs/replication-backlog/metrics",
            get(replication_backlog_metrics),
        )
        .route(
            "/api/v1/jobs/replication-backlog/retry",
            post(retry_matched_replication_backlog),
        )
        .route(
            "/api/v1/jobs/replication-backlog/cleanup",
            post(cleanup_replication_backlog),
        )
        .route(
            "/api/v1/jobs/replication-backlog/retry-all",
            post(retry_all_replication_backlog),
        )
        .route(
            "/api/v1/jobs/replication-backlog/{id}/retry",
            post(retry_replication_backlog_item),
        )
        .route("/api/v1/jobs/{id}/cancel", post(cancel_job))
        .route("/api/v1/events/stream", get(events_stream))
        .route(
            "/api/v1/internal/metadata-raft/sync",
            post(internal_metadata_raft_sync),
        )
        .route(
            "/api/v1/internal/metadata-raft/request-vote",
            post(internal_metadata_raft_request_vote),
        )
        .route(
            "/api/v1/internal/metadata-raft/pre-vote",
            post(internal_metadata_raft_pre_vote),
        )
        .route(
            "/api/v1/internal/metadata-raft/heartbeat",
            post(internal_metadata_raft_heartbeat),
        )
        .route(
            "/api/v1/internal/metadata-raft/read-index",
            post(internal_metadata_raft_read_index),
        )
        .route(
            "/api/v1/internal/metadata-raft/export",
            get(internal_metadata_raft_export),
        )
        .route(
            "/api/v1/internal/replication/apply",
            post(internal_replication_apply),
        )
        .route(
            "/api/v1/internal/auth/sessions/sync",
            post(internal_console_session_sync),
        )
        .route(
            "/api/v1/internal/auth/sessions/sync/{session_id}",
            axum::routing::delete(internal_console_session_delete),
        )
        .route(
            "/{bucket}",
            put(s3_root_create_bucket)
                .get(s3_root_bucket_get)
                .head(s3_root_head_bucket)
                .post(s3_root_bucket_post)
                .delete(s3_root_delete_bucket),
        )
        .route(
            "/{bucket}/",
            put(s3_root_create_bucket)
                .get(s3_root_bucket_get)
                .head(s3_root_head_bucket)
                .post(s3_root_bucket_post)
                .delete(s3_root_delete_bucket),
        )
        .route(
            "/{bucket}/{*key}",
            put(s3_root_put_object)
                .get(s3_root_get_object)
                .head(s3_root_head_object)
                .post(s3_root_post_object)
                .delete(s3_root_delete_object),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            track_request_activity,
        ))
        .layer(DefaultBodyLimit::max(s3_request_body_limit_bytes()))
        .with_state(state)
}

/// S3 请求体大小上限（字节）。默认 5 GiB，可经 `RUSTIO_S3_MAX_BODY_BYTES` 覆盖。
///
/// axum 默认上限仅 2 MiB，会导致任何稍大的对象上传被 413 拒绝。对象存储必须放开此限制；
/// 同时保留一个可配置的护栏，避免单次 PUT（当前仍全量缓冲）被超大请求打爆内存。
fn s3_request_body_limit_bytes() -> usize {
    std::env::var("RUSTIO_S3_MAX_BODY_BYTES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(5 * 1024 * 1024 * 1024)
}

async fn track_request_activity(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    state.record_request_activity();
    next.run(request).await
}

async fn index(State(state): State<Arc<AppState>>) -> Json<ApiEnvelope<serde_json::Value>> {
    wrap(json!({
        "name": "RustIO",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "m0-architecture-aligned",
        "architecture_version": state.architecture.version,
        "plane_count": state.architecture.planes.len()
    }))
}

async fn system_topology(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<ArchitectureTopology>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    Ok(wrap(state.architecture.clone()))
}

async fn system_alignment(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<ArchitectureAlignmentReport>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    Ok(wrap(state.architecture_alignment_report().await))
}

async fn system_metrics_summary(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<SystemMetricsSummary>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    Ok(wrap(build_system_metrics_summary(&state).await))
}

async fn system_storage_disks(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<SystemStorageDiskMetricsSummary>>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    let nodes = state.nodes.read().await.clone();
    let capacity_total_bytes = nodes
        .iter()
        .map(|node| node.capacity_total_bytes)
        .fold(0u64, u64::saturating_add);
    let capacity_used_bytes = nodes
        .iter()
        .map(|node| node.capacity_used_bytes)
        .fold(0u64, u64::saturating_add);
    Ok(wrap(
        build_system_storage_metrics(&state, capacity_total_bytes, capacity_used_bytes)
            .await
            .disks,
    ))
}

#[derive(Debug, Serialize)]
struct StorageGovernanceStatusResponse {
    summary: SystemStorageGovernanceMetricsSummary,
    scan_running: bool,
    worker_concurrency: usize,
    draining_disks: Vec<String>,
    decommissioned_disks: Vec<String>,
    disks: Vec<SystemStorageDiskMetricsSummary>,
}

#[derive(Debug, Deserialize, Default)]
struct StorageMaintenanceRequest {
    #[serde(default)]
    disk_ids: Vec<String>,
    reason: String,
}

async fn get_storage_governance_status(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<StorageGovernanceStatusResponse>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    let mut summary = build_system_metrics_summary(&state).await;
    let runtime = state.storage_governance.read().await.clone();
    for disk in &mut summary.storage.disks {
        disk.placement_state = storage_disk_placement_state(
            &disk.disk_id,
            &runtime.draining_disks,
            &runtime.decommissioned_disks,
        );
    }
    let governance_summary = summary.storage.governance.clone();
    let disks = summary.storage.disks.clone();
    let mut draining_disks = runtime.draining_disks.into_iter().collect::<Vec<_>>();
    draining_disks.sort();
    let mut decommissioned_disks = runtime.decommissioned_disks.into_iter().collect::<Vec<_>>();
    decommissioned_disks.sort();
    Ok(wrap(StorageGovernanceStatusResponse {
        summary: governance_summary,
        scan_running: runtime.scan_running,
        worker_concurrency: storage_job_concurrency_limit(),
        draining_disks,
        decommissioned_disks,
        disks,
    }))
}

async fn start_storage_rebalance(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<StorageMaintenanceRequest>,
) -> Result<Json<ApiEnvelope<JobStatus>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    let reason = body.reason.clone();
    let disk_ids = normalize_storage_disk_ids(&body.disk_ids, state.data_disks.len())?;
    let target = if disk_ids.is_empty() {
        "cluster".to_string()
    } else {
        disk_ids.join(",")
    };
    let job = upsert_storage_job(
        state.as_ref(),
        StorageJobDraft {
            kind: "rebalance:plan".to_string(),
            target: target.clone(),
            bucket: None,
            key: None,
            version_id: None,
            priority: Some(2200),
            affected_disks: disk_ids.clone(),
            missing_shards: 0,
            corrupted_shards: 0,
            source: "manual".to_string(),
            details: json!({
                "disk_ids": disk_ids,
                "reason": reason,
            }),
        },
        "pending",
    )
    .await;
    state
        .append_audit(
            &auth.username,
            "storage.governance.rebalance.start",
            "storage/governance/rebalance",
            "success",
            Some(body.reason),
            json!({
                "job_id": job.id,
                "disk_ids": job.affected_disks,
            }),
        )
        .await;
    state
        .push_event(
            "storage.governance.rebalance.started",
            "storage-governance",
            json!({
                "job_id": job.id,
                "disk_ids": job.affected_disks,
            }),
        )
        .await;
    Ok(wrap(job))
}

async fn start_storage_decommission(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<StorageMaintenanceRequest>,
) -> Result<Json<ApiEnvelope<JobStatus>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    let reason = body.reason.clone();
    let disk_ids = normalize_storage_disk_ids(&body.disk_ids, state.data_disks.len())?;
    if disk_ids.is_empty() {
        return Err(AppError::bad_request(
            "至少提供一个磁盘 ID / at least one disk id is required",
        ));
    }
    let job = upsert_storage_job(
        state.as_ref(),
        StorageJobDraft {
            kind: "decommission:plan".to_string(),
            target: disk_ids.join(","),
            bucket: None,
            key: None,
            version_id: None,
            priority: Some(2300),
            affected_disks: disk_ids.clone(),
            missing_shards: 0,
            corrupted_shards: 0,
            source: "manual".to_string(),
            details: json!({
                "disk_ids": disk_ids,
                "reason": reason,
            }),
        },
        "pending",
    )
    .await;
    state
        .append_audit(
            &auth.username,
            "storage.governance.decommission.start",
            "storage/governance/decommission",
            "success",
            Some(body.reason),
            json!({
                "job_id": job.id,
                "disk_ids": job.affected_disks,
            }),
        )
        .await;
    state
        .push_event(
            "storage.governance.decommission.started",
            "storage-governance",
            json!({
                "job_id": job.id,
                "disk_ids": job.affected_disks,
            }),
        )
        .await;
    Ok(wrap(job))
}

async fn system_raft_status(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<MetadataRaftStatus>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    ensure_metadata_read_barrier_api(&state).await?;
    Ok(wrap(state.metadata_raft_status().await))
}

async fn system_raft_read_index(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<MetadataRaftReadIndexResponse>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    let payload = state.metadata_read_index().await.map_err(|err| {
        AppError::new(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable", err)
    })?;
    Ok(wrap(payload))
}

async fn prometheus_metrics(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let summary = build_system_metrics_summary(&state).await;
    Ok((
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        render_prometheus_metrics(&summary),
    )
        .into_response())
}

fn cluster_status_from_counts(total: usize, online: usize) -> String {
    if total > 0 && online == total {
        "healthy".to_string()
    } else if online == 0 {
        "critical".to_string()
    } else {
        "degraded".to_string()
    }
}

fn count_firing_alerts(alert_history: &[AlertHistoryEntry]) -> usize {
    alert_history
        .iter()
        .filter(|entry| entry.status == "firing" && entry.resolved_at.is_none())
        .count()
}

fn prometheus_bool(value: bool) -> u8 {
    u8::from(value)
}

fn prometheus_escape_label_value(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('\n', r"\n")
        .replace('"', r#"\""#)
}

fn append_prometheus_header(rendered: &mut String, name: &str, kind: &str, help: &str) {
    rendered.push_str("# HELP ");
    rendered.push_str(name);
    rendered.push(' ');
    rendered.push_str(help);
    rendered.push('\n');
    rendered.push_str("# TYPE ");
    rendered.push_str(name);
    rendered.push(' ');
    rendered.push_str(kind);
    rendered.push('\n');
}

fn append_prometheus_sample(
    rendered: &mut String,
    name: &str,
    labels: &[(&str, String)],
    value: String,
) {
    rendered.push_str(name);
    if !labels.is_empty() {
        rendered.push('{');
        for (index, (label_key, label_value)) in labels.iter().enumerate() {
            if index > 0 {
                rendered.push(',');
            }
            rendered.push_str(label_key);
            rendered.push_str("=\"");
            rendered.push_str(&prometheus_escape_label_value(label_value));
            rendered.push('"');
        }
        rendered.push('}');
    }
    rendered.push(' ');
    rendered.push_str(&value);
    rendered.push('\n');
}

fn storage_job_kind_label(kind: &str) -> &str {
    kind.split(':').next().unwrap_or(kind)
}

fn storage_job_is_terminal(status: &str) -> bool {
    matches!(status, "completed" | "done" | "failed" | "cancelled")
}

fn storage_job_is_storage_work(kind: &str) -> bool {
    matches!(
        kind,
        "scan" | "scrub" | "heal" | "rebuild" | "rebalance" | "decommission"
    )
}

fn storage_disk_status(online: bool, missing: usize, corrupted: usize) -> String {
    if !online {
        return "offline".to_string();
    }
    if missing > 0 || corrupted > 0 {
        return "degraded".to_string();
    }
    "healthy".to_string()
}

fn storage_disk_id(index: usize) -> String {
    format!("disk-{index}")
}

fn storage_disk_placement_state(
    disk_id: &str,
    draining_disks: &HashSet<String>,
    decommissioned_disks: &HashSet<String>,
) -> String {
    if decommissioned_disks.contains(disk_id) {
        return "decommissioned".to_string();
    }
    if draining_disks.contains(disk_id) {
        return "draining".to_string();
    }
    "active".to_string()
}

#[derive(Debug, Clone, Default)]
struct StorageDiskAggregate {
    manifests_total: usize,
    shard_files: usize,
    shard_bytes: u64,
    shard_healthy: usize,
    shard_missing: usize,
    shard_corrupted: usize,
}

fn derived_ec_shard_path(
    state: &AppState,
    bucket: &str,
    key: &str,
    shard_index: usize,
) -> Option<(usize, PathBuf)> {
    if state.data_disks.is_empty() {
        return None;
    }
    let disk_index = shard_index % state.data_disks.len();
    let object_hash = sha256_hex(key.as_bytes());
    Some((
        disk_index,
        state.data_disks[disk_index]
            .join(bucket)
            .join(".rustio_ec")
            .join(object_hash)
            .join(format!("{shard_index}.bin")),
    ))
}

async fn summarize_ec_shard_file(
    path: &FsPath,
    expected_size: usize,
) -> std::io::Result<(u64, bool)> {
    let metadata = tokio::fs::metadata(path).await?;
    let size = metadata.len();
    Ok((size, size == expected_size as u64))
}

async fn build_system_storage_metrics(
    state: &Arc<AppState>,
    capacity_total_bytes: u64,
    capacity_used_bytes: u64,
) -> SystemStorageMetricsSummary {
    let capacity_free_bytes = capacity_total_bytes.saturating_sub(capacity_used_bytes);
    let utilization_ratio = if capacity_total_bytes == 0 {
        0.0
    } else {
        capacity_used_bytes as f64 / capacity_total_bytes as f64
    };

    let (ec_data_shards, ec_parity_shards) = ec_layout();
    if state.data_disks.is_empty() {
        return SystemStorageMetricsSummary {
            capacity_total_bytes,
            capacity_used_bytes,
            capacity_free_bytes,
            utilization_ratio,
            disks_total: 0,
            disks_online: 0,
            disks_degraded: 0,
            ec_data_shards,
            ec_parity_shards,
            shard_files_total: 0,
            shard_bytes_total: 0,
            shard_healthy_total: 0,
            shard_missing_total: 0,
            shard_corrupted_total: 0,
            governance: SystemStorageGovernanceMetricsSummary::default(),
            disks: vec![],
        };
    }

    let bucket_names = state
        .buckets
        .read()
        .await
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let mut aggregates = vec![StorageDiskAggregate::default(); state.data_disks.len()];
    for bucket in bucket_names {
        let Ok(bucket_root) = bucket_path(state, &bucket) else {
            continue;
        };
        let manifest_dir = bucket_root.join(".rustio_ec_meta");
        let mut entries = match tokio::fs::read_dir(&manifest_dir).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => continue,
        };
        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(_) => break,
            };
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let manifest_bytes = match tokio::fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let manifest = match serde_json::from_slice::<EcObjectManifest>(&manifest_bytes) {
                Ok(manifest) => manifest,
                Err(_) => continue,
            };
            let total_shards = manifest.data_shards + manifest.parity_shards;
            if total_shards == 0 {
                continue;
            }
            let mut manifest_disks = HashSet::new();
            let shard_map = manifest
                .shards
                .iter()
                .cloned()
                .map(|item| (item.shard_index, item))
                .collect::<HashMap<_, _>>();
            for shard_index in 0..total_shards {
                let shard = shard_map.get(&shard_index).cloned().or_else(|| {
                    derived_ec_shard_path(state, &bucket, &manifest.key, shard_index).map(
                        |(disk_index, shard_path)| EcShardInfo {
                            shard_index,
                            disk_index,
                            path: shard_path,
                            checksum: String::new(),
                        },
                    )
                });
                let Some(shard) = shard else {
                    continue;
                };
                if let Some(aggregate) = aggregates.get_mut(shard.disk_index) {
                    if manifest_disks.insert(shard.disk_index) {
                        aggregate.manifests_total += 1;
                    }
                    match summarize_ec_shard_file(&shard.path, manifest.shard_size).await {
                        Ok((size, healthy)) => {
                            aggregate.shard_files += 1;
                            aggregate.shard_bytes = aggregate.shard_bytes.saturating_add(size);
                            if healthy {
                                aggregate.shard_healthy += 1;
                            } else {
                                aggregate.shard_corrupted += 1;
                            }
                        }
                        Err(_) => aggregate.shard_missing += 1,
                    }
                }
            }
        }
    }

    let mut disks = Vec::with_capacity(state.data_disks.len());
    for (index, path) in state.data_disks.iter().enumerate() {
        let online = tokio::fs::try_exists(path).await.unwrap_or(false);
        let aggregate = aggregates.get(index).cloned().unwrap_or_default();
        disks.push(SystemStorageDiskMetricsSummary {
            disk_id: storage_disk_id(index),
            path: path.display().to_string(),
            online,
            status: storage_disk_status(online, aggregate.shard_missing, aggregate.shard_corrupted),
            placement_state: "active".to_string(),
            manifests_total: aggregate.manifests_total,
            shard_files: aggregate.shard_files,
            shard_bytes: aggregate.shard_bytes,
            shard_healthy: aggregate.shard_healthy,
            shard_missing: aggregate.shard_missing,
            shard_corrupted: aggregate.shard_corrupted,
            heal_pressure: 0,
            last_anomaly_at: None,
        });
    }

    SystemStorageMetricsSummary {
        capacity_total_bytes,
        capacity_used_bytes,
        capacity_free_bytes,
        utilization_ratio,
        disks_total: disks.len(),
        disks_online: disks.iter().filter(|disk| disk.online).count(),
        disks_degraded: disks
            .iter()
            .filter(|disk| disk.status == "degraded")
            .count(),
        ec_data_shards,
        ec_parity_shards,
        shard_files_total: disks.iter().map(|disk| disk.shard_files).sum(),
        shard_bytes_total: disks.iter().map(|disk| disk.shard_bytes).sum(),
        shard_healthy_total: disks.iter().map(|disk| disk.shard_healthy).sum(),
        shard_missing_total: disks.iter().map(|disk| disk.shard_missing).sum(),
        shard_corrupted_total: disks.iter().map(|disk| disk.shard_corrupted).sum(),
        governance: SystemStorageGovernanceMetricsSummary::default(),
        disks,
    }
}

fn latest_alert_delivery_error(queue: &[AlertDeliveryItem]) -> Option<String> {
    queue
        .iter()
        .filter(|item| !item.last_error.trim().is_empty())
        .max_by_key(|item| item.last_attempt_at.unwrap_or(item.queued_at))
        .map(|item| item.last_error.clone())
}

fn audit_category(action: &str) -> &'static str {
    if action.starts_with("auth.") {
        "auth"
    } else if action.starts_with("iam.") {
        "iam"
    } else if action.starts_with("security.kms.") {
        "kms"
    } else if action.starts_with("alerts.") {
        "alerts"
    } else if action.starts_with("replication.") || action.starts_with("bucket.replication.") {
        "replication"
    } else if action.starts_with("jobs.") {
        "jobs"
    } else {
        "other"
    }
}

fn build_system_kms_metrics(security: &rustio_core::SecurityConfig) -> SystemKmsMetricsSummary {
    let rotation_failed_objects_preview = security
        .kms_rotation_failed_objects
        .iter()
        .take(20)
        .cloned()
        .collect::<Vec<_>>();
    SystemKmsMetricsSummary {
        endpoint_configured: !security.kms_endpoint.trim().is_empty(),
        provider: kms_provider_label().to_string(),
        auth_mode: kms_auth_mode(),
        healthy: security.kms_healthy,
        last_error: security.kms_last_error.clone(),
        last_checked_at: security.kms_last_checked_at,
        last_success_at: security.kms_last_success_at,
        last_recovered_at: security.kms_last_recovered_at,
        rotation_status: security.kms_rotation_status.clone(),
        rotation_last_started_at: security.kms_rotation_last_started_at,
        rotation_last_completed_at: security.kms_rotation_last_completed_at,
        rotation_last_success_at: security.kms_rotation_last_success_at,
        rotation_last_failure_reason: security.kms_rotation_last_failure_reason.clone(),
        rotation_scanned: security.kms_rotation_scanned,
        rotation_rotated: security.kms_rotation_rotated,
        rotation_skipped: security.kms_rotation_skipped,
        rotation_failed: security.kms_rotation_failed,
        retry_recommended: !security.kms_rotation_failed_objects.is_empty(),
        rotation_failed_objects_preview,
    }
}

async fn update_security_runtime<F>(state: &AppState, mutate: F)
where
    F: FnOnce(&mut rustio_core::SecurityConfig),
{
    let snapshot = {
        let mut security = state.security.write().await;
        mutate(&mut security);
        security.clone()
    };
    let _ = AppState::persist_security_config_snapshot(&state.data_dir, &snapshot);
}

async fn mark_kms_health_failure(state: &AppState, message: impl Into<String>) {
    let now = Utc::now();
    let message = message.into();
    update_security_runtime(state, move |security| {
        security.kms_healthy = false;
        security.kms_last_checked_at = Some(now);
        security.kms_last_error = Some(message.clone());
    })
    .await;
}

async fn mark_kms_health_success(state: &AppState) {
    let now = Utc::now();
    update_security_runtime(state, move |security| {
        if !security.kms_healthy {
            security.kms_last_recovered_at = Some(now);
        }
        security.kms_healthy = true;
        security.kms_last_checked_at = Some(now);
        security.kms_last_success_at = Some(now);
        security.kms_last_error = None;
    })
    .await;
}
fn render_prometheus_metrics(summary: &SystemMetricsSummary) -> String {
    let mut rendered = String::new();
    for (name, kind, help, value) in [
        (
            "rustio_nodes_total",
            "gauge",
            "Total cluster nodes known by RustIO.",
            summary.nodes.total.to_string(),
        ),
        (
            "rustio_nodes_online",
            "gauge",
            "Online cluster nodes known by RustIO.",
            summary.nodes.online.to_string(),
        ),
        (
            "rustio_tenants_total",
            "gauge",
            "Configured tenant count.",
            summary.tenants_total.to_string(),
        ),
        (
            "rustio_storage_capacity_bytes",
            "gauge",
            "Total raw cluster storage capacity in bytes.",
            summary.storage.capacity_total_bytes.to_string(),
        ),
        (
            "rustio_storage_used_bytes",
            "gauge",
            "Used raw cluster storage in bytes.",
            summary.storage.capacity_used_bytes.to_string(),
        ),
        (
            "rustio_storage_disks_total",
            "gauge",
            "Configured storage disks.",
            summary.storage.disks_total.to_string(),
        ),
        (
            "rustio_storage_disks_online",
            "gauge",
            "Online storage disks.",
            summary.storage.disks_online.to_string(),
        ),
        (
            "rustio_storage_shard_missing_total",
            "gauge",
            "Missing erasure shards observed during governance scans.",
            summary.storage.shard_missing_total.to_string(),
        ),
        (
            "rustio_storage_shard_corrupted_total",
            "gauge",
            "Corrupted erasure shards observed during governance scans.",
            summary.storage.shard_corrupted_total.to_string(),
        ),
        (
            "rustio_storage_scan_runs_total",
            "counter",
            "Total background storage scan runs.",
            summary.storage.governance.scan_runs_total.to_string(),
        ),
        (
            "rustio_storage_scan_failures_total",
            "counter",
            "Total failed background storage scan runs.",
            summary.storage.governance.scan_failures_total.to_string(),
        ),
        (
            "rustio_storage_heal_objects_total",
            "counter",
            "Total healed or rebuilt objects.",
            summary.storage.governance.heal_objects_total.to_string(),
        ),
        (
            "rustio_storage_heal_failures_total",
            "counter",
            "Total failed heal or rebuild jobs.",
            summary.storage.governance.heal_failures_total.to_string(),
        ),
        (
            "rustio_storage_rebalance_objects_total",
            "counter",
            "Total completed storage rebalance objects.",
            summary
                .storage
                .governance
                .rebalance_objects_total
                .to_string(),
        ),
        (
            "rustio_storage_rebalance_failures_total",
            "counter",
            "Total failed storage rebalance objects.",
            summary
                .storage
                .governance
                .rebalance_failures_total
                .to_string(),
        ),
        (
            "rustio_storage_decommission_objects_total",
            "counter",
            "Total completed storage decommission objects.",
            summary
                .storage
                .governance
                .decommission_objects_total
                .to_string(),
        ),
        (
            "rustio_storage_decommission_failures_total",
            "counter",
            "Total failed storage decommission objects.",
            summary
                .storage
                .governance
                .decommission_failures_total
                .to_string(),
        ),
        (
            "rustio_storage_draining_disks",
            "gauge",
            "Storage disks currently draining for decommission.",
            summary.storage.governance.draining_disks.to_string(),
        ),
        (
            "rustio_storage_decommissioned_disks",
            "gauge",
            "Storage disks marked as decommissioned.",
            summary.storage.governance.decommissioned_disks.to_string(),
        ),
        (
            "rustio_storage_heal_duration_seconds",
            "gauge",
            "Duration in seconds of the last completed heal job.",
            summary
                .storage
                .governance
                .last_heal_duration_seconds
                .to_string(),
        ),
        (
            "rustio_raft_commit_index",
            "gauge",
            "Metadata raft commit index.",
            summary.raft.commit_index.to_string(),
        ),
        (
            "rustio_raft_online_peers",
            "gauge",
            "Metadata raft online peers.",
            summary.raft.online_peers.to_string(),
        ),
        (
            "rustio_replication_sites_total",
            "gauge",
            "Configured replication sites.",
            summary.replication.sites_total.to_string(),
        ),
        (
            "rustio_replication_backlog_total",
            "gauge",
            "Replication backlog items.",
            summary.replication.backlog_total.to_string(),
        ),
        (
            "rustio_replication_backlog_pending",
            "gauge",
            "Pending replication backlog items.",
            summary.replication.backlog_pending.to_string(),
        ),
        (
            "rustio_replication_backlog_failed",
            "gauge",
            "Failed replication backlog items.",
            summary.replication.backlog_failed.to_string(),
        ),
        (
            "rustio_replication_backlog_dead_letter",
            "gauge",
            "Dead-letter replication backlog items.",
            summary.replication.backlog_dead_letter.to_string(),
        ),
        (
            "rustio_alert_channels_total",
            "gauge",
            "Configured alert channels.",
            summary.alerts.channels_total.to_string(),
        ),
        (
            "rustio_alert_channels_healthy",
            "gauge",
            "Healthy alert channels.",
            summary.alerts.channels_healthy.to_string(),
        ),
        (
            "rustio_alerts_firing",
            "gauge",
            "Currently firing alerts.",
            summary.alerts.firing_alerts.to_string(),
        ),
        (
            "rustio_alert_delivery_failed",
            "gauge",
            "Failed alert delivery queue items.",
            summary.alerts.delivery_failed.to_string(),
        ),
        (
            "rustio_jobs_running",
            "gauge",
            "Running jobs.",
            summary.jobs.running.to_string(),
        ),
        (
            "rustio_iam_users_total",
            "gauge",
            "Configured IAM users.",
            summary.iam.users_total.to_string(),
        ),
        (
            "rustio_iam_service_accounts_enabled",
            "gauge",
            "Enabled service accounts.",
            summary.iam.service_accounts_enabled.to_string(),
        ),
        (
            "rustio_audit_events_total",
            "gauge",
            "Total audit events retained in memory.",
            summary.audit.events_total.to_string(),
        ),
        (
            "rustio_security_oidc_enabled",
            "gauge",
            "OIDC security path enabled.",
            prometheus_bool(summary.security.oidc_enabled).to_string(),
        ),
        (
            "rustio_security_ldap_enabled",
            "gauge",
            "LDAP security path enabled.",
            prometheus_bool(summary.security.ldap_enabled).to_string(),
        ),
        (
            "rustio_security_kms_healthy",
            "gauge",
            "KMS health status.",
            prometheus_bool(summary.security.kms_healthy).to_string(),
        ),
        (
            "rustio_kms_rotation_failed",
            "gauge",
            "Failed items from the latest KMS rotation.",
            summary.kms.rotation_failed.to_string(),
        ),
        (
            "rustio_sessions_admin_active",
            "gauge",
            "Active admin console sessions.",
            summary.sessions.admin_sessions_active.to_string(),
        ),
        (
            "rustio_sessions_sts_active",
            "gauge",
            "Active STS sessions.",
            summary.sessions.sts_sessions_active.to_string(),
        ),
    ] {
        append_prometheus_header(&mut rendered, name, kind, help);
        append_prometheus_sample(&mut rendered, name, &[], value);
    }

    append_prometheus_header(
        &mut rendered,
        "rustio_replication_site_lag_seconds",
        "gauge",
        "Replication lag in seconds for each site.",
    );
    for site in &summary.replication.sites {
        append_prometheus_sample(
            &mut rendered,
            "rustio_replication_site_lag_seconds",
            &[
                ("site_id", site.site_id.clone()),
                ("state", site.state.clone()),
                ("backlog_sla_status", site.backlog_sla_status.clone()),
            ],
            site.lag_seconds.to_string(),
        );
    }

    append_prometheus_header(
        &mut rendered,
        "rustio_replication_site_backlog_total",
        "gauge",
        "Replication backlog totals for each site and status.",
    );
    for site in &summary.replication.sites {
        for (status, value) in [
            ("total", site.backlog_total),
            ("pending", site.backlog_pending),
            ("failed", site.backlog_failed),
            ("dead_letter", site.backlog_dead_letter),
        ] {
            append_prometheus_sample(
                &mut rendered,
                "rustio_replication_site_backlog_total",
                &[
                    ("site_id", site.site_id.clone()),
                    ("status", status.to_string()),
                    ("backlog_sla_status", site.backlog_sla_status.clone()),
                ],
                value.to_string(),
            );
        }
    }

    append_prometheus_header(
        &mut rendered,
        "rustio_jobs_total",
        "gauge",
        "Job totals grouped by status and kind.",
    );
    for (status, value) in [
        ("running", summary.jobs.running),
        ("pending", summary.jobs.pending),
        ("completed", summary.jobs.completed),
        ("failed", summary.jobs.failed),
        ("cancelled", summary.jobs.cancelled),
        ("idle", summary.jobs.idle),
        ("other", summary.jobs.other),
        ("retrying", summary.jobs.retrying),
    ] {
        append_prometheus_sample(
            &mut rendered,
            "rustio_jobs_total",
            &[("status", status.to_string())],
            value.to_string(),
        );
    }
    for (kind, value) in [
        ("scan", summary.jobs.scan),
        ("scrub", summary.jobs.scrub),
        ("heal", summary.jobs.heal),
        ("rebuild", summary.jobs.rebuild),
    ] {
        append_prometheus_sample(
            &mut rendered,
            "rustio_jobs_total",
            &[("kind", kind.to_string())],
            value.to_string(),
        );
    }

    append_prometheus_header(
        &mut rendered,
        "rustio_sessions_total",
        "gauge",
        "Session and service-account totals grouped by kind.",
    );
    for (kind, value) in [
        (
            "service_accounts_total",
            summary.sessions.service_accounts_total,
        ),
        (
            "service_accounts_enabled",
            summary.sessions.service_accounts_enabled,
        ),
        (
            "admin_sessions_total",
            summary.sessions.admin_sessions_total,
        ),
        (
            "admin_sessions_active",
            summary.sessions.admin_sessions_active,
        ),
        ("sts_sessions_total", summary.sessions.sts_sessions_total),
        ("sts_sessions_active", summary.sessions.sts_sessions_active),
    ] {
        append_prometheus_sample(
            &mut rendered,
            "rustio_sessions_total",
            &[("kind", kind.to_string())],
            value.to_string(),
        );
    }

    append_prometheus_header(
        &mut rendered,
        "rustio_security_feature_enabled",
        "gauge",
        "Security feature enablement grouped by feature.",
    );
    for (feature, value) in [
        ("oidc", summary.security.oidc_enabled),
        ("ldap", summary.security.ldap_enabled),
        (
            "kms_endpoint_configured",
            summary.security.kms_endpoint_configured,
        ),
        ("kms_healthy", summary.security.kms_healthy),
    ] {
        append_prometheus_sample(
            &mut rendered,
            "rustio_security_feature_enabled",
            &[("feature", feature.to_string())],
            prometheus_bool(value).to_string(),
        );
    }

    append_prometheus_header(
        &mut rendered,
        "rustio_storage_disk_online",
        "gauge",
        "Storage disk online state and health grouped by disk.",
    );
    append_prometheus_header(
        &mut rendered,
        "rustio_storage_disk_shards_total",
        "gauge",
        "Shard totals grouped by disk and shard state.",
    );
    append_prometheus_header(
        &mut rendered,
        "rustio_storage_disk_heal_pressure",
        "gauge",
        "Heal queue pressure grouped by disk.",
    );
    append_prometheus_header(
        &mut rendered,
        "rustio_storage_disk_bytes",
        "gauge",
        "Stored erasure shard bytes grouped by disk.",
    );
    for disk in &summary.storage.disks {
        append_prometheus_sample(
            &mut rendered,
            "rustio_storage_disk_online",
            &[
                ("disk_id", disk.disk_id.clone()),
                ("path", disk.path.clone()),
                ("status", disk.status.clone()),
            ],
            prometheus_bool(disk.online).to_string(),
        );
        for (status, value) in [
            ("healthy", disk.shard_healthy),
            ("missing", disk.shard_missing),
            ("corrupted", disk.shard_corrupted),
        ] {
            append_prometheus_sample(
                &mut rendered,
                "rustio_storage_disk_shards_total",
                &[
                    ("disk_id", disk.disk_id.clone()),
                    ("status", status.to_string()),
                    ("disk_status", disk.status.clone()),
                ],
                value.to_string(),
            );
        }
        append_prometheus_sample(
            &mut rendered,
            "rustio_storage_disk_bytes",
            &[
                ("disk_id", disk.disk_id.clone()),
                ("status", disk.status.clone()),
            ],
            disk.shard_bytes.to_string(),
        );
        append_prometheus_sample(
            &mut rendered,
            "rustio_storage_disk_heal_pressure",
            &[
                ("disk_id", disk.disk_id.clone()),
                ("status", disk.status.clone()),
            ],
            disk.heal_pressure.to_string(),
        );
    }

    rendered
}

async fn build_system_metrics_summary(state: &Arc<AppState>) -> SystemMetricsSummary {
    let now = Utc::now();
    let expiring_threshold = now + Duration::hours(24);
    let tenants_total = state.tenants.read().await.len();
    let raft = state.metadata_raft_status().await;

    let (
        total_nodes,
        online_nodes,
        offline_nodes,
        zones_total,
        capacity_total_bytes,
        capacity_used_bytes,
    ) = {
        let nodes = state.nodes.read().await;
        let total_nodes = nodes.len();
        let online_nodes = nodes.iter().filter(|node| node.online).count();
        let offline_nodes = total_nodes.saturating_sub(online_nodes);
        let zones_total = nodes
            .iter()
            .map(|node| node.zone.as_str())
            .collect::<HashSet<_>>()
            .len();
        let capacity_total_bytes = nodes
            .iter()
            .map(|node| node.capacity_total_bytes)
            .fold(0u64, u64::saturating_add);
        let capacity_used_bytes = nodes
            .iter()
            .map(|node| node.capacity_used_bytes)
            .fold(0u64, u64::saturating_add);
        (
            total_nodes,
            online_nodes,
            offline_nodes,
            zones_total,
            capacity_total_bytes,
            capacity_used_bytes,
        )
    };
    let mut storage =
        build_system_storage_metrics(state, capacity_total_bytes, capacity_used_bytes).await;

    let replications_total = state.replications.read().await.len();
    let replication_checkpoints_total = state.replication_checkpoints.read().await.len();
    let alert_rules_total = state.alert_rules.read().await.len();
    let (channels_total, channels_enabled, channels_healthy) = {
        let alert_channels = state.alert_channels.read().await;
        (
            alert_channels.len(),
            alert_channels
                .iter()
                .filter(|channel| channel.enabled)
                .count(),
            alert_channels
                .iter()
                .filter(|channel| channel.enabled && channel.status == "healthy")
                .count(),
        )
    };
    let (
        backlog_metrics,
        replication_sites,
        sites_healthy,
        max_lag_seconds,
        firing_alerts,
        alert_history_total,
    ) = {
        let site_replications = state.site_replications.read().await;
        let replication_backlog = state.replication_backlog.read().await;
        let alert_history = state.alert_history.read().await;
        let backlog_metrics = compute_replication_backlog_metrics(
            &replication_backlog,
            &alert_history,
            &site_replications,
            &ReplicationBacklogQuery::default(),
            None,
            now,
        );
        let site_replication_map = site_replications
            .iter()
            .map(|site| (site.site_id.as_str(), site))
            .collect::<HashMap<_, _>>();
        let replication_sites = backlog_metrics
            .sites
            .iter()
            .map(|site| {
                let runtime = site_replication_map.get(site.site_id.as_str()).copied();
                SystemReplicationSiteMetricsSummary {
                    site_id: site.site_id.clone(),
                    endpoint: runtime.map(|site| site.endpoint.clone()),
                    state: runtime
                        .map(|site| site.state.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    lag_seconds: runtime.map(|site| site.lag_seconds).unwrap_or_default(),
                    backlog_total: site.total,
                    backlog_pending: site.pending,
                    backlog_failed: site.failed,
                    backlog_dead_letter: site.dead_letter,
                    backlog_sla_status: site.sla_status.clone(),
                    firing_alerts: site.firing_alerts,
                }
            })
            .collect::<Vec<_>>();
        let sites_healthy = replication_sites
            .iter()
            .filter(|site| site.state == "healthy")
            .count();
        let max_lag_seconds = replication_sites
            .iter()
            .map(|site| site.lag_seconds)
            .max()
            .unwrap_or_default();
        (
            backlog_metrics,
            replication_sites,
            sites_healthy,
            max_lag_seconds,
            count_firing_alerts(&alert_history),
            alert_history.len(),
        )
    };
    let (
        delivery_queued,
        delivery_in_progress,
        delivery_failed,
        delivery_done,
        last_delivery_error,
    ) = {
        let alert_delivery_queue = state.alert_delivery_queue.read().await;
        (
            alert_delivery_queue
                .iter()
                .filter(|item| item.status == "pending")
                .count(),
            alert_delivery_queue
                .iter()
                .filter(|item| item.status == "in_progress")
                .count(),
            alert_delivery_queue
                .iter()
                .filter(|item| matches!(item.status.as_str(), "failed" | "dead_letter"))
                .count(),
            alert_delivery_queue
                .iter()
                .filter(|item| item.status == "done")
                .count(),
            latest_alert_delivery_error(&alert_delivery_queue),
        )
    };
    let (users_total, users_enabled) = {
        let users = state.users.read().await;
        (
            users.len(),
            users.iter().filter(|user| user.enabled).count(),
        )
    };
    let groups_total = state.groups.read().await.len();
    let policies_total = state.policies.read().await.len();
    let (service_accounts_total, service_accounts_enabled) = {
        let service_accounts = state.service_accounts.read().await;
        (
            service_accounts.len(),
            service_accounts
                .iter()
                .filter(|account| account.status == "enabled")
                .count(),
        )
    };
    let (admin_sessions_total, admin_sessions_active, admin_sessions_expiring_24h) = {
        let admin_sessions = state.admin_sessions.read().await;
        (
            admin_sessions.len(),
            admin_sessions
                .iter()
                .filter(|session| session.status == "active" && session.access_expires_at > now)
                .count(),
            admin_sessions
                .iter()
                .filter(|session| {
                    session.status == "active"
                        && session.access_expires_at > now
                        && session.access_expires_at <= expiring_threshold
                })
                .count(),
        )
    };
    let (sts_sessions_total, sts_sessions_active, sts_sessions_expiring_24h) = {
        let sts_sessions = state.sts_sessions.read().await;
        (
            sts_sessions.len(),
            sts_sessions
                .iter()
                .filter(|session| session.status == "active" && session.expires_at > now)
                .count(),
            sts_sessions
                .iter()
                .filter(|session| {
                    session.status == "active"
                        && session.expires_at > now
                        && session.expires_at <= expiring_threshold
                })
                .count(),
        )
    };
    let (
        events_total,
        auth_events_total,
        iam_events_total,
        kms_events_total,
        alert_events_total,
        replication_events_total,
        job_events_total,
        failed_outcomes_total,
        latest_audit_event_at,
    ) = {
        let audits = state.audits.read().await;
        let mut auth_events_total = 0usize;
        let mut iam_events_total = 0usize;
        let mut kms_events_total = 0usize;
        let mut alert_events_total = 0usize;
        let mut replication_events_total = 0usize;
        let mut job_events_total = 0usize;
        let mut failed_outcomes_total = 0usize;
        let mut latest_audit_event_at = None;
        for event in audits.iter() {
            match audit_category(&event.action) {
                "auth" => auth_events_total += 1,
                "iam" => iam_events_total += 1,
                "kms" => kms_events_total += 1,
                "alerts" => alert_events_total += 1,
                "replication" => replication_events_total += 1,
                "jobs" => job_events_total += 1,
                _ => {}
            }
            if event.outcome != "success" {
                failed_outcomes_total += 1;
            }
            latest_audit_event_at = latest_audit_event_at.max(Some(event.timestamp));
        }
        (
            audits.len(),
            auth_events_total,
            iam_events_total,
            kms_events_total,
            alert_events_total,
            replication_events_total,
            job_events_total,
            failed_outcomes_total,
            latest_audit_event_at,
        )
    };
    let (
        jobs_total,
        running_jobs,
        pending_jobs,
        completed_jobs,
        failed_jobs,
        cancelled_jobs,
        idle_jobs,
        other_jobs,
        retrying_jobs,
        scan_jobs,
        scrub_jobs,
        heal_jobs,
        rebuild_jobs,
        pending_storage_objects,
        running_storage_objects,
        failed_storage_objects,
        retrying_storage_objects,
        disk_pressure,
        async_summary,
    ) = {
        let jobs = state.jobs.read().await;
        let replication_backlog = state.replication_backlog.read().await;
        let alert_delivery_queue = state.alert_delivery_queue.read().await;
        let async_summary =
            summarize_async_job_sources(&jobs, &replication_backlog, &alert_delivery_queue);
        let mut running_jobs = 0usize;
        let mut pending_jobs = 0usize;
        let mut completed_jobs = 0usize;
        let mut failed_jobs = 0usize;
        let mut cancelled_jobs = 0usize;
        let mut idle_jobs = 0usize;
        let mut other_jobs = 0usize;
        let mut retrying_jobs = 0usize;
        let mut scan_jobs = 0usize;
        let mut scrub_jobs = 0usize;
        let mut heal_jobs = 0usize;
        let mut rebuild_jobs = 0usize;
        let mut pending_storage_objects = 0usize;
        let mut running_storage_objects = 0usize;
        let mut failed_storage_objects = 0usize;
        let mut retrying_storage_objects = 0usize;
        let mut disk_pressure = HashMap::<String, usize>::new();

        for job in jobs.iter() {
            match job.status.as_str() {
                "running" => running_jobs += 1,
                "pending" | "queued" => pending_jobs += 1,
                "completed" | "done" => completed_jobs += 1,
                "failed" => failed_jobs += 1,
                "cancelled" => cancelled_jobs += 1,
                "idle" => idle_jobs += 1,
                "retrying" => retrying_jobs += 1,
                _ => other_jobs += 1,
            }

            let storage_kind = storage_job_kind_label(&job.kind);
            match storage_kind {
                "scan" => scan_jobs += 1,
                "scrub" => scrub_jobs += 1,
                "heal" => heal_jobs += 1,
                "rebuild" => rebuild_jobs += 1,
                _ => {}
            }

            if !storage_job_is_storage_work(storage_kind) {
                continue;
            }

            match job.status.as_str() {
                "pending" => pending_storage_objects += 1,
                "running" => running_storage_objects += 1,
                "failed" => failed_storage_objects += 1,
                "retrying" => retrying_storage_objects += 1,
                _ => {}
            }

            if !matches!(job.status.as_str(), "pending" | "running" | "retrying") {
                continue;
            }

            for disk in &job.affected_disks {
                *disk_pressure.entry(disk.clone()).or_default() += 1;
            }
        }

        (
            jobs.len(),
            running_jobs,
            pending_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
            idle_jobs,
            other_jobs,
            retrying_jobs,
            scan_jobs,
            scrub_jobs,
            heal_jobs,
            rebuild_jobs,
            pending_storage_objects,
            running_storage_objects,
            failed_storage_objects,
            retrying_storage_objects,
            disk_pressure,
            async_summary,
        )
    };
    let (object_lock_buckets, retention_buckets, legal_hold_buckets) = {
        let bucket_object_locks = state.bucket_object_locks.read().await;
        let bucket_retentions = state.bucket_retentions.read().await;
        let bucket_legal_holds = state.bucket_legal_holds.read().await;
        (
            bucket_object_locks
                .values()
                .filter(|item| item.enabled)
                .count(),
            bucket_retentions
                .values()
                .filter(|item| item.enabled)
                .count(),
            bucket_legal_holds
                .values()
                .filter(|item| item.enabled)
                .count(),
        )
    };
    let (retained_objects, legal_hold_objects) = {
        let all_meta: Vec<S3ObjectMeta> = state
            .object_meta
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        (
            all_meta
                .iter()
                .filter(|item| {
                    item.retention_until
                        .map(|until| until > now)
                        .unwrap_or(false)
                })
                .count(),
            all_meta.iter().filter(|item| item.legal_hold).count(),
        )
    };
    let governance_state = state.storage_governance.read().await.clone();
    let security = state.security.read().await.clone();

    for disk in &mut storage.disks {
        disk.heal_pressure = *disk_pressure.get(&disk.disk_id).unwrap_or(&0);
        disk.last_anomaly_at = governance_state
            .disk_last_anomaly_at
            .get(&disk.disk_id)
            .cloned();
        disk.placement_state = storage_disk_placement_state(
            &disk.disk_id,
            &governance_state.draining_disks,
            &governance_state.decommissioned_disks,
        );
    }

    storage.governance = SystemStorageGovernanceMetricsSummary {
        last_scan_at: governance_state.last_scan_at,
        last_heal_at: governance_state.last_heal_at,
        last_rebalance_at: governance_state.last_rebalance_at,
        last_decommission_at: governance_state.last_decommission_at,
        pending_objects: pending_storage_objects,
        running_objects: running_storage_objects,
        failed_objects: failed_storage_objects,
        retrying_objects: retrying_storage_objects,
        last_scan_result: if governance_state.last_scan_result.trim().is_empty() {
            "unknown".to_string()
        } else {
            governance_state.last_scan_result.clone()
        },
        last_heal_duration_seconds: governance_state.last_heal_duration_seconds,
        scan_runs_total: governance_state.scan_runs_total,
        scan_failures_total: governance_state.scan_failures_total,
        heal_objects_total: governance_state.heal_objects_total,
        heal_failures_total: governance_state.heal_failures_total,
        rebalance_objects_total: governance_state.rebalance_objects_total,
        rebalance_failures_total: governance_state.rebalance_failures_total,
        decommission_objects_total: governance_state.decommission_objects_total,
        decommission_failures_total: governance_state.decommission_failures_total,
        draining_disks: governance_state.draining_disks.len(),
        decommissioned_disks: governance_state.decommissioned_disks.len(),
        object_lock_buckets,
        retention_buckets,
        legal_hold_buckets,
        retained_objects,
        legal_hold_objects,
    };

    SystemMetricsSummary {
        generated_at: now,
        cluster_status: cluster_status_from_counts(total_nodes, online_nodes),
        tenants_total,
        nodes: SystemNodeMetricsSummary {
            total: total_nodes,
            online: online_nodes,
            offline: offline_nodes,
            zones_total,
        },
        storage,
        raft: SystemRaftMetricsSummary {
            cluster_id: raft.cluster_id,
            leader_id: raft.leader_id.clone(),
            leader_present: !raft.leader_id.trim().is_empty(),
            term: raft.term,
            commit_index: raft.commit_index,
            quorum: raft.quorum,
            online_peers: raft.online_peers,
            quorum_available: raft.online_peers >= raft.quorum,
            membership_phase: raft.membership_phase,
            last_error: raft.last_error,
        },
        replication: SystemReplicationMetricsSummary {
            rules_total: replications_total,
            sites_total: replication_sites.len(),
            sites_healthy,
            checkpoints_total: replication_checkpoints_total,
            max_lag_seconds,
            backlog_total: backlog_metrics.total,
            backlog_pending: backlog_metrics.pending,
            backlog_in_progress: backlog_metrics.in_progress,
            backlog_failed: backlog_metrics.failed,
            backlog_dead_letter: backlog_metrics.dead_letter,
            backlog_done: backlog_metrics.done,
            backlog_retryable: backlog_metrics.retryable,
            backlog_sla_firing_sites: replication_sites
                .iter()
                .filter(|site| site.backlog_sla_status == "firing")
                .count(),
            sites: replication_sites,
        },
        alerts: SystemAlertMetricsSummary {
            rules_total: alert_rules_total,
            channels_total,
            channels_enabled,
            channels_healthy,
            firing_alerts,
            history_total: alert_history_total,
            delivery_queued,
            delivery_in_progress,
            delivery_failed,
            delivery_done,
            last_delivery_error,
        },
        iam: SystemIamMetricsSummary {
            users_total,
            users_enabled,
            groups_total,
            policies_total,
            service_accounts_total,
            service_accounts_enabled,
        },
        audit: SystemAuditMetricsSummary {
            events_total,
            auth_events_total,
            iam_events_total,
            kms_events_total,
            alert_events_total,
            replication_events_total,
            job_events_total,
            failed_outcomes_total,
            latest_event_at: latest_audit_event_at,
        },
        kms: build_system_kms_metrics(&security),
        security: SystemSecurityMetricsSummary {
            oidc_enabled: security.oidc_enabled,
            ldap_enabled: security.ldap_enabled,
            kms_endpoint_configured: !security.kms_endpoint.trim().is_empty(),
            kms_healthy: security.kms_healthy,
            sse_mode: security.sse_mode,
        },
        jobs: SystemJobMetricsSummary {
            total: jobs_total,
            running: running_jobs,
            pending: pending_jobs,
            completed: completed_jobs,
            failed: failed_jobs,
            cancelled: cancelled_jobs,
            idle: idle_jobs,
            other: other_jobs,
            retrying: retrying_jobs,
            scan: scan_jobs,
            scrub: scrub_jobs,
            heal: heal_jobs,
            rebuild: rebuild_jobs,
            async_total: async_summary.total,
            async_pending: async_summary.pending,
            async_in_progress: async_summary.in_progress,
            async_completed: async_summary.completed,
            async_failed: async_summary.failed,
            async_dead_letter: async_summary.dead_letter,
            async_retryable: async_summary.retryable,
            kinds: async_summary
                .kinds
                .iter()
                .map(|kind| SystemJobKindMetricsSummary {
                    kind: kind.kind.clone(),
                    total: kind.total,
                    pending: kind.pending,
                    in_progress: kind.in_progress,
                    completed: kind.completed,
                    failed: kind.failed,
                    dead_letter: kind.dead_letter,
                    retryable: kind.retryable,
                })
                .collect(),
        },
        sessions: SystemSessionMetricsSummary {
            service_accounts_total,
            service_accounts_enabled,
            admin_sessions_total,
            admin_sessions_active,
            admin_sessions_expiring_24h,
            sts_sessions_total,
            sts_sessions_active,
            sts_sessions_expiring_24h,
        },
    }
}

#[derive(Debug, Deserialize)]
struct MetadataRaftAddPeerRequest {
    id: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    online: Option<bool>,
    #[serde(default)]
    auto_finalize: Option<bool>,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct MetadataRaftRemovePeerRequest {
    reason: String,
    #[serde(default)]
    auto_finalize: Option<bool>,
}

async fn system_raft_peer_add(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<MetadataRaftAddPeerRequest>,
) -> Result<Json<ApiEnvelope<MetadataRaftStatus>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    let status = state
        .add_metadata_peer(
            &body.id,
            body.endpoint.clone(),
            body.online.unwrap_or(false),
            body.auto_finalize.unwrap_or(true),
        )
        .await
        .map_err(AppError::bad_request)?;
    state
        .append_audit(
            &auth.username,
            "system.raft.peer.add",
            &format!("system/raft/peer/{}", body.id.trim()),
            "success",
            Some(body.reason),
            json!({
                "endpoint": body.endpoint,
                "online": body.online.unwrap_or(false),
                "auto_finalize": body.auto_finalize.unwrap_or(true),
            }),
        )
        .await;
    Ok(wrap(status))
}

async fn system_raft_elect(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<MetadataRaftStatus>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    let status = state
        .elect_metadata_leader(&id)
        .await
        .map_err(AppError::bad_request)?;
    state
        .append_audit(
            &auth.username,
            "system.raft.leader.elect",
            &format!("system/raft/leader/{id}"),
            "success",
            Some(body.reason),
            json!({ "leader_id": id }),
        )
        .await;
    Ok(wrap(status))
}

async fn system_raft_peer_offline(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<MetadataRaftStatus>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    let status = state
        .set_metadata_peer_state(&id, false)
        .await
        .map_err(AppError::bad_request)?;
    state
        .append_audit(
            &auth.username,
            "system.raft.peer.offline",
            &format!("system/raft/peer/{id}"),
            "success",
            Some(body.reason),
            json!({ "online": false }),
        )
        .await;
    Ok(wrap(status))
}

async fn system_raft_peer_online(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<MetadataRaftStatus>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    let status = state
        .set_metadata_peer_state(&id, true)
        .await
        .map_err(AppError::bad_request)?;
    let _ = state.sync_metadata_raft("peer-online").await;
    state
        .append_audit(
            &auth.username,
            "system.raft.peer.online",
            &format!("system/raft/peer/{id}"),
            "success",
            Some(body.reason),
            json!({ "online": true }),
        )
        .await;
    Ok(wrap(status))
}

async fn system_raft_peer_remove(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MetadataRaftRemovePeerRequest>,
) -> Result<Json<ApiEnvelope<MetadataRaftStatus>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    let status = state
        .remove_metadata_peer(&id, body.auto_finalize.unwrap_or(true))
        .await
        .map_err(AppError::bad_request)?;
    state
        .append_audit(
            &auth.username,
            "system.raft.peer.remove",
            &format!("system/raft/peer/{id}"),
            "success",
            Some(body.reason),
            json!({
                "removed": true,
                "auto_finalize": body.auto_finalize.unwrap_or(true),
            }),
        )
        .await;
    Ok(wrap(status))
}

async fn system_raft_membership_abort(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<MetadataRaftStatus>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    let status = state
        .abort_metadata_membership_change()
        .await
        .map_err(AppError::bad_request)?;
    state
        .append_audit(
            &auth.username,
            "system.raft.membership.abort",
            "system/raft/membership",
            "success",
            Some(body.reason),
            json!({ "aborted": true }),
        )
        .await;
    Ok(wrap(status))
}

async fn system_raft_membership_finalize(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<MetadataRaftStatus>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    let status = state
        .finalize_metadata_membership_change()
        .await
        .map_err(AppError::bad_request)?;
    state
        .append_audit(
            &auth.username,
            "system.raft.membership.finalize",
            "system/raft/membership",
            "success",
            Some(body.reason),
            json!({ "finalized": true }),
        )
        .await;
    Ok(wrap(status))
}

async fn root_entry(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = handle_root_sts_request(Arc::clone(&state), &method, &uri, None).await {
        return response;
    }
    if is_s3_signed_request(&headers, uri.query()) {
        if let Err(response) = ensure_s3_auth(&headers, &method, &uri, None, &state) {
            return response;
        }
        if let Err(response) = ensure_metadata_read_barrier_s3(&state, "root").await {
            return response;
        }
        return s3_list_buckets_xml(state).await;
    }

    if method == Method::GET || method == Method::HEAD {
        if let Some(response) = serve_console_path("", true).await {
            return response;
        }
    }

    index(State(state)).await.into_response()
}

async fn root_post(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Response {
    if let Some(response) =
        handle_root_sts_request(Arc::clone(&state), &method, &uri, Some(body.as_ref())).await
    {
        return response;
    }
    sts_error(
        StatusCode::BAD_REQUEST,
        "InvalidAction",
        "根路径 POST 仅支持 STS Action / root post only supports sts actions",
    )
}

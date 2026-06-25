//! 内部控制面同步（Raft、复制、会话）

use super::*;

pub(crate) fn ensure_internal_token(headers: &HeaderMap) -> Result<(), Response> {
    let expected = AppState::internal_control_token();
    let provided = headers
        .get("x-rustio-internal-token")
        .and_then(|value| value.to_str().ok());
    let matches = provided.is_some_and(|value| {
        crate::state::password::constant_time_eq(value.as_bytes(), expected.as_bytes())
    });
    if matches {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": bilingual_text("禁止访问", "forbidden") })),
        )
            .into_response())
    }
}

/// 元数据强一致读屏障(API 读路径,按需接入)。当前读默认走本地高可用,
/// 此函数保留供未来对关键强一致查询显式启用(leader 上执行 linearizable)。
#[allow(dead_code)]
pub(crate) async fn ensure_metadata_read_barrier_api(
    state: &Arc<AppState>,
) -> Result<(), AppError> {
    if let Some(raft) = state.meta_raft.get() {
        let is_leader = {
            let metrics = raft.metrics();
            let m = metrics.borrow();
            m.current_leader == Some(state.local_node_id)
        };
        if is_leader {
            raft.ensure_linearizable().await.map_err(|err| {
                AppError::new(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable", format!("{err:?}"))
            })?;
        }
    }
    Ok(())
}

/// 元数据读屏障(S3 读路径)。
///
/// 读一致性策略(Stage D):默认 follower 读本地状态,高可用、接受 stale;
/// 仅当本节点是 leader 时执行 linearizable 屏障(leader 本地状态最新,屏障几乎无成本)。
/// follower 上不调 `ensure_linearizable`——否则会因需向 leader 确认 read-index 而阻塞甚至超时,
/// 牺牲可用性。强一致读如有需要,由调用方显式选择 leader 节点。
pub(crate) async fn ensure_metadata_read_barrier_s3(
    state: &Arc<AppState>,
    resource: &str,
) -> Result<(), Response> {
    if let Some(raft) = state.meta_raft.get() {
        let is_leader = {
            let metrics = raft.metrics();
            let m = metrics.borrow();
            m.current_leader == Some(state.local_node_id)
        };
        if is_leader {
            raft.ensure_linearizable().await.map_err(|err| {
                s3_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ServiceUnavailable",
                    &format!("元数据线性读屏障失败 / metadata linearizable read barrier failed: {err:?}"),
                    resource,
                )
            })?;
        }
    }
    Ok(())
}

pub(crate) fn safe_internal_replication_path(root: &FsPath, key: &str) -> Option<PathBuf> {
    if key.is_empty() {
        return None;
    }
    let key_path = FsPath::new(key);
    for component in key_path.components() {
        match component {
            Component::Normal(_) => {}
            _ => return None,
        }
    }
    Some(root.join(key_path))
}

pub(crate) fn valid_internal_replication_version_id(version_id: &str) -> bool {
    !version_id.is_empty()
        && version_id.len() <= 128
        && version_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
}

pub(crate) fn internal_replication_meta_path(site_root: &FsPath, key: &str) -> Option<PathBuf> {
    let mut meta_key = key.to_string();
    meta_key.push_str(".json");
    safe_internal_replication_path(&site_root.join(".rustio_meta"), &meta_key)
}

pub(crate) fn internal_replication_versions_dir(site_root: &FsPath, key: &str) -> PathBuf {
    site_root
        .join(".rustio_versions")
        .join(sha256_hex(key.as_bytes()))
}

pub(crate) fn internal_replication_version_meta_path(
    site_root: &FsPath,
    key: &str,
    version_id: &str,
) -> Option<PathBuf> {
    if !valid_internal_replication_version_id(version_id) {
        return None;
    }
    Some(internal_replication_versions_dir(site_root, key).join(format!("{version_id}.json")))
}

pub(crate) fn internal_replication_version_payload_path(
    site_root: &FsPath,
    key: &str,
    version_id: &str,
) -> Option<PathBuf> {
    if !valid_internal_replication_version_id(version_id) {
        return None;
    }
    Some(internal_replication_versions_dir(site_root, key).join(format!("{version_id}.bin")))
}

pub(crate) fn internal_replication_object_space_root(
    data_dir: &FsPath,
    target_site: &str,
    source_bucket: &str,
) -> PathBuf {
    data_dir
        .join(".rustio_sites")
        .join(target_site)
        .join("data")
        .join(source_bucket)
}

pub(crate) async fn internal_replication_apply(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<InternalReplicationApplyRequest>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    if !valid_bucket_name(&body.source_bucket) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": bilingual_text("源桶名无效", "存储桶名称无效 / invalid bucket name") })),
        )
            .into_response();
    }
    let site_root = state
        .data_dir
        .join(".rustio_replication")
        .join("sites")
        .join(&body.target_site)
        .join(&body.source_bucket);
    let object_space_root = internal_replication_object_space_root(
        &state.data_dir,
        &body.target_site,
        &body.source_bucket,
    );
    let marker_path = state
        .data_dir
        .join(".rustio_replication")
        .join(".internal_applied")
        .join(format!("{}.done", body.idempotency_key));
    if marker_path.exists() {
        return (StatusCode::OK, Json(json!({ "status": "idempotent" }))).into_response();
    }

    let Some(target_path) = safe_internal_replication_path(&site_root, &body.object_key) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": bilingual_text("对象键无效", "invalid object key") })),
        )
            .into_response();
    };
    let Some(object_space_target_path) =
        safe_internal_replication_path(&object_space_root, &body.object_key)
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": bilingual_text("对象键无效", "invalid object key") })),
        )
            .into_response();
    };
    let object_meta = body.object_meta.clone();
    if body.operation == "delete" {
        let _ = tokio::fs::remove_file(&target_path).await;
        let _ = tokio::fs::remove_file(&object_space_target_path).await;
        if let Some(meta_path) = internal_replication_meta_path(&site_root, &body.object_key) {
            let _ = tokio::fs::remove_file(meta_path).await;
        }
        if let Some(meta_path) =
            internal_replication_meta_path(&object_space_root, &body.object_key)
        {
            let _ = tokio::fs::remove_file(meta_path).await;
        }
        if let Some(version_id) = body.version_id.as_deref() {
            if let Some(version_meta_path) =
                internal_replication_version_meta_path(&site_root, &body.object_key, version_id)
            {
                let _ = tokio::fs::remove_file(version_meta_path).await;
            }
            if let Some(version_payload_path) =
                internal_replication_version_payload_path(&site_root, &body.object_key, version_id)
            {
                let _ = tokio::fs::remove_file(version_payload_path).await;
            }
            if let Some(version_meta_path) = internal_replication_version_meta_path(
                &object_space_root,
                &body.object_key,
                version_id,
            ) {
                let _ = tokio::fs::remove_file(version_meta_path).await;
            }
            if let Some(version_payload_path) = internal_replication_version_payload_path(
                &object_space_root,
                &body.object_key,
                version_id,
            ) {
                let _ = tokio::fs::remove_file(version_payload_path).await;
            }
        }

        if object_meta
            .as_ref()
            .map(|meta| meta.delete_marker)
            .unwrap_or(false)
        {
            if let Some(meta_path) = internal_replication_meta_path(&site_root, &body.object_key) {
                if let Some(parent) = meta_path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                if let Some(meta) = object_meta.as_ref() {
                    if let Ok(bytes) = serde_json::to_vec_pretty(meta) {
                        let _ = tokio::fs::write(meta_path, bytes).await;
                    }
                }
            }
            if let Some(meta_path) =
                internal_replication_meta_path(&object_space_root, &body.object_key)
            {
                if let Some(parent) = meta_path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                if let Some(meta) = object_meta.as_ref() {
                    if let Ok(bytes) = serde_json::to_vec_pretty(meta) {
                        let _ = tokio::fs::write(meta_path, bytes).await;
                    }
                }
            }
            if let (Some(meta), Some(version_meta_path)) = (
                object_meta.as_ref(),
                body.version_id.as_deref().and_then(|version_id| {
                    internal_replication_version_meta_path(&site_root, &body.object_key, version_id)
                }),
            ) {
                if let Some(parent) = version_meta_path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                if let Ok(bytes) = serde_json::to_vec_pretty(meta) {
                    let _ = tokio::fs::write(version_meta_path, bytes).await;
                }
            }
            if let (Some(meta), Some(version_meta_path)) = (
                object_meta.as_ref(),
                body.version_id.as_deref().and_then(|version_id| {
                    internal_replication_version_meta_path(
                        &object_space_root,
                        &body.object_key,
                        version_id,
                    )
                }),
            ) {
                if let Some(parent) = version_meta_path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                if let Ok(bytes) = serde_json::to_vec_pretty(meta) {
                    let _ = tokio::fs::write(version_meta_path, bytes).await;
                }
            }
        }
    } else {
        let payload = body
            .payload_base64
            .as_deref()
            .and_then(|value| BASE64.decode(value).ok())
            .unwrap_or_default();
        if let Some(parent) = target_path.parent() {
            if let Err(err) = tokio::fs::create_dir_all(parent).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": bilingual_text(
                            "创建目标目录失败",
                            &format!("failed to create target dir: {err}")
                        )
                    })),
                )
                    .into_response();
            }
        }
        if let Some(parent) = object_space_target_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        if let Err(err) = tokio::fs::write(&target_path, &payload).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": bilingual_text(
                        "写入目标对象失败",
                        &format!("failed to write target object: {err}")
                    )
                })),
            )
                .into_response();
        }
        let _ = tokio::fs::write(&object_space_target_path, &payload).await;

        if let Some(meta) = object_meta.as_ref() {
            if let Some(meta_path) = internal_replication_meta_path(&site_root, &body.object_key) {
                if let Some(parent) = meta_path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                if let Ok(bytes) = serde_json::to_vec_pretty(meta) {
                    let _ = tokio::fs::write(meta_path, bytes).await;
                }
            }
            if let Some(meta_path) =
                internal_replication_meta_path(&object_space_root, &body.object_key)
            {
                if let Some(parent) = meta_path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                if let Ok(bytes) = serde_json::to_vec_pretty(meta) {
                    let _ = tokio::fs::write(meta_path, bytes).await;
                }
            }
            if let Some(version_id) = body.version_id.as_deref() {
                if let Some(version_meta_path) =
                    internal_replication_version_meta_path(&site_root, &body.object_key, version_id)
                {
                    if let Some(parent) = version_meta_path.parent() {
                        let _ = tokio::fs::create_dir_all(parent).await;
                    }
                    if let Ok(bytes) = serde_json::to_vec_pretty(meta) {
                        let _ = tokio::fs::write(version_meta_path, bytes).await;
                    }
                }
                if let Some(version_meta_path) = internal_replication_version_meta_path(
                    &object_space_root,
                    &body.object_key,
                    version_id,
                ) {
                    if let Some(parent) = version_meta_path.parent() {
                        let _ = tokio::fs::create_dir_all(parent).await;
                    }
                    if let Ok(bytes) = serde_json::to_vec_pretty(meta) {
                        let _ = tokio::fs::write(version_meta_path, bytes).await;
                    }
                }
                if let Some(version_payload_path) = internal_replication_version_payload_path(
                    &site_root,
                    &body.object_key,
                    version_id,
                ) {
                    if let Some(parent) = version_payload_path.parent() {
                        let _ = tokio::fs::create_dir_all(parent).await;
                    }
                    let _ = tokio::fs::write(version_payload_path, &payload).await;
                }
                if let Some(version_payload_path) = internal_replication_version_payload_path(
                    &object_space_root,
                    &body.object_key,
                    version_id,
                ) {
                    if let Some(parent) = version_payload_path.parent() {
                        let _ = tokio::fs::create_dir_all(parent).await;
                    }
                    let _ = tokio::fs::write(version_payload_path, &payload).await;
                }
            }
        }
    }

    if let Some(parent) = marker_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    if let Err(err) = tokio::fs::write(&marker_path, body.checkpoint.to_string()).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": bilingual_text(
                    "写入复制标记失败",
                    &format!("failed to persist marker: {err}")
                )
            })),
        )
            .into_response();
    }
    (StatusCode::OK, Json(json!({ "status": "applied" }))).into_response()
}

pub(crate) async fn internal_console_session_sync(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ConsoleSession>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    match state.upsert_console_session_runtime(body).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(message) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": bilingual_text(
                    "同步控制台会话失败",
                    &format!("failed to sync console session: {message}")
                )
            })),
        )
            .into_response(),
    }
}

pub(crate) async fn internal_console_session_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    match state.delete_console_session_runtime(&session_id).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(message) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": bilingual_text(
                    "删除控制台会话同步失败",
                    &format!("failed to delete synced console session: {message}")
                )
            })),
        )
            .into_response(),
    }
}

// ── openraft 内部 RPC 端点 ──

use crate::state::raft::TypeConfig;

pub(crate) async fn raft_append_entries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<openraft::raft::AppendEntriesRequest<TypeConfig>>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    let Some(raft) = state.meta_raft.get() else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"raft not initialized"})))
            .into_response();
    };
    match raft.append_entries(req).await {
        Ok(resp) => Json(resp).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("append_entries: {err:?}")})),
        )
            .into_response(),
    }
}

pub(crate) async fn raft_vote(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<openraft::raft::VoteRequest<u64>>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    let Some(raft) = state.meta_raft.get() else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"raft not initialized"})))
            .into_response();
    };
    match raft.vote(req).await {
        Ok(resp) => Json(resp).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("vote: {err:?}")})),
        )
            .into_response(),
    }
}

pub(crate) async fn raft_install_snapshot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<openraft::raft::InstallSnapshotRequest<TypeConfig>>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    let Some(raft) = state.meta_raft.get() else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"raft not initialized"})))
            .into_response();
    };
    match raft.install_snapshot(req).await {
        Ok(resp) => Json(resp).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("install_snapshot: {err:?}")})),
        )
            .into_response(),
    }
}

/// follower 转发来的元数据写:本节点须为 leader,经 client_write 提交复制。
pub(crate) async fn raft_metadata_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(cmd): Json<crate::state::raft::MetadataCommand>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    let Some(raft) = state.meta_raft.get() else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"raft not initialized"})))
            .into_response();
    };
    match raft.client_write(cmd).await {
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("metadata write: {err:?}")})),
        )
            .into_response(),
    }
}

/// 加节点请求(管理员端点或新节点自动 join 转发来):若本节点非 leader 则转发到 leader,
/// leader 执行 add_learner+change_membership。
pub(crate) async fn raft_membership_add(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(peer): Json<crate::state::cluster::ClusterPeerInfo>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    // 非 leader:转发到 leader(seed 节点收到新节点 join 时可能不是 leader)。
    if !state.is_metadata_leader() {
        let Some(leader_addr) = state.metadata_leader_addr() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "no known leader"})),
            )
                .into_response();
        };
        let token = AppState::internal_control_token();
        let url = format!("{leader_addr}/api/v1/internal/cluster/membership/add");
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
        {
            Ok(c) => c,
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("build client: {err}")})),
                )
                    .into_response()
            }
        };
        return match client
            .post(&url)
            .header("x-rustio-internal-token", &token)
            .json(&peer)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                (StatusCode::OK, Json(json!({"ok": true}))).into_response()
            }
            Ok(resp) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": format!("leader add member HTTP {}", resp.status())})),
            )
                .into_response(),
            Err(err) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": format!("forward to leader: {err}")})),
            )
                .into_response(),
        };
    }
    match state.raft_add_member(peer).await {
        Ok(()) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("add member: {err}")})),
        )
            .into_response(),
    }
}

/// 移除节点请求体(内部端点)。
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct RaftMembershipRemoveRequest {
    pub(crate) node_id: u64,
    /// force=true:强删死节点,移除后由 leader 侧后台 rebalance 重建丢失分片。
    #[serde(default)]
    pub(crate) force: bool,
}

/// 移除节点请求(管理员端点转发来):若本节点非 leader 则转发到 leader,
/// leader 执行 change_membership 收缩 + RemoveClusterPeer 拓扑复制。
pub(crate) async fn raft_membership_remove(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RaftMembershipRemoveRequest>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    // 非 leader:转发到 leader(change_membership 是 leader-only)。
    if !state.is_metadata_leader() {
        let Some(leader_addr) = state.metadata_leader_addr() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "no known leader"})),
            )
                .into_response();
        };
        let token = AppState::internal_control_token();
        let url = format!("{leader_addr}/api/v1/internal/cluster/membership/remove");
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
        {
            Ok(c) => c,
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("build client: {err}")})),
                )
                    .into_response()
            }
        };
        return match client
            .post(&url)
            .header("x-rustio-internal-token", &token)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                (StatusCode::OK, Json(json!({"ok": true}))).into_response()
            }
            Ok(resp) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": format!("leader remove member HTTP {}", resp.status())})),
            )
                .into_response(),
            Err(err) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": format!("forward to leader: {err}")})),
            )
                .into_response(),
        };
    }
    match crate::routes::locked_remove_member(&state, body.node_id, body.force).await {
        Ok(()) => {
            // force 强删:移除后该节点分片全缺失,leader 侧后台 rebalance 全量重建
            //(迁移原语走 RS 重建回退路径)。转发路径(管理端点非 leader)经此触发,
            // 与 leader 直发路径(remove_cluster_member 自身触发)互斥不重复。
            if body.force {
                crate::routes::spawn_cluster_rebalance(
                    &state,
                    crate::routes::RebalanceScope::All,
                    "force remove rebuild".to_string(),
                );
            }
            (StatusCode::OK, Json(json!({"ok": true}))).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("remove member: {err}")})),
        )
            .into_response(),
    }
}

// ── 跨节点 EC 分片 RPC 端点 ──

/// 校验对象哈希为 64 位十六进制(SHA-256),防止路径穿越。
fn valid_ec_object_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// 解析并校验分片 RPC 路径参数,返回该节点本地的分片落盘路径。
fn ec_shard_local_path(
    state: &AppState,
    bucket: &str,
    object_hash: &str,
    disk_index: usize,
    shard_index: usize,
) -> Result<PathBuf, Response> {
    if !valid_bucket_name(bucket) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": bilingual_text("存储桶名称无效", "invalid bucket name") })),
        )
            .into_response());
    }
    if !valid_ec_object_hash(object_hash) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": bilingual_text("对象哈希无效", "invalid object hash") })),
        )
            .into_response());
    }
    if disk_index >= state.data_disks.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": bilingual_text("磁盘索引越界", "disk index out of range") })),
        )
            .into_response());
    }
    Ok(state.data_disks[disk_index]
        .join(bucket)
        .join(".rustio_ec")
        .join(object_hash)
        .join(format!("{shard_index}.bin")))
}

/// 接收远程节点发来的 EC 分片并落本地磁盘,返回分片校验和。
pub(crate) async fn internal_ec_shard_put(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((bucket, object_hash, disk_index, shard_index)): Path<(String, String, usize, usize)>,
    body: Bytes,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    let shard_path = match ec_shard_local_path(&state, &bucket, &object_hash, disk_index, shard_index)
    {
        Ok(path) => path,
        Err(response) => return response,
    };
    if let Some(parent) = shard_path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": bilingual_text("创建分片目录失败", &format!("failed to create shard dir: {err}"))
                })),
            )
                .into_response();
        }
    }
    if let Err(err) = atomic_write(&shard_path, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": bilingual_text("写入分片失败", &format!("failed to write shard: {err}"))
            })),
        )
            .into_response();
    }
    let checksum = sha256_hex(&body);
    (StatusCode::OK, Json(json!({ "checksum": checksum }))).into_response()
}

/// 解析并校验 manifest RPC 路径参数,返回本节点 manifest 副本落盘路径。
fn ec_manifest_replica_path(
    state: &AppState,
    bucket: &str,
    object_hash: &str,
) -> Result<PathBuf, Response> {
    if !valid_bucket_name(bucket) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": bilingual_text("存储桶名称无效", "invalid bucket name") })),
        )
            .into_response());
    }
    if !valid_ec_object_hash(object_hash) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": bilingual_text("对象哈希无效", "invalid object hash") })),
        )
            .into_response());
    }
    // manifest 副本落本节点 data_dir/bucket/.rustio_ec_meta/<hash>.json(与 ec_manifest_path 同布局)。
    Ok(state
        .data_dir
        .join(bucket)
        .join(".rustio_ec_meta")
        .join(format!("{object_hash}.json")))
}

/// 接收远程节点发来的 manifest 副本并落本地。
pub(crate) async fn internal_ec_manifest_put(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((bucket, object_hash)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    let path = match ec_manifest_replica_path(&state, &bucket, &object_hash) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if let Some(parent) = path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": bilingual_text("创建清单目录失败", &format!("failed to create manifest dir: {err}")) })),
            )
                .into_response();
        }
    }
    if let Err(err) = atomic_write(&path, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": bilingual_text("写入清单失败", &format!("failed to write manifest: {err}")) })),
        )
            .into_response();
    }
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

/// 向远程请求方返回本地 manifest 副本字节(不存在返回 404)。
pub(crate) async fn internal_ec_manifest_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((bucket, object_hash)): Path<(String, String)>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    let path = match ec_manifest_replica_path(&state, &bucket, &object_hash) {
        Ok(path) => path,
        Err(response) => return response,
    };
    match tokio::fs::read(&path).await {
        Ok(bytes) => (StatusCode::OK, bytes).into_response(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": bilingual_text("清单不存在", "manifest not found") })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": bilingual_text("读取清单失败", &format!("failed to read manifest: {err}")) })),
        )
            .into_response(),
    }
}

/// 返回本地 manifest 副本的存在性 + updated_at(治理 healing 探测用,不存在返 200 exists:false)。
pub(crate) async fn internal_ec_manifest_stat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((bucket, object_hash)): Path<(String, String)>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    let path = match ec_manifest_replica_path(&state, &bucket, &object_hash) {
        Ok(path) => path,
        Err(response) => return response,
    };
    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let updated_at = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v.get("updated_at").and_then(|u| u.as_str().map(str::to_string)))
                .unwrap_or_default();
            (StatusCode::OK, Json(json!({ "exists": true, "updated_at": updated_at }))).into_response()
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            (StatusCode::OK, Json(json!({ "exists": false }))).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": bilingual_text("探测清单失败", &format!("failed to stat manifest: {err}")) })),
        )
            .into_response(),
    }
}

/// 向远程请求方返回本地 EC 分片原始字节。
pub(crate) async fn internal_ec_shard_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((bucket, object_hash, disk_index, shard_index)): Path<(String, String, usize, usize)>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    let shard_path = match ec_shard_local_path(&state, &bucket, &object_hash, disk_index, shard_index)
    {
        Ok(path) => path,
        Err(response) => return response,
    };
    match tokio::fs::read(&shard_path).await {
        Ok(bytes) => (StatusCode::OK, bytes).into_response(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": bilingual_text("分片不存在", "shard not found") })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": bilingual_text("读取分片失败", &format!("failed to read shard: {err}"))
            })),
        )
            .into_response(),
    }
}

/// 返回本地 EC 分片的存在性 / 大小 / 校验和(供属主节点远程感知扫描调用)。
///
/// 与 `internal_ec_shard_get` 的区别:分片不存在时返回 `200 {"exists":false}`(而非 404),
/// 让扫描客户端按 `exists` 字段判定 missing,网络/RPC 失败才视为不可达。
pub(crate) async fn internal_ec_shard_stat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((bucket, object_hash, disk_index, shard_index)): Path<(String, String, usize, usize)>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    let shard_path = match ec_shard_local_path(&state, &bucket, &object_hash, disk_index, shard_index)
    {
        Ok(path) => path,
        Err(response) => return response,
    };
    match tokio::fs::read(&shard_path).await {
        Ok(bytes) => (
            StatusCode::OK,
            Json(json!({
                "exists": true,
                "size": bytes.len(),
                "checksum": sha256_hex(&bytes),
            })),
        )
            .into_response(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            (StatusCode::OK, Json(json!({ "exists": false }))).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": bilingual_text("读取分片失败", &format!("failed to read shard: {err}"))
            })),
        )
            .into_response(),
    }
}

/// 删除本地 EC 分片(对象删除 / 写入回滚时由属主节点调用)。
pub(crate) async fn internal_ec_shard_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((bucket, object_hash, disk_index, shard_index)): Path<(String, String, usize, usize)>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    let shard_path = match ec_shard_local_path(&state, &bucket, &object_hash, disk_index, shard_index)
    {
        Ok(path) => path,
        Err(response) => return response,
    };
    match tokio::fs::remove_file(&shard_path).await {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": bilingual_text("删除分片失败", &format!("failed to delete shard: {err}"))
                })),
            )
                .into_response();
        }
    }
    (StatusCode::OK, Json(json!({ "status": "deleted" }))).into_response()
}

#[derive(Debug)]
pub(crate) struct ExternalIdentityProfile {
    pub(crate) username: String,
    pub(crate) role: String,
    pub(crate) display_name: String,
    pub(crate) groups: Vec<String>,
    pub(crate) provider: String,
    pub(crate) subject: Option<String>,
    pub(crate) audience: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct ExternalIdentityClaimOverrides {
    pub(crate) username_claim: Option<String>,
    pub(crate) groups_claim: Option<String>,
    pub(crate) role_claim: Option<String>,
    pub(crate) default_role: Option<String>,
    pub(crate) group_role_map: Option<String>,
    pub(crate) display_name_claim: Option<String>,
    pub(crate) subject_claim: Option<String>,
    pub(crate) audience_claim: Option<String>,
    pub(crate) provider_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OidcDiscoveryDocument {
    pub(crate) issuer: String,
    pub(crate) jwks_uri: String,
    pub(crate) authorization_endpoint: String,
    pub(crate) token_endpoint: String,
    #[serde(default)]
    pub(crate) id_token_signing_alg_values_supported: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OidcTokenResponse {
    #[serde(default)]
    pub(crate) id_token: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OidcCallbackQuery {
    pub(crate) code: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) error_description: Option<String>,
}

#[derive(Debug)]
pub(crate) struct LdapIdentityRecord {
    pub(crate) username: String,
    pub(crate) display_name: String,
    pub(crate) groups: Vec<String>,
}

// ── 对象元数据多副本 RPC（照搬 manifest RPC 模式，目标改为 redb MetaStore） ──

/// 接收远程 S3ObjectMeta JSON 副本，写入本地 redb + 更新 LRU。
pub(crate) async fn internal_meta_put(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((_bucket, _key)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    let meta: S3ObjectMeta = match serde_json::from_slice(&body) {
        Ok(m) => m,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": bilingual_text("元数据反序列化失败", &format!("failed to deserialize meta: {err}")) })),
            )
                .into_response();
        }
    };
    if let Err(err) = state.meta_store.put(&meta) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": bilingual_text("写入元数据失败", &format!("failed to write meta: {err}")) })),
        )
            .into_response();
    }
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

/// 返回本地 S3ObjectMeta JSON（不存在返回 404）。
pub(crate) async fn internal_meta_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    match state.meta_store.get(&bucket, &key) {
        Ok(Some(meta)) => {
            match serde_json::to_vec(&meta) {
                Ok(bytes) => (StatusCode::OK, bytes).into_response(),
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": bilingual_text("元数据序列化失败", &format!("failed to serialize meta: {err}")) })),
                )
                    .into_response(),
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": bilingual_text("元数据不存在", "meta not found") })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": bilingual_text("读取元数据失败", &format!("failed to read meta: {err}")) })),
        )
            .into_response(),
    }
}

/// 返回本地 S3ObjectMeta 的存在性 + created_at（healing 探测用，不存在返 200 exists:false）。
pub(crate) async fn internal_meta_stat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    match state.meta_store.get(&bucket, &key) {
        Ok(Some(meta)) => {
            let created_at = meta.created_at.to_rfc3339();
            (StatusCode::OK, Json(json!({ "exists": true, "created_at": created_at }))).into_response()
        }
        Ok(None) => {
            (StatusCode::OK, Json(json!({ "exists": false }))).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": bilingual_text("探测元数据失败", &format!("failed to stat meta: {err}")) })),
        )
            .into_response(),
    }
}


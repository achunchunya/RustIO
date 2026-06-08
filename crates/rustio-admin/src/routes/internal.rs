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

pub(crate) async fn ensure_metadata_read_barrier_api(
    state: &Arc<AppState>,
) -> Result<(), AppError> {
    if let Some(raft) = state.meta_raft.get() {
        let _ = raft.ensure_linearizable().await.map_err(|err| {
            AppError::new(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable", format!("{err:?}"))
        })?;
    }
    Ok(())
}

pub(crate) async fn ensure_metadata_read_barrier_s3(
    state: &Arc<AppState>,
    resource: &str,
) -> Result<(), Response> {
    if let Some(raft) = state.meta_raft.get() {
        let _ = raft.ensure_linearizable().await.map_err(|err| {
            s3_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                &format!("元数据线性读屏障失败 / metadata linearizable read barrier failed: {err:?}"),
                resource,
            )
        })?;
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


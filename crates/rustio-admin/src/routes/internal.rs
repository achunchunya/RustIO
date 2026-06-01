//! 内部控制面同步（Raft、复制、会话）

use super::*;

pub(crate) fn ensure_internal_token(headers: &HeaderMap) -> Result<(), Response> {
    let expected = AppState::internal_control_token();
    let provided = headers
        .get("x-rustio-internal-token")
        .and_then(|value| value.to_str().ok());
    if provided == Some(expected.as_str()) {
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
    state
        .metadata_read_index()
        .await
        .map(|_| ())
        .map_err(|err| AppError::new(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable", err))
}

pub(crate) async fn ensure_metadata_read_barrier_s3(
    state: &Arc<AppState>,
    resource: &str,
) -> Result<(), Response> {
    state
        .metadata_read_index()
        .await
        .map(|_| ())
        .map_err(|err| {
            s3_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                &format!("元数据线性读屏障失败 / metadata linearizable read barrier failed: {err}"),
                resource,
            )
        })
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

pub(crate) async fn internal_metadata_raft_sync(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<MetadataRaftSyncRequest>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    match state.apply_remote_metadata_raft_sync(body).await {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(message) => {
            (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
        }
    }
}

pub(crate) async fn internal_metadata_raft_request_vote(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<MetadataRaftVoteRequest>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    match state.handle_metadata_vote_request(body).await {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(message) => {
            (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
        }
    }
}

pub(crate) async fn internal_metadata_raft_pre_vote(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<MetadataRaftPreVoteRequest>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    match state.handle_metadata_pre_vote_request(body).await {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(message) => {
            (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
        }
    }
}

pub(crate) async fn internal_metadata_raft_heartbeat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<MetadataRaftHeartbeatRequest>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    match state.handle_metadata_heartbeat_request(body).await {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(message) => {
            (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
        }
    }
}

pub(crate) async fn internal_metadata_raft_read_index(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<MetadataRaftReadIndexRequest>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    match state.handle_metadata_read_index_request(body).await {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(message) => {
            (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
        }
    }
}

pub(crate) async fn internal_metadata_raft_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    match state
        .export_metadata_raft_sync_request("internal-export")
        .await
    {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(message) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": message })),
        )
            .into_response(),
    }
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

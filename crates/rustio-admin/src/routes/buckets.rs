//! 桶治理与远端分层配置

use super::*;

pub(crate) async fn list_buckets(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<BucketSpec>>>, AppError> {
    auth.require(Permission::BucketRead)?;
    let buckets = state
        .buckets
        .read()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    Ok(wrap(buckets))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateBucketSpecRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) tenant_id: Option<String>,
    #[serde(default)]
    pub(crate) project_id: Option<String>,
    pub(crate) versioning: bool,
    pub(crate) object_lock: bool,
    pub(crate) ilm_policy: Option<String>,
    pub(crate) replication_policy: Option<String>,
}

pub(crate) fn resolve_bucket_tenant_id(
    tenants: &[TenantSpec],
    tenant_id: Option<String>,
    project_id: Option<String>,
) -> Result<String, AppError> {
    let requested = normalize_optional_text(tenant_id)
        .or_else(|| normalize_optional_text(project_id))
        .unwrap_or_else(|| "default".to_string());
    let tenant = tenants
        .iter()
        .find(|tenant| tenant_matches_identifier(tenant, &requested))
        .ok_or_else(|| AppError::bad_request("租户不存在 / tenant not found"))?;
    Ok(tenant.id.clone())
}

pub(crate) async fn create_bucket_spec(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<CreateBucketSpecRequest>,
) -> Result<Json<ApiEnvelope<BucketSpec>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request(
            "存储桶名称不能为空 / bucket name cannot be empty",
        ));
    }

    let path = bucket_path(&state, &body.name)
        .map_err(|_| AppError::bad_request("存储桶名称无效 / invalid bucket name"))?;
    if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        return Err(AppError::bad_request(
            "存储桶已存在 / bucket already exists",
        ));
    }
    tokio::fs::create_dir_all(&path).await.map_err(|err| {
        AppError::internal(format!(
            "创建存储桶目录失败 / failed to create bucket dir: {err}"
        ))
    })?;

    let tenant_id =
        resolve_bucket_tenant_id(&state.tenants.read().await, body.tenant_id, body.project_id)?;
    let spec = BucketSpec {
        name: body.name,
        tenant_id: tenant_id.clone(),
        versioning: body.versioning,
        object_lock: body.object_lock,
        ilm_policy: body.ilm_policy,
        replication_policy: body.replication_policy,
    };

    state
        .buckets
        .write()
        .await
        .insert(spec.name.clone(), spec.clone());
    state
        .bucket_object_locks
        .write()
        .await
        .insert(spec.name.clone(), default_object_lock_config(&spec));
    state
        .bucket_retentions
        .write()
        .await
        .insert(spec.name.clone(), default_retention_config());
    state
        .bucket_legal_holds
        .write()
        .await
        .insert(spec.name.clone(), default_legal_hold_config());
    state
        .bucket_notifications
        .write()
        .await
        .insert(spec.name.clone(), Vec::new());
    state
        .bucket_lifecycle_rules
        .write()
        .await
        .insert(spec.name.clone(), Vec::new());
    state
        .bucket_acls
        .write()
        .await
        .insert(spec.name.clone(), default_bucket_acl_config());
    state.bucket_public_access_blocks.write().await.insert(
        spec.name.clone(),
        default_bucket_public_access_block_config(),
    );
    state
        .sync_metadata_raft("bucket-create")
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "元数据 Raft 提交失败 / metadata raft commit failed: {err}"
            ))
        })?;

    state
        .append_audit(
            &auth.username,
            "bucket.create",
            &format!("bucket/{}", spec.name),
            "success",
            None,
            json!({ "tenant": spec.tenant_id }),
        )
        .await;
    Ok(wrap(spec))
}

pub(crate) async fn delete_bucket_spec(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    if !valid_bucket_name(&name) {
        return Err(AppError::bad_request(
            "存储桶名称无效 / invalid bucket name",
        ));
    }

    if !state.buckets.read().await.contains_key(&name) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }

    let bucket_dir = state.data_dir.join(&name);
    if !tokio::fs::try_exists(&bucket_dir).await.unwrap_or(false) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }

    let has_objects = bucket_has_objects(&bucket_dir, &bucket_dir)
        .map_err(|err| AppError::internal(err.to_string()))?;
    if has_objects {
        return Err(AppError::bad_request("存储桶非空 / bucket is not empty"));
    }

    tokio::fs::remove_dir_all(&bucket_dir)
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "删除存储桶目录失败 / failed to remove bucket dir: {err}"
            ))
        })?;

    state.buckets.write().await.remove(&name);
    state.bucket_object_locks.write().await.remove(&name);
    state.bucket_retentions.write().await.remove(&name);
    state.bucket_legal_holds.write().await.remove(&name);
    state.bucket_notifications.write().await.remove(&name);
    state.bucket_lifecycle_rules.write().await.remove(&name);
    state.bucket_acls.write().await.remove(&name);
    state
        .bucket_public_access_blocks
        .write()
        .await
        .remove(&name);
    state.bucket_policies.write().await.remove(&name);
    state.bucket_cors_rules.write().await.remove(&name);
    state.bucket_tags.write().await.remove(&name);
    state.bucket_encryptions.write().await.remove(&name);
    state
        .replications
        .write()
        .await
        .retain(|rule| rule.source_bucket != name);
    state
        .replication_backlog
        .write()
        .await
        .retain(|item| item.source_bucket != name);
    state.object_meta.retain(|(bucket, _), _| bucket != &name);
    state
        .sync_metadata_raft("bucket-delete")
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "元数据 Raft 提交失败 / metadata raft commit failed: {err}"
            ))
        })?;

    state
        .append_audit(
            &auth.username,
            "bucket.delete",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({}),
        )
        .await;

    Ok(wrap(json!({ "deleted": true, "name": name })))
}

pub(crate) fn default_object_lock_config(bucket: &BucketSpec) -> BucketObjectLockConfig {
    BucketObjectLockConfig {
        enabled: bucket.object_lock,
        mode: "GOVERNANCE".to_string(),
        default_retention_days: 30,
    }
}

pub(crate) fn default_retention_config() -> BucketRetentionConfig {
    BucketRetentionConfig {
        enabled: false,
        mode: "GOVERNANCE".to_string(),
        duration_days: 30,
    }
}

pub(crate) fn default_legal_hold_config() -> BucketLegalHoldConfig {
    BucketLegalHoldConfig { enabled: false }
}

pub(crate) fn default_bucket_acl_config() -> BucketAclConfig {
    BucketAclConfig {
        acl: "private".to_string(),
    }
}

pub(crate) fn default_bucket_public_access_block_config() -> BucketPublicAccessBlockConfig {
    BucketPublicAccessBlockConfig {
        block_public_acls: false,
        ignore_public_acls: false,
        block_public_policy: false,
        restrict_public_buckets: false,
    }
}

pub(crate) fn normalize_bucket_policy_value(policy: Value) -> Result<Value, AppError> {
    if !policy.is_object() {
        return Err(AppError::bad_request(
            "policy document must be a JSON object",
        ));
    }
    Ok(policy)
}

pub(crate) fn normalize_bucket_acl_value(acl: &str) -> Result<String, AppError> {
    let normalized = acl.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "private" | "public-read" | "public-read-write" | "authenticated-read" => Ok(normalized),
        _ => Err(AppError::bad_request(
            "acl must be private/public-read/public-read-write/authenticated-read",
        )),
    }
}

pub(crate) fn normalize_retention_mode(mode: &str) -> Result<String, AppError> {
    let normalized = mode.trim().to_ascii_uppercase();
    match normalized.as_str() {
        "GOVERNANCE" | "COMPLIANCE" => Ok(normalized),
        _ => Err(AppError::bad_request(
            "mode must be GOVERNANCE or COMPLIANCE",
        )),
    }
}

pub(crate) fn normalize_cors_rule(rule: BucketCorsRule) -> Result<BucketCorsRule, AppError> {
    let id = rule.id.trim().to_string();
    if id.is_empty() {
        return Err(AppError::bad_request(
            "CORS 规则 ID 不能为空 / cors rule id cannot be empty",
        ));
    }

    let allowed_origins = rule
        .allowed_origins
        .into_iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if allowed_origins.is_empty() {
        return Err(AppError::bad_request(
            "cors allowed_origins cannot be empty",
        ));
    }

    let allowed_methods = rule
        .allowed_methods
        .into_iter()
        .map(|item| item.trim().to_ascii_uppercase())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if allowed_methods.is_empty() {
        return Err(AppError::bad_request(
            "cors allowed_methods cannot be empty",
        ));
    }

    let allowed_headers = rule
        .allowed_headers
        .into_iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    let expose_headers = rule
        .expose_headers
        .into_iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();

    Ok(BucketCorsRule {
        id,
        allowed_origins,
        allowed_methods,
        allowed_headers,
        expose_headers,
        max_age_seconds: rule.max_age_seconds,
    })
}

pub(crate) fn normalize_bucket_tag(tag: BucketTag) -> Result<BucketTag, AppError> {
    let key = tag.key.trim().to_string();
    if key.is_empty() {
        return Err(AppError::bad_request(
            "标签键不能为空 / tag key cannot be empty",
        ));
    }
    let value = tag.value.trim().to_string();
    Ok(BucketTag { key, value })
}

pub(crate) fn normalize_s3_tagset(
    tags: Vec<BucketTag>,
    allow_empty: bool,
) -> Result<Vec<BucketTag>, &'static str> {
    if tags.is_empty() && !allow_empty {
        return Err("TagSet cannot be empty");
    }

    if tags.len() > 10 {
        return Err("TagSet cannot contain more than 10 tags");
    }

    let mut normalized = Vec::with_capacity(tags.len());
    let mut keys = HashSet::new();
    for tag in tags {
        let key = tag.key.trim().to_string();
        if key.is_empty() {
            return Err("Tag key cannot be empty");
        }
        if key.chars().count() > 128 {
            return Err("Tag key cannot exceed 128 characters");
        }

        let value = tag.value.trim().to_string();
        if value.chars().count() > 256 {
            return Err("Tag value cannot exceed 256 characters");
        }

        if !keys.insert(key.clone()) {
            return Err("Tag keys must be unique");
        }

        normalized.push(BucketTag { key, value });
    }
    Ok(normalized)
}

pub(crate) fn parse_s3_tagging_header(value: &str) -> Result<Vec<BucketTag>, &'static str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let mut tags = Vec::new();
    for (key, value) in parse_query_pairs(trimmed) {
        tags.push(BucketTag { key, value });
    }
    normalize_s3_tagset(tags, true)
}

pub(crate) fn extract_user_metadata(headers: &HeaderMap) -> HashMap<String, String> {
    let mut output = HashMap::new();
    for (name, value) in headers {
        let header_name = name.as_str();
        if !header_name.starts_with("x-amz-meta-") {
            continue;
        }
        let meta_key = header_name
            .trim_start_matches("x-amz-meta-")
            .trim()
            .to_string();
        if meta_key.is_empty() {
            continue;
        }
        if let Ok(meta_value) = value.to_str() {
            output.insert(meta_key, meta_value.to_string());
        }
    }
    output
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SseCustomerHeaderKind {
    Request,
    CopySource,
}

impl SseCustomerHeaderKind {
    fn algorithm_header(self) -> &'static str {
        match self {
            Self::Request => "x-amz-server-side-encryption-customer-algorithm",
            Self::CopySource => "x-amz-copy-source-server-side-encryption-customer-algorithm",
        }
    }

    fn key_header(self) -> &'static str {
        match self {
            Self::Request => "x-amz-server-side-encryption-customer-key",
            Self::CopySource => "x-amz-copy-source-server-side-encryption-customer-key",
        }
    }

    fn key_md5_header(self) -> &'static str {
        match self {
            Self::Request => "x-amz-server-side-encryption-customer-key-md5",
            Self::CopySource => "x-amz-copy-source-server-side-encryption-customer-key-md5",
        }
    }

    fn mode_label(self) -> &'static str {
        match self {
            Self::Request => "SSE-C",
            Self::CopySource => "CopySource SSE-C",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SseCustomerRequest {
    pub(crate) algorithm: String,
    pub(crate) key_md5: String,
}

pub(crate) fn encryption_uses_customer_key(encryption: &S3ObjectEncryptionMeta) -> bool {
    encryption
        .customer_key_md5
        .as_deref()
        .map(str::trim)
        .map(|value| !value.is_empty())
        .unwrap_or(false)
}

pub(crate) fn validate_sse_customer_headers(
    headers: &HeaderMap,
    resource: &str,
    header_kind: SseCustomerHeaderKind,
    supported: bool,
) -> Result<Option<SseCustomerRequest>, Response> {
    let algorithm = header_value(headers, header_kind.algorithm_header());
    let key = header_value(headers, header_kind.key_header());
    let key_md5 = header_value(headers, header_kind.key_md5_header());
    if algorithm.is_none() && key.is_none() && key_md5.is_none() {
        return Ok(None);
    }
    if !supported {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            &format!(
                "当前接口暂不支持 {} / {} is not supported for this operation",
                header_kind.mode_label(),
                header_kind.mode_label()
            ),
            resource,
        ));
    }

    let Some(algorithm) = algorithm else {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            &format!(
                "{} 缺少算法头 / {} requires customer algorithm header",
                header_kind.mode_label(),
                header_kind.mode_label()
            ),
            resource,
        ));
    };
    let Some(key) = key else {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            &format!(
                "{} 缺少客户密钥 / {} requires customer key header",
                header_kind.mode_label(),
                header_kind.mode_label()
            ),
            resource,
        ));
    };

    if !algorithm.eq_ignore_ascii_case("AES256") {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            &format!(
                "{} 仅支持 AES256 / {} only supports AES256",
                header_kind.mode_label(),
                header_kind.mode_label()
            ),
            resource,
        ));
    }

    let key_bytes = BASE64.decode(key.as_bytes()).map_err(|_| {
        s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            &format!(
                "{} 客户密钥必须是 Base64 / {} customer key must be valid Base64",
                header_kind.mode_label(),
                header_kind.mode_label()
            ),
            resource,
        )
    })?;
    if key_bytes.len() != 32 {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            &format!(
                "{} 客户密钥必须是 256 位 / {} customer key must be 256 bits",
                header_kind.mode_label(),
                header_kind.mode_label()
            ),
            resource,
        ));
    }

    let computed_key_md5 = BASE64.encode(Md5::digest(&key_bytes));
    if let Some(provided_key_md5) = key_md5.as_deref() {
        if provided_key_md5 != computed_key_md5 {
            return Err(s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                &format!(
                    "{} 的 Key-MD5 校验失败 / {} key MD5 validation failed",
                    header_kind.mode_label(),
                    header_kind.mode_label()
                ),
                resource,
            ));
        }
    }

    Ok(Some(SseCustomerRequest {
        algorithm: "AES256".to_string(),
        key_md5: computed_key_md5,
    }))
}

pub(crate) fn ensure_sse_customer_access(
    resource: &str,
    encryption: &S3ObjectEncryptionMeta,
    request: Option<&SseCustomerRequest>,
    header_kind: SseCustomerHeaderKind,
) -> Result<(), Response> {
    let expected_key_md5 = encryption
        .customer_key_md5
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match (expected_key_md5, request) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            &format!(
                "对象未启用 SSE-C，不能提供 {} 请求头 / object is not encrypted with SSE-C, {} headers are invalid",
                header_kind.mode_label(),
                header_kind.mode_label()
            ),
            resource,
        )),
        (Some(_), None) => Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            &format!(
                "对象启用了 SSE-C，必须提供 {} 请求头 / object uses SSE-C and requires {} headers",
                header_kind.mode_label(),
                header_kind.mode_label()
            ),
            resource,
        )),
        (Some(expected_key_md5), Some(request)) => {
            if !request.algorithm.eq_ignore_ascii_case("AES256")
                || request.key_md5 != expected_key_md5
            {
                return Err(s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    &format!(
                        "{} 不匹配对象的 SSE-C 密钥 / {} does not match the object's SSE-C key",
                        header_kind.mode_label(),
                        header_kind.mode_label()
                    ),
                    resource,
                ));
            }
            Ok(())
        }
    }
}

pub(crate) fn apply_object_encryption_headers(
    response: &mut Response,
    encryption: &S3ObjectEncryptionMeta,
) {
    if !encryption.enabled || encryption.algorithm.trim().is_empty() {
        return;
    }
    if encryption_uses_customer_key(encryption) {
        if let Ok(value) = HeaderValue::from_str(encryption.algorithm.trim()) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static(
                    "x-amz-server-side-encryption-customer-algorithm",
                ),
                value,
            );
        }
        if let Some(customer_key_md5) = encryption.customer_key_md5.as_deref() {
            if let Ok(value) = HeaderValue::from_str(customer_key_md5) {
                response.headers_mut().insert(
                    axum::http::header::HeaderName::from_static(
                        "x-amz-server-side-encryption-customer-key-md5",
                    ),
                    value,
                );
            }
        }
        return;
    }
    if let Ok(value) = HeaderValue::from_str(encryption.algorithm.trim()) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-server-side-encryption"),
            value,
        );
    }
    if encryption.algorithm.eq_ignore_ascii_case("aws:kms") {
        if let Some(kms_key_id) = encryption.kms_key_id.as_deref() {
            if let Ok(value) = HeaderValue::from_str(kms_key_id) {
                response.headers_mut().insert(
                    axum::http::header::HeaderName::from_static(
                        "x-amz-server-side-encryption-aws-kms-key-id",
                    ),
                    value,
                );
            }
        }
    }
}

pub(crate) fn apply_object_metadata_headers(response: &mut Response, meta: &S3ObjectMeta) {
    let storage_class = object_storage_class(meta);
    if !storage_class.eq_ignore_ascii_case("STANDARD") {
        if let Ok(value) = axum::http::HeaderValue::from_str(storage_class) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-storage-class"),
                value,
            );
        }
    }
    if !meta.tags.is_empty() {
        if let Ok(value) = axum::http::HeaderValue::from_str(&meta.tags.len().to_string()) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-tagging-count"),
                value,
            );
        }
    }
    if let Some(value) = object_restore_header_value(meta) {
        if let Ok(value) = axum::http::HeaderValue::from_str(&value) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-restore"),
                value,
            );
        }
    }

    for (key, value) in &meta.user_metadata {
        let header_name = format!("x-amz-meta-{key}");
        let Ok(header_name) = axum::http::header::HeaderName::from_bytes(header_name.as_bytes())
        else {
            continue;
        };
        let Ok(header_value) = axum::http::HeaderValue::from_str(value) else {
            continue;
        };
        response.headers_mut().insert(header_name, header_value);
    }
    apply_object_encryption_headers(response, &meta.encryption);
}

pub(crate) fn object_restore_is_active(meta: &S3ObjectMeta) -> bool {
    let Some(restore) = meta.restore.as_ref() else {
        return false;
    };
    if restore.ongoing_request {
        return false;
    }
    restore
        .expiry_at
        .map(|value| value > Utc::now())
        .unwrap_or(false)
}

pub(crate) fn object_restore_header_value(meta: &S3ObjectMeta) -> Option<String> {
    let restore = meta.restore.as_ref()?;
    if restore.ongoing_request {
        return Some(r#"ongoing-request="true""#.to_string());
    }
    let expiry_at = restore.expiry_at?;
    if expiry_at <= Utc::now() {
        return None;
    }
    Some(format!(
        r#"ongoing-request="false", expiry-date="{}""#,
        format_http_date(expiry_at)
    ))
}

pub(crate) fn build_storage_inventory_entry(
    meta: S3ObjectMeta,
    is_current: bool,
) -> StorageInventoryEntry {
    let restored = object_restore_is_active(&meta);
    let restore_remaining_seconds = meta
        .restore
        .as_ref()
        .and_then(|item| item.expiry_at)
        .map(|expiry_at| (expiry_at - Utc::now()).num_seconds())
        .filter(|seconds| *seconds > 0);
    let restore_expiring_soon = restore_remaining_seconds
        .map(|seconds| seconds <= 3_600)
        .unwrap_or(false);
    StorageInventoryEntry {
        bucket: meta.bucket.clone(),
        object_key: meta.key.clone(),
        version_id: meta.version_id.clone(),
        is_current,
        size: meta.size,
        storage_class: object_storage_class(&meta).to_string(),
        remote_tier: meta.remote_tier.as_ref().map(|item| item.tier.clone()),
        remote_storage_class: meta
            .remote_tier
            .as_ref()
            .map(|item| item.storage_class.clone()),
        created_at: meta.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        archive_state: storage_archive_state(&meta).to_string(),
        restored,
        restore_ongoing: meta
            .restore
            .as_ref()
            .map(|item| item.ongoing_request)
            .unwrap_or(false),
        restore_requested_at: meta.restore.as_ref().and_then(|item| {
            item.requested_at
                .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true))
        }),
        restore_expiry: meta.restore.as_ref().and_then(|item| {
            item.expiry_at
                .filter(|value| *value > Utc::now())
                .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true))
        }),
        restore_remaining_seconds,
        restore_expiring_soon,
        tiering_age_seconds: meta
            .remote_tier
            .as_ref()
            .map(|item| (Utc::now() - item.transitioned_at).num_seconds().max(0)),
    }
}

pub(crate) fn storage_restore_state(meta: &S3ObjectMeta) -> &'static str {
    match meta.restore.as_ref() {
        Some(restore) if restore.ongoing_request => "restoring",
        Some(_) if object_restore_is_active(meta) => "restored",
        Some(_) => "expired",
        None => "none",
    }
}

pub(crate) fn storage_archive_state(meta: &S3ObjectMeta) -> &'static str {
    if meta.remote_tier.is_none() {
        "hot"
    } else {
        match storage_restore_state(meta) {
            "restoring" => "restore-in-progress",
            "restored" => "restored-hot-copy",
            "expired" => "cold-remote-expired",
            _ => "cold-remote",
        }
    }
}

pub(crate) fn normalize_storage_restore_state_filter(
    value: Option<&str>,
) -> Result<Option<String>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(None);
    }
    match normalized.as_str() {
        "none" | "restoring" | "restored" | "expired" => Ok(Some(normalized)),
        _ => Err(AppError::bad_request(
            "restore_state 仅支持 none/restoring/restored/expired / restore_state must be one of none, restoring, restored, expired",
        )),
    }
}

pub(crate) fn storage_inventory_requires_remote(query: &StorageInventoryQuery) -> bool {
    query.remote_only.unwrap_or(false)
        || query
            .tier
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        || query.restored_only.unwrap_or(false)
        || query
            .restore_state
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        || query.restore_expiring_within_minutes.is_some()
}

pub(crate) fn storage_inventory_matches_filters(
    meta: &S3ObjectMeta,
    is_current: bool,
    prefix: &str,
    query: &StorageInventoryQuery,
    normalized_tier: Option<&str>,
    normalized_restore_state: Option<&str>,
) -> bool {
    let current_only = query.current_only.unwrap_or(false);
    let noncurrent_only = query.noncurrent_only.unwrap_or(false);
    if current_only && !is_current {
        return false;
    }
    if noncurrent_only && is_current {
        return false;
    }
    if meta.delete_marker || !meta.key.starts_with(prefix) {
        return false;
    }
    if storage_inventory_requires_remote(query) && meta.remote_tier.is_none() {
        return false;
    }
    if let Some(tier) = normalized_tier {
        if meta
            .remote_tier
            .as_ref()
            .map(|item| !item.tier.eq_ignore_ascii_case(tier))
            .unwrap_or(true)
        {
            return false;
        }
    }
    if query.restored_only.unwrap_or(false) && !object_restore_is_active(meta) {
        return false;
    }
    if let Some(state) = normalized_restore_state {
        if storage_restore_state(meta) != state {
            return false;
        }
    }
    if let Some(minutes) = query.restore_expiring_within_minutes {
        let within = (minutes.min(7 * 24 * 60) as i64) * 60;
        let Some(remaining) = meta
            .restore
            .as_ref()
            .and_then(|item| item.expiry_at)
            .map(|expiry_at| (expiry_at - Utc::now()).num_seconds())
            .filter(|seconds| *seconds > 0)
        else {
            return false;
        };
        if remaining > within {
            return false;
        }
    }
    true
}

pub(crate) async fn collect_storage_inventory_candidates(
    state: &Arc<AppState>,
    query: &StorageInventoryQuery,
) -> Result<Vec<StorageInventoryCandidate>, AppError> {
    let current_only = query.current_only.unwrap_or(false);
    let noncurrent_only = query.noncurrent_only.unwrap_or(false);
    if current_only && noncurrent_only {
        return Err(AppError::bad_request(
            "current_only 与 noncurrent_only 不能同时为 true / current_only and noncurrent_only cannot both be true",
        ));
    }
    if matches!(query.limit, Some(0)) {
        return Err(AppError::bad_request(
            "inventory limit 必须大于 0 / inventory limit must be greater than 0",
        ));
    }

    let prefix = query.prefix.clone().unwrap_or_default();
    let requested_bucket = query.bucket.clone();
    let normalized_tier = query
        .tier
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let normalized_restore_state =
        normalize_storage_restore_state_filter(query.restore_state.as_deref())?;
    let mut buckets = if let Some(bucket) = requested_bucket.clone() {
        vec![bucket]
    } else {
        state
            .buckets
            .read()
            .await
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    };
    buckets.sort();

    let mut entries = Vec::new();
    let mut seen_versions = HashSet::new();
    for bucket in buckets {
        let bucket_root = bucket_path(state, &bucket)
            .map_err(|_| AppError::bad_request("存储桶名称无效 / invalid bucket name"))?;
        let bucket_exists = tokio::fs::try_exists(&bucket_root).await.unwrap_or(false);
        if !bucket_exists {
            if requested_bucket.is_some() {
                return Err(AppError::not_found("存储桶不存在 / bucket not found"));
            }
            continue;
        }

        if !noncurrent_only {
            for meta in scan_bucket_current_object_meta_from_disk(&bucket_root, &bucket).await {
                if !storage_inventory_matches_filters(
                    &meta,
                    true,
                    &prefix,
                    query,
                    normalized_tier,
                    normalized_restore_state.as_deref(),
                ) {
                    continue;
                }
                let version_identity = (
                    meta.bucket.clone(),
                    meta.key.clone(),
                    meta.version_id.clone(),
                );
                if seen_versions.insert(version_identity) {
                    entries.push(StorageInventoryCandidate {
                        meta,
                        is_current: true,
                    });
                }
            }
        }

        if !current_only {
            for meta in scan_bucket_archived_object_meta_from_disk(&bucket_root, &bucket).await {
                if !storage_inventory_matches_filters(
                    &meta,
                    false,
                    &prefix,
                    query,
                    normalized_tier,
                    normalized_restore_state.as_deref(),
                ) {
                    continue;
                }
                let version_identity = (
                    meta.bucket.clone(),
                    meta.key.clone(),
                    meta.version_id.clone(),
                );
                if seen_versions.insert(version_identity) {
                    entries.push(StorageInventoryCandidate {
                        meta,
                        is_current: false,
                    });
                }
            }
        }
    }

    entries.sort_by(|left, right| {
        left.meta
            .bucket
            .cmp(&right.meta.bucket)
            .then(left.meta.key.cmp(&right.meta.key))
            .then(right.is_current.cmp(&left.is_current))
            .then(right.meta.created_at.cmp(&left.meta.created_at))
    });
    if let Some(limit) = query.limit {
        entries.truncate(limit);
    }
    Ok(entries)
}

pub(crate) fn build_storage_inventory_csv(
    entries: &[StorageInventoryEntry],
) -> Result<String, AppError> {
    let mut writer = WriterBuilder::new().from_writer(vec![]);
    writer
        .write_record([
            "bucket",
            "object_key",
            "version_id",
            "is_current",
            "size",
            "storage_class",
            "remote_tier",
            "remote_storage_class",
            "created_at",
            "archive_state",
            "restored",
            "restore_ongoing",
            "restore_requested_at",
            "restore_expiry",
            "restore_remaining_seconds",
            "restore_expiring_soon",
            "tiering_age_seconds",
        ])
        .map_err(|err| {
            AppError::internal(format!(
                "写入 inventory CSV 头失败 / failed to write inventory csv header: {err}"
            ))
        })?;
    for entry in entries {
        writer
            .write_record([
                entry.bucket.as_str(),
                entry.object_key.as_str(),
                entry.version_id.as_str(),
                if entry.is_current { "true" } else { "false" },
                &entry.size.to_string(),
                entry.storage_class.as_str(),
                entry.remote_tier.as_deref().unwrap_or(""),
                entry.remote_storage_class.as_deref().unwrap_or(""),
                entry.created_at.as_str(),
                entry.archive_state.as_str(),
                if entry.restored { "true" } else { "false" },
                if entry.restore_ongoing {
                    "true"
                } else {
                    "false"
                },
                entry.restore_requested_at.as_deref().unwrap_or(""),
                entry.restore_expiry.as_deref().unwrap_or(""),
                &entry
                    .restore_remaining_seconds
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                if entry.restore_expiring_soon {
                    "true"
                } else {
                    "false"
                },
                &entry
                    .tiering_age_seconds
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            ])
            .map_err(|err| {
                AppError::internal(format!(
                    "写入 inventory CSV 行失败 / failed to write inventory csv row: {err}"
                ))
            })?;
    }
    String::from_utf8(writer.into_inner().map_err(|err| {
        AppError::internal(format!(
            "导出 inventory CSV 失败 / failed to finalize inventory csv export: {err}"
        ))
    })?)
    .map_err(|err| {
        AppError::internal(format!(
            "inventory CSV 编码失败 / failed to encode inventory csv as utf-8: {err}"
        ))
    })
}

pub(crate) fn storage_inventory_filters_json(query: &StorageInventoryQuery) -> Value {
    json!({
        "bucket": query.bucket,
        "prefix": query.prefix,
        "current_only": query.current_only.unwrap_or(false),
        "noncurrent_only": query.noncurrent_only.unwrap_or(false),
        "remote_only": query.remote_only.unwrap_or(false),
        "tier": query.tier,
        "restore_state": query.restore_state,
        "restored_only": query.restored_only.unwrap_or(false),
        "restore_expiring_within_minutes": query.restore_expiring_within_minutes,
        "limit": query.limit,
    })
}

pub(crate) fn build_storage_archive_report_from_entries(
    query: &StorageInventoryQuery,
    entries: &[StorageInventoryEntry],
) -> StorageArchiveReport {
    let mut by_tier: HashMap<String, StorageArchiveTierSummary> = HashMap::new();
    let mut remote_objects = 0usize;
    let mut remote_bytes = 0u64;
    let mut current_versions = 0usize;
    let mut noncurrent_versions = 0usize;
    let mut cold_objects = 0usize;
    let mut restoring_objects = 0usize;
    let mut restored_objects = 0usize;
    let mut expired_restore_objects = 0usize;
    let mut expiring_soon_objects = 0usize;

    for entry in entries {
        if entry.is_current {
            current_versions += 1;
        } else {
            noncurrent_versions += 1;
        }
        if entry.remote_tier.is_none() {
            continue;
        }
        remote_objects += 1;
        remote_bytes = remote_bytes.saturating_add(entry.size);
        if entry.restore_ongoing {
            restoring_objects += 1;
        } else if entry.restored {
            restored_objects += 1;
        } else if entry.archive_state == "cold-remote-expired" {
            expired_restore_objects += 1;
        } else {
            cold_objects += 1;
        }
        if entry.restore_expiring_soon {
            expiring_soon_objects += 1;
        }
        let tier = entry
            .remote_tier
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let summary = by_tier
            .entry(tier.clone())
            .or_insert(StorageArchiveTierSummary {
                tier,
                objects: 0,
                bytes: 0,
                current_versions: 0,
                noncurrent_versions: 0,
                restoring_objects: 0,
                restored_objects: 0,
                expiring_soon_objects: 0,
            });
        summary.objects += 1;
        summary.bytes = summary.bytes.saturating_add(entry.size);
        if entry.is_current {
            summary.current_versions += 1;
        } else {
            summary.noncurrent_versions += 1;
        }
        if entry.restore_ongoing {
            summary.restoring_objects += 1;
        }
        if entry.restored {
            summary.restored_objects += 1;
        }
        if entry.restore_expiring_soon {
            summary.expiring_soon_objects += 1;
        }
    }
    let mut tiers = by_tier.into_values().collect::<Vec<_>>();
    tiers.sort_by(|left, right| left.tier.cmp(&right.tier));

    StorageArchiveReport {
        generated_at: Utc::now(),
        filters: storage_inventory_filters_json(query),
        summary: StorageArchiveSummary {
            total_objects: entries.len(),
            remote_objects,
            remote_bytes,
            current_versions,
            noncurrent_versions,
            cold_objects,
            restoring_objects,
            restored_objects,
            expired_restore_objects,
            expiring_soon_objects,
            tiers,
        },
        items: entries.to_vec(),
    }
}

pub(crate) fn build_storage_archive_report_csv(
    report: &StorageArchiveReport,
) -> Result<String, AppError> {
    build_storage_inventory_csv(&report.items)
}

pub(crate) fn normalize_sse_algorithm(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "aes256" => Some("AES256"),
        "aws:kms" => Some("aws:kms"),
        _ => None,
    }
}

pub(crate) async fn resolve_object_encryption_meta(
    state: &Arc<AppState>,
    bucket: &str,
    headers: &HeaderMap,
    resource: &str,
    allow_sse_customer: bool,
) -> Result<S3ObjectEncryptionMeta, Response> {
    let sse_customer_request = validate_sse_customer_headers(
        headers,
        resource,
        SseCustomerHeaderKind::Request,
        allow_sse_customer,
    )?;
    let request_algorithm = headers
        .get("x-amz-server-side-encryption")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let request_kms_key_id = headers
        .get("x-amz-server-side-encryption-aws-kms-key-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    if request_algorithm.is_none() && request_kms_key_id.is_some() {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "x-amz-server-side-encryption is required when x-amz-server-side-encryption-aws-kms-key-id is set",
            resource,
        ));
    }
    if sse_customer_request.is_some()
        && (request_algorithm.is_some() || request_kms_key_id.is_some())
    {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "SSE-C cannot be combined with x-amz-server-side-encryption headers",
            resource,
        ));
    }

    let bucket_default = state.bucket_encryptions.read().await.get(bucket).cloned();
    if let Some(sse_customer_request) = sse_customer_request {
        return Ok(S3ObjectEncryptionMeta {
            enabled: true,
            algorithm: sse_customer_request.algorithm,
            customer_key_md5: Some(sse_customer_request.key_md5),
            kms_key_id: None,
            nonce_base64: None,
            wrapped_key_base64: None,
        });
    }
    if let Some(algorithm) = request_algorithm {
        let Some(normalized) = normalize_sse_algorithm(&algorithm) else {
            return Err(s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "x-amz-server-side-encryption must be AES256 or aws:kms",
                resource,
            ));
        };
        if normalized == "AES256" && request_kms_key_id.is_some() {
            return Err(s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "x-amz-server-side-encryption-aws-kms-key-id requires x-amz-server-side-encryption=aws:kms",
                resource,
            ));
        }
        let kms_key_id = if normalized == "aws:kms" {
            request_kms_key_id
                .or_else(|| {
                    bucket_default
                        .as_ref()
                        .and_then(|config| config.kms_key_id.clone())
                })
                .or_else(|| Some("rustio-default-kms-key".to_string()))
        } else {
            None
        };
        let meta = S3ObjectEncryptionMeta {
            enabled: true,
            algorithm: normalized.to_string(),
            customer_key_md5: None,
            kms_key_id,
            nonce_base64: None,
            wrapped_key_base64: None,
        };
        ensure_kms_runtime_ready_for_encryption(state, resource, &meta).await?;
        return Ok(meta);
    }

    if let Some(default_config) = bucket_default.filter(|item| item.enabled) {
        let Some(normalized) = normalize_sse_algorithm(&default_config.algorithm) else {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "Bucket default encryption algorithm is invalid",
                resource,
            ));
        };
        let kms_key_id = if normalized == "aws:kms" {
            default_config
                .kms_key_id
                .or_else(|| Some("rustio-default-kms-key".to_string()))
        } else {
            None
        };
        let meta = S3ObjectEncryptionMeta {
            enabled: true,
            algorithm: normalized.to_string(),
            customer_key_md5: None,
            kms_key_id,
            nonce_base64: None,
            wrapped_key_base64: None,
        };
        ensure_kms_runtime_ready_for_encryption(state, resource, &meta).await?;
        return Ok(meta);
    }

    Ok(S3ObjectEncryptionMeta::default())
}

pub(crate) async fn ensure_kms_runtime_ready_for_encryption(
    state: &Arc<AppState>,
    resource: &str,
    encryption: &S3ObjectEncryptionMeta,
) -> Result<(), Response> {
    if !encryption.enabled || !encryption.algorithm.eq_ignore_ascii_case("aws:kms") {
        return Ok(());
    }
    if !kms_external_enabled() {
        return Ok(());
    }
    let endpoint = state
        .security
        .read()
        .await
        .kms_endpoint
        .trim()
        .trim_end_matches('/')
        .to_string();
    if kms_endpoint_valid(&endpoint) {
        return Ok(());
    }
    mark_kms_health_failure(
        state.as_ref(),
        bilingual_s3_message(
            "KMSNotConfigured",
            "KMS endpoint is not configured for external mode",
        ),
    )
    .await;
    Err(s3_kms_not_configured(
        resource,
        "KMS endpoint is not configured for external mode",
    ))
}

pub(crate) fn normalize_bucket_encryption(
    mut config: BucketEncryptionConfig,
) -> Result<BucketEncryptionConfig, AppError> {
    config.algorithm = match config.algorithm.trim().to_ascii_lowercase().as_str() {
        "aes256" => "AES256".to_string(),
        "aws:kms" => "aws:kms".to_string(),
        _ => {
            return Err(AppError::bad_request(
                "算法必须是 AES256 或 aws:kms / algorithm must be AES256 or aws:kms",
            ))
        }
    };
    config.kms_key_id = config
        .kms_key_id
        .and_then(|value| (!value.trim().is_empty()).then(|| value.trim().to_string()));
    Ok(config)
}

pub(crate) fn normalize_notification_rule(
    mut rule: BucketNotificationRule,
) -> Result<BucketNotificationRule, AppError> {
    rule.id = rule.id.trim().to_string();
    if rule.id.is_empty() {
        return Err(AppError::bad_request(
            "notification rule id cannot be empty",
        ));
    }
    rule.event = rule.event.trim().to_string();
    if rule.event.is_empty() {
        return Err(AppError::bad_request(
            "notification rule event cannot be empty",
        ));
    }
    rule.target = rule.target.trim().to_string();
    if rule.target.is_empty() {
        return Err(AppError::bad_request(
            "notification rule target cannot be empty",
        ));
    }
    rule.prefix = rule
        .prefix
        .and_then(|value| (!value.trim().is_empty()).then(|| value.trim().to_string()));
    rule.suffix = rule
        .suffix
        .and_then(|value| (!value.trim().is_empty()).then(|| value.trim().to_string()));
    Ok(rule)
}

pub(crate) fn normalize_lifecycle_status(status: &str) -> Result<String, AppError> {
    let normalized = status.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "enabled" => Ok("Enabled".to_string()),
        "disabled" => Ok("Disabled".to_string()),
        _ => Err(AppError::bad_request(
            "lifecycle status must be Enabled or Disabled",
        )),
    }
}

pub(crate) fn normalize_remote_tier_name(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

pub(crate) fn default_storage_class() -> String {
    "STANDARD".to_string()
}

pub(crate) fn object_storage_class(meta: &S3ObjectMeta) -> &str {
    if meta.storage_class.trim().is_empty() {
        "STANDARD"
    } else {
        meta.storage_class.trim()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteTierBackendKind {
    Filesystem,
    S3Compatible,
    Minio,
    AzureBlob,
    Gcs,
}

pub(crate) fn normalize_remote_tier_backend(value: &str) -> Result<String, AppError> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" | "filesystem" | "file" => Ok("filesystem".to_string()),
        "s3-compatible" | "s3_compatible" | "s3" => Ok("s3-compatible".to_string()),
        "minio" => Ok("minio".to_string()),
        "azure-blob" | "azure_blob" | "azure" => Ok("azure-blob".to_string()),
        "gcs" | "google-cloud-storage" | "google_cloud_storage" => Ok("gcs".to_string()),
        _ => Err(AppError::bad_request(
            "远端层 backend 必须是 filesystem、s3-compatible、minio、azure-blob 或 gcs / remote tier backend must be filesystem, s3-compatible, minio, azure-blob, or gcs",
        )),
    }
}

pub(crate) fn remote_tier_backend_kind(
    config: &RemoteTierConfig,
) -> Result<RemoteTierBackendKind, String> {
    match config.backend.trim().to_ascii_lowercase().as_str() {
        "" | "filesystem" | "file" => Ok(RemoteTierBackendKind::Filesystem),
        "s3-compatible" | "s3_compatible" | "s3" => Ok(RemoteTierBackendKind::S3Compatible),
        "minio" => Ok(RemoteTierBackendKind::Minio),
        "azure-blob" | "azure_blob" | "azure" => Ok(RemoteTierBackendKind::AzureBlob),
        "gcs" | "google-cloud-storage" | "google_cloud_storage" => Ok(RemoteTierBackendKind::Gcs),
        other => Err(format!(
            "远端层 backend 不支持：{other} / unsupported remote tier backend: {other}"
        )),
    }
}

pub(crate) fn normalize_remote_tier_health_status(value: &str, enabled: bool) -> String {
    if !enabled {
        return "paused".to_string();
    }
    match value.trim().to_ascii_lowercase().as_str() {
        "healthy" => "healthy".to_string(),
        "degraded" => "degraded".to_string(),
        "paused" => "paused".to_string(),
        _ => "unknown".to_string(),
    }
}

pub(crate) fn normalize_remote_tier_headers(
    headers: HashMap<String, String>,
) -> Result<HashMap<String, String>, AppError> {
    let mut normalized = HashMap::new();
    for (key, value) in headers {
        let key = key.trim();
        if key.is_empty() {
            return Err(AppError::bad_request(
                "远端层请求头名称不能为空 / remote tier header name cannot be empty",
            ));
        }
        normalized.insert(key.to_string(), value.trim().to_string());
    }
    Ok(normalized)
}

pub(crate) fn normalize_remote_tier_config(
    mut tier: RemoteTierConfig,
) -> Result<RemoteTierConfig, AppError> {
    let name = normalize_remote_tier_name(&tier.name);
    if name.is_empty() {
        return Err(AppError::bad_request(
            "远端层名称不能为空 / remote tier name cannot be empty",
        ));
    }
    let backend = normalize_remote_tier_backend(&tier.backend)?;
    let endpoint = tier.endpoint.trim().to_string();
    if endpoint.is_empty() {
        return Err(AppError::bad_request(
            "远端层端点不能为空 / remote tier endpoint cannot be empty",
        ));
    }
    match backend.as_str() {
        "filesystem" => {
            if endpoint.contains("://") && !endpoint.starts_with("file://") {
                return Err(AppError::bad_request(
                    "filesystem 远端层仅支持 file:// 或文件路径 / filesystem remote tier supports only file:// or filesystem paths",
                ));
            }
        }
        _ => {
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(AppError::bad_request(
                    "HTTP 远端层必须使用 http:// 或 https:// 端点 / http remote tiers require http:// or https:// endpoints",
                ));
            }
        }
    }
    let storage_class = if tier.storage_class.trim().is_empty() {
        name.clone()
    } else {
        tier.storage_class.trim().to_ascii_uppercase()
    };
    tier.name = name;
    tier.backend = backend;
    tier.endpoint = endpoint;
    tier.prefix = tier
        .prefix
        .and_then(|value| (!value.trim().is_empty()).then(|| value.trim().to_string()));
    tier.storage_class = storage_class;
    tier.credential_key = normalize_optional_text(tier.credential_key);
    tier.credential_secret = normalize_optional_text(tier.credential_secret);
    tier.credential_token = normalize_optional_text(tier.credential_token);
    if tier.credential_key.is_some() ^ tier.credential_secret.is_some() {
        return Err(AppError::bad_request(
            "远端层账号认证需要同时提供 credential_key 与 credential_secret / remote tier basic auth requires both credential_key and credential_secret",
        ));
    }
    tier.extra_headers = normalize_remote_tier_headers(tier.extra_headers)?;
    tier.health_status = normalize_remote_tier_health_status(&tier.health_status, tier.enabled);
    Ok(tier)
}

pub(crate) fn normalize_lifecycle_rule(
    mut rule: BucketLifecycleRule,
) -> Result<BucketLifecycleRule, AppError> {
    let id = rule.id.trim().to_string();
    if id.is_empty() {
        return Err(AppError::bad_request(
            "生命周期规则 ID 不能为空 / lifecycle rule id cannot be empty",
        ));
    }
    rule.id = id;
    rule.status = normalize_lifecycle_status(&rule.status)?;
    rule.prefix = rule
        .prefix
        .and_then(|value| (!value.trim().is_empty()).then(|| value.trim().to_string()));
    rule.transition_tier = rule
        .transition_tier
        .and_then(|value| (!value.trim().is_empty()).then(|| normalize_remote_tier_name(&value)));
    rule.noncurrent_transition_tier = rule
        .noncurrent_transition_tier
        .and_then(|value| (!value.trim().is_empty()).then(|| normalize_remote_tier_name(&value)));

    if rule.transition_days.is_some() != rule.transition_tier.is_some() {
        return Err(AppError::bad_request(
            "transition_days 与 transition_tier 必须同时设置 / transition_days and transition_tier must be set together",
        ));
    }
    if rule.noncurrent_transition_days.is_some() != rule.noncurrent_transition_tier.is_some() {
        return Err(AppError::bad_request(
            "noncurrent_transition_days 与 noncurrent_transition_tier 必须同时设置 / noncurrent_transition_days and noncurrent_transition_tier must be set together",
        ));
    }

    if rule.expiration_days.is_none()
        && rule.noncurrent_expiration_days.is_none()
        && rule.transition_days.is_none()
        && rule.noncurrent_transition_days.is_none()
    {
        return Err(AppError::bad_request(
            "生命周期规则至少要定义过期或转层条件 / lifecycle rule must define expiration or transition settings",
        ));
    }
    Ok(rule)
}

pub(crate) async fn get_bucket_object_lock(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<BucketObjectLockConfig>>, AppError> {
    auth.require(Permission::BucketRead)?;
    let bucket = state
        .buckets
        .read()
        .await
        .get(&name)
        .cloned()
        .ok_or_else(|| AppError::not_found("存储桶不存在 / bucket not found"))?;

    let config = state
        .bucket_object_locks
        .read()
        .await
        .get(&name)
        .cloned()
        .unwrap_or_else(|| default_object_lock_config(&bucket));
    Ok(wrap(config))
}

pub(crate) async fn update_bucket_object_lock(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(mut body): Json<BucketObjectLockConfig>,
) -> Result<Json<ApiEnvelope<BucketObjectLockConfig>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    body.mode = normalize_retention_mode(&body.mode)?;
    if body.default_retention_days == 0 {
        return Err(AppError::bad_request(
            "default_retention_days 必须大于 0 / default_retention_days must be > 0",
        ));
    }

    {
        let mut buckets = state.buckets.write().await;
        let bucket = buckets
            .get_mut(&name)
            .ok_or_else(|| AppError::not_found("存储桶不存在 / bucket not found"))?;
        bucket.object_lock = body.enabled;
    }
    state
        .bucket_object_locks
        .write()
        .await
        .insert(name.clone(), body.clone());

    state
        .append_audit(
            &auth.username,
            "bucket.object_lock.update",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({
                "enabled": body.enabled,
                "mode": body.mode,
                "default_retention_days": body.default_retention_days,
            }),
        )
        .await;
    Ok(wrap(body))
}

pub(crate) async fn get_bucket_retention(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<BucketRetentionConfig>>, AppError> {
    auth.require(Permission::BucketRead)?;
    if !state.buckets.read().await.contains_key(&name) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }
    let config = state
        .bucket_retentions
        .read()
        .await
        .get(&name)
        .cloned()
        .unwrap_or_else(default_retention_config);
    Ok(wrap(config))
}

pub(crate) async fn update_bucket_retention(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(mut body): Json<BucketRetentionConfig>,
) -> Result<Json<ApiEnvelope<BucketRetentionConfig>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    body.mode = normalize_retention_mode(&body.mode)?;
    if body.duration_days == 0 {
        return Err(AppError::bad_request(
            "duration_days 必须大于 0 / duration_days must be > 0",
        ));
    }
    if !state.buckets.read().await.contains_key(&name) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }
    state
        .bucket_retentions
        .write()
        .await
        .insert(name.clone(), body.clone());

    state
        .append_audit(
            &auth.username,
            "bucket.retention.update",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({
                "enabled": body.enabled,
                "mode": body.mode,
                "duration_days": body.duration_days,
            }),
        )
        .await;
    Ok(wrap(body))
}

pub(crate) async fn get_bucket_legal_hold(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<BucketLegalHoldConfig>>, AppError> {
    auth.require(Permission::BucketRead)?;
    if !state.buckets.read().await.contains_key(&name) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }
    let config = state
        .bucket_legal_holds
        .read()
        .await
        .get(&name)
        .cloned()
        .unwrap_or_else(default_legal_hold_config);
    Ok(wrap(config))
}

pub(crate) async fn update_bucket_legal_hold(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<BucketLegalHoldConfig>,
) -> Result<Json<ApiEnvelope<BucketLegalHoldConfig>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    if !state.buckets.read().await.contains_key(&name) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }
    state
        .bucket_legal_holds
        .write()
        .await
        .insert(name.clone(), body.clone());

    state
        .append_audit(
            &auth.username,
            "bucket.legal_hold.update",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({ "enabled": body.enabled }),
        )
        .await;
    Ok(wrap(body))
}

pub(crate) async fn list_bucket_notifications(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<Vec<BucketNotificationRule>>>, AppError> {
    auth.require(Permission::BucketRead)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;
    let mut cached = state.bucket_notifications.read().await.get(&name).cloned();
    if cached.is_none() {
        let path = bucket_notifications_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed = serde_json::from_slice::<Vec<BucketNotificationRule>>(&bytes)
                    .map_err(|err| {
                        AppError::internal(format!(
                            "解析存储桶通知配置失败 / failed to decode bucket notifications: {err}"
                        ))
                    })?;
                state
                    .bucket_notifications
                    .write()
                    .await
                    .insert(name.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(AppError::internal(format!(
                    "读取存储桶通知配置失败 / failed to read bucket notifications: {err}"
                )))
            }
        }
    }
    let rules = cached.unwrap_or_default();
    Ok(wrap(rules))
}

pub(crate) async fn update_bucket_notifications(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<Vec<BucketNotificationRule>>,
) -> Result<Json<ApiEnvelope<Vec<BucketNotificationRule>>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;

    let mut normalized = Vec::with_capacity(body.len());
    let mut seen_ids = HashSet::new();
    for rule in body {
        let normalized_rule = normalize_notification_rule(rule)?;
        if !seen_ids.insert(normalized_rule.id.clone()) {
            return Err(AppError::bad_request(
                "通知规则 ID 必须唯一 / notification rule id must be unique",
            ));
        }
        normalized.push(normalized_rule);
    }

    write_pretty_json_file(&bucket_notifications_path(&bucket_dir), &normalized).await?;

    state
        .bucket_notifications
        .write()
        .await
        .insert(name.clone(), normalized.clone());

    state
        .append_audit(
            &auth.username,
            "bucket.notifications.update",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({ "rules": normalized.len() }),
        )
        .await;
    Ok(wrap(normalized))
}

pub(crate) async fn get_bucket_acl(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<BucketAclConfig>>, AppError> {
    auth.require(Permission::BucketRead)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;

    let mut cached = state.bucket_acls.read().await.get(&name).cloned();
    if cached.is_none() {
        let path = bucket_acl_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed = serde_json::from_slice::<BucketAclConfig>(&bytes).map_err(|err| {
                    AppError::internal(format!(
                        "解析存储桶 ACL 失败 / failed to decode bucket acl: {err}"
                    ))
                })?;
                state
                    .bucket_acls
                    .write()
                    .await
                    .insert(name.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(AppError::internal(format!(
                    "读取存储桶 ACL 失败 / failed to read bucket acl: {err}"
                )))
            }
        }
    }

    Ok(wrap(cached.unwrap_or_else(default_bucket_acl_config)))
}

pub(crate) async fn update_bucket_acl(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(mut body): Json<BucketAclConfig>,
) -> Result<Json<ApiEnvelope<BucketAclConfig>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;
    body.acl = normalize_bucket_acl_value(&body.acl)?;

    write_pretty_json_file(&bucket_acl_path(&bucket_dir), &body).await?;
    state
        .bucket_acls
        .write()
        .await
        .insert(name.clone(), body.clone());

    state
        .append_audit(
            &auth.username,
            "bucket.acl.update",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({ "acl": body.acl }),
        )
        .await;
    Ok(wrap(body))
}

pub(crate) async fn get_bucket_public_access_block(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<BucketPublicAccessBlockConfig>>, AppError> {
    auth.require(Permission::BucketRead)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;

    let mut cached = state
        .bucket_public_access_blocks
        .read()
        .await
        .get(&name)
        .cloned();
    if cached.is_none() {
        let path = bucket_public_access_block_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed = serde_json::from_slice::<BucketPublicAccessBlockConfig>(&bytes)
                    .map_err(|err| {
                        AppError::internal(format!("解析公共访问阻止配置失败 / failed to decode public access block: {err}"))
                    })?;
                state
                    .bucket_public_access_blocks
                    .write()
                    .await
                    .insert(name.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(AppError::internal(format!(
                    "读取公共访问阻止配置失败 / failed to read public access block: {err}"
                )))
            }
        }
    }

    Ok(wrap(
        cached.unwrap_or_else(default_bucket_public_access_block_config),
    ))
}

pub(crate) async fn update_bucket_public_access_block(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<BucketPublicAccessBlockConfig>,
) -> Result<Json<ApiEnvelope<BucketPublicAccessBlockConfig>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;

    write_pretty_json_file(&bucket_public_access_block_path(&bucket_dir), &body).await?;
    state
        .bucket_public_access_blocks
        .write()
        .await
        .insert(name.clone(), body.clone());

    state
        .append_audit(
            &auth.username,
            "bucket.public_access_block.update",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({
                "block_public_acls": body.block_public_acls,
                "ignore_public_acls": body.ignore_public_acls,
                "block_public_policy": body.block_public_policy,
                "restrict_public_buckets": body.restrict_public_buckets,
            }),
        )
        .await;
    Ok(wrap(body))
}

pub(crate) async fn delete_bucket_public_access_block(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;
    state
        .bucket_public_access_blocks
        .write()
        .await
        .remove(&name);
    let path = bucket_public_access_block_path(&bucket_dir);
    if let Err(err) = tokio::fs::remove_file(path).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(AppError::internal(format!(
                "删除公共访问阻止配置失败 / failed to delete public access block: {err}"
            )));
        }
    }
    state
        .append_audit(
            &auth.username,
            "bucket.public_access_block.delete",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "name": name })))
}

pub(crate) async fn list_bucket_lifecycle_rules(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<Vec<BucketLifecycleRule>>>, AppError> {
    auth.require(Permission::BucketRead)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;

    let mut cached = state
        .bucket_lifecycle_rules
        .read()
        .await
        .get(&name)
        .cloned();
    if cached.is_none() {
        let path = bucket_lifecycle_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed =
                    serde_json::from_slice::<Vec<BucketLifecycleRule>>(&bytes).map_err(|err| {
                        AppError::internal(format!(
                            "解析生命周期规则失败 / failed to decode lifecycle rules: {err}"
                        ))
                    })?;
                state
                    .bucket_lifecycle_rules
                    .write()
                    .await
                    .insert(name.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(AppError::internal(format!(
                    "读取生命周期规则失败 / failed to read lifecycle rules: {err}"
                )))
            }
        }
    }

    let rules = cached
        .ok_or_else(|| AppError::not_found("存储桶生命周期不存在 / bucket lifecycle not found"))?;
    Ok(wrap(rules))
}

pub(crate) async fn update_bucket_lifecycle_rules(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<Vec<BucketLifecycleRule>>,
) -> Result<Json<ApiEnvelope<Vec<BucketLifecycleRule>>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;

    let mut normalized = Vec::with_capacity(body.len());
    let mut ids = HashSet::new();
    for rule in body {
        let rule = normalize_lifecycle_rule(rule)?;
        if !ids.insert(rule.id.clone()) {
            return Err(AppError::bad_request(
                "生命周期规则 ID 必须唯一 / lifecycle rule id must be unique",
            ));
        }
        normalized.push(rule);
    }

    write_pretty_json_file(&bucket_lifecycle_path(&bucket_dir), &normalized).await?;
    state
        .bucket_lifecycle_rules
        .write()
        .await
        .insert(name.clone(), normalized.clone());

    state
        .append_audit(
            &auth.username,
            "bucket.lifecycle.update",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({ "rules": normalized.len() }),
        )
        .await;
    Ok(wrap(normalized))
}

pub(crate) async fn delete_bucket_lifecycle_rules(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;
    state.bucket_lifecycle_rules.write().await.remove(&name);

    let path = bucket_lifecycle_path(&bucket_dir);
    if let Err(err) = tokio::fs::remove_file(path).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(AppError::internal(format!(
                "删除生命周期规则失败 / failed to delete lifecycle rules: {err}"
            )));
        }
    }

    state
        .append_audit(
            &auth.username,
            "bucket.lifecycle.delete",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "name": name })))
}

pub(crate) async fn list_remote_tiers(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<RemoteTierConfig>>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    let mut tiers = state
        .remote_tiers
        .read()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    tiers.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(wrap(tiers))
}

pub(crate) async fn list_storage_inventory(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<StorageInventoryQuery>,
) -> Result<Json<ApiEnvelope<Vec<StorageInventoryEntry>>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    let entries = collect_storage_inventory_candidates(&state, &query)
        .await?
        .into_iter()
        .map(|candidate| build_storage_inventory_entry(candidate.meta, candidate.is_current))
        .collect::<Vec<_>>();
    Ok(wrap(entries))
}

pub(crate) async fn export_storage_inventory(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<StorageInventoryExportQuery>,
) -> Result<Response, AppError> {
    auth.require(Permission::ClusterRead)?;
    let entries = collect_storage_inventory_candidates(&state, &query.filters)
        .await?
        .into_iter()
        .map(|candidate| build_storage_inventory_entry(candidate.meta, candidate.is_current))
        .collect::<Vec<_>>();
    let format = query
        .format
        .as_deref()
        .unwrap_or("json")
        .trim()
        .to_ascii_lowercase();
    match format.as_str() {
        "json" => {
            let body = serde_json::to_string_pretty(&entries).map_err(|err| {
                AppError::internal(format!(
                    "序列化 inventory 导出失败 / failed to serialize inventory export: {err}"
                ))
            })?;
            let disposition =
                HeaderValue::from_str("attachment; filename=\"rustio-storage-inventory.json\"")
                    .map_err(|_| {
                        AppError::internal(
                            "构建 inventory 导出失败 / failed to build inventory export",
                        )
                    })?;
            Ok((
                StatusCode::OK,
                [
                    (
                        CONTENT_TYPE,
                        HeaderValue::from_static("application/json; charset=utf-8"),
                    ),
                    (CONTENT_DISPOSITION, disposition),
                ],
                body,
            )
                .into_response())
        }
        "csv" => {
            let body = build_storage_inventory_csv(&entries)?;
            let disposition =
                HeaderValue::from_str("attachment; filename=\"rustio-storage-inventory.csv\"")
                    .map_err(|_| {
                        AppError::internal(
                            "构建 inventory 导出失败 / failed to build inventory export",
                        )
                    })?;
            Ok((
                StatusCode::OK,
                [
                    (
                        CONTENT_TYPE,
                        HeaderValue::from_static("text/csv; charset=utf-8"),
                    ),
                    (CONTENT_DISPOSITION, disposition),
                ],
                body,
            )
                .into_response())
        }
        _ => Err(AppError::bad_request(
            "inventory 导出 format 仅支持 json/csv / inventory export format must be json or csv",
        )),
    }
}

pub(crate) async fn get_storage_archive_report(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<StorageArchiveReportQuery>,
) -> Result<Json<ApiEnvelope<StorageArchiveReport>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    let entries = collect_storage_inventory_candidates(&state, &query.filters)
        .await?
        .into_iter()
        .map(|candidate| build_storage_inventory_entry(candidate.meta, candidate.is_current))
        .collect::<Vec<_>>();
    Ok(wrap(build_storage_archive_report_from_entries(
        &query.filters,
        &entries,
    )))
}

pub(crate) async fn export_storage_archive_report(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<StorageArchiveReportQuery>,
) -> Result<Response, AppError> {
    auth.require(Permission::ClusterRead)?;
    let entries = collect_storage_inventory_candidates(&state, &query.filters)
        .await?
        .into_iter()
        .map(|candidate| build_storage_inventory_entry(candidate.meta, candidate.is_current))
        .collect::<Vec<_>>();
    let report = build_storage_archive_report_from_entries(&query.filters, &entries);
    let format = query
        .format
        .as_deref()
        .unwrap_or("json")
        .trim()
        .to_ascii_lowercase();
    match format.as_str() {
        "json" => {
            let body = serde_json::to_string_pretty(&report).map_err(|err| {
                AppError::internal(format!(
                    "序列化归档报告失败 / failed to serialize archive report: {err}"
                ))
            })?;
            let disposition = HeaderValue::from_str(
                "attachment; filename=\"rustio-storage-archive-report.json\"",
            )
            .map_err(|_| AppError::internal("构建归档报告导出失败 / failed to build archive report export"))?;
            Ok((
                StatusCode::OK,
                [
                    (
                        CONTENT_TYPE,
                        HeaderValue::from_static("application/json; charset=utf-8"),
                    ),
                    (CONTENT_DISPOSITION, disposition),
                ],
                body,
            )
                .into_response())
        }
        "csv" => {
            let body = build_storage_archive_report_csv(&report)?;
            let disposition = HeaderValue::from_str(
                "attachment; filename=\"rustio-storage-archive-report.csv\"",
            )
            .map_err(|_| AppError::internal("构建归档报告导出失败 / failed to build archive report export"))?;
            Ok((
                StatusCode::OK,
                [
                    (CONTENT_TYPE, HeaderValue::from_static("text/csv; charset=utf-8")),
                    (CONTENT_DISPOSITION, disposition),
                ],
                body,
            )
                .into_response())
        }
        _ => Err(AppError::bad_request(
            "archive report 导出 format 仅支持 json/csv / archive report export format must be json or csv",
        )),
    }
}

pub(crate) async fn prewarm_storage_archive(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<StorageArchivePrewarmRequest>,
) -> Result<Json<ApiEnvelope<StorageArchivePrewarmResult>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    let reason = require_non_empty_reason(body.reason)?;
    if body.current_only && body.noncurrent_only {
        return Err(AppError::bad_request(
            "archive prewarm 不能同时指定 current_only 与 noncurrent_only / archive prewarm cannot set both current_only and noncurrent_only",
        ));
    }
    if matches!(body.limit, Some(0)) {
        return Err(AppError::bad_request(
            "archive prewarm limit 必须大于 0 / archive prewarm limit must be greater than 0",
        ));
    }
    let restore_days = body.restore_days.unwrap_or(1).clamp(1, 30);
    let query = StorageInventoryQuery {
        bucket: body.bucket,
        prefix: body.prefix,
        current_only: Some(body.current_only),
        noncurrent_only: Some(body.noncurrent_only),
        remote_only: Some(true),
        tier: body.tier,
        restore_state: None,
        restored_only: Some(false),
        restore_expiring_within_minutes: None,
        limit: body.limit,
    };
    let candidates = collect_storage_inventory_candidates(&state, &query).await?;
    let matched = candidates.len();
    let requested_at = Utc::now();
    let mut restored = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    let mut failures_preview = Vec::new();
    for candidate in candidates {
        if candidate.meta.remote_tier.is_none() {
            skipped += 1;
            continue;
        }
        if object_restore_is_active(&candidate.meta) {
            skipped += 1;
            continue;
        }
        match admin_prewarm_remote_archived_object(
            state.as_ref(),
            &candidate.meta,
            candidate.is_current,
            restore_days,
            requested_at,
        )
        .await
        {
            Ok(true) => restored += 1,
            Ok(false) => skipped += 1,
            Err(message) => {
                failed += 1;
                if failures_preview.len() < 20 {
                    failures_preview.push(StorageArchivePrewarmFailure {
                        bucket: candidate.meta.bucket.clone(),
                        object_key: candidate.meta.key.clone(),
                        version_id: candidate.meta.version_id.clone(),
                        is_current: candidate.is_current,
                        message,
                    });
                }
            }
        }
    }
    state
        .append_audit(
            &auth.username,
            "storage.archive.prewarm",
            "storage/archive",
            if failed == 0 { "success" } else { "partial" },
            Some(reason),
            json!({
                "matched": matched,
                "restored": restored,
                "skipped": skipped,
                "failed": failed,
                "restore_days": restore_days,
            }),
        )
        .await;
    Ok(wrap(StorageArchivePrewarmResult {
        requested_at,
        restore_days,
        matched,
        restored,
        skipped,
        failed,
        failures_preview,
    }))
}

pub(crate) async fn update_remote_tiers(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<Vec<RemoteTierConfig>>,
) -> Result<Json<ApiEnvelope<Vec<RemoteTierConfig>>>, AppError> {
    auth.require(Permission::ClusterWrite)?;

    let mut normalized = Vec::with_capacity(body.len());
    let mut ids = HashSet::new();
    for tier in body {
        let tier = probe_remote_tier_connectivity(normalize_remote_tier_config(tier)?).await;
        if !ids.insert(tier.name.clone()) {
            return Err(AppError::bad_request(
                "远端层名称必须唯一 / remote tier name must be unique",
            ));
        }
        normalized.push(tier);
    }
    let tiers_map = normalized
        .iter()
        .cloned()
        .map(|tier| (tier.name.clone(), tier))
        .collect::<HashMap<_, _>>();
    AppState::persist_remote_tiers_snapshot(&state.data_dir, &tiers_map).map_err(|err| {
        AppError::internal(format!(
            "持久化远端层配置失败 / failed to persist remote tiers: {err}"
        ))
    })?;
    *state.remote_tiers.write().await = tiers_map;
    state
        .sync_metadata_raft("remote-tiers-update")
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "同步远端层配置失败 / failed to sync remote tiers to metadata raft: {err}"
            ))
        })?;

    state
        .append_audit(
            &auth.username,
            "storage.tiers.update",
            "storage/tiers",
            "success",
            None,
            json!({ "tiers": normalized.len() }),
        )
        .await;
    Ok(wrap(normalized))
}

#[derive(Debug, Deserialize)]
pub(crate) struct RotateRemoteTierSecretRequest {
    #[serde(default)]
    pub(crate) credential_key: Option<String>,
    #[serde(default)]
    pub(crate) credential_secret: Option<String>,
    #[serde(default)]
    pub(crate) credential_token: Option<String>,
    #[serde(default)]
    pub(crate) extra_headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub(crate) secret_version: Option<u64>,
}

pub(crate) async fn check_remote_tier_health(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<RemoteTierConfig>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    let normalized_name = normalize_remote_tier_name(&name);
    let current = state
        .remote_tiers
        .read()
        .await
        .get(&normalized_name)
        .cloned()
        .ok_or_else(|| AppError::not_found("远端层不存在 / remote tier not found"))?;
    let probed = probe_remote_tier_connectivity(current).await;
    let tiers_snapshot = {
        let mut tiers = state.remote_tiers.write().await;
        tiers.insert(normalized_name.clone(), probed.clone());
        tiers.clone()
    };
    AppState::persist_remote_tiers_snapshot(&state.data_dir, &tiers_snapshot).map_err(|err| {
        AppError::internal(format!(
            "持久化远端层配置失败 / failed to persist remote tiers: {err}"
        ))
    })?;
    state
        .sync_metadata_raft("remote-tier-health-check")
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "同步远端层配置失败 / failed to sync remote tiers to metadata raft: {err}"
            ))
        })?;
    state
        .append_audit(
            &auth.username,
            "storage.tiers.health_check",
            &format!("storage/tiers/{normalized_name}"),
            "success",
            None,
            json!({
                "health_status": probed.health_status,
                "last_error": probed.last_error,
            }),
        )
        .await;
    Ok(wrap(probed))
}

pub(crate) async fn rotate_remote_tier_secret(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<RotateRemoteTierSecretRequest>,
) -> Result<Json<ApiEnvelope<RemoteTierConfig>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    let normalized_name = normalize_remote_tier_name(&name);
    let updated = {
        let tiers = state.remote_tiers.read().await;
        let current = tiers
            .get(&normalized_name)
            .cloned()
            .ok_or_else(|| AppError::not_found("远端层不存在 / remote tier not found"))?;
        drop(tiers);
        let mut next = current;
        let mut touched_secret = false;
        if body.credential_key.is_some() {
            next.credential_key = normalize_optional_text(body.credential_key);
            touched_secret = true;
        }
        if body.credential_secret.is_some() {
            next.credential_secret = normalize_optional_text(body.credential_secret);
            touched_secret = true;
        }
        if body.credential_token.is_some() {
            next.credential_token = normalize_optional_text(body.credential_token);
            touched_secret = true;
        }
        if let Some(extra_headers) = body.extra_headers {
            next.extra_headers = normalize_remote_tier_headers(extra_headers)?;
            touched_secret = true;
        }
        next.secret_version = body.secret_version.unwrap_or_else(|| {
            if touched_secret {
                next.secret_version + 1
            } else {
                next.secret_version
            }
        });
        probe_remote_tier_connectivity(normalize_remote_tier_config(next)?).await
    };
    let tiers_snapshot = {
        let mut tiers = state.remote_tiers.write().await;
        tiers.insert(normalized_name.clone(), updated.clone());
        tiers.clone()
    };
    AppState::persist_remote_tiers_snapshot(&state.data_dir, &tiers_snapshot).map_err(|err| {
        AppError::internal(format!(
            "持久化远端层配置失败 / failed to persist remote tiers: {err}"
        ))
    })?;
    state
        .sync_metadata_raft("remote-tier-rotate-secret")
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "同步远端层配置失败 / failed to sync remote tiers to metadata raft: {err}"
            ))
        })?;
    state
        .append_audit(
            &auth.username,
            "storage.tiers.rotate_secret",
            &format!("storage/tiers/{normalized_name}"),
            "success",
            None,
            json!({
                "secret_version": updated.secret_version,
                "health_status": updated.health_status,
            }),
        )
        .await;
    Ok(wrap(updated))
}

pub(crate) async fn delete_remote_tier(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<Value>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    let normalized_name = normalize_remote_tier_name(&name);
    if normalized_name.is_empty() {
        return Err(AppError::bad_request(
            "远端层名称不能为空 / remote tier name cannot be empty",
        ));
    }
    let lifecycle_rules = state.bucket_lifecycle_rules.read().await.clone();
    for (bucket, rules) in lifecycle_rules {
        if rules.iter().any(|rule| {
            rule.transition_tier.as_deref() == Some(normalized_name.as_str())
                || rule.noncurrent_transition_tier.as_deref() == Some(normalized_name.as_str())
        }) {
            return Err(AppError::bad_request(format!(
                "远端层仍被生命周期规则引用：{bucket} / remote tier is still referenced by lifecycle rules: {bucket}"
            )));
        }
    }
    if state.object_meta.iter().any(|entry| {
        let meta = entry.value();
        meta.remote_tier
            .as_ref()
            .map(|item| normalize_remote_tier_name(&item.tier) == normalized_name)
            .unwrap_or(false)
    }) {
        return Err(AppError::bad_request(
            "远端层仍被当前对象引用 / remote tier is still referenced by current objects",
        ));
    }
    let mut archived_meta_files = Vec::new();
    collect_json_files(&state.data_dir, &mut archived_meta_files).map_err(|err| {
        AppError::internal(format!(
            "扫描远端层引用失败 / failed to scan remote tier references: {err}"
        ))
    })?;
    for file in archived_meta_files {
        let Ok(bytes) = std::fs::read(&file) else {
            continue;
        };
        let Ok(meta) = serde_json::from_slice::<S3ObjectMeta>(&bytes) else {
            continue;
        };
        if meta
            .remote_tier
            .as_ref()
            .map(|item| normalize_remote_tier_name(&item.tier) == normalized_name)
            .unwrap_or(false)
        {
            return Err(AppError::bad_request(
                "远端层仍被对象版本引用 / remote tier is still referenced by object versions",
            ));
        }
    }

    let mut remote_tiers = state.remote_tiers.write().await;
    if remote_tiers.remove(&normalized_name).is_none() {
        return Err(AppError::not_found("远端层不存在 / remote tier not found"));
    }
    AppState::persist_remote_tiers_snapshot(&state.data_dir, &remote_tiers).map_err(|err| {
        AppError::internal(format!(
            "持久化远端层配置失败 / failed to persist remote tiers: {err}"
        ))
    })?;
    drop(remote_tiers);

    state
        .sync_metadata_raft("remote-tier-delete")
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "同步远端层配置失败 / failed to sync remote tier delete to metadata raft: {err}"
            ))
        })?;

    state
        .append_audit(
            &auth.username,
            "storage.tiers.delete",
            &format!("storage/tiers/{normalized_name}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "name": normalized_name })))
}

pub(crate) async fn ensure_bucket_directory(
    state: &AppState,
    name: &str,
) -> Result<PathBuf, AppError> {
    if !state.buckets.read().await.contains_key(name) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }
    let bucket_dir = bucket_path(state, name)
        .map_err(|_| AppError::bad_request("存储桶名称无效 / invalid bucket name"))?;
    if !tokio::fs::try_exists(&bucket_dir).await.unwrap_or(false) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }
    Ok(bucket_dir)
}

pub(crate) async fn write_pretty_json_file<T: Serialize>(
    path: &PathBuf,
    payload: &T,
) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|err| {
            AppError::internal(format!(
                "创建元数据目录失败 / failed to create metadata dir: {err}"
            ))
        })?;
    }
    let bytes = serde_json::to_vec_pretty(payload).map_err(|err| {
        AppError::internal(format!("编码元数据失败 / failed to encode metadata: {err}"))
    })?;
    tokio::fs::write(path, bytes).await.map_err(|err| {
        AppError::internal(format!(
            "持久化元数据失败 / failed to persist metadata: {err}"
        ))
    })?;
    Ok(())
}

pub(crate) async fn get_bucket_policy(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<Value>>, AppError> {
    auth.require(Permission::BucketRead)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;

    let mut cached = state.bucket_policies.read().await.get(&name).cloned();
    if cached.is_none() {
        let path = bucket_policy_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed = serde_json::from_slice::<Value>(&bytes).map_err(|err| {
                    AppError::internal(format!("解析策略失败 / failed to decode policy: {err}"))
                })?;
                state
                    .bucket_policies
                    .write()
                    .await
                    .insert(name.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(AppError::internal(format!(
                    "读取存储桶策略失败 / failed to read bucket policy: {err}"
                )))
            }
        }
    }

    let policy =
        cached.ok_or_else(|| AppError::not_found("存储桶策略不存在 / bucket policy not found"))?;
    Ok(wrap(policy))
}

pub(crate) async fn update_bucket_policy(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<ApiEnvelope<Value>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;
    let policy = normalize_bucket_policy_value(body)?;

    write_pretty_json_file(&bucket_policy_path(&bucket_dir), &policy).await?;
    state
        .bucket_policies
        .write()
        .await
        .insert(name.clone(), policy.clone());

    state
        .append_audit(
            &auth.username,
            "bucket.policy.update",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(policy))
}

pub(crate) async fn delete_bucket_policy(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;
    state.bucket_policies.write().await.remove(&name);

    let path = bucket_policy_path(&bucket_dir);
    if let Err(err) = tokio::fs::remove_file(path).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(AppError::internal(format!(
                "删除存储桶策略失败 / failed to delete bucket policy: {err}"
            )));
        }
    }

    state
        .append_audit(
            &auth.username,
            "bucket.policy.delete",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "name": name })))
}

pub(crate) async fn list_bucket_cors(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<Vec<BucketCorsRule>>>, AppError> {
    auth.require(Permission::BucketRead)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;

    let mut cached = state.bucket_cors_rules.read().await.get(&name).cloned();
    if cached.is_none() {
        let path = bucket_cors_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed =
                    serde_json::from_slice::<Vec<BucketCorsRule>>(&bytes).map_err(|err| {
                        AppError::internal(format!(
                            "解析跨域配置失败 / failed to decode cors: {err}"
                        ))
                    })?;
                state
                    .bucket_cors_rules
                    .write()
                    .await
                    .insert(name.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(AppError::internal(format!(
                    "读取跨域配置失败 / failed to read cors: {err}"
                )))
            }
        }
    }
    let rules =
        cached.ok_or_else(|| AppError::not_found("存储桶 CORS 不存在 / bucket cors not found"))?;
    Ok(wrap(rules))
}

pub(crate) async fn update_bucket_cors(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<Vec<BucketCorsRule>>,
) -> Result<Json<ApiEnvelope<Vec<BucketCorsRule>>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;

    let mut normalized = Vec::with_capacity(body.len());
    let mut ids = HashSet::new();
    for rule in body {
        let rule = normalize_cors_rule(rule)?;
        if !ids.insert(rule.id.clone()) {
            return Err(AppError::bad_request(
                "CORS 规则 ID 必须唯一 / cors rule id must be unique",
            ));
        }
        normalized.push(rule);
    }

    write_pretty_json_file(&bucket_cors_path(&bucket_dir), &normalized).await?;
    state
        .bucket_cors_rules
        .write()
        .await
        .insert(name.clone(), normalized.clone());

    state
        .append_audit(
            &auth.username,
            "bucket.cors.update",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({ "rules": normalized.len() }),
        )
        .await;
    Ok(wrap(normalized))
}

pub(crate) async fn delete_bucket_cors(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;
    state.bucket_cors_rules.write().await.remove(&name);

    let path = bucket_cors_path(&bucket_dir);
    if let Err(err) = tokio::fs::remove_file(path).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(AppError::internal(format!(
                "删除跨域配置失败 / failed to delete bucket cors: {err}"
            )));
        }
    }

    state
        .append_audit(
            &auth.username,
            "bucket.cors.delete",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "name": name })))
}

pub(crate) async fn list_bucket_tags(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<Vec<BucketTag>>>, AppError> {
    auth.require(Permission::BucketRead)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;

    let mut cached = state.bucket_tags.read().await.get(&name).cloned();
    if cached.is_none() {
        let path = bucket_tags_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed = serde_json::from_slice::<Vec<BucketTag>>(&bytes).map_err(|err| {
                    AppError::internal(format!("解析标签配置失败 / failed to decode tags: {err}"))
                })?;
                state
                    .bucket_tags
                    .write()
                    .await
                    .insert(name.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(AppError::internal(format!(
                    "读取标签配置失败 / failed to read tags: {err}"
                )))
            }
        }
    }

    let tags =
        cached.ok_or_else(|| AppError::not_found("存储桶标签不存在 / bucket tags not found"))?;
    Ok(wrap(tags))
}

pub(crate) async fn update_bucket_tags(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<Vec<BucketTag>>,
) -> Result<Json<ApiEnvelope<Vec<BucketTag>>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;

    let mut normalized = Vec::with_capacity(body.len());
    let mut keys = HashSet::new();
    for tag in body {
        let tag = normalize_bucket_tag(tag)?;
        if !keys.insert(tag.key.clone()) {
            return Err(AppError::bad_request(
                "标签键必须唯一 / tag key must be unique",
            ));
        }
        normalized.push(tag);
    }

    write_pretty_json_file(&bucket_tags_path(&bucket_dir), &normalized).await?;
    state
        .bucket_tags
        .write()
        .await
        .insert(name.clone(), normalized.clone());

    state
        .append_audit(
            &auth.username,
            "bucket.tags.update",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({ "count": normalized.len() }),
        )
        .await;
    Ok(wrap(normalized))
}

pub(crate) async fn delete_bucket_tags(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;
    state.bucket_tags.write().await.remove(&name);

    let path = bucket_tags_path(&bucket_dir);
    if let Err(err) = tokio::fs::remove_file(path).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(AppError::internal(format!(
                "删除标签配置失败 / failed to delete bucket tags: {err}"
            )));
        }
    }

    state
        .append_audit(
            &auth.username,
            "bucket.tags.delete",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "name": name })))
}

pub(crate) async fn get_bucket_encryption(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<BucketEncryptionConfig>>, AppError> {
    auth.require(Permission::BucketRead)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;

    let mut cached = state.bucket_encryptions.read().await.get(&name).cloned();
    if cached.is_none() {
        let path = bucket_encryption_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed =
                    serde_json::from_slice::<BucketEncryptionConfig>(&bytes).map_err(|err| {
                        AppError::internal(format!(
                            "解析存储桶加密配置失败 / failed to decode encryption: {err}"
                        ))
                    })?;
                state
                    .bucket_encryptions
                    .write()
                    .await
                    .insert(name.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(AppError::internal(format!(
                    "读取存储桶加密配置失败 / failed to read bucket encryption: {err}"
                )))
            }
        }
    }

    let config = cached
        .ok_or_else(|| AppError::not_found("存储桶加密配置不存在 / bucket encryption not found"))?;
    Ok(wrap(config))
}

pub(crate) async fn update_bucket_encryption(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<BucketEncryptionConfig>,
) -> Result<Json<ApiEnvelope<BucketEncryptionConfig>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;
    let normalized = normalize_bucket_encryption(body)?;

    write_pretty_json_file(&bucket_encryption_path(&bucket_dir), &normalized).await?;
    state
        .bucket_encryptions
        .write()
        .await
        .insert(name.clone(), normalized.clone());

    state
        .append_audit(
            &auth.username,
            "bucket.encryption.update",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({
                "enabled": normalized.enabled,
                "algorithm": normalized.algorithm,
            }),
        )
        .await;
    Ok(wrap(normalized))
}

pub(crate) async fn delete_bucket_encryption(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let bucket_dir = ensure_bucket_directory(&state, &name).await?;
    state.bucket_encryptions.write().await.remove(&name);

    let path = bucket_encryption_path(&bucket_dir);
    if let Err(err) = tokio::fs::remove_file(path).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(AppError::internal(format!(
                "删除存储桶加密配置失败 / failed to delete bucket encryption: {err}"
            )));
        }
    }

    state
        .append_audit(
            &auth.username,
            "bucket.encryption.delete",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "name": name })))
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct BucketObjectQuery {
    pub(crate) prefix: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct BucketObjectVersionQuery {
    pub(crate) version_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BucketObjectVersionsQuery {
    pub(crate) key: String,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct StorageInventoryQuery {
    pub(crate) bucket: Option<String>,
    pub(crate) prefix: Option<String>,
    pub(crate) current_only: Option<bool>,
    pub(crate) noncurrent_only: Option<bool>,
    pub(crate) remote_only: Option<bool>,
    pub(crate) tier: Option<String>,
    pub(crate) restore_state: Option<String>,
    pub(crate) restored_only: Option<bool>,
    pub(crate) restore_expiring_within_minutes: Option<u64>,
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct StorageInventoryExportQuery {
    #[serde(flatten)]
    pub(crate) filters: StorageInventoryQuery,
    pub(crate) format: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct StorageArchiveReportQuery {
    #[serde(flatten)]
    pub(crate) filters: StorageInventoryQuery,
    pub(crate) format: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StorageArchivePrewarmRequest {
    pub(crate) reason: Option<String>,
    pub(crate) bucket: Option<String>,
    pub(crate) prefix: Option<String>,
    #[serde(default)]
    pub(crate) current_only: bool,
    #[serde(default)]
    pub(crate) noncurrent_only: bool,
    pub(crate) tier: Option<String>,
    pub(crate) limit: Option<usize>,
    pub(crate) restore_days: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BucketObjectEntry {
    pub(crate) key: String,
    pub(crate) size: u64,
    pub(crate) etag: String,
    pub(crate) last_modified: String,
    pub(crate) storage_class: String,
    pub(crate) version_id: Option<String>,
    pub(crate) retention_until: Option<String>,
    pub(crate) legal_hold: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct BucketObjectVersionEntry {
    pub(crate) key: String,
    pub(crate) version_id: String,
    pub(crate) size: u64,
    pub(crate) etag: String,
    pub(crate) last_modified: String,
    pub(crate) storage_class: String,
    pub(crate) delete_marker: bool,
    pub(crate) legal_hold: bool,
    pub(crate) retention_until: Option<String>,
    pub(crate) is_latest: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StorageInventoryEntry {
    pub(crate) bucket: String,
    pub(crate) object_key: String,
    pub(crate) version_id: String,
    pub(crate) is_current: bool,
    pub(crate) size: u64,
    pub(crate) storage_class: String,
    pub(crate) remote_tier: Option<String>,
    pub(crate) remote_storage_class: Option<String>,
    pub(crate) created_at: String,
    pub(crate) archive_state: String,
    pub(crate) restored: bool,
    pub(crate) restore_ongoing: bool,
    pub(crate) restore_requested_at: Option<String>,
    pub(crate) restore_expiry: Option<String>,
    pub(crate) restore_remaining_seconds: Option<i64>,
    pub(crate) restore_expiring_soon: bool,
    pub(crate) tiering_age_seconds: Option<i64>,
}

#[derive(Debug, Clone)]
pub(crate) struct StorageInventoryCandidate {
    pub(crate) meta: S3ObjectMeta,
    pub(crate) is_current: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct StorageArchiveTierSummary {
    pub(crate) tier: String,
    pub(crate) objects: usize,
    pub(crate) bytes: u64,
    pub(crate) current_versions: usize,
    pub(crate) noncurrent_versions: usize,
    pub(crate) restoring_objects: usize,
    pub(crate) restored_objects: usize,
    pub(crate) expiring_soon_objects: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct StorageArchiveSummary {
    pub(crate) total_objects: usize,
    pub(crate) remote_objects: usize,
    pub(crate) remote_bytes: u64,
    pub(crate) current_versions: usize,
    pub(crate) noncurrent_versions: usize,
    pub(crate) cold_objects: usize,
    pub(crate) restoring_objects: usize,
    pub(crate) restored_objects: usize,
    pub(crate) expired_restore_objects: usize,
    pub(crate) expiring_soon_objects: usize,
    pub(crate) tiers: Vec<StorageArchiveTierSummary>,
}

#[derive(Debug, Serialize)]
pub(crate) struct StorageArchiveReport {
    pub(crate) generated_at: DateTime<Utc>,
    pub(crate) filters: Value,
    pub(crate) summary: StorageArchiveSummary,
    pub(crate) items: Vec<StorageInventoryEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StorageArchivePrewarmFailure {
    pub(crate) bucket: String,
    pub(crate) object_key: String,
    pub(crate) version_id: String,
    pub(crate) is_current: bool,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct StorageArchivePrewarmResult {
    pub(crate) requested_at: DateTime<Utc>,
    pub(crate) restore_days: u32,
    pub(crate) matched: usize,
    pub(crate) restored: usize,
    pub(crate) skipped: usize,
    pub(crate) failed: usize,
    pub(crate) failures_preview: Vec<StorageArchivePrewarmFailure>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SiteReplicationBootstrapRequest {
    pub(crate) site_id: String,
    pub(crate) endpoint: String,
    pub(crate) reason: String,
    #[serde(default)]
    pub(crate) preferred_primary: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SiteReplicationJoinRequest {
    pub(crate) reason: String,
    #[serde(default)]
    pub(crate) endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SiteReplicationTopologyDrift {
    pub(crate) current_endpoint: String,
    pub(crate) expected_endpoints: Vec<String>,
    pub(crate) endpoint_alignment: String,
    pub(crate) managed_buckets_expected: usize,
    pub(crate) managed_buckets_present: usize,
    pub(crate) managed_buckets_missing: usize,
    pub(crate) unexpected_bucket_roots: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SiteReplicationBucketDriftEntry {
    pub(crate) bucket: String,
    pub(crate) state: String,
    pub(crate) reason: String,
    pub(crate) path: String,
    pub(crate) rule_ids: Vec<String>,
    pub(crate) pending_backlog: usize,
    pub(crate) failed_backlog: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SiteReplicationRuleDriftEntry {
    pub(crate) rule_id: String,
    pub(crate) rule_name: Option<String>,
    pub(crate) source_bucket: String,
    pub(crate) endpoint: Option<String>,
    pub(crate) status: String,
    pub(crate) priority: i32,
    pub(crate) lag_seconds: u64,
    pub(crate) replicate_existing: bool,
    pub(crate) sync_deletes: bool,
    pub(crate) drift_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SiteReplicationGuardrails {
    pub(crate) safe_to_reconcile: bool,
    pub(crate) confirmation_required: bool,
    pub(crate) blocking_reasons: Vec<String>,
    pub(crate) blocking_reason_messages: Vec<String>,
    pub(crate) preview_actions: Vec<String>,
    pub(crate) expected_missing_bucket_roots_after_reconcile: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SiteReplicationDriftReport {
    pub(crate) site_id: String,
    pub(crate) generated_at: DateTime<Utc>,
    pub(crate) mode: String,
    pub(crate) site: SiteReplicationStatus,
    pub(crate) topology: SiteReplicationTopologyDrift,
    pub(crate) buckets: Vec<SiteReplicationBucketDriftEntry>,
    pub(crate) rules: Vec<SiteReplicationRuleDriftEntry>,
    pub(crate) guardrails: SiteReplicationGuardrails,
    pub(crate) suggested_actions: Vec<String>,
}

pub(crate) fn site_replication_data_root(state: &AppState, site_id: &str) -> PathBuf {
    state
        .data_dir
        .join(".rustio_sites")
        .join(site_id)
        .join("data")
}

pub(crate) fn site_replication_bucket_root(
    state: &AppState,
    site_id: &str,
    bucket: &str,
) -> PathBuf {
    site_replication_data_root(state, site_id).join(bucket)
}

pub(crate) async fn site_replication_actual_bucket_roots(
    state: &AppState,
    site_id: &str,
) -> Result<Vec<String>, AppError> {
    let mut buckets = Vec::new();
    let root = site_replication_data_root(state, site_id);
    let mut entries = match tokio::fs::read_dir(&root).await {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(buckets),
        Err(err) => {
            return Err(AppError::internal(format!(
                "读取站点复制目录失败 / failed to read site replication dir: {err}"
            )));
        }
    };

    while let Some(entry) = entries.next_entry().await.map_err(|err| {
        AppError::internal(format!(
            "遍历站点复制目录失败 / failed to iterate site replication dir: {err}"
        ))
    })? {
        let file_type = entry.file_type().await.map_err(|err| {
            AppError::internal(format!(
                "读取站点复制目录项失败 / failed to read site replication dir entry: {err}"
            ))
        })?;
        if !file_type.is_dir() {
            continue;
        }
        buckets.push(entry.file_name().to_string_lossy().to_string());
    }
    buckets.sort();
    Ok(buckets)
}

pub(crate) async fn build_site_replication_drift_report(
    state: &Arc<AppState>,
    site_id: &str,
    mode: &str,
) -> Result<SiteReplicationDriftReport, AppError> {
    sync_site_replication_from_rules(state).await;

    let site = state
        .site_replications
        .read()
        .await
        .iter()
        .find(|site| site.site_id == site_id)
        .cloned()
        .ok_or_else(|| AppError::not_found("复制站点不存在 / replication site not found"))?;
    let mut rules = state
        .replications
        .read()
        .await
        .iter()
        .filter(|rule| rule.target_site == site_id)
        .cloned()
        .collect::<Vec<_>>();
    rules.sort_by(|left, right| {
        left.source_bucket
            .cmp(&right.source_bucket)
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    let backlog = state.replication_backlog.read().await.clone();
    let actual_bucket_roots = site_replication_actual_bucket_roots(state.as_ref(), site_id).await?;
    let actual_bucket_set = actual_bucket_roots.iter().cloned().collect::<HashSet<_>>();
    let expected_bucket_set = rules
        .iter()
        .map(|rule| rule.source_bucket.clone())
        .collect::<HashSet<_>>();
    let mut expected_endpoints = rules
        .iter()
        .filter_map(|rule| rule.endpoint.clone())
        .filter(|endpoint| !endpoint.trim().is_empty())
        .collect::<Vec<_>>();
    expected_endpoints.sort();
    expected_endpoints.dedup();

    let mut bucket_rule_ids: HashMap<String, Vec<String>> = HashMap::new();
    for rule in &rules {
        bucket_rule_ids
            .entry(rule.source_bucket.clone())
            .or_default()
            .push(rule.rule_id.clone());
    }

    let mut expected_buckets = expected_bucket_set.into_iter().collect::<Vec<_>>();
    expected_buckets.sort();
    let mut buckets = Vec::new();
    for bucket in &expected_buckets {
        let exists = actual_bucket_set.contains(bucket);
        let pending_backlog = backlog
            .iter()
            .filter(|item| {
                item.target_site == site_id
                    && item.source_bucket == *bucket
                    && !matches!(item.status.as_str(), "done" | "completed")
            })
            .count();
        let failed_backlog = backlog
            .iter()
            .filter(|item| {
                item.target_site == site_id
                    && item.source_bucket == *bucket
                    && matches!(item.status.as_str(), "failed" | "dead_letter")
            })
            .count();
        let state_value = if !exists {
            "missing_site_root"
        } else if failed_backlog > 0 {
            "failed_backlog"
        } else if pending_backlog > 0 {
            "pending_resync"
        } else {
            "aligned"
        };
        let reason = match state_value {
            "missing_site_root" => {
                "站点桶根目录缺失，需要执行 reconcile / site bucket root is missing and needs reconcile"
                    .to_string()
            }
            "failed_backlog" => {
                "站点存在失败 backlog，建议先处理失败对象 / site has failed backlog, retry failures first"
                    .to_string()
            }
            "pending_resync" => {
                "站点仍有待追平 backlog / site still has pending resync backlog".to_string()
            }
            _ => "站点桶目录与复制规则一致 / site bucket root matches replication rules".to_string(),
        };
        buckets.push(SiteReplicationBucketDriftEntry {
            bucket: bucket.clone(),
            state: state_value.to_string(),
            reason,
            path: site_replication_bucket_root(state.as_ref(), site_id, bucket)
                .display()
                .to_string(),
            rule_ids: bucket_rule_ids.get(bucket).cloned().unwrap_or_default(),
            pending_backlog,
            failed_backlog,
        });
    }

    let mut unexpected_bucket_roots = actual_bucket_set
        .difference(&expected_buckets.iter().cloned().collect::<HashSet<_>>())
        .cloned()
        .collect::<Vec<_>>();
    unexpected_bucket_roots.sort();

    let endpoint_alignment = if expected_endpoints.len() > 1 {
        "conflicting_rules"
    } else if expected_endpoints.is_empty() {
        "implicit"
    } else if expected_endpoints[0].trim() == site.endpoint.trim() {
        "aligned"
    } else {
        "drifted"
    };
    let topology = SiteReplicationTopologyDrift {
        current_endpoint: site.endpoint.clone(),
        expected_endpoints: expected_endpoints.clone(),
        endpoint_alignment: endpoint_alignment.to_string(),
        managed_buckets_expected: expected_buckets.len(),
        managed_buckets_present: buckets
            .iter()
            .filter(|bucket| bucket.state != "missing_site_root")
            .count(),
        managed_buckets_missing: buckets
            .iter()
            .filter(|bucket| bucket.state == "missing_site_root")
            .count(),
        unexpected_bucket_roots: unexpected_bucket_roots.clone(),
    };

    let mut rule_entries = Vec::new();
    for rule in &rules {
        let mut drift_reasons = Vec::new();
        if let Some(endpoint) = rule.endpoint.as_ref() {
            if endpoint.trim() != site.endpoint.trim() {
                drift_reasons.push("endpoint_mismatch".to_string());
            }
        }
        if buckets.iter().any(|bucket| {
            bucket.bucket == rule.source_bucket && bucket.state == "missing_site_root"
        }) {
            drift_reasons.push("missing_bucket_root".to_string());
        }
        if backlog.iter().any(|item| {
            item.target_site == site_id
                && item.source_bucket == rule.source_bucket
                && matches!(item.status.as_str(), "failed" | "dead_letter")
        }) {
            drift_reasons.push("failed_backlog".to_string());
        }
        rule_entries.push(SiteReplicationRuleDriftEntry {
            rule_id: rule.rule_id.clone(),
            rule_name: rule.rule_name.clone(),
            source_bucket: rule.source_bucket.clone(),
            endpoint: rule.endpoint.clone(),
            status: rule.status.clone(),
            priority: rule.priority,
            lag_seconds: rule.lag_seconds,
            replicate_existing: rule.replicate_existing,
            sync_deletes: rule.sync_deletes,
            drift_reasons,
        });
    }

    let mut blocking_reasons = Vec::new();
    let mut blocking_reason_messages = Vec::new();
    if rules.is_empty() {
        blocking_reasons.push("no_managed_buckets".to_string());
        blocking_reason_messages.push(
            "站点没有可收敛的复制规则 / site has no managed replication rules to reconcile"
                .to_string(),
        );
    }
    if site.state == "offline" {
        blocking_reasons.push("site_offline".to_string());
        blocking_reason_messages.push(
            "站点当前离线，禁止执行 reconcile / site is offline and reconcile is blocked"
                .to_string(),
        );
    }
    if endpoint_alignment == "conflicting_rules" {
        blocking_reasons.push("conflicting_rule_endpoints".to_string());
        blocking_reason_messages.push(
            "同一站点存在多个冲突 endpoint 规则，请先统一配置 / replication rules for this site use conflicting endpoints, normalize them first"
                .to_string(),
        );
    }

    let mut preview_actions = buckets
        .iter()
        .filter(|bucket| bucket.state == "missing_site_root")
        .map(|bucket| format!("create_bucket_root:{}", bucket.bucket))
        .collect::<Vec<_>>();
    for bucket in &unexpected_bucket_roots {
        preview_actions.push(format!("inspect_unexpected_bucket_root:{bucket}"));
    }
    if endpoint_alignment == "drifted" {
        preview_actions.push("normalize_site_endpoint".to_string());
    }

    let mut suggested_actions = Vec::new();
    if topology.managed_buckets_missing > 0 && blocking_reasons.is_empty() {
        suggested_actions.push(
            "可先执行 dry-run reconcile，再执行正式 reconcile 重建缺失桶目录 / run reconcile preview first, then reconcile to recreate missing bucket roots"
                .to_string(),
        );
    }
    if endpoint_alignment == "drifted" {
        suggested_actions.push(
            "统一 rule endpoint 与 site endpoint，避免长期漂移 / align rule endpoints with site endpoint to avoid topology drift"
                .to_string(),
        );
    }
    if buckets.iter().any(|bucket| bucket.failed_backlog > 0) {
        suggested_actions.push(
            "先处理 failed/dead-letter backlog，再评估 failover / retry failed or dead-letter backlog before failover decisions"
                .to_string(),
        );
    }
    if !unexpected_bucket_roots.is_empty() {
        suggested_actions.push(
            "检查站点残留桶目录是否为历史配置遗留 / inspect unexpected site bucket roots for stale topology leftovers"
                .to_string(),
        );
    }
    if suggested_actions.is_empty() {
        suggested_actions.push(
            "站点拓扑与规则基本一致，可继续观察 backlog 与 lag / topology is aligned, keep monitoring backlog and lag"
                .to_string(),
        );
    }
    let expected_missing_bucket_roots_after_reconcile = if endpoint_alignment == "conflicting_rules"
    {
        buckets
            .iter()
            .filter(|bucket| bucket.state == "missing_site_root")
            .count()
    } else {
        0
    };

    Ok(SiteReplicationDriftReport {
        site_id: site_id.to_string(),
        generated_at: Utc::now(),
        mode: mode.to_string(),
        site,
        topology,
        buckets,
        rules: rule_entries,
        guardrails: SiteReplicationGuardrails {
            safe_to_reconcile: blocking_reasons.is_empty(),
            confirmation_required: true,
            blocking_reasons,
            blocking_reason_messages,
            preview_actions,
            expected_missing_bucket_roots_after_reconcile,
        },
        suggested_actions,
    })
}

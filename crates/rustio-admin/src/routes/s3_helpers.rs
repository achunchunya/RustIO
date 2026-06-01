//! S3 基础操作与通用 helper（建桶、列举、对象元数据、XML 转义、wrap）

use super::*;

pub(crate) fn valid_bucket_name(name: &str) -> bool {
    if name.len() < 3 || name.len() > 63 {
        return false;
    }
    if name.starts_with('.') || name.ends_with('.') || name.starts_with('-') || name.ends_with('-')
    {
        return false;
    }
    if name.contains("..") {
        return false;
    }
    name.chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '-')
}

pub(crate) fn collect_objects(
    bucket_root: &FsPath,
    dir: &FsPath,
    output: &mut Vec<DiskObjectEntry>,
) -> std::io::Result<()> {
    let mut entries = HashMap::<String, DiskObjectEntry>::new();
    collect_object_payload_files(bucket_root, dir, &mut entries)?;
    collect_object_meta_entries(bucket_root, &mut entries)?;
    output.extend(entries.into_values());
    Ok(())
}

pub(crate) fn collect_object_payload_files(
    bucket_root: &FsPath,
    dir: &FsPath,
    output: &mut HashMap<String, DiskObjectEntry>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        let rel = path
            .strip_prefix(bucket_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");

        if rel == ".rustio_meta"
            || rel.starts_with(".rustio_meta/")
            || rel == ".rustio_versions"
            || rel.starts_with(".rustio_versions/")
        {
            continue;
        }

        if metadata.is_dir() {
            collect_object_payload_files(bucket_root, &path, output)?;
            continue;
        }

        if !metadata.is_file() {
            continue;
        }

        let modified = metadata.modified().ok();
        let modified_at: DateTime<Utc> =
            modified.map(DateTime::<Utc>::from).unwrap_or_else(Utc::now);
        let modified_secs = modified
            .and_then(|v| v.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|v| v.as_secs())
            .unwrap_or(0);

        output.insert(
            rel.clone(),
            DiskObjectEntry {
                key: rel,
                size: metadata.len(),
                etag: format!("{:x}{:x}", metadata.len(), modified_secs),
                last_modified: modified_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                storage_class: default_storage_class(),
            },
        );
    }
    Ok(())
}

pub(crate) fn collect_object_meta_entries(
    bucket_root: &FsPath,
    output: &mut HashMap<String, DiskObjectEntry>,
) -> std::io::Result<()> {
    let mut meta_files = Vec::new();
    collect_json_files(&bucket_root.join(".rustio_meta"), &mut meta_files)?;
    for file in meta_files {
        let Ok(bytes) = std::fs::read(&file) else {
            continue;
        };
        let Ok(meta) = serde_json::from_slice::<S3ObjectMeta>(&bytes) else {
            continue;
        };
        if meta.delete_marker {
            output.remove(&meta.key);
            continue;
        }
        output.insert(
            meta.key.clone(),
            DiskObjectEntry {
                key: meta.key.clone(),
                size: meta.size,
                etag: meta.etag.clone(),
                last_modified: meta.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                storage_class: object_storage_class(&meta).to_string(),
            },
        );
    }
    Ok(())
}

pub(crate) fn is_bucket_control_plane_metadata_path(bucket_root: &FsPath, path: &FsPath) -> bool {
    let rel = path
        .strip_prefix(bucket_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    matches!(
        rel.as_str(),
        ".rustio_meta/bucket-policy.json"
            | ".rustio_meta/bucket-lifecycle.json"
            | ".rustio_meta/bucket-notifications.json"
            | ".rustio_meta/bucket-acl.json"
            | ".rustio_meta/bucket-public-access-block.json"
            | ".rustio_meta/bucket-cors.json"
            | ".rustio_meta/bucket-tags.json"
            | ".rustio_meta/bucket-encryption.json"
    )
}

pub(crate) fn bucket_has_objects(bucket_root: &FsPath, dir: &FsPath) -> std::io::Result<bool> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if is_bucket_control_plane_metadata_path(bucket_root, &path) {
            continue;
        }
        if metadata.is_file() {
            return Ok(true);
        }
        if metadata.is_dir() && bucket_has_objects(bucket_root, &path)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn remove_empty_dirs_until(
    mut current: &FsPath,
    stop_at: &FsPath,
) -> std::io::Result<()> {
    while current.starts_with(stop_at) && current != stop_at {
        if std::fs::read_dir(current)?.next().is_some() {
            break;
        }
        std::fs::remove_dir(current)?;
        if let Some(parent) = current.parent() {
            current = parent;
        } else {
            break;
        }
    }
    Ok(())
}

pub(crate) fn weak_etag(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

pub(crate) fn format_http_date(value: DateTime<Utc>) -> String {
    value.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

pub(crate) fn parse_http_date(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|parsed| parsed.with_timezone(&Utc))
        .or_else(|| {
            DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|parsed| parsed.with_timezone(&Utc))
        })
}

pub(crate) fn parse_range_header(headers: &HeaderMap, size: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(raw) = headers
        .get(axum::http::header::RANGE)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    if size == 0 {
        return Err(());
    }

    let Some(spec) = raw.strip_prefix("bytes=") else {
        return Err(());
    };
    if spec.contains(',') {
        return Err(());
    }

    let mut split = spec.splitn(2, '-');
    let start_raw = split.next().unwrap_or_default().trim();
    let end_raw = split.next().ok_or(())?.trim();
    if start_raw.is_empty() {
        let suffix_len = end_raw.parse::<u64>().map_err(|_| ())?;
        if suffix_len == 0 {
            return Err(());
        }
        let start = size.saturating_sub(suffix_len);
        let end = size - 1;
        return Ok(Some((start, end)));
    }

    let start = start_raw.parse::<u64>().map_err(|_| ())?;
    if start >= size {
        return Err(());
    }

    let end = if end_raw.is_empty() {
        size - 1
    } else {
        end_raw.parse::<u64>().map_err(|_| ())?.min(size - 1)
    };
    if start > end {
        return Err(());
    }
    Ok(Some((start, end)))
}

pub(crate) fn normalize_etag_token(token: &str) -> &str {
    token
        .trim()
        .trim_start_matches("W/")
        .trim_start_matches("w/")
        .trim()
}

pub(crate) fn if_header_matches_etag(value: &str, etag: &str, etag_quoted: &str) -> bool {
    value.split(',').map(str::trim).any(|item| {
        let token = normalize_etag_token(item);
        token == "*" || token == etag_quoted || token.trim_matches('"') == etag
    })
}

pub(crate) fn precondition_response(
    method: &Method,
    status: StatusCode,
    code: &str,
    message: &str,
    key: &str,
) -> Response {
    if *method == Method::HEAD {
        status.into_response()
    } else {
        s3_error(status, code, message, key)
    }
}

pub(crate) fn evaluate_object_preconditions(
    method: &Method,
    headers: &HeaderMap,
    etag: &str,
    etag_quoted: &str,
    last_modified: DateTime<Utc>,
    key: &str,
) -> Option<Response> {
    let if_match = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|value| value.to_str().ok());
    if let Some(value) = if_match {
        if !if_header_matches_etag(value, etag, etag_quoted) {
            return Some(precondition_response(
                method,
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "At least one of the pre-conditions you specified did not hold",
                key,
            ));
        }
    }

    let if_unmodified_since = headers
        .get(axum::http::header::IF_UNMODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_date);
    if if_match.is_none() {
        if let Some(boundary) = if_unmodified_since {
            if last_modified > boundary {
                return Some(precondition_response(
                    method,
                    StatusCode::PRECONDITION_FAILED,
                    "PreconditionFailed",
                    "At least one of the pre-conditions you specified did not hold",
                    key,
                ));
            }
        }
    }

    let if_none_match = headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok());
    if let Some(value) = if_none_match {
        if if_header_matches_etag(value, etag, etag_quoted) {
            return Some(StatusCode::NOT_MODIFIED.into_response());
        }
    }

    let if_modified_since = headers
        .get(axum::http::header::IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_date);
    if if_none_match.is_none() {
        if let Some(boundary) = if_modified_since {
            if last_modified <= boundary {
                return Some(StatusCode::NOT_MODIFIED.into_response());
            }
        }
    }

    None
}

pub(crate) fn evaluate_copy_source_preconditions(
    headers: &HeaderMap,
    etag: &str,
    last_modified: DateTime<Utc>,
    resource: &str,
) -> Option<Response> {
    let etag_quoted = format!("\"{etag}\"");
    let if_match = headers
        .get(axum::http::header::HeaderName::from_static(
            "x-amz-copy-source-if-match",
        ))
        .and_then(|value| value.to_str().ok());
    if let Some(value) = if_match {
        if !if_header_matches_etag(value, etag, &etag_quoted) {
            return Some(s3_error(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "At least one of the pre-conditions you specified did not hold",
                resource,
            ));
        }
    }

    let if_unmodified_since = headers
        .get(axum::http::header::HeaderName::from_static(
            "x-amz-copy-source-if-unmodified-since",
        ))
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_date);
    if if_match.is_none() {
        if let Some(boundary) = if_unmodified_since {
            if last_modified > boundary {
                return Some(s3_error(
                    StatusCode::PRECONDITION_FAILED,
                    "PreconditionFailed",
                    "At least one of the pre-conditions you specified did not hold",
                    resource,
                ));
            }
        }
    }

    let if_none_match = headers
        .get(axum::http::header::HeaderName::from_static(
            "x-amz-copy-source-if-none-match",
        ))
        .and_then(|value| value.to_str().ok());
    if let Some(value) = if_none_match {
        if if_header_matches_etag(value, etag, &etag_quoted) {
            return Some(s3_error(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "At least one of the pre-conditions you specified did not hold",
                resource,
            ));
        }
    }

    let if_modified_since = headers
        .get(axum::http::header::HeaderName::from_static(
            "x-amz-copy-source-if-modified-since",
        ))
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_date);
    if if_none_match.is_none() {
        if let Some(boundary) = if_modified_since {
            if last_modified <= boundary {
                return Some(s3_error(
                    StatusCode::PRECONDITION_FAILED,
                    "PreconditionFailed",
                    "At least one of the pre-conditions you specified did not hold",
                    resource,
                ));
            }
        }
    }

    None
}

pub(crate) fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(crate) fn s3_xml_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/xml; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

pub(crate) fn bilingual_s3_message(code: &str, message: &str) -> String {
    if message.contains(" / ") {
        return message.to_string();
    }

    let (zh, en_default) = match code {
        "NoSuchBucket" => ("桶不存在", "The specified bucket does not exist"),
        "NoSuchKey" => ("对象不存在", "The specified key does not exist"),
        "NoSuchUpload" => (
            "分片上传不存在",
            "The specified multipart upload does not exist",
        ),
        "NoSuchVersion" => (
            "对象版本不存在",
            "The specified object version does not exist",
        ),
        "NoSuchBucketPolicy" => ("桶策略不存在", "The bucket policy does not exist"),
        "NoSuchCORSConfiguration" => ("CORS 配置不存在", "The CORS configuration does not exist"),
        "NoSuchTagSet" => ("标签配置不存在", "The tag set does not exist"),
        "NoSuchLifecycleConfiguration" => (
            "生命周期配置不存在",
            "The lifecycle configuration does not exist",
        ),
        "BucketAlreadyOwnedByYou" => (
            "桶已存在且归属于当前账号",
            "Your previous request to create the named bucket succeeded",
        ),
        "BucketNotEmpty" => ("桶不为空", "The bucket you tried to delete is not empty"),
        "InvalidBucketName" => ("桶名称无效", "The specified bucket is not valid"),
        "InvalidObjectName" => ("对象名称无效", "The specified object name is not valid"),
        "InvalidVersionId" => ("版本号无效", "The specified version ID is not valid"),
        "InvalidRange" => ("请求范围无效", "The requested range is not satisfiable"),
        "InvalidTag" => ("标签参数无效", "The Tag provided was not a valid tag"),
        "InvalidArgument" => ("参数无效", "Invalid Argument"),
        "InvalidRequest" => ("请求不合法", "Invalid Request"),
        "PreconditionFailed" => (
            "前置条件不满足",
            "At least one of the preconditions you specified did not hold",
        ),
        "MalformedXML" => ("XML 格式错误", "The XML you provided was not well-formed"),
        "MalformedPolicy" => ("策略文档格式错误", "The policy document is malformed"),
        "ObjectLockConfigurationNotFoundError" => (
            "对象锁配置不存在",
            "Object Lock configuration does not exist",
        ),
        "ServerSideEncryptionConfigurationNotFoundError" => (
            "桶加密配置不存在",
            "Server side encryption configuration was not found",
        ),
        "AccessDenied" => ("访问被拒绝", "Access Denied"),
        "SignatureDoesNotMatch" => (
            "签名不匹配",
            "The request signature we calculated does not match the signature you provided",
        ),
        "ExpiredToken" => ("令牌已过期", "The provided token has expired"),
        "InvalidToken" => (
            "令牌无效",
            "The security token included in the request is invalid",
        ),
        "InvalidAccessKeyId" => (
            "AccessKey 不存在或无效",
            "The Access Key Id you provided does not exist in our records.",
        ),
        "AuthorizationHeaderMalformed" => (
            "Authorization 头格式错误",
            "The authorization header is malformed",
        ),
        "AuthorizationQueryParametersError" => (
            "签名查询参数错误",
            "The query string authorization parameters are malformed",
        ),
        "XAmzContentSHA256Mismatch" => (
            "请求体 SHA256 校验不匹配",
            "The provided x-amz-content-sha256 does not match",
        ),
        "InvalidPart" => (
            "分片参数无效",
            "One or more of the specified parts could not be found",
        ),
        "MethodNotAllowed" => (
            "方法不被允许",
            "The specified method is not allowed against this resource",
        ),
        "KMSNotConfigured" => ("KMS 未配置", "KMS is not configured"),
        "KMSUnavailable" => ("KMS 不可用", "KMS service is unavailable"),
        "InternalError" => ("服务器内部错误", "We encountered an internal error"),
        _ => ("S3 请求失败", "S3 request failed"),
    };

    let text = message.trim();
    if text.is_empty() {
        return format!("{zh} / {en_default}");
    }

    if contains_cjk_chars(text) && !contains_ascii_alpha(text) {
        return format!("{text} / {en_default}");
    }

    format!("{zh} / {text}")
}

pub(crate) fn contains_ascii_alpha(text: &str) -> bool {
    text.chars().any(|ch| ch.is_ascii_alphabetic())
}

pub(crate) fn contains_cjk_chars(text: &str) -> bool {
    text.chars().any(|ch| {
        matches!(
            ch as u32,
            0x3400..=0x4DBF
                | 0x4E00..=0x9FFF
                | 0xF900..=0xFAFF
                | 0x20000..=0x2A6DF
                | 0x2A700..=0x2B73F
                | 0x2B740..=0x2B81F
                | 0x2B820..=0x2CEAF
                | 0x2EBF0..=0x2EE5F
        )
    })
}

pub(crate) fn s3_error(status: StatusCode, code: &str, message: &str, resource: &str) -> Response {
    let message = bilingual_s3_message(code, message);
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>{}</Code><Message>{}</Message><Resource>{}</Resource><RequestId>{}</RequestId></Error>"#,
        xml_escape(code),
        xml_escape(&message),
        xml_escape(resource),
        Uuid::new_v4()
    );
    s3_xml_response(status, body)
}

pub(crate) async fn s3_create_bucket(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(bucket): Path<String>,
) -> Result<Json<ApiEnvelope<BucketSpec>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let mut buckets = state.buckets.write().await;
    if buckets.contains_key(&bucket) {
        return Err(AppError::bad_request(
            "存储桶已存在 / bucket already exists",
        ));
    }

    let spec = BucketSpec {
        name: bucket.clone(),
        tenant_id: "default".to_string(),
        versioning: true,
        object_lock: false,
        ilm_policy: None,
        replication_policy: None,
    };

    buckets.insert(bucket.clone(), spec.clone());
    drop(buckets);

    state
        .bucket_object_locks
        .write()
        .await
        .insert(bucket.clone(), default_object_lock_config(&spec));
    state
        .bucket_retentions
        .write()
        .await
        .insert(bucket.clone(), default_retention_config());
    state
        .bucket_legal_holds
        .write()
        .await
        .insert(bucket.clone(), default_legal_hold_config());
    state
        .bucket_notifications
        .write()
        .await
        .insert(bucket.clone(), Vec::new());
    state
        .bucket_lifecycle_rules
        .write()
        .await
        .insert(bucket.clone(), Vec::new());
    state
        .bucket_acls
        .write()
        .await
        .insert(bucket.clone(), default_bucket_acl_config());
    state
        .bucket_public_access_blocks
        .write()
        .await
        .insert(bucket.clone(), default_bucket_public_access_block_config());
    state
        .append_audit(
            &auth.username,
            "s3.bucket.create",
            &format!("bucket/{bucket}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(spec))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ListObjectQuery {
    pub(crate) prefix: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct S3ListResponse {
    pub(crate) bucket: String,
    pub(crate) objects: Vec<S3ObjectMeta>,
}

pub(crate) async fn s3_list_objects(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(bucket): Path<String>,
    Query(query): Query<ListObjectQuery>,
) -> Result<Json<ApiEnvelope<S3ListResponse>>, AppError> {
    auth.require(Permission::BucketRead)?;
    ensure_metadata_read_barrier_api(&state).await?;
    if !state.buckets.read().await.contains_key(&bucket) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }

    let prefix = query.prefix.unwrap_or_default();
    let objects = state
        .object_meta
        .read()
        .await
        .values()
        .filter(|meta| meta.bucket == bucket && meta.key.starts_with(&prefix))
        .cloned()
        .collect::<Vec<_>>();

    Ok(wrap(S3ListResponse { bucket, objects }))
}

pub(crate) async fn s3_put_object(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path((bucket, key)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<ApiEnvelope<S3ObjectMeta>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    if !state.buckets.read().await.contains_key(&bucket) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }

    let etag = Uuid::new_v4().to_string();
    let meta = S3ObjectMeta {
        bucket: bucket.clone(),
        key: key.clone(),
        version_id: Uuid::new_v4().to_string(),
        size: body.len() as u64,
        etag,
        created_at: Utc::now(),
        storage_class: default_storage_class(),
        retention_mode: None,
        retention_until: None,
        legal_hold: false,
        delete_marker: false,
        remote_tier: None,
        restore: None,
        tags: Vec::new(),
        user_metadata: HashMap::new(),
        encryption: S3ObjectEncryptionMeta::default(),
    };

    state
        .object_store
        .write()
        .await
        .insert((bucket.clone(), key.clone()), body.to_vec());
    state
        .object_meta
        .write()
        .await
        .insert((bucket.clone(), key.clone()), meta.clone());

    state
        .push_event(
            "s3.object.put",
            "s3-gateway",
            json!({ "bucket": bucket, "key": key, "size": meta.size }),
        )
        .await;

    Ok(wrap(meta))
}

pub(crate) async fn s3_get_object(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    auth.require(Permission::BucketRead)?;
    ensure_metadata_read_barrier_api(&state).await?;
    let store = state.object_store.read().await;
    let bytes = store
        .get(&(bucket.clone(), key.clone()))
        .ok_or_else(|| AppError::not_found("对象不存在 / object not found"))?
        .clone();

    let meta = state
        .object_meta
        .read()
        .await
        .get(&(bucket, key))
        .cloned()
        .ok_or_else(|| AppError::not_found("对象元数据缺失 / object metadata missing"))?;

    let mut response = (StatusCode::OK, bytes).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        axum::http::header::HeaderName::from_static("x-rustio-version-id"),
        axum::http::HeaderValue::from_str(&meta.version_id)
            .map_err(|_| AppError::internal("version_id 请求头无效 / invalid version_id header"))?,
    );
    response.headers_mut().insert(
        axum::http::header::ETAG,
        axum::http::HeaderValue::from_str(&meta.etag)
            .map_err(|_| AppError::internal("etag 请求头无效 / invalid etag header"))?,
    );

    Ok(response)
}

pub(crate) async fn s3_delete_object(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let removed = state
        .object_store
        .write()
        .await
        .remove(&(bucket.clone(), key.clone()))
        .is_some();
    state
        .object_meta
        .write()
        .await
        .remove(&(bucket.clone(), key.clone()));

    if !removed {
        return Err(AppError::not_found("对象不存在 / object not found"));
    }

    state
        .push_event(
            "s3.object.delete",
            "s3-gateway",
            json!({ "bucket": bucket, "key": key }),
        )
        .await;
    Ok(wrap(json!({ "deleted": true })))
}

pub(crate) fn ensure_confirm_header(headers: &HeaderMap) -> Result<(), AppError> {
    let confirmed = headers
        .get("x-rustio-confirm")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if confirmed {
        Ok(())
    } else {
        Err(AppError::precondition(
            "dangerous action requires x-rustio-confirm: true",
        ))
    }
}

pub(crate) fn extract_access_token(
    headers: &HeaderMap,
    query_token: Option<String>,
) -> Option<String> {
    if let Some(token) = query_token {
        return Some(token);
    }

    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.to_string())
}

pub(crate) fn wrap<T>(data: T) -> Json<ApiEnvelope<T>> {
    Json(ApiEnvelope {
        data,
        request_id: Uuid::new_v4().to_string(),
    })
}

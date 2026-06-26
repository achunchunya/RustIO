//! S3 对象写入、属性查询、Select

use super::*;

pub(crate) async fn s3_root_bucket_get(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(bucket): Path<String>,
    Query(query): Query<S3BucketQuery>,
) -> Response {
    if method == Method::GET
        && uri.query().is_none()
        && !is_s3_signed_request(&headers, uri.query())
    {
        // bucket 配了 website 则按静态网站语义服务根路径(优先于 console fallback)。
        if let Some(response) = serve_website_request(&state, &bucket, "").await {
            return response;
        }
        if let Some(response) = serve_console_path(&bucket, request_accepts_html(&headers)).await {
            return response;
        }
    }

    if let Err(response) = ensure_s3_auth(&headers, &method, &uri, None, &state) {
        return response;
    }
    if let Err(response) = ensure_metadata_read_barrier_s3(&state, &bucket).await {
        return response;
    }

    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };

    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    if query_has_key(uri.query(), "policy") {
        return s3_root_get_bucket_policy(state, bucket).await;
    }

    if query_has_key(uri.query(), "acl") {
        return s3_root_get_bucket_acl(state, bucket).await;
    }

    if query_has_key(uri.query(), "cors") {
        return s3_root_get_bucket_cors(state, bucket).await;
    }

    if query_has_key(uri.query(), "website") {
        return s3_root_get_bucket_website(state, bucket).await;
    }

    if query_has_key(uri.query(), "replication") {
        return s3_root_get_bucket_replication(state, bucket).await;
    }

    if query_has_key(uri.query(), "tagging") {
        return s3_root_get_bucket_tagging(state, bucket).await;
    }

    if query_has_key(uri.query(), "encryption") {
        return s3_root_get_bucket_encryption(state, bucket).await;
    }

    if query_has_key(uri.query(), "lifecycle") {
        return s3_root_get_bucket_lifecycle(state, bucket).await;
    }

    if query_has_key(uri.query(), "object-lock") {
        return s3_root_get_bucket_object_lock(state, bucket).await;
    }

    if query_has_key(uri.query(), "notification") {
        return s3_root_get_bucket_notification(state, bucket).await;
    }

    if query_has_key(uri.query(), "publicAccessBlock")
        || query_has_key(uri.query(), "public-access-block")
    {
        return s3_root_get_bucket_public_access_block(state, bucket).await;
    }

    if query_has_key(uri.query(), "accelerate") {
        return s3_root_get_bucket_accelerate(state, bucket).await;
    }
    if query_has_key(uri.query(), "logging") {
        return s3_root_get_bucket_logging(state, bucket).await;
    }
    if query_has_key(uri.query(), "requestPayment") {
        return s3_root_get_bucket_request_payment(state, bucket).await;
    }
    if query_has_key(uri.query(), "analytics") {
        return s3_root_get_bucket_analytics(state, bucket).await;
    }
    if query_has_key(uri.query(), "metrics") {
        return s3_root_get_bucket_metrics(state, bucket).await;
    }
    if query_has_key(uri.query(), "inventory") {
        return s3_root_get_bucket_inventory(state, bucket).await;
    }

    if query_has_key(uri.query(), "versioning") {
        // S3 三态:从未配置(versioning_configured=false)→ 空响应(无 Status);
        // 配置过 → Enabled(versioning=true)/ Suspended(false)。
        let (configured, enabled) = state
            .buckets
            .read()
            .await
            .get(&bucket)
            .map(|item| (item.versioning_configured, item.versioning))
            .unwrap_or((false, false));
        let status_xml = if !configured {
            String::new()
        } else if enabled {
            "<Status>Enabled</Status>".to_string()
        } else {
            "<Status>Suspended</Status>".to_string()
        };
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">{status_xml}</VersioningConfiguration>"#
        );
        return s3_xml_response(StatusCode::OK, xml);
    }

    if query_has_key(uri.query(), "uploads") {
        let max_uploads = query_value(uri.query(), "max-uploads")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1000)
            .clamp(0, 1000);
        return s3_list_multipart_uploads_xml(
            state,
            &bucket,
            query.prefix.as_deref().unwrap_or_default(),
            query.delimiter.as_deref().unwrap_or_default(),
            query.key_marker.as_deref().unwrap_or_default(),
            query_value(uri.query(), "upload-id-marker")
                .as_deref()
                .unwrap_or_default(),
            max_uploads,
            query.encoding_type.as_deref() == Some("url"),
        )
        .await;
    }

    if query_has_key(uri.query(), "versions") {
        let prefix = query.prefix.unwrap_or_default();
        let delimiter = query.delimiter.unwrap_or_default();
        let max_keys = query.max_keys.unwrap_or(1000).clamp(0, 1000);
        return s3_list_object_versions_xml(
            state,
            &bucket,
            &prefix,
            &delimiter,
            max_keys,
            query.key_marker.as_deref().unwrap_or_default(),
            query.version_id_marker.as_deref().unwrap_or_default(),
            query.encoding_type.as_deref() == Some("url"),
        )
        .await;
    }

    if query.location.is_some() {
        return s3_xml_response(
            StatusCode::OK,
            r#"<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>"#
                .to_string(),
        );
    }

    let prefix = query.prefix.unwrap_or_default();
    let delimiter = query.delimiter.unwrap_or_default();
    // AWS 上限 1000；max-keys=0 合法（返回空结果 + IsTruncated=false）
    let max_keys = query.max_keys.unwrap_or(1000).clamp(0, 1000);
    let encoding_url = match query.encoding_type.as_deref() {
        None => false,
        Some("url") => true,
        Some(_) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "encoding-type must be url",
                &bucket,
            );
        }
    };

    // ── LIST v2 真分页快路径(含 delimiter range-seek) ──
    // 条件:list-type=2 且非 walk-fs 回退。以前 delimiter 走全量(CommonPrefix 折叠需全量去重),
    // 现在 scan_bucket_delimiter_page 用 redb range seek 跳过公共前缀,O(前缀数)替代 O(总对象数)。
    if query.list_type.as_deref() == Some("2")
        && !list_walk_fs_fallback_enabled()
    {
        let continuation_token = query
            .continuation_token
            .as_deref()
            .filter(|value| !value.is_empty());
        let start_after = query
            .start_after
            .as_deref()
            .filter(|value| !value.is_empty());
        let boundary = continuation_token.or(start_after);

        if delimiter.is_empty() {
            // 无 delimiter 原有真分页快路径(不变)
            let (page_objects, truncated) = if max_keys == 0 {
                (Vec::new(), false)
            } else {
                collect_objects_page_indexed(&state, &bucket, &prefix, boundary.unwrap_or(""), max_keys)
            };
            let next_token = if truncated {
                page_objects.last().map(|o| o.key.clone())
            } else {
                None
            };
            return s3_xml_response(
                StatusCode::OK,
                build_list_objects_v2_xml(
                    &bucket,
                    &prefix,
                    &delimiter,
                    max_keys,
                    page_objects.len(),
                    truncated,
                    continuation_token,
                    start_after,
                    next_token.as_deref(),
                    &page_objects,
                    &[],
                    encoding_url,
                ),
            );
        } else {
            // delimiter range-seek 分页快路径(新)
            let limit = if max_keys == 0 { 1 } else { max_keys };
            match state.meta_store.scan_bucket_delimiter_page(
                &bucket,
                &prefix,
                &delimiter,
                boundary,
                limit,
            ) {
                Ok((items, next_token)) => {
                    let mut objects = Vec::new();
                    let mut common_prefixes = Vec::new();
                    let mut count = 0;
                    for item in items {
                        count += 1;
                        match item {
                            DelimiterPageItem::CommonPrefix(cp) => {
                                common_prefixes.push(cp);
                            }
                            DelimiterPageItem::Object(meta) => {
                                objects.push(DiskObjectEntry {
                                    key: meta.key.clone(),
                                    size: meta.size,
                                    etag: meta.etag.clone(),
                                    last_modified: meta.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                                    storage_class: object_storage_class(&meta).to_string(),
                                });
                            }
                        }
                    }
                    let truncated = count >= max_keys;
                    return s3_xml_response(
                        StatusCode::OK,
                        build_list_objects_v2_xml(
                            &bucket,
                            &prefix,
                            &delimiter,
                            max_keys,
                            count,
                            truncated,
                            continuation_token,
                            start_after,
                            next_token.as_deref(),
                            &objects,
                            &common_prefixes,
                            encoding_url,
                        ),
                    );
                }
                Err(err) => {
                    return s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to list objects with delimiter: {err}"),
                        &bucket,
                    );
                }
            }
        }
    }

    // 全量路径:list v1、或 walk-fs 回退(保留不变)
    // LIST 主路径:纯 redb 索引枚举(无 walk-fs、无逐对象 stat);
    // RUSTIO_LIST_WALK_FS=1 回退 walk-fs(异常恢复 / 基准对比 MinIO 行为)。
    let objects = if list_walk_fs_fallback_enabled() {
        let mut walked = Vec::new();
        if let Err(err) = collect_objects(&state, &bucket, &bucket_dir, &bucket_dir, &mut walked) {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to list objects: {err}"),
                &bucket,
            );
        }
        walked
    } else {
        collect_objects_indexed(&state, &bucket)
    };

    let mut filtered = objects
        .into_iter()
        .filter(|entry| entry.key.starts_with(&prefix))
        .collect::<Vec<_>>();
    filtered.sort_by(|a, b| a.key.cmp(&b.key));

    if query.list_type.as_deref() == Some("2") {
        let continuation_token = query
            .continuation_token
            .as_deref()
            .filter(|value| !value.is_empty());
        let start_after = query
            .start_after
            .as_deref()
            .filter(|value| !value.is_empty());
        let page = build_s3_list_page(
            filtered,
            &prefix,
            &delimiter,
            continuation_token.or(start_after),
            max_keys,
        );
        return s3_xml_response(
            StatusCode::OK,
            build_list_objects_v2_xml(
                &bucket,
                &prefix,
                &delimiter,
                max_keys,
                page.result_count,
                page.truncated,
                continuation_token,
                start_after,
                page.next_token.as_deref(),
                &page.objects,
                &page.common_prefixes,
                encoding_url,
            ),
        );
    }
    if query
        .list_type
        .as_deref()
        .map(|value| value != "1")
        .unwrap_or(false)
    {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "list-type must be 1 or 2",
            &bucket,
        );
    }

    // V1 仅接受 marker 参数（key-marker 是 ListObjectVersions 的参数，不混用）
    let marker = query.marker.unwrap_or_default();
    let marker_ref = if marker.is_empty() {
        None
    } else {
        Some(marker.as_str())
    };
    let page = build_s3_list_page(filtered, &prefix, &delimiter, marker_ref, max_keys);
    s3_xml_response(
        StatusCode::OK,
        build_list_objects_v1_xml(
            &bucket,
            &prefix,
            &delimiter,
            &marker,
            max_keys,
            page.truncated,
            page.next_token.as_deref(),
            &page.objects,
            &page.common_prefixes,
            encoding_url,
        ),
    )
}

pub(crate) async fn s3_root_head_bucket(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(bucket): Path<String>,
) -> Response {
    if let Err(response) = ensure_s3_auth(&headers, &method, &uri, None, &state) {
        return response;
    }
    if let Err(response) = ensure_metadata_read_barrier_s3(&state, &bucket).await {
        return response;
    }

    if !state.buckets.read().await.contains_key(&bucket) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let mut response = StatusCode::OK.into_response();
    response.headers_mut().insert(
        axum::http::header::HeaderName::from_static("x-amz-bucket-region"),
        axum::http::HeaderValue::from_static("us-east-1"),
    );
    response
}

pub(crate) async fn s3_root_bucket_post(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(bucket): Path<String>,
    body: Bytes,
) -> Response {
    // 检测 Content-Type: multipart/form-data → 表单上传
    if let Some(content_type) = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        if content_type.starts_with("multipart/form-data") {
            let body_vec = body.to_vec();
            return s3_form_upload(state, bucket, content_type, body_vec).await;
        }
    }

    if let Err(response) = ensure_s3_auth(&headers, &method, &uri, Some(body.as_ref()), &state) {
        return response;
    }

    if query_has_key(uri.query(), "delete") {
        // 批量删除可带 x-amz-bypass-governance-retention 头绕过 GOVERNANCE retention。
        let bypass_governance = headers
            .get("x-amz-bypass-governance-retention")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        return s3_root_delete_objects(state, bucket, body, bypass_governance).await;
    }

    s3_error(
        StatusCode::BAD_REQUEST,
        "InvalidRequest",
        "POST bucket requires delete subresource",
        &bucket,
    )
}

pub(crate) async fn s3_root_delete_objects(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
    bypass_governance: bool,
) -> Response {
    let bucket_root = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_root.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let parsed = match from_xml_str::<S3DeleteObjectsBody>(&String::from_utf8_lossy(&body)) {
        Ok(value) => value,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!("Failed to parse delete objects XML: {err}"),
                &bucket,
            );
        }
    };

    if parsed.objects.is_empty() {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "Delete request must contain at least one object",
            &bucket,
        );
    }
    if parsed.objects.len() > 1000 {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "Delete request cannot contain more than 1000 objects",
            &bucket,
        );
    }

    let quiet = parsed
        .quiet
        .as_deref()
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut deleted = Vec::new();
    let mut errors = Vec::new();
    for item in parsed.objects {
        let key = item.key.unwrap_or_default().trim().to_string();
        if key.is_empty() {
            errors.push(S3DeleteObjectErrorEntry {
                key: String::new(),
                version_id: item.version_id,
                code: "InvalidArgument".to_string(),
                message: "Object key cannot be empty".to_string(),
            });
            continue;
        }
        if is_reserved_internal_key(&key) {
            errors.push(S3DeleteObjectErrorEntry {
                key,
                version_id: item.version_id,
                code: "InvalidObjectName".to_string(),
                message: "Object key uses reserved internal namespace".to_string(),
            });
            continue;
        }

        match s3_delete_object_single(&state, &bucket, &key, item.version_id.as_deref(), bypass_governance).await {
            Ok(entry) => deleted.push(entry),
            Err(entry) => errors.push(entry),
        }
    }

    s3_xml_response(
        StatusCode::OK,
        build_delete_objects_result_xml(&deleted, &errors, quiet),
    )
}

pub(crate) async fn s3_delete_object_single(
    state: &Arc<AppState>,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    bypass_governance: bool,
) -> Result<S3DeleteObjectResultEntry, S3DeleteObjectErrorEntry> {
    let bucket_root = bucket_path(state, bucket).map_err(|_| S3DeleteObjectErrorEntry {
        key: key.to_string(),
        version_id: version_id.map(ToOwned::to_owned),
        code: "InvalidBucketName".to_string(),
        message: "The specified bucket is not valid.".to_string(),
    })?;
    if !bucket_root.exists() {
        return Err(S3DeleteObjectErrorEntry {
            key: key.to_string(),
            version_id: version_id.map(ToOwned::to_owned),
            code: "NoSuchBucket".to_string(),
            message: "The specified bucket does not exist".to_string(),
        });
    }

    if let Some(version_id) = version_id {
        let removed = delete_object_version(state, bucket, key, version_id, bypass_governance)
            .await
            .map_err(|_| S3DeleteObjectErrorEntry {
                key: key.to_string(),
                version_id: Some(version_id.to_string()),
                code: "AccessDenied".to_string(),
                message: "Failed to delete object version".to_string(),
            })?;
        if !removed {
            return Err(S3DeleteObjectErrorEntry {
                key: key.to_string(),
                version_id: Some(version_id.to_string()),
                code: "NoSuchVersion".to_string(),
                message: "The specified version does not exist".to_string(),
            });
        }
        return Ok(S3DeleteObjectResultEntry {
            key: key.to_string(),
            version_id: Some(version_id.to_string()),
            delete_marker: false,
            delete_marker_version_id: None,
        });
    }

    let versioning_enabled = state
        .buckets
        .read()
        .await
        .get(bucket)
        .map(|item| item.versioning)
        .unwrap_or(true);
    let current_meta = read_current_object_meta(state, bucket, key)
        .await
        .map_err(|_| S3DeleteObjectErrorEntry {
            key: key.to_string(),
            version_id: None,
            code: "InternalError".to_string(),
            message: "Failed to read object metadata".to_string(),
        })?;
    let legal_hold_from_bucket = state
        .bucket_legal_holds
        .read()
        .await
        .get(bucket)
        .cloned()
        .unwrap_or_else(default_legal_hold_config)
        .enabled;
    let retention_from_bucket = state
        .bucket_retentions
        .read()
        .await
        .get(bucket)
        .cloned()
        .unwrap_or_else(default_retention_config)
        .enabled;
    let object_lock_from_bucket = state
        .bucket_object_locks
        .read()
        .await
        .get(bucket)
        .map(|item| item.enabled)
        .unwrap_or(false);

    if current_meta
        .as_ref()
        .map(|item| item.legal_hold)
        .unwrap_or(legal_hold_from_bucket)
    {
        return Err(S3DeleteObjectErrorEntry {
            key: key.to_string(),
            version_id: None,
            code: "AccessDenied".to_string(),
            message: "Object is under legal hold".to_string(),
        });
    }

    let retention_until = current_meta.as_ref().and_then(|item| item.retention_until);
    // GOVERNANCE 模式 + bypass 头可绕过;COMPLIANCE 不可。
    let governance_bypassed = current_meta
        .as_ref()
        .and_then(|item| item.retention_mode.as_deref())
        == Some("GOVERNANCE")
        && bypass_governance;
    if retention_until
        .map(|value| value > Utc::now())
        .unwrap_or(false)
        && !governance_bypassed
    {
        return Err(S3DeleteObjectErrorEntry {
            key: key.to_string(),
            version_id: None,
            code: "AccessDenied".to_string(),
            message: "Object retention period has not expired".to_string(),
        });
    }

    if current_meta.is_none() && (retention_from_bucket || object_lock_from_bucket) {
        return Err(S3DeleteObjectErrorEntry {
            key: key.to_string(),
            version_id: None,
            code: "AccessDenied".to_string(),
            message: "Bucket retention is enabled for this object".to_string(),
        });
    }

    if versioning_enabled {
        if let Some(meta) = current_meta.as_ref() {
            archive_object_version(state, bucket, key, meta)
                .await
                .map_err(|_| S3DeleteObjectErrorEntry {
                    key: key.to_string(),
                    version_id: None,
                    code: "InternalError".to_string(),
                    message: "Failed to archive current object version".to_string(),
                })?;
        }
    }

    remove_current_hot_object_payload(state, bucket, key)
        .await
        .map_err(|_| S3DeleteObjectErrorEntry {
            key: key.to_string(),
            version_id: None,
            code: "InternalError".to_string(),
            message: "Failed to delete object".to_string(),
        })?;

    if versioning_enabled {
        let marker =
            build_object_meta_for_current_version(state, bucket, key, 0, String::new(), true, ObjectSystemMetadata::default()).await;
        let marker_version_id = marker.version_id.clone();
        persist_current_object_meta(state, marker)
            .await
            .map_err(|_| S3DeleteObjectErrorEntry {
                key: key.to_string(),
                version_id: None,
                code: "InternalError".to_string(),
                message: "Failed to persist delete marker".to_string(),
            })?;
        return Ok(S3DeleteObjectResultEntry {
            key: key.to_string(),
            version_id: None,
            delete_marker: true,
            delete_marker_version_id: Some(marker_version_id),
        });
    }

    remove_current_object_meta(state, bucket, key)
        .await
        .map_err(|_| S3DeleteObjectErrorEntry {
            key: key.to_string(),
            version_id: None,
            code: "InternalError".to_string(),
            message: "Failed to remove object metadata".to_string(),
        })?;
    if let Some(meta) = current_meta.as_ref() {
        remove_remote_tier_payload_for_meta(state, meta)
            .await
            .map_err(|_| S3DeleteObjectErrorEntry {
                key: key.to_string(),
                version_id: None,
                code: "InternalError".to_string(),
                message: "Failed to delete remote tier object".to_string(),
            })?;
    }

    Ok(S3DeleteObjectResultEntry {
        key: key.to_string(),
        version_id: None,
        delete_marker: false,
        delete_marker_version_id: None,
    })
}

pub(crate) async fn s3_root_delete_bucket(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(bucket): Path<String>,
) -> Response {
    if let Err(response) = ensure_s3_auth(&headers, &method, &uri, None, &state) {
        return response;
    }

    if query_has_key(uri.query(), "policy") {
        return s3_root_delete_bucket_policy(state, bucket).await;
    }

    if query_has_key(uri.query(), "acl") {
        return s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource.",
            &bucket,
        );
    }

    if query_has_key(uri.query(), "cors") {
        return s3_root_delete_bucket_cors(state, bucket).await;
    }

    if query_has_key(uri.query(), "website") {
        return s3_root_delete_bucket_website(state, bucket).await;
    }

    if query_has_key(uri.query(), "replication") {
        return s3_root_delete_bucket_replication(state, bucket).await;
    }

    if query_has_key(uri.query(), "tagging") {
        return s3_root_delete_bucket_tagging(state, bucket).await;
    }

    if query_has_key(uri.query(), "encryption") {
        return s3_root_delete_bucket_encryption(state, bucket).await;
    }

    if query_has_key(uri.query(), "lifecycle") {
        return s3_root_delete_bucket_lifecycle(state, bucket).await;
    }

    if query_has_key(uri.query(), "object-lock") {
        return s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource.",
            &bucket,
        );
    }

    if query_has_key(uri.query(), "notification") {
        return s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource.",
            &bucket,
        );
    }

    if query_has_key(uri.query(), "publicAccessBlock")
        || query_has_key(uri.query(), "public-access-block")
    {
        return s3_root_delete_bucket_public_access_block(state, bucket).await;
    }

    if query_has_key(uri.query(), "analytics") {
        return s3_root_delete_bucket_analytics(state, bucket).await;
    }
    if query_has_key(uri.query(), "metrics") {
        return s3_root_delete_bucket_metrics(state, bucket).await;
    }
    if query_has_key(uri.query(), "inventory") {
        return s3_root_delete_bucket_inventory(state, bucket).await;
    }

    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };

    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let has_objects = match bucket_has_objects(&bucket_dir, &bucket_dir) {
        Ok(value) => value,
        Err(err) => {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to read bucket: {err}"),
                &bucket,
            );
        }
    };

    if has_objects {
        return s3_error(
            StatusCode::CONFLICT,
            "BucketNotEmpty",
            "The bucket you tried to delete is not empty",
            &bucket,
        );
    }

    if let Err(err) = tokio::fs::remove_dir_all(&bucket_dir).await {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to remove bucket: {err}"),
            &bucket,
        );
    }

    if let Err(err) = state
        .submit_metadata_command(MetadataCommand::DeleteBucket { name: bucket })
        .await
    {
        return s3_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "InternalError",
            &format!("metadata raft commit failed: {err}"),
            "/",
        );
    }
    StatusCode::NO_CONTENT.into_response()
}

pub(crate) async fn s3_root_put_object(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Path((bucket, key)): Path<(String, String)>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    if let Some(upload_id) = query_value(uri.query(), "uploadId") {
        let Some(part_number_raw) = query_value(uri.query(), "partNumber") else {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "partNumber is required when uploadId is set",
                &key,
            );
        };
        let part_number = match part_number_raw.parse::<u32>() {
            Ok(value) if (1..=10_000).contains(&value) => value,
            _ => {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "partNumber must be between 1 and 10000",
                    &key,
                );
            }
        };

        // 流式请求：先验 seed 签名（header-only），解码时逐块验签
        let auth_outcome = match ensure_s3_auth(&headers, &method, &uri, None, &state) {
            Ok(outcome) => outcome,
            Err(response) => return response,
        };

        // UploadPartCopy:带 x-amz-copy-source 时从源对象拷贝字节作为 part(而非读请求 body)。
        if let Some(copy_source) = headers
            .get("x-amz-copy-source")
            .and_then(|value| value.to_str().ok())
        {
            let copy_source_range = headers
                .get("x-amz-copy-source-range")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            return s3_upload_part_copy(
                state,
                bucket,
                key,
                upload_id,
                part_number,
                copy_source.to_string(),
                copy_source_range,
            )
            .await;
        }

        // part 上传走流式路径（传 body + 完整 auth outcome 给 s3_upload_part，支持 chunked/trailer/checksum）
        return s3_upload_part_streaming(
            state,
            bucket,
            key,
            upload_id,
            part_number,
            body,
            auth_outcome,
            headers,
        )
        .await
        .unwrap_or_else(|response| response);
    }

    // 单次 PUT 对象数据（非子资源/copy）走流式：不全量收集 body，验签后边读边写盘，内存恒定。
    // 其余分支（legal-hold/retention/tagging/acl/copy）body 小或为空，保持全量收集后验签。
    let is_object_data_put = !query_has_key(uri.query(), "legal-hold")
        && !query_has_key(uri.query(), "retention")
        && !query_has_key(uri.query(), "tagging")
        && !query_has_key(uri.query(), "acl")
        && !headers.contains_key("x-amz-copy-source");

    let mut streaming_body: Option<axum::body::Body> = None;
    let mut streaming_auth = S3AuthOutcome::default();
    let body_bytes = if is_object_data_put {
        // 流式分叉：先验签名（body=None，签名 HMAC 不依赖 body），body 留待流式消费
        match ensure_s3_auth(&headers, &method, &uri, None, &state) {
            Ok(outcome) => streaming_auth = outcome,
            Err(response) => return response,
        }
        streaming_body = Some(body);
        Bytes::new()
    } else {
        // 其他分支（legal-hold/retention/tagging/copy）：需先收集 body 验签
        let bytes = match to_bytes(body, usize::MAX).await {
            Ok(bytes) => bytes,
            Err(err) => {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "IncompleteBody",
                    &format!("Failed to read request body: {err}"),
                    &key,
                );
            }
        };
        // 非流式验签（需完整 body）
        if let Err(response) = ensure_s3_auth(&headers, &method, &uri, Some(bytes.as_ref()), &state)
        {
            return response;
        }
        bytes
    };

    if query_has_key(uri.query(), "legal-hold") {
        return s3_put_object_legal_hold(
            state,
            bucket,
            key,
            query_value(uri.query(), "versionId"),
            body_bytes,
        )
        .await;
    }

    if query_has_key(uri.query(), "retention") {
        return s3_put_object_retention(
            state,
            bucket,
            key,
            query_value(uri.query(), "versionId"),
            body_bytes,
        )
        .await;
    }

    if query_has_key(uri.query(), "tagging") {
        return s3_put_object_tagging(
            state,
            bucket,
            key,
            query_value(uri.query(), "versionId"),
            body_bytes,
        )
        .await;
    }

    if query_has_key(uri.query(), "acl") {
        return s3_put_object_acl(state, bucket, key, headers, body_bytes).await;
    }

    if is_reserved_internal_key(&key) {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidObjectName",
            "Object key uses reserved internal namespace",
            &key,
        );
    }

    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };

    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let current_meta = match read_current_object_meta(&state, &bucket, &key).await {
        Ok(meta) => meta,
        Err(response) => return response,
    };
    if let Some(current_meta) = current_meta.as_ref() {
        if current_meta.legal_hold {
            state
                .append_audit(
                    "s3-root",
                    "object.put",
                    &format!("bucket/{bucket}/{key}"),
                    "denied",
                    None,
                    json!({
                        "reason": "legal_hold",
                        "version_id": current_meta.version_id,
                        "via": "s3",
                    }),
                )
                .await;
            return s3_error(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "Object is under legal hold",
                &key,
            );
        }
        if current_meta
            .retention_until
            .map(|value| value > Utc::now())
            .unwrap_or(false)
        {
            state
                .append_audit(
                    "s3-root",
                    "object.put",
                    &format!("bucket/{bucket}/{key}"),
                    "denied",
                    None,
                    json!({
                        "reason": "retention_active",
                        "version_id": current_meta.version_id,
                        "retention_until": current_meta.retention_until,
                        "via": "s3",
                    }),
                )
                .await;
            return s3_error(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "Object retention period has not expired",
                &key,
            );
        }
    }

    // PUT 条件写(S3 语义): If-None-Match: * 对象已存在 → 412(防覆盖); If-Match 对现有对象 etag 不符 → 412。
    if let Some(if_none_match) = headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
    {
        if if_none_match.trim() == "*" && current_meta.is_some() {
            return s3_error(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "At least one of the pre-conditions you specified did not hold",
                &key,
            );
        }
    }
    if let Some(if_match) = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
    {
        let matched = current_meta
            .as_ref()
            .map(|meta| if_header_matches_etag(if_match, &meta.etag, &format!("\"{}\"", meta.etag)))
            .unwrap_or(false);
        if !matched {
            return s3_error(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "At least one of the pre-conditions you specified did not hold",
                &key,
            );
        }
    }
    let versioning_enabled = state
        .buckets
        .read()
        .await
        .get(&bucket)
        .map(|item| item.versioning)
        .unwrap_or(true);
    if versioning_enabled {
        if let Some(ref meta) = current_meta {
            if let Err(response) = archive_object_version(&state, &bucket, &key, meta).await {
                return response;
            }
        }
    }

    let request_user_metadata = extract_user_metadata(&headers);
    // 提取系统定义元数据(标准内容头 + storage-class),storage-class 非法提前拒绝(写盘前)。
    let request_system_meta = match extract_object_system_metadata(&headers) {
        Ok(system_meta) => system_meta,
        Err(invalid_class) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidStorageClass",
                &format!("The storage class you specified is not valid: {invalid_class}"),
                &key,
            );
        }
    };
    let request_tags = match headers
        .get(axum::http::header::HeaderName::from_static("x-amz-tagging"))
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => match parse_s3_tagging_header(value) {
            Ok(tags) => tags,
            Err(message) => return s3_error(StatusCode::BAD_REQUEST, "InvalidTag", message, &key),
        },
        None => Vec::new(),
    };
    let (requested_encryption, sse_customer_key) =
        match resolve_object_encryption_meta(&state, &bucket, &headers, &key, true).await {
            Ok(value) => value,
            Err(response) => return response,
        };

    if let Some(copy_source_raw) = headers
        .get("x-amz-copy-source")
        .and_then(|value| value.to_str().ok())
    {
        let (source_bucket, source_key, source_version_id) =
            match parse_copy_source_header(copy_source_raw) {
                Ok(value) => value,
                Err(message) => {
                    return s3_error(StatusCode::BAD_REQUEST, "InvalidArgument", &message, &key);
                }
            };

        if is_reserved_internal_key(&source_key) {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidObjectName",
                "Source object key uses reserved internal namespace",
                &source_key,
            );
        }

        let source_bucket_path = match bucket_path(&state, &source_bucket) {
            Ok(path) => path,
            Err(response) => return response,
        };
        if !source_bucket_path.exists() {
            return s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "The specified source bucket does not exist",
                &source_bucket,
            );
        }

        let source_current_meta =
            match read_current_object_meta(&state, &source_bucket, &source_key).await {
                Ok(meta) => meta,
                Err(response) => return response,
            };
        let (source_meta, source_is_current) = if let Some(version_id) = source_version_id {
            match resolve_object_version_meta(
                &state,
                &source_bucket,
                &source_key,
                &version_id,
                source_current_meta,
            )
            .await
            {
                Ok(Some(value)) => value,
                Ok(None) => {
                    return s3_error(
                        StatusCode::NOT_FOUND,
                        "NoSuchVersion",
                        "The specified source version does not exist",
                        &source_key,
                    );
                }
                Err(response) => return response,
            }
        } else {
            let Some(meta) = source_current_meta else {
                return s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchKey",
                    "The specified source key does not exist",
                    &source_key,
                );
            };
            (meta, true)
        };

        if source_meta.delete_marker {
            return s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified source key does not exist",
                &source_key,
            );
        }
        let source_sse_customer_request = match validate_sse_customer_headers(
            &headers,
            &source_key,
            SseCustomerHeaderKind::CopySource,
            true,
        ) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let source_sse_customer_key = source_sse_customer_request
            .as_ref()
            .map(|req| &req.key_bytes);
        if let Err(response) = ensure_sse_customer_access(
            &source_key,
            &source_meta.encryption,
            source_sse_customer_request.as_ref(),
            SseCustomerHeaderKind::CopySource,
        ) {
            return response;
        }

        let metadata_directive = match headers
            .get(axum::http::header::HeaderName::from_static(
                "x-amz-metadata-directive",
            ))
            .and_then(|value| value.to_str().ok())
        {
            Some(value) => {
                let normalized = value.trim().to_ascii_uppercase();
                if normalized != "COPY" && normalized != "REPLACE" {
                    return s3_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidArgument",
                        "x-amz-metadata-directive must be COPY or REPLACE",
                        &key,
                    );
                }
                normalized
            }
            None => "COPY".to_string(),
        };
        let tagging_directive = match headers
            .get(axum::http::header::HeaderName::from_static(
                "x-amz-tagging-directive",
            ))
            .and_then(|value| value.to_str().ok())
        {
            Some(value) => {
                let normalized = value.trim().to_ascii_uppercase();
                if normalized != "COPY" && normalized != "REPLACE" {
                    return s3_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidArgument",
                        "x-amz-tagging-directive must be COPY or REPLACE",
                        &key,
                    );
                }
                normalized
            }
            None => "COPY".to_string(),
        };

        let source_bytes = if source_is_current {
            match read_current_object_payload(
                &state,
                &source_bucket,
                &source_key,
                Some(&source_meta),
                source_sse_customer_key,
            )
            .await
            {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    return s3_error(
                        StatusCode::NOT_FOUND,
                        "NoSuchKey",
                        "The specified source key does not exist",
                        &source_key,
                    );
                }
                Err(response) => return response,
            }
        } else {
            match read_archived_object_payload(
                &state,
                &source_bucket,
                &source_key,
                &source_meta.version_id,
            )
            .await
            {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    return s3_error(
                        StatusCode::NOT_FOUND,
                        "NoSuchVersion",
                        "The specified source version does not exist",
                        &source_key,
                    );
                }
                Err(response) => return response,
            }
        };

        let source_etag = if source_meta.etag.is_empty() {
            weak_etag(&source_bytes)
        } else {
            source_meta.etag.clone()
        };
        if let Some(response) = evaluate_copy_source_preconditions(
            &headers,
            &source_etag,
            source_meta.created_at,
            &source_key,
        ) {
            return response;
        }

        let target_path = match object_payload_path(&bucket_dir, &key) {
            Ok(path) => path,
            Err(response) => return response,
        };
        if let Some(parent) = target_path.parent() {
            // create_dir_all 忽略已存在错误:连续/重复 PUT 同一 key 时目录可能已在之前请求中创建
            if let Err(err) = tokio::fs::create_dir_all(parent).await {
                if err.kind() != std::io::ErrorKind::AlreadyExists {
                    return s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to create object directory: {err}"),
                        &key,
                    );
                }
            }
        }
        // 系统内容头:COPY 继承源对象,REPLACE 用请求头;storage-class 请求优先、回退源。
        let copy_system_meta = if metadata_directive == "COPY" {
            ObjectSystemMetadata {
                content_type: source_meta.content_type.clone(),
                cache_control: source_meta.cache_control.clone(),
                content_disposition: source_meta.content_disposition.clone(),
                content_encoding: source_meta.content_encoding.clone(),
                content_language: source_meta.content_language.clone(),
                expires: source_meta.expires.clone(),
                website_redirect_location: source_meta.website_redirect_location.clone(),
                storage_class: request_system_meta
                    .storage_class
                    .clone()
                    .or_else(|| Some(source_meta.storage_class.clone())),
            }
        } else {
            ObjectSystemMetadata {
                storage_class: request_system_meta
                    .storage_class
                    .clone()
                    .or_else(|| Some(source_meta.storage_class.clone())),
                ..request_system_meta.clone()
            }
        };
        let mut meta = build_object_meta_for_current_version(
            &state,
            &bucket,
            &key,
            source_bytes.len() as u64,
            source_etag.clone(),
            false,
            copy_system_meta,
        )
        .await;
        meta.user_metadata = if metadata_directive == "COPY" {
            source_meta.user_metadata.clone()
        } else {
            request_user_metadata.clone()
        };
        meta.tags = if tagging_directive == "COPY" {
            source_meta.tags.clone()
        } else {
            request_tags.clone()
        };
        meta.encryption = requested_encryption.clone();
        // 拷贝字节与源一致，FULL_OBJECT/COMPOSITE checksum 沿用源对象
        meta.checksum = source_meta.checksum.clone();
        if let Err(err) = tokio::fs::write(&target_path, &source_bytes).await {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to write copied object: {err}"),
                &key,
            );
        }
        // 明文文件已就位。非加密 Copy 用流式 EC 编码(从目标文件读,消除 source_bytes 二次驻留);
        // 加密对象仍需整体 AES-GCM 全量(整体 AEAD 限制)。
        if !encryption_enabled(&meta) {
            let total = source_bytes.len() as u64;
            drop(source_bytes);
            if let Err(response) =
                write_ec_object_streaming(&state, &bucket, &key, &target_path, total).await
            {
                return response;
            }
        } else {
            if let Err(response) = write_ec_object(
                &state,
                &bucket,
                &key,
                &source_bytes,
                &mut meta,
                sse_customer_key.as_ref(),
            )
            .await
            {
                return response;
            }
        }
        if let Err(response) = persist_current_object_meta(&state, meta.clone()).await {
            return response;
        }
        if !versioning_enabled {
            if let Some(previous_meta) = current_meta.as_ref() {
                if let Err(response) =
                    remove_remote_tier_payload_for_meta(&state, previous_meta).await
                {
                    return response;
                }
            }
        }
        enqueue_replication_for_object(
            &state,
            &bucket,
            &key,
            "put",
            Some(meta.version_id.clone()),
            Some(&meta),
        )
        .await;
        emit_bucket_object_event_best_effort(
            &state,
            &bucket,
            &key,
            "s3:ObjectCreated:Copy",
            Some(&meta),
            "s3",
        )
        .await;

        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>{}</LastModified><ETag>"{}"</ETag></CopyObjectResult>"#,
            meta.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            xml_escape(&source_etag),
        );
        let mut response = s3_xml_response(StatusCode::OK, xml);
        if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-version-id"),
                value,
            );
        }
        if let Ok(value) = axum::http::HeaderValue::from_str(&source_meta.version_id) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-copy-source-version-id"),
                value,
            );
        }
        apply_object_encryption_headers(&mut response, &meta.encryption);
        return response;
    }

    let target_path = match object_payload_path(&bucket_dir, &key) {
        Ok(path) => path,
        Err(response) => return response,
    };

    if let Some(parent) = target_path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            if err.kind() != std::io::ErrorKind::AlreadyExists {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to create object directory: {err}"),
                    &key,
                );
            }
        }
    }

    // 单次 PUT 对象数据：先流式写入唯一命名的临时文件，验证通过后原子 rename 到目标路径，
    // 避免整个对象驻留内存，且新写入失败时不破坏旧对象明文（last-writer-wins 与原行为一致）。
    use crate::routes::s3_chunked::{AwsChunkedDecoder, WeakEtagHasher};

    // 解析 checksum 请求头（x-amz-checksum-* / x-amz-sdk-checksum-algorithm）
    let checksum_request = match parse_checksum_headers(&headers) {
        Ok(value) => value,
        Err(message) => {
            return s3_error(StatusCode::BAD_REQUEST, "InvalidRequest", &message, &key);
        }
    };
    let mut checksum_hasher = checksum_request
        .as_ref()
        .map(|req| req.algorithm.hasher());

    let staging = {
        let file_name = target_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("object");
        target_path.with_file_name(format!(".{file_name}.{}.rustio_puttmp", Uuid::new_v4()))
    };
    let mut file = match tokio::fs::File::create(&staging).await {
        Ok(file) => file,
        Err(err) => {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create object staging file: {err}"),
                &key,
            );
        }
    };

    let body = streaming_body
        .take()
        .expect("object data PUT must carry streaming body");
    let mut etag_hasher = WeakEtagHasher::new();
    // trailer 提供的 checksum 期望值（aws-chunked trailer 模式）
    let mut trailer_checksum: Option<(String, String)> = None;
    let is_chunked_body =
        streaming_auth.streaming_context.is_some() || streaming_auth.unsigned_chunked;
    let total: u64 = if is_chunked_body {
        // (a) aws-chunked（签名或 unsigned，可带 trailer）：真流式解码 + 链式验签
        use futures::TryStreamExt;
        use tokio_util::io::StreamReader;
        let reader = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
        let mut decoder = AwsChunkedDecoder::with_options(
            reader,
            streaming_auth.streaming_context.take(),
            streaming_auth.chunked_trailer,
        );
        match decoder
            .decode_into(&mut file, &mut etag_hasher, checksum_hasher.as_mut())
            .await
        {
            Ok(total) => {
                for (name, value) in decoder.trailers() {
                    if name.starts_with("x-amz-checksum-") {
                        trailer_checksum = Some((name.clone(), value.clone()));
                    }
                }
                total
            }
            Err(err) => {
                let _ = tokio::fs::remove_file(&staging).await;
                let (code, message) = if err.kind() == std::io::ErrorKind::PermissionDenied {
                    (
                        "SignatureDoesNotMatch",
                        "aws-chunked chunk signature does not match".to_string(),
                    )
                } else {
                    (
                        "IncompleteBody",
                        format!("aws-chunked decode failed: {err}"),
                    )
                };
                return s3_error(StatusCode::BAD_REQUEST, code, &message, &key);
            }
        }
    } else {
        // (b)/(c)：逐帧写盘 + 增量 weak_etag/sha256，EOF 后按需比对 x-amz-content-sha256
        use futures::StreamExt;
        let mut stream = body.into_data_stream();
        let mut sha = Sha256::new();
        let mut total: u64 = 0;
        while let Some(result) = stream.next().await {
            let frame = match result {
                Ok(frame) => frame,
                Err(err) => {
                    let _ = tokio::fs::remove_file(&staging).await;
                    return s3_error(
                        StatusCode::BAD_REQUEST,
                        "IncompleteBody",
                        &format!("Failed to read request body: {err}"),
                        &key,
                    );
                }
            };
            if let Err(err) = file.write_all(&frame).await {
                let _ = tokio::fs::remove_file(&staging).await;
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to write object: {err}"),
                    &key,
                );
            }
            etag_hasher.update(&frame);
            sha.update(&frame);
            if let Some(hasher) = checksum_hasher.as_mut() {
                hasher.update(&frame);
            }
            total += frame.len() as u64;
        }
        // 普通 SigV4（声明 64 位 hex）：流式消费后比对 body SHA256 防篡改
        if let Some(expected) = streaming_auth.expected_payload_sha256.as_deref() {
            let computed = hex::encode(sha.finalize());
            if !computed.eq_ignore_ascii_case(expected) {
                let _ = tokio::fs::remove_file(&staging).await;
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "XAmzContentSHA256Mismatch",
                    "x-amz-content-sha256 does not match request body",
                    &key,
                );
            }
        }
        total
    };

    // checksum 校验：期望值来自请求头或 aws-chunked trailer，不匹配回 BadDigest
    let mut stored_checksum: Option<rustio_core::types::S3ObjectChecksum> = None;
    if let (Some(request), Some(hasher)) = (checksum_request.as_ref(), checksum_hasher.take()) {
        let computed = hasher.finalize();
        let expected = request.expected.clone().or_else(|| {
            trailer_checksum
                .as_ref()
                .filter(|(name, _)| name == request.algorithm.header_name())
                .map(|(_, value)| value.clone())
        });
        if let Some(expected) = expected {
            if expected.trim() != computed {
                let _ = tokio::fs::remove_file(&staging).await;
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "BadDigest",
                    &format!(
                        "The {} you specified did not match the calculated checksum",
                        request.algorithm.name()
                    ),
                    &key,
                );
            }
        }
        stored_checksum = Some(rustio_core::types::S3ObjectChecksum {
            algorithm: request.algorithm.name().to_string(),
            value: computed,
            checksum_type: "FULL_OBJECT".to_string(),
        });
    }

    if let Err(err) = file.sync_all().await {
        let _ = tokio::fs::remove_file(&staging).await;
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to flush object staging file: {err}"),
            &key,
        );
    }
    drop(file);

    // 原子替换：临时文件就位后 rename 到目标路径。target_path 明文供 replication 源读取
    // 与热层读取 fallback 依赖（load_replication_payload / read_current_hot_object_payload）。
    // 失败仅删临时文件，旧对象明文保持不变（比直接覆盖写目标文件更安全）。
    if let Err(err) = tokio::fs::rename(&staging, &target_path).await {
        let _ = tokio::fs::remove_file(&staging).await;
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to finalize object file: {err}"),
            &key,
        );
    }

    let etag = etag_hasher.finalize();
    // Content-MD5 完整性校验(S3 语义): 请求头为 body MD5 的 base64; etag 即 MD5 hex,转字节后比对。
    if let Some(content_md5) = headers
        .get("content-md5")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let computed_b64 = hex::decode(&etag)
            .ok()
            .map(|bytes| BASE64.encode(bytes))
            .unwrap_or_default();
        if content_md5 != computed_b64 {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "BadDigest",
                "The Content-MD5 you specified did not match what we received",
                &key,
            );
        }
    }
    let mut meta =
        build_object_meta_for_current_version(&state, &bucket, &key, total, etag.clone(), false, request_system_meta)
            .await;
    meta.user_metadata = request_user_metadata;
    meta.tags = request_tags;
    meta.encryption = requested_encryption;
    meta.checksum = stored_checksum;
    // PUT object 携带 canned x-amz-acl 头时记录到对象 meta(非法值忽略,沿用默认 private)。
    meta.acl = headers
        .get(axum::http::header::HeaderName::from_static("x-amz-acl"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| normalize_bucket_acl_value(value).ok());

    if !encryption_enabled(&meta) {
        // 非加密：从已落盘的目标文件流式 EC 编码，内存恒定
        if let Err(response) =
            write_ec_object_streaming(&state, &bucket, &key, &target_path, total).await
        {
            return response;
        }
    } else {
        // 加密对象:整体 AES-GCM 加密(AES-GCM 认证标签依赖全文,无法流式;与 S3 SSE 语义一致)。
        // 内存峰值 = 1 份 payload(加密后立即 drop 源数据);大对象走 staging 文件不驻留双份。
        let plaintext = match tokio::fs::read(&target_path).await {
            Ok(bytes) => bytes,
            Err(err) => {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to read object file: {err}"),
                    &key,
                );
            }
        };
        if let Err(response) = write_ec_object(
            &state,
            &bucket,
            &key,
            &plaintext,
            &mut meta,
            sse_customer_key.as_ref(),
        )
        .await
        {
            return response;
        }
    }
    if let Err(response) = persist_current_object_meta(&state, meta.clone()).await {
        return response;
    }
    if !versioning_enabled {
        if let Some(previous_meta) = current_meta.as_ref() {
            if let Err(response) = remove_remote_tier_payload_for_meta(&state, previous_meta).await
            {
                return response;
            }
        }
    }
    enqueue_replication_for_object(
        &state,
        &bucket,
        &key,
        "put",
        Some(meta.version_id.clone()),
        Some(&meta),
    )
    .await;
    emit_bucket_object_event_best_effort(
        &state,
        &bucket,
        &key,
        "s3:ObjectCreated:Put",
        Some(&meta),
        "s3",
    )
    .await;

    let mut response = StatusCode::OK.into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&format!("\"{etag}\"")) {
        response
            .headers_mut()
            .insert(axum::http::header::ETAG, value);
    }
    if let Some(ref ct) = meta.content_type {
        if let Ok(value) = axum::http::HeaderValue::from_str(ct) {
            response
                .headers_mut()
                .insert(axum::http::header::CONTENT_TYPE, value);
        }
    }
    // 仅版本化桶返回 x-amz-version-id;非版本化桶 version_id="null",不返回该 header
    //(S3 语义:未配置版本化的桶 PUT 响应不含 VersionId)。
    if meta.version_id != "null" {
        if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-version-id"),
                value,
            );
        }
    }
    if let Some(ref checksum) = meta.checksum {
        apply_checksum_headers(&mut response, checksum);
    }
    apply_object_encryption_headers(&mut response, &meta.encryption);
    response
}

pub(crate) fn parse_content_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let header_name = axum::http::header::HeaderName::from_bytes(name.as_bytes()).ok()?;
    headers
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) async fn load_selected_object_for_advanced_api(
    state: &AppState,
    bucket: &str,
    key: &str,
    requested_version_id: Option<&str>,
    sse_customer_request: Option<&SseCustomerRequest>,
) -> Result<(S3ObjectMeta, bool, Vec<u8>), Response> {
    let bucket_root = bucket_path(state, bucket)?;
    if !bucket_root.exists() {
        return Err(s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            bucket,
        ));
    }
    if is_reserved_internal_key(key) {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidObjectName",
            "Object key uses reserved internal namespace",
            key,
        ));
    }

    let current_meta = read_current_object_meta(state, bucket, key).await?;
    let (selected_meta, selected_is_current) = if let Some(version_id) = requested_version_id {
        let resolved =
            resolve_object_version_meta(state, bucket, key, version_id, current_meta).await?;
        let Some((meta, is_current)) = resolved else {
            return Err(s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchVersion",
                "The specified version does not exist",
                key,
            ));
        };
        (meta, is_current)
    } else {
        let Some(meta) = current_meta else {
            return Err(s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified key does not exist",
                key,
            ));
        };
        (meta, true)
    };

    if selected_meta.delete_marker {
        let mut response = if requested_version_id.is_some() {
            s3_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "The specified method is not allowed against this resource",
                key,
            )
        } else {
            s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified key does not exist",
                key,
            )
        };
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-delete-marker"),
            axum::http::HeaderValue::from_static("true"),
        );
        if let Ok(value) = axum::http::HeaderValue::from_str(&selected_meta.version_id) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-version-id"),
                value,
            );
        }
        return Err(response);
    }
    ensure_sse_customer_access(
        key,
        &selected_meta.encryption,
        sse_customer_request,
        SseCustomerHeaderKind::Request,
    )?;

    let customer_key = sse_customer_request.map(|req| &req.key_bytes);
    let bytes = if selected_is_current {
        match read_current_object_payload(state, bucket, key, Some(&selected_meta), customer_key)
            .await?
        {
            Some(bytes) => bytes,
            None => {
                return Err(s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchKey",
                    "The specified key does not exist",
                    key,
                ))
            }
        }
    } else {
        match read_archived_object_payload_by_meta(state, &selected_meta).await? {
            Some(bytes) => bytes,
            None => {
                return Err(s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchVersion",
                    "The specified version does not exist",
                    key,
                ))
            }
        }
    };

    touch_object_access_heat(state, bucket, key).await;
    Ok((selected_meta, selected_is_current, bytes))
}

pub(crate) fn decode_select_token(raw: &str) -> String {
    match raw {
        "\\n" => "\n".to_string(),
        "\\r" => "\r".to_string(),
        "\\r\\n" => "\r\n".to_string(),
        "\\t" => "\t".to_string(),
        value => value.to_string(),
    }
}

pub(crate) fn normalize_select_char(
    raw: Option<&str>,
    default_value: u8,
    field_name: &str,
) -> Result<u8, Response> {
    let Some(raw) = raw else {
        return Ok(default_value);
    };
    let normalized = decode_select_token(raw);
    let bytes = normalized.as_bytes();
    if bytes.len() != 1 {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            &format!("{field_name} 必须是单字符 / {field_name} must be a single character"),
            field_name,
        ));
    }
    Ok(bytes[0])
}

pub(crate) fn normalize_select_record_delimiter(raw: Option<&str>, default_value: &str) -> String {
    raw.map(decode_select_token)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default_value.to_string())
}

pub(crate) fn parse_select_input_format(
    body: &SelectObjectContentRequestBody,
) -> Result<SelectInputFormat, Response> {
    let Some(input) = body.input_serialization.as_ref() else {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "缺少 InputSerialization / missing InputSerialization",
            "SelectObjectContent",
        ));
    };
    let compression = input
        .compression_type
        .as_deref()
        .unwrap_or("NONE")
        .trim()
        .to_ascii_uppercase();
    if compression != "NONE" {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "当前仅支持 NONE 压缩 / only NONE compression is supported",
            "SelectObjectContent",
        ));
    }
    match (&input.csv, &input.json) {
        (Some(csv), None) => Ok(SelectInputFormat::Csv(SelectCsvRuntimeConfig {
            file_header_info: csv
                .file_header_info
                .as_deref()
                .unwrap_or("NONE")
                .trim()
                .to_ascii_uppercase(),
            field_delimiter: normalize_select_char(
                csv.field_delimiter.as_deref(),
                b',',
                "FieldDelimiter",
            )?,
            quote_character: normalize_select_char(
                csv.quote_character.as_deref(),
                b'"',
                "QuoteCharacter",
            )?,
            quote_escape_character: normalize_select_char(
                csv.quote_escape_character.as_deref(),
                b'"',
                "QuoteEscapeCharacter",
            )?,
            record_delimiter: normalize_select_record_delimiter(
                csv.record_delimiter.as_deref(),
                "\n",
            ),
        })),
        (None, Some(json)) => Ok(SelectInputFormat::Json(SelectJsonRuntimeConfig {
            json_type: json
                .json_type
                .as_deref()
                .unwrap_or("LINES")
                .trim()
                .to_ascii_uppercase(),
        })),
        (Some(_), Some(_)) => Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "InputSerialization 不能同时包含 CSV 和 JSON / InputSerialization cannot contain both CSV and JSON",
            "SelectObjectContent",
        )),
        (None, None) => Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "InputSerialization 必须包含 CSV 或 JSON / InputSerialization must contain CSV or JSON",
            "SelectObjectContent",
        )),
    }
}

pub(crate) fn parse_select_output_format(
    body: &SelectObjectContentRequestBody,
) -> Result<SelectOutputFormat, Response> {
    let Some(output) = body.output_serialization.as_ref() else {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "缺少 OutputSerialization / missing OutputSerialization",
            "SelectObjectContent",
        ));
    };
    match (&output.csv, &output.json) {
        (Some(csv), None) => Ok(SelectOutputFormat::Csv(SelectCsvOutputRuntimeConfig {
            field_delimiter: normalize_select_char(
                csv.field_delimiter.as_deref(),
                b',',
                "FieldDelimiter",
            )?,
            quote_character: normalize_select_char(
                csv.quote_character.as_deref(),
                b'"',
                "QuoteCharacter",
            )?,
            quote_escape_character: normalize_select_char(
                csv.quote_escape_character.as_deref(),
                b'"',
                "QuoteEscapeCharacter",
            )?,
            record_delimiter: normalize_select_record_delimiter(
                csv.record_delimiter.as_deref(),
                "\n",
            ),
        })),
        (None, Some(json)) => Ok(SelectOutputFormat::Json(SelectJsonOutputRuntimeConfig {
            record_delimiter: normalize_select_record_delimiter(
                json.record_delimiter.as_deref(),
                "\n",
            ),
        })),
        (Some(_), Some(_)) => Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "OutputSerialization 不能同时包含 CSV 和 JSON / OutputSerialization cannot contain both CSV and JSON",
            "SelectObjectContent",
        )),
        (None, None) => Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "OutputSerialization 必须包含 CSV 或 JSON / OutputSerialization must contain CSV or JSON",
            "SelectObjectContent",
        )),
    }
}

pub(crate) fn strip_select_alias(path: &str) -> String {
    let trimmed = path.trim();
    if let Some((prefix, suffix)) = trimmed.split_once('.') {
        if prefix.eq_ignore_ascii_case("s") {
            return suffix.trim().to_string();
        }
    }
    trimmed.to_string()
}

pub(crate) fn parse_select_literal(raw: &str) -> Value {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("null") {
        return Value::Null;
    }
    if trimmed.eq_ignore_ascii_case("true") {
        return Value::Bool(true);
    }
    if trimmed.eq_ignore_ascii_case("false") {
        return Value::Bool(false);
    }
    if trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2 {
        return Value::String(trimmed[1..trimmed.len() - 1].replace("''", "'"));
    }
    if let Ok(value) = trimmed.parse::<i64>() {
        return Value::Number(value.into());
    }
    if let Ok(value) = trimmed.parse::<u64>() {
        return Value::Number(value.into());
    }
    if let Ok(value) = trimmed.parse::<f64>() {
        if let Some(number) = serde_json::Number::from_f64(value) {
            return Value::Number(number);
        }
    }
    Value::String(trimmed.to_string())
}

pub(crate) fn parse_select_predicate(raw: &str) -> Result<SelectPredicate, Response> {
    let operators = [">=", "<=", "!=", "<>", "=", ">", "<"];
    for operator in operators {
        if let Some(index) = raw.find(operator) {
            let left = raw[..index].trim();
            let right = raw[index + operator.len()..].trim();
            if left.is_empty() || right.is_empty() {
                break;
            }
            return Ok(SelectPredicate {
                path: strip_select_alias(left),
                operator: operator.to_string(),
                value: parse_select_literal(right),
            });
        }
    }
    Err(s3_error(
        StatusCode::BAD_REQUEST,
        "InvalidRequest",
        "当前仅支持单条件比较 WHERE / only single comparison WHERE clauses are supported",
        "SelectObjectContent",
    ))
}

pub(crate) fn parse_select_expression(
    expression: &str,
) -> Result<ParsedSelectExpression, Response> {
    let expression = expression.trim().trim_end_matches(';').trim();
    let lower = expression.to_ascii_lowercase();
    if !lower.starts_with("select ") {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "当前仅支持 SELECT 查询 / only SELECT statements are supported",
            "SelectObjectContent",
        ));
    }
    let from_index = lower.find(" from ").ok_or_else(|| {
        s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "缺少 FROM 子句 / missing FROM clause",
            "SelectObjectContent",
        )
    })?;
    let projection_raw = expression["select ".len()..from_index].trim();
    let remaining = expression[from_index + " from ".len()..].trim();
    let remaining_lower = remaining.to_ascii_lowercase();
    let where_index = remaining_lower.find(" where ");
    let from_source = where_index
        .map(|index| remaining[..index].trim())
        .unwrap_or(remaining);
    if from_source
        .split_whitespace()
        .next()
        .map(|value| !value.eq_ignore_ascii_case("s3object"))
        .unwrap_or(true)
    {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "当前仅支持 FROM S3Object / only FROM S3Object is supported",
            "SelectObjectContent",
        ));
    }
    let where_clause = where_index
        .map(|index| parse_select_predicate(remaining[index + " where ".len()..].trim()))
        .transpose()?;

    let projections = projection_raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| {
            if item == "*" || item.eq_ignore_ascii_case("s.*") {
                return Ok(SelectProjection {
                    path: None,
                    alias: "*".to_string(),
                    star: true,
                });
            }
            let lower_item = item.to_ascii_lowercase();
            let (path, alias) = if let Some(index) = lower_item.find(" as ") {
                (
                    item[..index].trim(),
                    item[index + " as ".len()..].trim().to_string(),
                )
            } else {
                let path = item.trim();
                let alias = strip_select_alias(path)
                    .split('.')
                    .next_back()
                    .unwrap_or(path)
                    .to_string();
                (path, alias)
            };
            if path.is_empty() || alias.trim().is_empty() {
                return Err(s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "SELECT 列定义无效 / invalid SELECT projection",
                    "SelectObjectContent",
                ));
            }
            Ok(SelectProjection {
                path: Some(strip_select_alias(path)),
                alias: alias.trim().to_string(),
                star: false,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if projections.is_empty() {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "SELECT 列不能为空 / SELECT projection cannot be empty",
            "SelectObjectContent",
        ));
    }
    Ok(ParsedSelectExpression {
        projections,
        where_clause,
    })
}

pub(crate) fn normalize_csv_text_input(
    bytes: &[u8],
    record_delimiter: &str,
) -> Result<Vec<u8>, Response> {
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| {
        s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "CSV 输入必须是 UTF-8 文本 / CSV input must be UTF-8 text",
            "SelectObjectContent",
        )
    })?;
    if record_delimiter == "\n" {
        return Ok(text.into_bytes());
    }
    Ok(text.replace(record_delimiter, "\n").into_bytes())
}

pub(crate) fn parse_select_rows(
    payload: &[u8],
    input_format: &SelectInputFormat,
) -> Result<Vec<SelectRow>, Response> {
    match input_format {
        SelectInputFormat::Csv(config) => {
            let normalized = normalize_csv_text_input(payload, &config.record_delimiter)?;
            let mut reader = ReaderBuilder::new()
                .has_headers(false)
                .delimiter(config.field_delimiter)
                .quote(config.quote_character)
                .escape(Some(config.quote_escape_character))
                .flexible(true)
                .from_reader(normalized.as_slice());
            let mut rows = Vec::new();
            let mut header_row = None::<Vec<String>>;
            for (index, record) in reader.records().enumerate() {
                let record = record.map_err(|err| {
                    s3_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidRequest",
                        &format!("解析 CSV 失败：{err} / failed to parse CSV input: {err}"),
                        "SelectObjectContent",
                    )
                })?;
                let values = record
                    .iter()
                    .map(|item| item.to_string())
                    .collect::<Vec<_>>();
                if index == 0 && config.file_header_info == "USE" {
                    header_row = Some(values);
                    continue;
                }
                if index == 0 && config.file_header_info == "IGNORE" {
                    continue;
                }
                rows.push(SelectRow::Csv {
                    values,
                    headers: header_row.clone(),
                });
            }
            Ok(rows)
        }
        SelectInputFormat::Json(config) => {
            if config.json_type == "DOCUMENT" {
                let value = serde_json::from_slice::<Value>(payload).map_err(|err| {
                    s3_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidRequest",
                        &format!(
                            "解析 JSON 文档失败：{err} / failed to parse JSON document: {err}"
                        ),
                        "SelectObjectContent",
                    )
                })?;
                match value {
                    Value::Array(items) => Ok(items.into_iter().map(SelectRow::Json).collect()),
                    other => Ok(vec![SelectRow::Json(other)]),
                }
            } else {
                let text = String::from_utf8(payload.to_vec()).map_err(|_| {
                    s3_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidRequest",
                        "JSON Lines 输入必须是 UTF-8 文本 / JSON Lines input must be UTF-8 text",
                        "SelectObjectContent",
                    )
                })?;
                text.lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(|line| {
                        serde_json::from_str::<Value>(line).map(SelectRow::Json).map_err(|err| {
                            s3_error(
                                StatusCode::BAD_REQUEST,
                                "InvalidRequest",
                                &format!("解析 JSON 行失败：{err} / failed to parse JSON line: {err}"),
                                "SelectObjectContent",
                            )
                        })
                    })
                    .collect()
            }
        }
    }
}

pub(crate) fn lookup_json_value(value: &Value, path: &str) -> Option<Value> {
    let mut current = value;
    for segment in strip_select_alias(path).split('.') {
        if segment.is_empty() {
            continue;
        }
        if let Some(index) = segment
            .strip_prefix('_')
            .and_then(|raw| raw.parse::<usize>().ok())
        {
            let Value::Array(items) = current else {
                return None;
            };
            current = items.get(index.saturating_sub(1))?;
            continue;
        }
        let Value::Object(map) = current else {
            return None;
        };
        current = map.get(segment).or_else(|| {
            map.iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(segment))
                .map(|(_, value)| value)
        })?;
    }
    Some(current.clone())
}

pub(crate) fn csv_row_as_json(values: &[String], headers: Option<&Vec<String>>) -> Value {
    let mut object = serde_json::Map::new();
    for (index, value) in values.iter().enumerate() {
        let key = headers
            .and_then(|items| items.get(index))
            .cloned()
            .unwrap_or_else(|| format!("_{}", index + 1));
        object.insert(key, Value::String(value.clone()));
    }
    Value::Object(object)
}

pub(crate) fn json_value_to_csv_values(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items.iter().map(value_to_select_string).collect(),
        Value::Object(map) => {
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            keys.into_iter()
                .filter_map(|key| map.get(&key))
                .map(value_to_select_string)
                .collect()
        }
        other => vec![value_to_select_string(other)],
    }
}

pub(crate) fn value_to_select_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(item) => item.to_string(),
        Value::Number(item) => item.to_string(),
        Value::String(item) => item.clone(),
        other => other.to_string(),
    }
}

impl SelectRow {
    fn lookup_value(&self, path: &str) -> Option<Value> {
        match self {
            SelectRow::Csv { values, headers } => {
                let path = strip_select_alias(path);
                if let Some(index) = path
                    .strip_prefix('_')
                    .and_then(|raw| raw.parse::<usize>().ok())
                {
                    return values
                        .get(index.saturating_sub(1))
                        .cloned()
                        .map(Value::String);
                }
                let headers = headers.as_ref()?;
                headers
                    .iter()
                    .position(|header| header == &path || header.eq_ignore_ascii_case(&path))
                    .and_then(|index| values.get(index))
                    .cloned()
                    .map(Value::String)
            }
            SelectRow::Json(value) => lookup_json_value(value, path),
        }
    }

    fn star_json_value(&self) -> Value {
        match self {
            SelectRow::Csv { values, headers } => csv_row_as_json(values, headers.as_ref()),
            SelectRow::Json(value) => value.clone(),
        }
    }

    fn star_csv_values(&self) -> Vec<String> {
        match self {
            SelectRow::Csv { values, .. } => values.clone(),
            SelectRow::Json(value) => json_value_to_csv_values(value),
        }
    }
}

pub(crate) fn value_to_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Number(item) => item.as_f64(),
        Value::String(item) => item.parse::<f64>().ok(),
        Value::Bool(item) => Some(if *item { 1.0 } else { 0.0 }),
        _ => None,
    }
}

pub(crate) fn compare_select_values(left: &Value, operator: &str, right: &Value) -> bool {
    if let (Some(left_number), Some(right_number)) = (value_to_f64(left), value_to_f64(right)) {
        return match operator {
            "=" => left_number == right_number,
            "!=" | "<>" => left_number != right_number,
            ">" => left_number > right_number,
            "<" => left_number < right_number,
            ">=" => left_number >= right_number,
            "<=" => left_number <= right_number,
            _ => false,
        };
    }
    let left_text = value_to_select_string(left);
    let right_text = value_to_select_string(right);
    match operator {
        "=" => left_text == right_text,
        "!=" | "<>" => left_text != right_text,
        ">" => left_text > right_text,
        "<" => left_text < right_text,
        ">=" => left_text >= right_text,
        "<=" => left_text <= right_text,
        _ => false,
    }
}

pub(crate) fn select_row_matches(row: &SelectRow, predicate: Option<&SelectPredicate>) -> bool {
    let Some(predicate) = predicate else {
        return true;
    };
    row.lookup_value(&predicate.path)
        .map(|value| compare_select_values(&value, &predicate.operator, &predicate.value))
        .unwrap_or(false)
}

pub(crate) fn render_select_output(
    rows: &[SelectRow],
    expression: &ParsedSelectExpression,
    output_format: &SelectOutputFormat,
) -> Result<Vec<u8>, Response> {
    match output_format {
        SelectOutputFormat::Csv(config) => {
            let mut writer = WriterBuilder::new()
                .has_headers(false)
                .delimiter(config.field_delimiter)
                .quote(config.quote_character)
                .escape(config.quote_escape_character)
                .from_writer(Vec::new());
            for row in rows {
                if !select_row_matches(row, expression.where_clause.as_ref()) {
                    continue;
                }
                let record = if expression.projections.len() == 1 && expression.projections[0].star
                {
                    row.star_csv_values()
                } else {
                    expression
                        .projections
                        .iter()
                        .map(|projection| {
                            projection
                                .path
                                .as_deref()
                                .and_then(|path| row.lookup_value(path))
                                .map(|value| value_to_select_string(&value))
                                .unwrap_or_default()
                        })
                        .collect::<Vec<_>>()
                };
                writer
                    .write_record(&StringRecord::from(record))
                    .map_err(|err| {
                        s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &format!(
                                "生成 CSV 输出失败：{err} / failed to render CSV output: {err}"
                            ),
                            "SelectObjectContent",
                        )
                    })?;
            }
            let rendered = writer.into_inner().map_err(|err| {
                s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("刷新 CSV 输出失败：{err} / failed to flush CSV output: {err}"),
                    "SelectObjectContent",
                )
            })?;
            if config.record_delimiter == "\n" {
                return Ok(rendered);
            }
            let text = String::from_utf8(rendered).map_err(|_| {
                s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "CSV 输出不是 UTF-8 / CSV output is not UTF-8",
                    "SelectObjectContent",
                )
            })?;
            Ok(text.replace('\n', &config.record_delimiter).into_bytes())
        }
        SelectOutputFormat::Json(config) => {
            let mut rendered = String::new();
            for row in rows {
                if !select_row_matches(row, expression.where_clause.as_ref()) {
                    continue;
                }
                let value = if expression.projections.len() == 1 && expression.projections[0].star {
                    row.star_json_value()
                } else {
                    let mut object = serde_json::Map::new();
                    for projection in &expression.projections {
                        if projection.star {
                            if let Value::Object(fields) = row.star_json_value() {
                                for (key, value) in fields {
                                    object.insert(key, value);
                                }
                            }
                            continue;
                        }
                        object.insert(
                            projection.alias.clone(),
                            projection
                                .path
                                .as_deref()
                                .and_then(|path| row.lookup_value(path))
                                .unwrap_or(Value::Null),
                        );
                    }
                    Value::Object(object)
                };
                rendered.push_str(&serde_json::to_string(&value).map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("生成 JSON 输出失败：{err} / failed to render JSON output: {err}"),
                        "SelectObjectContent",
                    )
                })?);
                rendered.push_str(&config.record_delimiter);
            }
            Ok(rendered.into_bytes())
        }
    }
}

pub(crate) fn append_event_stream_string_header(target: &mut Vec<u8>, name: &str, value: &str) {
    target.push(name.len() as u8);
    target.extend_from_slice(name.as_bytes());
    target.push(7);
    target.extend_from_slice(&(value.len() as u16).to_be_bytes());
    target.extend_from_slice(value.as_bytes());
}

pub(crate) fn encode_event_stream_message(headers: &[(&str, &str)], payload: &[u8]) -> Vec<u8> {
    let mut encoded_headers = Vec::new();
    for (name, value) in headers {
        append_event_stream_string_header(&mut encoded_headers, name, value);
    }
    let total_len = 16 + encoded_headers.len() + payload.len();
    let headers_len = encoded_headers.len();
    let mut message = Vec::with_capacity(total_len);
    message.extend_from_slice(&(total_len as u32).to_be_bytes());
    message.extend_from_slice(&(headers_len as u32).to_be_bytes());
    let prelude_crc = {
        let mut hasher = Crc32Hasher::new();
        hasher.update(&message);
        hasher.finalize()
    };
    message.extend_from_slice(&prelude_crc.to_be_bytes());
    message.extend_from_slice(&encoded_headers);
    message.extend_from_slice(payload);
    let message_crc = {
        let mut hasher = Crc32Hasher::new();
        hasher.update(&message);
        hasher.finalize()
    };
    message.extend_from_slice(&message_crc.to_be_bytes());
    message
}

pub(crate) fn build_select_stats_payload(scanned_bytes: usize, returned_bytes: usize) -> Vec<u8> {
    format!(
        r#"<Stats xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><BytesScanned>{}</BytesScanned><BytesProcessed>{}</BytesProcessed><BytesReturned>{}</BytesReturned></Stats>"#,
        scanned_bytes, scanned_bytes, returned_bytes
    )
    .into_bytes()
}

pub(crate) fn build_select_event_stream(result_payload: &[u8], scanned_bytes: usize) -> Vec<u8> {
    let mut stream = Vec::new();
    if !result_payload.is_empty() {
        stream.extend_from_slice(&encode_event_stream_message(
            &[
                (":message-type", "event"),
                (":event-type", "Records"),
                (":content-type", "application/octet-stream"),
            ],
            result_payload,
        ));
    }
    stream.extend_from_slice(&encode_event_stream_message(
        &[
            (":message-type", "event"),
            (":event-type", "Stats"),
            (":content-type", "text/xml"),
        ],
        &build_select_stats_payload(scanned_bytes, result_payload.len()),
    ));
    stream.extend_from_slice(&encode_event_stream_message(
        &[(":message-type", "event"), (":event-type", "End")],
        &[],
    ));
    stream
}

pub(crate) async fn s3_get_object_attributes(
    state: Arc<AppState>,
    headers: HeaderMap,
    bucket: String,
    key: String,
    requested_version_id: Option<String>,
) -> Response {
    let requested = header_value(&headers, "x-amz-object-attributes").unwrap_or_default();
    if requested.trim().is_empty() {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "缺少 x-amz-object-attributes 请求头 / missing x-amz-object-attributes header",
            &key,
        );
    }
    let sse_customer_request =
        match validate_sse_customer_headers(&headers, &key, SseCustomerHeaderKind::Request, true) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let (meta, _, _bytes) = match load_selected_object_for_advanced_api(
        &state,
        &bucket,
        &key,
        requested_version_id.as_deref(),
        sse_customer_request.as_ref(),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    // 使用 PutObject/CompleteMPU 时存储的 checksum（不再现场全量读对象计算）
    let stored_checksum = meta.checksum.clone();
    let requested_items = requested
        .split(',')
        .map(|item| item.trim().to_ascii_uppercase())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if requested_items.is_empty() {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "x-amz-object-attributes 不能为空 / x-amz-object-attributes cannot be empty",
            &key,
        );
    }

    let checksum_inner_xml = stored_checksum.as_ref().and_then(|checksum| {
        ChecksumAlgorithm::parse(&checksum.algorithm).map(|algorithm| {
            format!(
                "<{tag}>{value}</{tag}><ChecksumType>{ctype}</ChecksumType>",
                tag = algorithm.xml_tag(),
                value = xml_escape(&checksum.value),
                ctype = xml_escape(&checksum.checksum_type),
            )
        })
    });

    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><GetObjectAttributesOutput xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    for item in requested_items {
        match item.as_str() {
            "ETAG" => {
                xml.push_str(&format!(
                    "<ETag>&quot;{}&quot;</ETag>",
                    xml_escape(&meta.etag)
                ));
            }
            "CHECKSUM" => {
                if let Some(ref inner) = checksum_inner_xml {
                    xml.push_str("<Checksum>");
                    xml.push_str(inner);
                    xml.push_str("</Checksum>");
                }
            }
            "OBJECTSIZE" => {
                xml.push_str(&format!("<ObjectSize>{}</ObjectSize>", meta.size));
            }
            "STORAGECLASS" => {
                xml.push_str(&format!(
                    "<StorageClass>{}</StorageClass>",
                    xml_escape(&meta.storage_class)
                ));
            }
            "OBJECTPARTS" => {
                // multipart 对象 ETag 以 `-N` 结尾，N 为 part 数；单段对象输出单 part
                let parts_count = meta
                    .etag
                    .rsplit_once('-')
                    .and_then(|(_, count)| count.parse::<u64>().ok())
                    .unwrap_or(1);
                xml.push_str("<ObjectParts>");
                xml.push_str("<IsTruncated>false</IsTruncated>");
                xml.push_str(&format!("<MaxParts>{parts_count}</MaxParts>"));
                xml.push_str("<PartNumberMarker>0</PartNumberMarker>");
                xml.push_str("<NextPartNumberMarker>0</NextPartNumberMarker>");
                xml.push_str(&format!("<PartsCount>{parts_count}</PartsCount>"));
                xml.push_str("</ObjectParts>");
            }
            _ => {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    &format!("不支持的对象属性：{item} / unsupported object attribute: {item}"),
                    &key,
                );
            }
        }
    }
    xml.push_str("</GetObjectAttributesOutput>");
    let mut response = s3_xml_response(StatusCode::OK, xml);
    if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-version-id"),
            value,
        );
    }
    response
}

pub(crate) async fn s3_select_object_content(
    state: Arc<AppState>,
    headers: HeaderMap,
    bucket: String,
    key: String,
    raw_query: Option<&str>,
    body: Bytes,
) -> Response {
    let select_type = query_value(raw_query, "select-type").unwrap_or_else(|| "2".to_string());
    if select_type != "2" {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "当前仅支持 select-type=2 / only select-type=2 is supported",
            &key,
        );
    }
    let request_body = match String::from_utf8(body.to_vec()) {
        Ok(value) => value,
        Err(_) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "Select 请求体必须是 UTF-8 XML / select request body must be UTF-8 XML",
                &key,
            )
        }
    };
    let parsed_body = match from_xml_str::<SelectObjectContentRequestBody>(&request_body) {
        Ok(value) => value,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!("解析 Select 请求失败：{err} / failed to parse select request: {err}"),
                &key,
            )
        }
    };
    let expression_type = parsed_body
        .expression_type
        .as_deref()
        .unwrap_or("SQL")
        .trim()
        .to_ascii_uppercase();
    if expression_type != "SQL" {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "当前仅支持 SQL 表达式 / only SQL expression type is supported",
            &key,
        );
    }
    let expression = match parsed_body.expression.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => value,
        _ => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "缺少 Select 表达式 / missing Select expression",
                &key,
            )
        }
    };
    let input_format = match parse_select_input_format(&parsed_body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let output_format = match parse_select_output_format(&parsed_body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let parsed_expression = match parse_select_expression(expression) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let sse_customer_request =
        match validate_sse_customer_headers(&headers, &key, SseCustomerHeaderKind::Request, true) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let requested_version_id = query_value(raw_query, "versionId");
    let (meta, _, bytes) = match load_selected_object_for_advanced_api(
        &state,
        &bucket,
        &key,
        requested_version_id.as_deref(),
        sse_customer_request.as_ref(),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let rows = match parse_select_rows(&bytes, &input_format) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let rendered = match render_select_output(&rows, &parsed_expression, &output_format) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let event_stream = build_select_event_stream(&rendered, bytes.len());
    let mut response = (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/vnd.amazon.eventstream"),
        )],
        event_stream,
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&meta.version_id) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-version-id"),
            value,
        );
    }
    response
}

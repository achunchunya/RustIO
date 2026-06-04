//! S3 对象读取、标签、保留、分片上传

use super::*;

#[allow(unused_variables)]
pub(crate) async fn s3_root_get_object(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    if method == Method::GET
        && uri.query().is_none()
        && !is_s3_signed_request(&headers, uri.query())
    {
        let requested = format!("{bucket}/{key}");
        if let Some(response) = serve_console_path(&requested, request_accepts_html(&headers)).await
        {
            return response;
        }
    }

    if let Err(response) = ensure_s3_auth(&headers, &method, &uri, None, &state) {
        return response;
    }
    if let Err(response) = ensure_metadata_read_barrier_s3(&state, &bucket).await {
        return response;
    }

    if query_has_key(uri.query(), "legal-hold") {
        return s3_get_object_legal_hold(state, bucket, key, query_value(uri.query(), "versionId"))
            .await;
    }

    if query_has_key(uri.query(), "attributes") {
        return s3_get_object_attributes(
            state,
            headers,
            bucket,
            key,
            query_value(uri.query(), "versionId"),
        )
        .await;
    }

    if query_has_key(uri.query(), "retention") {
        return s3_get_object_retention(state, bucket, key, query_value(uri.query(), "versionId"))
            .await;
    }

    if query_has_key(uri.query(), "tagging") {
        return s3_get_object_tagging(state, bucket, key, query_value(uri.query(), "versionId"))
            .await;
    }

    if let Some(upload_id) = query_value(uri.query(), "uploadId") {
        return s3_list_multipart_parts_xml(state, bucket, key, upload_id).await;
    }

    if is_reserved_internal_key(&key) {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidObjectName",
            "Object key uses reserved internal namespace",
            &key,
        );
    }

    let bucket_path = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };

    if !bucket_path.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let requested_version_id = query_value(uri.query(), "versionId");
    let current_meta = match read_current_object_meta(&state, &bucket, &key).await {
        Ok(meta) => meta,
        Err(response) => return response,
    };
    let mut selected_meta = current_meta.clone();
    let mut selected_is_current = true;
    if let Some(version_id) = requested_version_id.as_deref() {
        let resolved = match resolve_object_version_meta(
            &state,
            &bucket,
            &key,
            version_id,
            current_meta,
        )
        .await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
        let Some((meta, is_current)) = resolved else {
            return s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchVersion",
                "The specified version does not exist",
                &key,
            );
        };
        selected_meta = Some(meta);
        selected_is_current = is_current;
    }

    if selected_meta
        .as_ref()
        .map(|meta| meta.delete_marker)
        .unwrap_or(false)
    {
        let mut response = if requested_version_id.is_some() {
            s3_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "The specified method is not allowed against this resource",
                &key,
            )
        } else {
            s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified key does not exist",
                &key,
            )
        };
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-delete-marker"),
            axum::http::HeaderValue::from_static("true"),
        );
        if let Some(meta) = selected_meta {
            if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
                response.headers_mut().insert(
                    axum::http::header::HeaderName::from_static("x-amz-version-id"),
                    value,
                );
            }
        }
        return response;
    }
    let sse_customer_request =
        match validate_sse_customer_headers(&headers, &key, SseCustomerHeaderKind::Request, true) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let customer_key = sse_customer_request.as_ref().map(|req| &req.key_bytes);
    if let Some(meta) = selected_meta.as_ref() {
        if let Err(response) = ensure_sse_customer_access(
            &key,
            &meta.encryption,
            sse_customer_request.as_ref(),
            SseCustomerHeaderKind::Request,
        ) {
            return response;
        }
    }

    // 流式下载快路径：无 Range 请求 + 当前对象 + etag 非空 + 非加密 + 非远端层 + 非 restore-active。
    // 满足时内存恒定（不随对象大小增长）；其余情况落入下方全量加载路径（Range/归档版本/加密等）。
    let has_range = headers.contains_key(axum::http::header::RANGE);
    let stream_eligible = !has_range
        && selected_is_current
        && selected_meta.as_ref().is_some_and(|meta| {
            !meta.etag.is_empty()
                && !encryption_enabled(meta)
                && meta.remote_tier.is_none()
                && !object_restore_is_active(meta)
        });
    if stream_eligible {
        match read_ec_object_streaming(&state, &bucket, &key, selected_meta.as_ref(), customer_key)
            .await
        {
            Ok(Some(body)) => {
                touch_object_access_heat(&state, &bucket, &key).await;
                let meta = selected_meta
                    .as_ref()
                    .expect("stream_eligible guarantees meta exists");
                let etag_quoted = format!("\"{}\"", meta.etag);
                let last_modified = meta.created_at;
                if let Some(response) = evaluate_object_preconditions(
                    &method,
                    &headers,
                    &meta.etag,
                    &etag_quoted,
                    last_modified,
                    &key,
                ) {
                    return response;
                }
                let mut response = body.into_response();
                *response.status_mut() = StatusCode::OK;
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/octet-stream"),
                );
                response.headers_mut().insert(
                    axum::http::header::HeaderName::from_static("accept-ranges"),
                    axum::http::HeaderValue::from_static("bytes"),
                );
                if let Ok(value) =
                    axum::http::HeaderValue::from_str(&format_http_date(last_modified))
                {
                    response
                        .headers_mut()
                        .insert(axum::http::header::LAST_MODIFIED, value);
                }
                if let Ok(value) = axum::http::HeaderValue::from_str(&meta.size.to_string()) {
                    response
                        .headers_mut()
                        .insert(axum::http::header::CONTENT_LENGTH, value);
                }
                if let Ok(value) = axum::http::HeaderValue::from_str(&etag_quoted) {
                    response
                        .headers_mut()
                        .insert(axum::http::header::ETAG, value);
                }
                if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
                    response.headers_mut().insert(
                        axum::http::header::HeaderName::from_static("x-amz-version-id"),
                        value,
                    );
                }
                if let Some(mode) = meta.retention_mode.as_deref() {
                    if let Ok(value) = axum::http::HeaderValue::from_str(mode) {
                        response.headers_mut().insert(
                            axum::http::header::HeaderName::from_static("x-amz-object-lock-mode"),
                            value,
                        );
                    }
                }
                if let Some(retention_until) = meta.retention_until {
                    if let Ok(value) = axum::http::HeaderValue::from_str(
                        &retention_until.to_rfc3339_opts(SecondsFormat::Secs, true),
                    ) {
                        response.headers_mut().insert(
                            axum::http::header::HeaderName::from_static(
                                "x-amz-object-lock-retain-until-date",
                            ),
                            value,
                        );
                    }
                }
                if meta.legal_hold {
                    response.headers_mut().insert(
                        axum::http::header::HeaderName::from_static("x-amz-object-lock-legal-hold"),
                        axum::http::HeaderValue::from_static("ON"),
                    );
                }
                apply_object_metadata_headers(&mut response, meta);
                return response;
            }
            Ok(None) => {}
            Err(response) => return response,
        }
    }

    let bytes = if selected_is_current {
        match read_current_object_payload(
            &state,
            &bucket,
            &key,
            selected_meta.as_ref(),
            customer_key,
        )
        .await
        {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchKey",
                    "The specified key does not exist",
                    &key,
                );
            }
            Err(response) => return response,
        }
    } else {
        let Some(meta) = selected_meta.as_ref() else {
            return s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchVersion",
                "The specified version does not exist",
                &key,
            );
        };
        match read_archived_object_payload_by_meta(&state, meta).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchVersion",
                    "The specified version does not exist",
                    &key,
                );
            }
            Err(response) => return response,
        }
    };
    touch_object_access_heat(&state, &bucket, &key).await;

    let etag = selected_meta
        .as_ref()
        .map(|meta| meta.etag.clone())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| weak_etag(&bytes));
    let etag_quoted = format!("\"{etag}\"");
    let last_modified = selected_meta
        .as_ref()
        .map(|meta| meta.created_at)
        .unwrap_or_else(Utc::now);
    if let Some(response) =
        evaluate_object_preconditions(&method, &headers, &etag, &etag_quoted, last_modified, &key)
    {
        return response;
    }

    let mut status = StatusCode::OK;
    let mut payload = bytes;
    let mut content_range = None::<String>;
    if let Some((start, end)) = match parse_range_header(&headers, payload.len() as u64) {
        Ok(value) => value,
        Err(_) => {
            return s3_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "InvalidRange",
                "The requested range is not satisfiable",
                &key,
            );
        }
    } {
        status = StatusCode::PARTIAL_CONTENT;
        content_range = Some(format!("bytes {start}-{end}/{}", payload.len()));
        payload = payload[start as usize..=end as usize].to_vec();
    }

    let payload_len = payload.len();
    let mut response = (status, payload).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        axum::http::header::HeaderName::from_static("accept-ranges"),
        axum::http::HeaderValue::from_static("bytes"),
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&format_http_date(last_modified)) {
        response
            .headers_mut()
            .insert(axum::http::header::LAST_MODIFIED, value);
    }
    if let Ok(value) = axum::http::HeaderValue::from_str(&payload_len.to_string()) {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_LENGTH, value);
    }
    if let Some(range_header) = content_range {
        if let Ok(value) = axum::http::HeaderValue::from_str(&range_header) {
            response
                .headers_mut()
                .insert(axum::http::header::CONTENT_RANGE, value);
        }
    }
    if let Ok(value) = axum::http::HeaderValue::from_str(&etag_quoted) {
        response
            .headers_mut()
            .insert(axum::http::header::ETAG, value);
    }
    if let Some(meta) = selected_meta.as_ref() {
        if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-version-id"),
                value,
            );
        }
        if let Some(mode) = meta.retention_mode.as_deref() {
            if let Ok(value) = axum::http::HeaderValue::from_str(mode) {
                response.headers_mut().insert(
                    axum::http::header::HeaderName::from_static("x-amz-object-lock-mode"),
                    value,
                );
            }
        }
        if let Some(retention_until) = meta.retention_until {
            if let Ok(value) = axum::http::HeaderValue::from_str(
                &retention_until.to_rfc3339_opts(SecondsFormat::Secs, true),
            ) {
                response.headers_mut().insert(
                    axum::http::header::HeaderName::from_static(
                        "x-amz-object-lock-retain-until-date",
                    ),
                    value,
                );
            }
        }
        if meta.legal_hold {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-object-lock-legal-hold"),
                axum::http::HeaderValue::from_static("ON"),
            );
        }
        apply_object_metadata_headers(&mut response, meta);
    }
    response
}

pub(crate) async fn s3_root_delete_object(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    if let Err(response) = ensure_s3_auth(&headers, &method, &uri, None, &state) {
        return response;
    }

    if query_has_key(uri.query(), "tagging") {
        return s3_delete_object_tagging(state, bucket, key, query_value(uri.query(), "versionId"))
            .await;
    }

    if let Some(upload_id) = query_value(uri.query(), "uploadId") {
        return s3_abort_multipart_upload(state, bucket, key, upload_id).await;
    }

    if let Some(version_id) = query_value(uri.query(), "versionId") {
        let removed = match delete_object_version(&state, &bucket, &key, &version_id).await {
            Ok(value) => value,
            Err(response) => return response,
        };
        if !removed {
            return s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchVersion",
                "The specified version does not exist",
                &key,
            );
        }

        let mut response = StatusCode::NO_CONTENT.into_response();
        if let Ok(value) = axum::http::HeaderValue::from_str(&version_id) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-version-id"),
                value,
            );
        }
        return response;
    }

    if is_reserved_internal_key(&key) {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidObjectName",
            "Object key uses reserved internal namespace",
            &key,
        );
    }

    let bucket_path = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };

    if !bucket_path.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let versioning_enabled = state
        .buckets
        .read()
        .await
        .get(&bucket)
        .map(|item| item.versioning)
        .unwrap_or(true);
    let current_meta = match read_current_object_meta(&state, &bucket, &key).await {
        Ok(meta) => meta,
        Err(response) => return response,
    };
    let legal_hold_from_bucket = state
        .bucket_legal_holds
        .read()
        .await
        .get(&bucket)
        .cloned()
        .unwrap_or_else(default_legal_hold_config)
        .enabled;
    let retention_from_bucket = state
        .bucket_retentions
        .read()
        .await
        .get(&bucket)
        .cloned()
        .unwrap_or_else(default_retention_config)
        .enabled;
    let object_lock_from_bucket = state
        .bucket_object_locks
        .read()
        .await
        .get(&bucket)
        .map(|item| item.enabled)
        .unwrap_or(false);

    if current_meta
        .as_ref()
        .map(|item| item.legal_hold)
        .unwrap_or(legal_hold_from_bucket)
    {
        state
            .append_audit(
                "s3-root",
                "object.delete",
                &format!("bucket/{bucket}/{key}"),
                "denied",
                None,
                json!({ "reason": "legal_hold", "via": "s3" }),
            )
            .await;
        return s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Object is under legal hold",
            &key,
        );
    }

    let retention_until = current_meta.as_ref().and_then(|item| item.retention_until);
    if retention_until
        .map(|value| value > Utc::now())
        .unwrap_or(false)
    {
        state
            .append_audit(
                "s3-root",
                "object.delete",
                &format!("bucket/{bucket}/{key}"),
                "denied",
                None,
                json!({
                    "reason": "retention_active",
                    "retention_until": retention_until,
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

    if current_meta.is_none() && (retention_from_bucket || object_lock_from_bucket) {
        return s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Bucket retention is enabled for this object",
            &key,
        );
    }

    if versioning_enabled {
        if let Some(meta) = current_meta.as_ref() {
            if let Err(response) = archive_object_version(&state, &bucket, &key, meta).await {
                return response;
            }
        }
    }

    if let Err(response) = remove_current_hot_object_payload(&state, &bucket, &key).await {
        return response;
    }

    if versioning_enabled {
        let marker =
            build_object_meta_for_current_version(&state, &bucket, &key, 0, String::new(), true, None)
                .await;
        if let Err(response) = persist_current_object_meta(&state, marker.clone()).await {
            return response;
        }
        enqueue_replication_for_object(
            &state,
            &bucket,
            &key,
            "delete",
            Some(marker.version_id.clone()),
            current_meta.as_ref(),
        )
        .await;
        emit_bucket_object_event_best_effort(
            &state,
            &bucket,
            &key,
            "s3:ObjectRemoved:Delete",
            Some(&marker),
            "s3",
        )
        .await;

        let mut response = StatusCode::NO_CONTENT.into_response();
        if let Ok(value) = axum::http::HeaderValue::from_str(&marker.version_id) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-version-id"),
                value,
            );
        }
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-delete-marker"),
            axum::http::HeaderValue::from_static("true"),
        );
        return response;
    }

    if let Err(response) = remove_current_object_meta(&state, &bucket, &key).await {
        return response;
    }
    if let Some(meta) = current_meta.as_ref() {
        if let Err(response) = remove_remote_tier_payload_for_meta(&state, meta).await {
            return response;
        }
    }
    enqueue_replication_for_object(&state, &bucket, &key, "delete", None, current_meta.as_ref())
        .await;
    emit_bucket_object_event_best_effort(
        &state,
        &bucket,
        &key,
        "s3:ObjectRemoved:Delete",
        current_meta.as_ref(),
        "s3",
    )
    .await;

    StatusCode::NO_CONTENT.into_response()
}

pub(crate) async fn s3_root_head_object(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    if let Err(response) = ensure_s3_auth(&headers, &method, &uri, None, &state) {
        return response;
    }
    if let Err(response) = ensure_metadata_read_barrier_s3(&state, &bucket).await {
        return response;
    }

    if is_reserved_internal_key(&key) {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidObjectName",
            "Object key uses reserved internal namespace",
            &key,
        );
    }

    let bucket_path = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };

    if !bucket_path.exists() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let requested_version_id = query_value(uri.query(), "versionId");
    let current_meta = match read_current_object_meta(&state, &bucket, &key).await {
        Ok(meta) => meta,
        Err(response) => return response,
    };
    let mut selected_meta = current_meta.clone();
    let mut selected_is_current = true;
    if let Some(version_id) = requested_version_id.as_deref() {
        let resolved = match resolve_object_version_meta(
            &state,
            &bucket,
            &key,
            version_id,
            current_meta,
        )
        .await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
        let Some((meta, is_current)) = resolved else {
            return StatusCode::NOT_FOUND.into_response();
        };
        selected_meta = Some(meta);
        selected_is_current = is_current;
    }

    if selected_meta
        .as_ref()
        .map(|meta| meta.delete_marker)
        .unwrap_or(false)
    {
        if requested_version_id.is_some() {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let sse_customer_request =
        match validate_sse_customer_headers(&headers, &key, SseCustomerHeaderKind::Request, true) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let customer_key = sse_customer_request.as_ref().map(|req| &req.key_bytes);
    if let Some(meta) = selected_meta.as_ref() {
        if let Err(response) = ensure_sse_customer_access(
            &key,
            &meta.encryption,
            sse_customer_request.as_ref(),
            SseCustomerHeaderKind::Request,
        ) {
            return response;
        }
    }

    let bytes = if selected_is_current {
        match read_current_object_payload(
            &state,
            &bucket,
            &key,
            selected_meta.as_ref(),
            customer_key,
        )
        .await
        {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(response) => return response,
        }
    } else {
        let Some(meta) = selected_meta.as_ref() else {
            return StatusCode::NOT_FOUND.into_response();
        };
        match read_archived_object_payload_by_meta(&state, meta).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(response) => return response,
        }
    };

    let etag = selected_meta
        .as_ref()
        .map(|meta| meta.etag.clone())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| weak_etag(&bytes));
    let etag_quoted = format!("\"{etag}\"");
    let last_modified = selected_meta
        .as_ref()
        .map(|meta| meta.created_at)
        .unwrap_or_else(Utc::now);
    if let Some(response) =
        evaluate_object_preconditions(&method, &headers, &etag, &etag_quoted, last_modified, &key)
    {
        return response;
    }
    let mut response = StatusCode::OK.into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        axum::http::header::HeaderName::from_static("accept-ranges"),
        axum::http::HeaderValue::from_static("bytes"),
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&format_http_date(last_modified)) {
        response
            .headers_mut()
            .insert(axum::http::header::LAST_MODIFIED, value);
    }
    if let Ok(length) = axum::http::HeaderValue::from_str(&bytes.len().to_string()) {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_LENGTH, length);
    }
    if let Ok(value) = axum::http::HeaderValue::from_str(&etag_quoted) {
        response
            .headers_mut()
            .insert(axum::http::header::ETAG, value);
    }
    if let Some(meta) = selected_meta.as_ref() {
        if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-version-id"),
                value,
            );
        }
        if let Some(mode) = meta.retention_mode.as_deref() {
            if let Ok(value) = axum::http::HeaderValue::from_str(mode) {
                response.headers_mut().insert(
                    axum::http::header::HeaderName::from_static("x-amz-object-lock-mode"),
                    value,
                );
            }
        }
        if let Some(retention_until) = meta.retention_until {
            if let Ok(value) = axum::http::HeaderValue::from_str(
                &retention_until.to_rfc3339_opts(SecondsFormat::Secs, true),
            ) {
                response.headers_mut().insert(
                    axum::http::header::HeaderName::from_static(
                        "x-amz-object-lock-retain-until-date",
                    ),
                    value,
                );
            }
        }
        if meta.legal_hold {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-object-lock-legal-hold"),
                axum::http::HeaderValue::from_static("ON"),
            );
        }
        apply_object_metadata_headers(&mut response, meta);
    }
    response
}

pub(crate) async fn s3_get_object_tagging(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    version_id: Option<String>,
) -> Response {
    let bucket_path = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_path.exists() {
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
    let selected = if let Some(version_id) = version_id {
        match resolve_object_version_meta(&state, &bucket, &key, &version_id, current_meta).await {
            Ok(Some(value)) => value,
            Ok(None) => {
                return s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchVersion",
                    "The specified version does not exist",
                    &key,
                );
            }
            Err(response) => return response,
        }
    } else {
        let Some(meta) = current_meta else {
            return s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified key does not exist",
                &key,
            );
        };
        (meta, true)
    };

    let (meta, _) = selected;
    if meta.delete_marker {
        return s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource",
            &key,
        );
    }

    let xml = build_object_tagging_xml(&meta.tags);
    let mut response = s3_xml_response(StatusCode::OK, xml);
    if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-version-id"),
            value,
        );
    }
    response
}

pub(crate) async fn s3_put_object_tagging(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    version_id: Option<String>,
    body: Bytes,
) -> Response {
    let bucket_path = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_path.exists() {
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
    let selected = if let Some(version_id) = version_id {
        match resolve_object_version_meta(&state, &bucket, &key, &version_id, current_meta).await {
            Ok(Some(value)) => value,
            Ok(None) => {
                return s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchVersion",
                    "The specified version does not exist",
                    &key,
                );
            }
            Err(response) => return response,
        }
    } else {
        let Some(meta) = current_meta else {
            return s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified key does not exist",
                &key,
            );
        };
        (meta, true)
    };

    let xml_text = String::from_utf8_lossy(&body);
    let parsed = match from_xml_str::<S3TaggingBody>(&xml_text) {
        Ok(value) => value,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!("Failed to parse object tagging XML: {err}"),
                &key,
            );
        }
    };
    let normalized_tags = match normalize_s3_tagset(
        parsed
            .tag_set
            .unwrap_or_default()
            .tags
            .into_iter()
            .map(|tag| BucketTag {
                key: tag.key.unwrap_or_default(),
                value: tag.value.unwrap_or_default(),
            })
            .collect(),
        true,
    ) {
        Ok(tags) => tags,
        Err(message) => return s3_error(StatusCode::BAD_REQUEST, "InvalidTag", message, &key),
    };

    let (mut meta, is_latest) = selected;
    if meta.delete_marker {
        return s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource",
            &key,
        );
    }
    meta.tags = normalized_tags;

    if is_latest {
        if let Err(response) = persist_current_object_meta(&state, meta.clone()).await {
            return response;
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
    } else if let Err(response) = persist_archived_object_meta(&state, &meta).await {
        return response;
    }

    let mut response = StatusCode::OK.into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-version-id"),
            value,
        );
    }
    response
}

pub(crate) async fn s3_delete_object_tagging(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    version_id: Option<String>,
) -> Response {
    let bucket_path = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_path.exists() {
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
    let selected = if let Some(version_id) = version_id {
        match resolve_object_version_meta(&state, &bucket, &key, &version_id, current_meta).await {
            Ok(Some(value)) => value,
            Ok(None) => {
                return s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchVersion",
                    "The specified version does not exist",
                    &key,
                );
            }
            Err(response) => return response,
        }
    } else {
        let Some(meta) = current_meta else {
            return s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified key does not exist",
                &key,
            );
        };
        (meta, true)
    };

    let (mut meta, is_latest) = selected;
    if meta.delete_marker {
        return s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource",
            &key,
        );
    }
    meta.tags.clear();

    if is_latest {
        if let Err(response) = persist_current_object_meta(&state, meta.clone()).await {
            return response;
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
    } else if let Err(response) = persist_archived_object_meta(&state, &meta).await {
        return response;
    }

    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-version-id"),
            value,
        );
    }
    response
}

pub(crate) async fn s3_get_object_legal_hold(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    version_id: Option<String>,
) -> Response {
    let bucket_path = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_path.exists() {
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
    let selected = if let Some(version_id) = version_id {
        match resolve_object_version_meta(&state, &bucket, &key, &version_id, current_meta).await {
            Ok(Some(value)) => value,
            Ok(None) => {
                return s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchVersion",
                    "The specified version does not exist",
                    &key,
                )
            }
            Err(response) => return response,
        }
    } else {
        let Some(meta) = current_meta else {
            return s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified key does not exist",
                &key,
            );
        };
        (meta, true)
    };

    let (meta, _) = selected;
    if meta.delete_marker {
        return s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource",
            &key,
        );
    }

    let status = if meta.legal_hold { "ON" } else { "OFF" };
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ObjectLockLegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>{status}</Status></ObjectLockLegalHold>"#
    );
    let mut response = s3_xml_response(StatusCode::OK, xml);
    if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-version-id"),
            value,
        );
    }
    response
}

pub(crate) async fn s3_put_object_legal_hold(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    version_id: Option<String>,
    body: Bytes,
) -> Response {
    let bucket_path = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_path.exists() {
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
    let selected = if let Some(version_id) = version_id {
        match resolve_object_version_meta(&state, &bucket, &key, &version_id, current_meta).await {
            Ok(Some(value)) => value,
            Ok(None) => {
                return s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchVersion",
                    "The specified version does not exist",
                    &key,
                )
            }
            Err(response) => return response,
        }
    } else {
        let Some(meta) = current_meta else {
            return s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified key does not exist",
                &key,
            );
        };
        (meta, true)
    };

    let xml_text = String::from_utf8_lossy(&body);
    let parsed = match from_xml_str::<S3ObjectLockLegalHoldBody>(&xml_text) {
        Ok(value) => value,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!("Failed to parse legal hold XML: {err}"),
                &key,
            )
        }
    };
    let status = parsed
        .status
        .unwrap_or_else(|| "OFF".to_string())
        .trim()
        .to_ascii_uppercase();
    let enabled = match status.as_str() {
        "ON" => true,
        "OFF" => false,
        _ => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "Status must be ON or OFF",
                &key,
            )
        }
    };

    let (mut meta, is_latest) = selected;
    if meta.delete_marker {
        return s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource",
            &key,
        );
    }
    meta.legal_hold = enabled;
    if is_latest {
        if let Err(response) = persist_current_object_meta(&state, meta.clone()).await {
            return response;
        }
    } else if let Err(response) = persist_archived_object_meta(&state, &meta).await {
        return response;
    }
    state
        .append_audit(
            "s3-root",
            "object.legal_hold.update",
            &format!("bucket/{bucket}/{key}"),
            "success",
            None,
            json!({
                "version_id": meta.version_id,
                "enabled": enabled,
                "via": "s3",
            }),
        )
        .await;

    let mut response = StatusCode::OK.into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-version-id"),
            value,
        );
    }
    response
}

pub(crate) async fn s3_get_object_retention(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    version_id: Option<String>,
) -> Response {
    let bucket_path = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_path.exists() {
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
    let selected = if let Some(version_id) = version_id {
        match resolve_object_version_meta(&state, &bucket, &key, &version_id, current_meta).await {
            Ok(Some(value)) => value,
            Ok(None) => {
                return s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchVersion",
                    "The specified version does not exist",
                    &key,
                )
            }
            Err(response) => return response,
        }
    } else {
        let Some(meta) = current_meta else {
            return s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified key does not exist",
                &key,
            );
        };
        (meta, true)
    };

    let (meta, _) = selected;
    if meta.delete_marker {
        return s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource",
            &key,
        );
    }

    let mode = meta
        .retention_mode
        .clone()
        .unwrap_or_else(|| "GOVERNANCE".to_string());
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ObjectLockRetention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    if let Some(retain_until) = meta.retention_until {
        xml.push_str("<Mode>");
        xml.push_str(&xml_escape(&mode));
        xml.push_str("</Mode><RetainUntilDate>");
        xml.push_str(&retain_until.to_rfc3339_opts(SecondsFormat::Secs, true));
        xml.push_str("</RetainUntilDate>");
    }
    xml.push_str("</ObjectLockRetention>");

    let mut response = s3_xml_response(StatusCode::OK, xml);
    if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-version-id"),
            value,
        );
    }
    response
}

pub(crate) async fn s3_put_object_retention(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    version_id: Option<String>,
    body: Bytes,
) -> Response {
    let bucket_path = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_path.exists() {
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
    let selected = if let Some(version_id) = version_id {
        match resolve_object_version_meta(&state, &bucket, &key, &version_id, current_meta).await {
            Ok(Some(value)) => value,
            Ok(None) => {
                return s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchVersion",
                    "The specified version does not exist",
                    &key,
                )
            }
            Err(response) => return response,
        }
    } else {
        let Some(meta) = current_meta else {
            return s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified key does not exist",
                &key,
            );
        };
        (meta, true)
    };

    let xml_text = String::from_utf8_lossy(&body);
    let parsed = match from_xml_str::<S3ObjectLockRetentionBody>(&xml_text) {
        Ok(value) => value,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!("Failed to parse retention XML: {err}"),
                &key,
            )
        }
    };

    let (mut meta, is_latest) = selected;
    if meta.delete_marker {
        return s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource",
            &key,
        );
    }

    let mode = parsed.mode.unwrap_or_else(|| "GOVERNANCE".to_string());
    let mode = match normalize_retention_mode(&mode) {
        Ok(value) => value,
        Err(_) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "Mode must be GOVERNANCE or COMPLIANCE",
                &key,
            )
        }
    };
    let retain_until = match parsed.retain_until_date {
        Some(value) => match DateTime::parse_from_rfc3339(value.trim()) {
            Ok(parsed) => Some(parsed.with_timezone(&Utc)),
            Err(_) => {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "MalformedXML",
                    "RetainUntilDate must be RFC3339 datetime",
                    &key,
                )
            }
        },
        None => None,
    };
    meta.retention_mode = retain_until.as_ref().map(|_| mode);
    meta.retention_until = retain_until;

    if is_latest {
        if let Err(response) = persist_current_object_meta(&state, meta.clone()).await {
            return response;
        }
    } else if let Err(response) = persist_archived_object_meta(&state, &meta).await {
        return response;
    }
    state
        .append_audit(
            "s3-root",
            "object.retention.update",
            &format!("bucket/{bucket}/{key}"),
            "success",
            None,
            json!({
                "version_id": meta.version_id,
                "mode": meta.retention_mode,
                "retention_until": meta.retention_until,
                "via": "s3",
            }),
        )
        .await;

    let mut response = StatusCode::OK.into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-version-id"),
            value,
        );
    }
    response
}

pub(crate) async fn s3_root_post_object(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path((bucket, key)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if let Err(response) = ensure_s3_auth(&headers, &method, &uri, Some(body.as_ref()), &state) {
        return response;
    }

    if query_has_key(uri.query(), "select") || query_has_key(uri.query(), "select-type") {
        return s3_select_object_content(state, headers, bucket, key, uri.query(), body).await;
    }

    if query_has_key(uri.query(), "restore") {
        return s3_restore_object(state, bucket, key, uri.query(), body).await;
    }

    if query_has_key(uri.query(), "uploads") {
        return s3_initiate_multipart_upload(state, bucket, key, headers).await;
    }

    if let Some(upload_id) = query_value(uri.query(), "uploadId") {
        return s3_complete_multipart_upload(state, bucket, key, upload_id, body, headers).await;
    }

    s3_error(
        StatusCode::BAD_REQUEST,
        "InvalidRequest",
        "POST object requires restore, uploads or uploadId subresource",
        &key,
    )
}

pub(crate) async fn s3_restore_object(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    query: Option<&str>,
    body: Bytes,
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
    if is_reserved_internal_key(&key) {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidObjectName",
            "Object key uses reserved internal namespace",
            &key,
        );
    }

    let requested_version_id = query_value(query, "versionId");
    let current_meta = match read_current_object_meta(&state, &bucket, &key).await {
        Ok(meta) => meta,
        Err(response) => return response,
    };
    let resolved = if let Some(version_id) = requested_version_id.as_deref() {
        match resolve_object_version_meta(&state, &bucket, &key, version_id, current_meta).await {
            Ok(value) => value,
            Err(response) => return response,
        }
    } else {
        current_meta.map(|meta| (meta, true))
    };
    let Some((mut meta, is_current)) = resolved else {
        return s3_error(
            StatusCode::NOT_FOUND,
            if requested_version_id.is_some() {
                "NoSuchVersion"
            } else {
                "NoSuchKey"
            },
            if requested_version_id.is_some() {
                "The specified version does not exist"
            } else {
                "The specified key does not exist"
            },
            &key,
        );
    };
    if meta.delete_marker {
        return s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource",
            &key,
        );
    }
    if meta.remote_tier.is_none() {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "对象未归档到远端层 / object is not archived in remote tier",
            &key,
        );
    }

    let restore_request = if body.is_empty() {
        S3RestoreObjectRequestBody::default()
    } else {
        let request_body = String::from_utf8_lossy(&body);
        match from_xml_str::<S3RestoreObjectRequestBody>(&request_body) {
            Ok(value) => value,
            Err(_) => {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "MalformedXML",
                    "The XML you provided was not well-formed",
                    &key,
                )
            }
        }
    };
    let restore_days = restore_request.days.unwrap_or(1).max(1);
    let payload = match read_remote_tier_payload_for_meta(&state, &meta).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return s3_error(
                StatusCode::NOT_FOUND,
                if requested_version_id.is_some() {
                    "NoSuchVersion"
                } else {
                    "NoSuchKey"
                },
                if requested_version_id.is_some() {
                    "The specified archived object version payload does not exist"
                } else {
                    "The specified archived object payload does not exist"
                },
                &key,
            )
        }
        Err(response) => return response,
    };

    if is_current {
        if let Err(response) =
            persist_restored_current_object_payload(&state, &meta, &payload).await
        {
            return response;
        }
    } else if let Err(response) =
        persist_restored_archived_object_payload(&state, &meta, &payload).await
    {
        return response;
    }

    let now = Utc::now();
    meta.restore = Some(ObjectRestoreStatus {
        ongoing_request: false,
        requested_at: Some(now),
        expiry_at: Some(now + Duration::days(restore_days as i64)),
    });
    if is_current {
        if let Err(response) = persist_current_object_meta(&state, meta.clone()).await {
            return response;
        }
    } else if let Err(response) = persist_archived_object_meta(&state, &meta).await {
        return response;
    }

    let requested_tier = restore_request.tier.clone().or_else(|| {
        restore_request
            .glacier_job_parameters
            .as_ref()
            .and_then(|item| item.tier.clone())
    });
    let restore_description = restore_request.description.clone();
    state
        .append_audit(
            "s3-root",
            "object.restore",
            &format!("bucket/{bucket}/{key}"),
            "success",
            None,
            json!({
                "version_id": meta.version_id,
                "is_current": is_current,
                "restore_days": restore_days,
                "requested_tier": requested_tier,
                "description": restore_description,
            }),
        )
        .await;
    emit_bucket_object_event_best_effort(
        &state,
        &bucket,
        &key,
        "s3:ObjectRestore:Post",
        Some(&meta),
        "s3",
    )
    .await;

    let mut response = StatusCode::ACCEPTED.into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-version-id"),
            value,
        );
    }
    response
}

pub(crate) async fn s3_initiate_multipart_upload(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    headers: HeaderMap,
) -> Response {
    let bucket_path = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_path.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }
    if is_reserved_internal_key(&key) {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidObjectName",
            "Object key uses reserved internal namespace",
            &key,
        );
    }
    if object_path(&bucket_path, &key).is_err() {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidObjectName",
            "Invalid object key path",
            &key,
        );
    }

    let (encryption, _sse_customer_key) =
        match resolve_object_encryption_meta(&state, &bucket, &headers, &key, false).await {
            Ok(value) => value,
            Err(response) => return response,
        };

    let upload_id = Uuid::new_v4().to_string();
    let upload_dir = multipart_upload_dir(&state, &upload_id);
    if let Err(err) = tokio::fs::create_dir_all(&upload_dir).await {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to initialize multipart upload: {err}"),
            &key,
        );
    }

    state.multipart_uploads.write().await.insert(
        upload_id.clone(),
        MultipartUpload {
            upload_id: upload_id.clone(),
            bucket: bucket.clone(),
            key: key.clone(),
            initiated_at: Utc::now(),
            parts: HashMap::new(),
            encryption: encryption.clone(),
        },
    );

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>"#,
        xml_escape(&bucket),
        xml_escape(&key),
        xml_escape(&upload_id),
    );
    let mut response = s3_xml_response(StatusCode::OK, xml);
    apply_object_encryption_headers(&mut response, &encryption);
    response
}

/// 流式分片上传：接收 axum Body（可含 aws-chunked），流式写入 part 文件并增量计算 weak_etag。
///
/// - 若 `streaming_context` 存在（aws-chunked 编码），先用 `AwsChunkedDecoder` 解码 + 链式验签，
///   累积解码后的明文再写文件（单个 part 大小有自然上限，不会 OOM）
/// - 否则直接消费 body 帧，边写边喂 hasher，内存恒定
pub(crate) async fn s3_upload_part_streaming(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    upload_id: String,
    part_number: u32,
    body: axum::body::Body,
    streaming_context: Option<StreamingSigV4Context>,
) -> Result<Response, Response> {
    use crate::routes::s3_chunked::{AwsChunkedDecoder, WeakEtagHasher};
    use futures::StreamExt;

    let bucket_path = bucket_path(&state, &bucket)?;
    if !bucket_path.exists() {
        return Err(s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        ));
    }

    let mut uploads = state.multipart_uploads.write().await;
    let Some(upload) = uploads.get_mut(&upload_id) else {
        return Err(s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified upload does not exist",
            &key,
        ));
    };
    if upload.bucket != bucket || upload.key != key {
        return Err(s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified upload does not match bucket/key",
            &key,
        ));
    }

    let upload_dir = multipart_upload_dir(&state, &upload_id);
    tokio::fs::create_dir_all(&upload_dir)
        .await
        .map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create multipart upload directory: {err}"),
                &key,
            )
        })?;

    let part_path = upload_dir.join(format!("{part_number}.part"));
    let mut file = tokio::fs::File::create(&part_path).await.map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to create part file: {err}"),
            &key,
        )
    })?;

    let mut total_size: u64 = 0;
    let mut hasher = WeakEtagHasher::new();

    if let Some(ctx) = streaming_context {
        // aws-chunked：解码 + 链式验签 → 写出（单个 part 大小有自然上限，先解码到 Vec 没问题）
        let mut full_body = Vec::new();
        let mut stream = body.into_data_stream();
        while let Some(result) = stream.next().await {
            let frame = result.map_err(|err| {
                s3_error(
                    StatusCode::BAD_REQUEST,
                    "IncompleteBody",
                    &format!("Failed to read request body: {err}"),
                    &key,
                )
            })?;
            full_body.extend_from_slice(&frame);
        }
        let reader = std::io::Cursor::new(full_body);
        let decoder = AwsChunkedDecoder::new(reader, ctx);
        let decoded = decoder.decode_all().await.map_err(|err| {
            s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidChunk",
                &format!("aws-chunked decode failed: {err}"),
                &key,
            )
        })?;
        file.write_all(&decoded).await.map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to write part: {err}"),
                &key,
            )
        })?;
        hasher.update(&decoded);
        total_size = decoded.len() as u64;
    } else {
        // 非 chunked：直接消费 body 帧，边写边喂 hasher
        let mut stream = body.into_data_stream();
        while let Some(result) = stream.next().await {
            let frame = result.map_err(|err| {
                s3_error(
                    StatusCode::BAD_REQUEST,
                    "IncompleteBody",
                    &format!("Failed to read request body: {err}"),
                    &key,
                )
            })?;
            file.write_all(&frame).await.map_err(|err| {
                s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to write part: {err}"),
                    &key,
                )
            })?;
            hasher.update(&frame);
            total_size += frame.len() as u64;
        }
    }

    let etag = hasher.finalize();

    // Amazon S3 要求除最后一个分片外所有分片至少 5 MiB(EntityTooSmall),对分片最小大小进行校验。
    let min_part_size: u64 = std::env::var("RUSTIO_S3_MIN_PART_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5 * 1024 * 1024);
    if total_size > 0 && total_size < min_part_size {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "EntityTooSmall",
            &format!(
                "Your proposed upload is smaller than the minimum allowed size of {} bytes",
                min_part_size
            ),
            &key,
        ));
    }

    upload.parts.insert(
        part_number,
        MultipartPart {
            part_number,
            etag: etag.clone(),
            size: total_size,
            path: part_path,
            updated_at: Utc::now(),
        },
    );
    drop(uploads);

    let mut response = StatusCode::OK.into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&format!("\"{etag}\"")) {
        response
            .headers_mut()
            .insert(axum::http::header::ETAG, value);
    }
    Ok(response)
}

pub(crate) async fn s3_list_multipart_parts_xml(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    upload_id: String,
) -> Response {
    let uploads = state.multipart_uploads.read().await;
    let Some(upload) = uploads.get(&upload_id) else {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified upload does not exist",
            &key,
        );
    };
    if upload.bucket != bucket || upload.key != key {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified upload does not match bucket/key",
            &key,
        );
    }

    let mut parts = upload.parts.values().cloned().collect::<Vec<_>>();
    parts.sort_by_key(|part| part.part_number);

    let mut xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId><PartNumberMarker>0</PartNumberMarker><NextPartNumberMarker>0</NextPartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>false</IsTruncated>"#,
        xml_escape(&bucket),
        xml_escape(&key),
        xml_escape(&upload_id),
    );
    for part in parts {
        xml.push_str("<Part><PartNumber>");
        xml.push_str(&part.part_number.to_string());
        xml.push_str("</PartNumber><LastModified>");
        xml.push_str(&part.updated_at.to_rfc3339_opts(SecondsFormat::Secs, true));
        xml.push_str("</LastModified><ETag>\"");
        xml.push_str(&xml_escape(&part.etag));
        xml.push_str("\"</ETag><Size>");
        xml.push_str(&part.size.to_string());
        xml.push_str("</Size></Part>");
    }
    xml.push_str("</ListPartsResult>");
    s3_xml_response(StatusCode::OK, xml)
}

pub(crate) async fn s3_complete_multipart_upload(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    upload_id: String,
    body: Bytes,
    _headers: HeaderMap,
) -> Response {
    let bucket_path = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_path.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }
    if is_reserved_internal_key(&key) {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidObjectName",
            "Object key uses reserved internal namespace",
            &key,
        );
    }

    let versioning_enabled = state
        .buckets
        .read()
        .await
        .get(&bucket)
        .map(|item| item.versioning)
        .unwrap_or(true);
    if versioning_enabled {
        let current_meta = match read_current_object_meta(&state, &bucket, &key).await {
            Ok(meta) => meta,
            Err(response) => return response,
        };
        if let Some(meta) = current_meta {
            if let Err(response) = archive_object_version(&state, &bucket, &key, &meta).await {
                return response;
            }
        }
    }

    let mut uploads = state.multipart_uploads.write().await;
    let Some(upload) = uploads.get(&upload_id) else {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified upload does not exist",
            &key,
        );
    };
    if upload.bucket != bucket || upload.key != key {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified upload does not match bucket/key",
            &key,
        );
    }
    let upload_encryption = upload.encryption.clone();

    let xml_text = String::from_utf8_lossy(&body);
    let request = match from_xml_str::<CompleteMultipartUploadRequest>(&xml_text) {
        Ok(parsed) => parsed,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!("Failed to parse complete multipart XML: {err}"),
                &key,
            );
        }
    };

    if request.parts.is_empty() {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "CompleteMultipartUpload requires at least one part",
            &key,
        );
    }

    let target_path = match object_path(&bucket_path, &key) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if let Some(parent) = target_path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create object directory: {err}"),
                &key,
            );
        }
    }

    let mut target_file = match tokio::fs::File::create(&target_path).await {
        Ok(file) => file,
        Err(err) => {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create final object file: {err}"),
                &key,
            );
        }
    };

    let mut hasher = Sha256::new();
    for part in &request.parts {
        let Some(part_meta) = upload.parts.get(&part.part_number) else {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidPart",
                &format!("Missing uploaded part {}", part.part_number),
                &key,
            );
        };

        if let Some(expected_etag) = &part.etag {
            let normalized = expected_etag.trim_matches('"');
            if normalized != part_meta.etag {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidPart",
                    &format!("ETag mismatch for part {}", part.part_number),
                    &key,
                );
            }
        }

        let mut part_file = match tokio::fs::File::open(&part_meta.path).await {
            Ok(file) => file,
            Err(err) => {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to open uploaded part: {err}"),
                    &key,
                );
            }
        };

        let mut buffer = vec![0u8; 1024 * 64];
        loop {
            let read = match part_file.read(&mut buffer).await {
                Ok(0) => break,
                Ok(size) => size,
                Err(err) => {
                    return s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to read uploaded part: {err}"),
                        &key,
                    );
                }
            };

            if let Err(err) = target_file.write_all(&buffer[..read]).await {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to write final object: {err}"),
                    &key,
                );
            }
            hasher.update(&buffer[..read]);
        }
    }

    let final_etag = hex::encode(hasher.finalize());
    uploads.remove(&upload_id);
    drop(uploads);

    if let Err(err) = tokio::fs::remove_dir_all(multipart_upload_dir(&state, &upload_id)).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to cleanup multipart upload files: {err}"),
                &key,
            );
        }
    }

    let target_len = match tokio::fs::metadata(&target_path).await {
        Ok(metadata) => metadata.len(),
        Err(err) => {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to read completed object metadata: {err}"),
                &key,
            );
        }
    };
    let mut object_meta = build_object_meta_for_current_version(
        &state,
        &bucket,
        &key,
        target_len,
        final_etag.clone(),
        false,
        None,
    )
    .await;
    object_meta.encryption = upload_encryption;
    if encryption_enabled(&object_meta) {
        // 加密对象需整体 AES-GCM 加密，暂走全量读取路径（流式分块加密为后续阶段）
        let complete_bytes = match tokio::fs::read(&target_path).await {
            Ok(bytes) => bytes,
            Err(err) => {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to read completed object payload: {err}"),
                    &key,
                );
            }
        };
        if let Err(response) = write_ec_object(
            &state,
            &bucket,
            &key,
            &complete_bytes,
            &mut object_meta,
            None,
        )
        .await
        {
            return response;
        }
    } else if let Err(response) =
        write_ec_object_streaming(&state, &bucket, &key, &target_path, target_len).await
    {
        // 非加密对象：从合并后的临时文件流式编码，内存恒定，不随对象大小增长
        return response;
    }
    if let Err(response) = persist_current_object_meta(&state, object_meta.clone()).await {
        return response;
    }
    enqueue_replication_for_object(
        &state,
        &bucket,
        &key,
        "put",
        Some(object_meta.version_id.clone()),
        Some(&object_meta),
    )
    .await;
    emit_bucket_object_event_best_effort(
        &state,
        &bucket,
        &key,
        "s3:ObjectCreated:CompleteMultipartUpload",
        Some(&object_meta),
        "s3",
    )
    .await;

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Location>/{}/{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>"{}"</ETag></CompleteMultipartUploadResult>"#,
        xml_escape(&bucket),
        xml_escape(&key),
        xml_escape(&bucket),
        xml_escape(&key),
        xml_escape(&final_etag),
    );
    let mut response = s3_xml_response(StatusCode::OK, xml);
    if let Ok(value) = axum::http::HeaderValue::from_str(&object_meta.version_id) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-version-id"),
            value,
        );
    }
    apply_object_encryption_headers(&mut response, &object_meta.encryption);
    response
}

pub(crate) async fn s3_abort_multipart_upload(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    upload_id: String,
) -> Response {
    let mut uploads = state.multipart_uploads.write().await;
    let Some(upload) = uploads.get(&upload_id) else {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified upload does not exist",
            &key,
        );
    };
    if upload.bucket != bucket || upload.key != key {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified upload does not match bucket/key",
            &key,
        );
    }
    uploads.remove(&upload_id);
    drop(uploads);

    if let Err(err) = tokio::fs::remove_dir_all(multipart_upload_dir(&state, &upload_id)).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to cleanup multipart upload files: {err}"),
                &key,
            );
        }
    }

    StatusCode::NO_CONTENT.into_response()
}

pub(crate) async fn s3_list_multipart_uploads_xml(state: Arc<AppState>, bucket: &str) -> Response {
    let uploads = state.multipart_uploads.read().await;
    let mut items = uploads
        .values()
        .filter(|upload| upload.bucket == bucket)
        .cloned()
        .collect::<Vec<_>>();
    items.sort_by(|a, b| a.key.cmp(&b.key));

    let mut xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>{}</Bucket><KeyMarker></KeyMarker><UploadIdMarker></UploadIdMarker><NextKeyMarker></NextKeyMarker><NextUploadIdMarker></NextUploadIdMarker><Delimiter></Delimiter><Prefix></Prefix><MaxUploads>1000</MaxUploads><IsTruncated>false</IsTruncated>"#,
        xml_escape(bucket),
    );
    for upload in items {
        xml.push_str("<Upload><Key>");
        xml.push_str(&xml_escape(&upload.key));
        xml.push_str("</Key><UploadId>");
        xml.push_str(&xml_escape(&upload.upload_id));
        xml.push_str("</UploadId><Initiated>");
        xml.push_str(
            &upload
                .initiated_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
        );
        xml.push_str("</Initiated></Upload>");
    }
    xml.push_str("</ListMultipartUploadsResult>");
    s3_xml_response(StatusCode::OK, xml)
}

pub(crate) async fn s3_list_buckets_xml(state: Arc<AppState>) -> Response {
    let mut buckets = state
        .buckets
        .read()
        .await
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    buckets.sort();

    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>rustio</ID><DisplayName>rustio</DisplayName></Owner><Buckets>"#,
    );
    for bucket in buckets {
        xml.push_str("<Bucket><Name>");
        xml.push_str(&xml_escape(&bucket));
        xml.push_str("</Name><CreationDate>");
        xml.push_str(&now);
        xml.push_str("</CreationDate></Bucket>");
    }
    xml.push_str("</Buckets></ListAllMyBucketsResult>");
    s3_xml_response(StatusCode::OK, xml)
}

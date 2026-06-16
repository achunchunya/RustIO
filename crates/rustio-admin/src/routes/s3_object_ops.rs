//! S3 对象读取、标签、保留、分片上传

use super::*;

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
        let part_number_marker = query_value(uri.query(), "part-number-marker")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);
        let max_parts = query_value(uri.query(), "max-parts")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1000)
            .clamp(0, 1000);
        return s3_list_multipart_parts_xml(
            state,
            bucket,
            key,
            upload_id,
            part_number_marker,
            max_parts,
        )
        .await;
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
                if checksum_mode_enabled(&headers) {
                    if let Some(ref checksum) = meta.checksum {
                        apply_checksum_headers(&mut response, checksum);
                    }
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
        // 原地裁剪到 [start, end],避免再分配一份 range 大小的拷贝。
        // 注:此路径仍全量加载对象到内存(Range 流式化需改造 EC 流读,属后续优化项);
        // 此处仅消除切片时的额外拷贝。
        payload.truncate(end as usize + 1);
        payload.drain(..start as usize);
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
        if checksum_mode_enabled(&headers) {
            if let Some(ref checksum) = meta.checksum {
                apply_checksum_headers(&mut response, checksum);
            }
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
        let Some((meta, _is_current)) = resolved else {
            return StatusCode::NOT_FOUND.into_response();
        };
        selected_meta = Some(meta);
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

    // HEAD 只返回头部,不需要对象 body。直接用 meta 的 size/etag,避免读取整个对象进内存
    // (大对象 HEAD 原会全量加载导致 OOM)。
    let Some(meta_ref) = selected_meta.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let content_length = meta_ref.size;
    let etag = meta_ref.etag.clone();
    let etag_quoted = format!("\"{etag}\"");
    let last_modified = meta_ref.created_at;
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
    if let Ok(length) = axum::http::HeaderValue::from_str(&content_length.to_string()) {
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
        if checksum_mode_enabled(&headers) {
            if let Some(ref checksum) = meta.checksum {
                apply_checksum_headers(&mut response, checksum);
            }
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

    // CreateMultipartUpload 可声明 checksum 算法与合成类型（FULL_OBJECT/COMPOSITE）
    let checksum_algorithm = headers
        .get("x-amz-checksum-algorithm")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let checksum_algorithm = match checksum_algorithm {
        Some(name) => match ChecksumAlgorithm::parse(name) {
            Some(algorithm) => Some(algorithm),
            None => {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    &format!("Unsupported checksum algorithm: {name}"),
                    &key,
                );
            }
        },
        None => None,
    };
    let checksum_type = headers
        .get("x-amz-checksum-type")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty());
    if let Some(ref value) = checksum_type {
        if value != "FULL_OBJECT" && value != "COMPOSITE" {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "x-amz-checksum-type must be FULL_OBJECT or COMPOSITE",
                &key,
            );
        }
        if checksum_algorithm.is_none() {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "x-amz-checksum-type requires x-amz-checksum-algorithm",
                &key,
            );
        }
    }
    if let (Some(algorithm), Some(checksum_type)) = (checksum_algorithm, checksum_type.as_deref())
    {
        if checksum_type == "COMPOSITE" && !algorithm.supports_composite() {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "CRC64NVME only supports FULL_OBJECT checksum type",
                &key,
            );
        }
    }
    // 默认合成类型：声明了算法未声明类型时为 COMPOSITE（CRC64NVME 例外，仅支持 FULL_OBJECT）
    let checksum_type = match (checksum_algorithm, checksum_type) {
        (Some(algorithm), None) => Some(if algorithm.supports_composite() {
            "COMPOSITE".to_string()
        } else {
            "FULL_OBJECT".to_string()
        }),
        (_, value) => value,
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
            checksum_algorithm: checksum_algorithm.map(|algorithm| algorithm.name().to_string()),
            checksum_type: checksum_type.clone(),
        },
    );

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>"#,
        xml_escape(&bucket),
        xml_escape(&key),
        xml_escape(&upload_id),
    );
    let mut response = s3_xml_response(StatusCode::OK, xml);
    if let Some(algorithm) = checksum_algorithm {
        if let Ok(value) = axum::http::HeaderValue::from_str(algorithm.name()) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-checksum-algorithm"),
                value,
            );
        }
    }
    if let Some(ref checksum_type) = checksum_type {
        if let Ok(value) = axum::http::HeaderValue::from_str(checksum_type) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-checksum-type"),
                value,
            );
        }
    }
    apply_object_encryption_headers(&mut response, &encryption);
    response
}

/// 流式分片上传：接收 axum Body（可含 aws-chunked），流式写入 part 文件并增量计算 weak_etag。
///
/// - 若 aws-chunked 编码（签名或 unsigned，可带 trailer），用 `AwsChunkedDecoder` 解码 +
///   链式验签，流式写入 part 文件
/// - 否则直接消费 body 帧，边写边喂 hasher，内存恒定
/// - 支持 x-amz-checksum-*（头或 trailer 提供期望值）：校验失败回 BadDigest，
///   通过则存入 `MultipartPart.checksum` 并在响应回显
pub(crate) async fn s3_upload_part_streaming(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    upload_id: String,
    part_number: u32,
    body: axum::body::Body,
    auth_outcome: S3AuthOutcome,
    headers: HeaderMap,
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

    let checksum_request = parse_checksum_headers(&headers)
        .map_err(|message| s3_error(StatusCode::BAD_REQUEST, "InvalidRequest", &message, &key))?;
    let mut checksum_hasher = checksum_request
        .as_ref()
        .map(|req| req.algorithm.hasher());

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
    let mut trailer_checksum: Option<(String, String)> = None;
    let mut auth_outcome = auth_outcome;
    let is_chunked_body =
        auth_outcome.streaming_context.is_some() || auth_outcome.unsigned_chunked;

    if is_chunked_body {
        // aws-chunked（签名或 unsigned，可带 trailer）：解码 + 链式验签 → 写出
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
        let mut decoder = AwsChunkedDecoder::with_options(
            reader,
            auth_outcome.streaming_context.take(),
            auth_outcome.chunked_trailer,
        );
        let decoded = decoder.decode_all().await.map_err(|err| {
            s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidChunk",
                &format!("aws-chunked decode failed: {err}"),
                &key,
            )
        })?;
        for (name, value) in decoder.trailers() {
            if name.starts_with("x-amz-checksum-") {
                trailer_checksum = Some((name.clone(), value.clone()));
            }
        }
        file.write_all(&decoded).await.map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to write part: {err}"),
                &key,
            )
        })?;
        hasher.update(&decoded);
        if let Some(checksum) = checksum_hasher.as_mut() {
            checksum.update(&decoded);
        }
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
            if let Some(checksum) = checksum_hasher.as_mut() {
                checksum.update(&frame);
            }
            total_size += frame.len() as u64;
        }
    }

    let etag = hasher.finalize();

    // checksum 校验：期望值来自请求头或 trailer，不匹配回 BadDigest
    let mut part_checksum: Option<(String, String)> = None;
    if let (Some(request), Some(checksum)) = (checksum_request.as_ref(), checksum_hasher.take()) {
        let computed = checksum.finalize();
        let expected = request.expected.clone().or_else(|| {
            trailer_checksum
                .as_ref()
                .filter(|(name, _)| name == request.algorithm.header_name())
                .map(|(_, value)| value.clone())
        });
        if let Some(expected) = expected {
            if expected.trim() != computed {
                let _ = tokio::fs::remove_file(&part_path).await;
                return Err(s3_error(
                    StatusCode::BAD_REQUEST,
                    "BadDigest",
                    &format!(
                        "The {} you specified did not match the calculated checksum",
                        request.algorithm.name()
                    ),
                    &key,
                ));
            }
        }
        part_checksum = Some((request.algorithm.name().to_string(), computed));
    }

    // 注意:UploadPart 阶段不校验分片最小大小。S3 协议规定 EntityTooSmall 仅在
    // CompleteMultipartUpload 时对「除最后一个分片外」的分片校验——服务端在 UploadPart
    // 时无从得知该分片是否为最后一个,任何大小都必须接受(否则合法的小尾片/小对象会被误拒)。
    upload.parts.insert(
        part_number,
        MultipartPart {
            part_number,
            etag: etag.clone(),
            size: total_size,
            path: part_path,
            updated_at: Utc::now(),
            checksum: part_checksum.clone(),
        },
    );
    drop(uploads);

    let mut response = StatusCode::OK.into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&format!("\"{etag}\"")) {
        response
            .headers_mut()
            .insert(axum::http::header::ETAG, value);
    }
    if let Some((algorithm_name, value)) = part_checksum {
        if let Some(algorithm) = ChecksumAlgorithm::parse(&algorithm_name) {
            if let Ok(value) = axum::http::HeaderValue::from_str(&value) {
                response.headers_mut().insert(
                    axum::http::header::HeaderName::from_static(algorithm.header_name()),
                    value,
                );
            }
        }
    }
    Ok(response)
}

/// UploadPartCopy:`PUT {bucket}/{key}?uploadId=&partNumber=` + `x-amz-copy-source`。
/// 从源对象(可选 `x-amz-copy-source-range: bytes=a-b`)拷贝字节作为目标 multipart 的一个 part。
/// 大对象服务端拷贝 / TransferManager 分片复制必用。返回 CopyPartResult。
pub(crate) async fn s3_upload_part_copy(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    upload_id: String,
    part_number: u32,
    copy_source_raw: String,
    copy_source_range: Option<String>,
) -> Response {
    // 解析源对象。
    let (source_bucket, source_key, source_version_id) =
        match parse_copy_source_header(&copy_source_raw) {
            Ok(value) => value,
            Err(message) => return s3_error(StatusCode::BAD_REQUEST, "InvalidArgument", &message, &key),
        };
    if is_reserved_internal_key(&source_key) {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidObjectName",
            "Source object key uses reserved internal namespace",
            &source_key,
        );
    }
    let source_current_meta =
        match read_current_object_meta(&state, &source_bucket, &source_key).await {
            Ok(meta) => meta,
            Err(response) => return response,
        };
    let source_meta = if let Some(version_id) = source_version_id {
        match resolve_object_version_meta(
            &state,
            &source_bucket,
            &source_key,
            &version_id,
            source_current_meta,
        )
        .await
        {
            Ok(Some((meta, _))) => meta,
            Ok(None) => {
                return s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchVersion",
                    "The specified source version does not exist",
                    &source_key,
                )
            }
            Err(response) => return response,
        }
    } else {
        match source_current_meta {
            Some(meta) => meta,
            None => {
                return s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchKey",
                    "The specified source key does not exist",
                    &source_key,
                )
            }
        }
    };
    if source_meta.delete_marker {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "The specified source key does not exist",
            &source_key,
        );
    }

    // 读源字节(全量;加密源 SSE-C 这里不支持,返回错误而非误拷)。
    let source_bytes = match read_current_object_payload(
        &state,
        &source_bucket,
        &source_key,
        Some(&source_meta),
        None,
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
            )
        }
        Err(response) => return response,
    };

    // 可选 copy-source-range: bytes=start-end(闭区间)。
    let part_bytes = if let Some(range_spec) = copy_source_range.as_deref() {
        match parse_copy_source_byte_range(range_spec, source_bytes.len() as u64) {
            Some((start, end)) => source_bytes[start as usize..=end as usize].to_vec(),
            None => {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "Invalid x-amz-copy-source-range",
                    &key,
                )
            }
        }
    } else {
        source_bytes
    };

    // 落 part(复用 multipart part 落盘结构)。
    let mut uploads = state.multipart_uploads.write().await;
    let Some(upload) = uploads.get_mut(&upload_id) else {
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
    let upload_dir = multipart_upload_dir(&state, &upload_id);
    if let Err(err) = tokio::fs::create_dir_all(&upload_dir).await {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to create multipart upload directory: {err}"),
            &key,
        );
    }
    let part_path = upload_dir.join(format!("{part_number}.part"));
    if let Err(err) = atomic_write(&part_path, &part_bytes).await {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to write copied part: {err}"),
            &key,
        );
    }
    let etag = format!("{:x}", Md5::digest(&part_bytes));
    let last_modified = Utc::now();
    upload.parts.insert(
        part_number,
        MultipartPart {
            part_number,
            etag: etag.clone(),
            size: part_bytes.len() as u64,
            path: part_path,
            updated_at: last_modified,
            checksum: None,
        },
    );
    drop(uploads);

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><CopyPartResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>{}</LastModified><ETag>"{}"</ETag></CopyPartResult>"#,
        last_modified.to_rfc3339_opts(SecondsFormat::Secs, true),
        etag,
    );
    s3_xml_response(StatusCode::OK, xml)
}

/// 解析 `x-amz-copy-source-range: bytes=start-end`(闭区间,均必填),返回 (start,end)。
fn parse_copy_source_byte_range(spec: &str, size: u64) -> Option<(u64, u64)> {
    let rest = spec.trim().strip_prefix("bytes=")?;
    let (start_s, end_s) = rest.split_once('-')?;
    let start: u64 = start_s.trim().parse().ok()?;
    let end: u64 = end_s.trim().parse().ok()?;
    if start > end || size == 0 || end >= size {
        return None;
    }
    Some((start, end))
}

pub(crate) async fn s3_list_multipart_parts_xml(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    upload_id: String,
    part_number_marker: u32,
    max_parts: usize,
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
    // 分页：part-number-marker 之后的 part，取 max-parts 个
    let remaining = parts
        .into_iter()
        .filter(|part| part.part_number > part_number_marker)
        .collect::<Vec<_>>();
    let is_truncated = remaining.len() > max_parts;
    let page = &remaining[..max_parts.min(remaining.len())];
    let next_part_number_marker = if is_truncated {
        page.last().map(|part| part.part_number).unwrap_or(0)
    } else {
        0
    };
    let checksum_algorithm_xml = upload
        .checksum_algorithm
        .as_deref()
        .map(|name| format!("<ChecksumAlgorithm>{}</ChecksumAlgorithm>", xml_escape(name)))
        .unwrap_or_default();
    let checksum_type_xml = upload
        .checksum_type
        .as_deref()
        .map(|value| format!("<ChecksumType>{}</ChecksumType>", xml_escape(value)))
        .unwrap_or_default();

    let mut xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId><PartNumberMarker>{}</PartNumberMarker><NextPartNumberMarker>{}</NextPartNumberMarker><MaxParts>{}</MaxParts><IsTruncated>{}</IsTruncated>{}{}"#,
        xml_escape(&bucket),
        xml_escape(&key),
        xml_escape(&upload_id),
        part_number_marker,
        next_part_number_marker,
        max_parts,
        is_truncated,
        checksum_algorithm_xml,
        checksum_type_xml,
    );
    for part in page {
        xml.push_str("<Part><PartNumber>");
        xml.push_str(&part.part_number.to_string());
        xml.push_str("</PartNumber><LastModified>");
        xml.push_str(&part.updated_at.to_rfc3339_opts(SecondsFormat::Secs, true));
        xml.push_str("</LastModified><ETag>\"");
        xml.push_str(&xml_escape(&part.etag));
        xml.push_str("\"</ETag><Size>");
        xml.push_str(&part.size.to_string());
        xml.push_str("</Size>");
        if let Some((algorithm_name, value)) = part.checksum.as_ref() {
            if let Some(algorithm) = ChecksumAlgorithm::parse(algorithm_name) {
                xml.push_str(&format!(
                    "<{tag}>{value}</{tag}>",
                    tag = algorithm.xml_tag(),
                    value = xml_escape(value),
                ));
            }
        }
        xml.push_str("</Part>");
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
    // checksum 合成参数：算法以 initiate 声明为准，否则从首个带 checksum 的 part 推断
    let mut upload_checksum_algorithm = upload
        .checksum_algorithm
        .as_deref()
        .and_then(ChecksumAlgorithm::parse);
    let upload_checksum_type = upload.checksum_type.clone();

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

    // 先校验所有 part(存在性 / ETag / checksum / 顺序严格递增),全部通过后再落盘,
    // 避免缺片或非法请求截断并损坏已存在的对象。
    let mut etag_md5_concat: Vec<u8> = Vec::with_capacity(request.parts.len() * 16);
    let mut part_checksums: Vec<String> = Vec::with_capacity(request.parts.len());
    let mut last_part_number: Option<u32> = None;
    // S3 规定除最后一个分片外,每个参与 complete 的分片须 ≥5 MiB(EntityTooSmall);
    // 最后一个分片不限大小。此校验只能在 complete 时做(此刻才知道哪个是最后一个)。
    let min_part_size: u64 = std::env::var("RUSTIO_S3_MIN_PART_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5 * 1024 * 1024);
    let total_parts = request.parts.len();
    for (part_index, part) in request.parts.iter().enumerate() {
        if let Some(prev) = last_part_number {
            if part.part_number <= prev {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidPartOrder",
                    "The list of parts was not in ascending order; parts must be ordered by part number",
                    &key,
                );
            }
        }
        last_part_number = Some(part.part_number);

        let Some(part_meta) = upload.parts.get(&part.part_number) else {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidPart",
                &format!("Missing uploaded part {}", part.part_number),
                &key,
            );
        };

        // 非最后一个分片须 ≥ min_part_size(最后一个分片豁免)。
        let is_last_part = part_index + 1 == total_parts;
        if !is_last_part && part_meta.size < min_part_size {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "EntityTooSmall",
                &format!(
                    "Your proposed upload is smaller than the minimum allowed size of {min_part_size} bytes"
                ),
                &key,
            );
        }

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

        // 请求 XML 中的 part checksum 与 UploadPart 存储值比对
        let declared = match part.declared_checksum() {
            Ok(value) => value,
            Err(message) => {
                return s3_error(StatusCode::BAD_REQUEST, "InvalidRequest", &message, &key);
            }
        };
        if let Some((algorithm, expected)) = declared {
            if upload_checksum_algorithm.is_none() {
                upload_checksum_algorithm = Some(algorithm);
            }
            if upload_checksum_algorithm != Some(algorithm) {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    &format!(
                        "Checksum algorithm mismatch for part {}",
                        part.part_number
                    ),
                    &key,
                );
            }
            match part_meta.checksum.as_ref() {
                Some((stored_algorithm, stored_value))
                    if ChecksumAlgorithm::parse(stored_algorithm) == Some(algorithm) =>
                {
                    if stored_value != &expected {
                        return s3_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidPart",
                            &format!("Checksum mismatch for part {}", part.part_number),
                            &key,
                        );
                    }
                }
                _ => {
                    return s3_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidPart",
                        &format!(
                            "Part {} was not uploaded with a {} checksum",
                            part.part_number,
                            algorithm.name()
                        ),
                        &key,
                    );
                }
            }
        }
        if let Some((stored_algorithm, stored_value)) = part_meta.checksum.as_ref() {
            if upload_checksum_algorithm.is_none() {
                upload_checksum_algorithm = ChecksumAlgorithm::parse(stored_algorithm);
            }
            if upload_checksum_algorithm == ChecksumAlgorithm::parse(stored_algorithm) {
                part_checksums.push(stored_value.clone());
            }
        }

        // part_meta.etag 是该 part 内容的 MD5 hex,解码为原始 16 字节用于计算 multipart ETag。
        match hex::decode(&part_meta.etag) {
            Ok(raw) => etag_md5_concat.extend_from_slice(&raw),
            Err(_) => {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Invalid stored ETag for part {}", part.part_number),
                    &key,
                );
            }
        }
    }

    // 解析 complete 请求头中的 x-amz-checksum-type（可覆盖 initiate 声明）
    let request_checksum_type = headers
        .get("x-amz-checksum-type")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty());
    let effective_checksum_type = request_checksum_type
        .or(upload_checksum_type)
        .unwrap_or_else(|| "COMPOSITE".to_string());
    // FULL_OBJECT 模式需要对合并后的整体数据计算 checksum
    let mut full_object_hasher = match (&upload_checksum_algorithm, effective_checksum_type.as_str())
    {
        (Some(algorithm), "FULL_OBJECT") => Some(algorithm.hasher()),
        _ => None,
    };

    // 合并到唯一命名的临时文件,sync 后原子 rename 覆盖目标对象;中途任何失败只删临时文件,
    // 不破坏原有对象(对齐单次 PUT 的写入语义)。
    let staging = {
        let file_name = target_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("object");
        target_path.with_file_name(format!(".{file_name}.{upload_id}.rustio_mpu"))
    };
    let mut target_file = match tokio::fs::File::create(&staging).await {
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

    for part in &request.parts {
        let Some(part_meta) = upload.parts.get(&part.part_number) else {
            let _ = tokio::fs::remove_file(&staging).await;
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidPart",
                &format!("Missing uploaded part {}", part.part_number),
                &key,
            );
        };

        let mut part_file = match tokio::fs::File::open(&part_meta.path).await {
            Ok(file) => file,
            Err(err) => {
                let _ = tokio::fs::remove_file(&staging).await;
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
                    let _ = tokio::fs::remove_file(&staging).await;
                    return s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to read uploaded part: {err}"),
                        &key,
                    );
                }
            };

            if let Err(err) = target_file.write_all(&buffer[..read]).await {
                let _ = tokio::fs::remove_file(&staging).await;
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to write final object: {err}"),
                    &key,
                );
            }
            if let Some(hasher) = full_object_hasher.as_mut() {
                hasher.update(&buffer[..read]);
            }
        }
    }

    if let Err(err) = target_file.sync_all().await {
        let _ = tokio::fs::remove_file(&staging).await;
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to flush final object: {err}"),
            &key,
        );
    }
    drop(target_file);
    if let Err(err) = tokio::fs::rename(&staging, &target_path).await {
        let _ = tokio::fs::remove_file(&staging).await;
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to finalize object: {err}"),
            &key,
        );
    }

    // multipart 对象 ETag = MD5(各 part MD5 原始字节拼接) + "-<part 数>"(符合 S3 规范)。
    let final_etag = format!("{:x}-{}", Md5::digest(&etag_md5_concat), request.parts.len());

    // 最终 checksum：FULL_OBJECT 直接取全对象 hasher；COMPOSITE 为 checksum-of-checksums-N
    // （要求所有 part 都带同算法 checksum，缺失则跳过不输出）
    let final_checksum: Option<rustio_core::types::S3ObjectChecksum> =
        match (upload_checksum_algorithm, full_object_hasher.take()) {
            (Some(algorithm), Some(hasher)) => Some(rustio_core::types::S3ObjectChecksum {
                algorithm: algorithm.name().to_string(),
                value: hasher.finalize(),
                checksum_type: "FULL_OBJECT".to_string(),
            }),
            (Some(algorithm), None) if part_checksums.len() == request.parts.len() => {
                match compute_composite_checksum(algorithm, &part_checksums) {
                    Ok(value) => Some(rustio_core::types::S3ObjectChecksum {
                        algorithm: algorithm.name().to_string(),
                        value,
                        checksum_type: "COMPOSITE".to_string(),
                    }),
                    Err(_) => None,
                }
            }
            _ => None,
        };
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
    object_meta.checksum = final_checksum.clone();
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

    let checksum_xml = final_checksum
        .as_ref()
        .and_then(|checksum| {
            ChecksumAlgorithm::parse(&checksum.algorithm).map(|algorithm| {
                format!(
                    "<{tag}>{value}</{tag}><ChecksumType>{ctype}</ChecksumType>",
                    tag = algorithm.xml_tag(),
                    value = xml_escape(&checksum.value),
                    ctype = xml_escape(&checksum.checksum_type),
                )
            })
        })
        .unwrap_or_default();
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Location>/{}/{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>"{}"</ETag>{}</CompleteMultipartUploadResult>"#,
        xml_escape(&bucket),
        xml_escape(&key),
        xml_escape(&bucket),
        xml_escape(&key),
        xml_escape(&final_etag),
        checksum_xml,
    );
    let mut response = s3_xml_response(StatusCode::OK, xml);
    if let Some(ref checksum) = final_checksum {
        apply_checksum_headers(&mut response, checksum);
    }
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn s3_list_multipart_uploads_xml(
    state: Arc<AppState>,
    bucket: &str,
    prefix: &str,
    delimiter: &str,
    key_marker: &str,
    upload_id_marker: &str,
    max_uploads: usize,
    encoding_url: bool,
) -> Response {
    let uploads = state.multipart_uploads.read().await;
    let mut items = uploads
        .values()
        .filter(|upload| upload.bucket == bucket && upload.key.starts_with(prefix))
        .cloned()
        .collect::<Vec<_>>();
    // AWS 排序：key 升序，同 key 按 upload_id 升序
    items.sort_by(|a, b| {
        a.key
            .cmp(&b.key)
            .then_with(|| a.upload_id.cmp(&b.upload_id))
    });

    // marker 过滤：key > key-marker，或 key == key-marker 且 upload_id > upload-id-marker
    if !key_marker.is_empty() {
        items.retain(|upload| {
            upload.key.as_str() > key_marker
                || (upload.key == key_marker
                    && !upload_id_marker.is_empty()
                    && upload.upload_id.as_str() > upload_id_marker)
        });
    }

    // delimiter 折叠：prefix 之后含 delimiter 的 key 归入 CommonPrefixes
    let mut entries: Vec<Result<MultipartUpload, String>> = Vec::new();
    let mut seen_prefixes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for upload in items {
        if !delimiter.is_empty() {
            let rest = &upload.key[prefix.len()..];
            if let Some(pos) = rest.find(delimiter) {
                let common = format!("{prefix}{}{delimiter}", &rest[..pos]);
                if seen_prefixes.insert(common.clone()) {
                    entries.push(Err(common));
                }
                continue;
            }
        }
        entries.push(Ok(upload));
    }

    let is_truncated = entries.len() > max_uploads;
    entries.truncate(max_uploads);
    let (next_key_marker, next_upload_id_marker) = if is_truncated {
        match entries.last() {
            Some(Ok(upload)) => (upload.key.clone(), upload.upload_id.clone()),
            Some(Err(common)) => (common.clone(), String::new()),
            None => (String::new(), String::new()),
        }
    } else {
        (String::new(), String::new())
    };

    let mut xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>{}</Bucket><KeyMarker>{}</KeyMarker><UploadIdMarker>{}</UploadIdMarker><NextKeyMarker>{}</NextKeyMarker><NextUploadIdMarker>{}</NextUploadIdMarker><Delimiter>{}</Delimiter><Prefix>{}</Prefix><MaxUploads>{}</MaxUploads><IsTruncated>{}</IsTruncated>{}"#,
        xml_escape(bucket),
        xml_escape(&s3_encode_key(key_marker, encoding_url)),
        xml_escape(upload_id_marker),
        xml_escape(&s3_encode_key(&next_key_marker, encoding_url)),
        xml_escape(&next_upload_id_marker),
        xml_escape(&s3_encode_key(delimiter, encoding_url)),
        xml_escape(&s3_encode_key(prefix, encoding_url)),
        max_uploads,
        is_truncated,
        if encoding_url {
            "<EncodingType>url</EncodingType>"
        } else {
            ""
        },
    );
    for entry in &entries {
        match entry {
            Ok(upload) => {
                xml.push_str("<Upload><Key>");
                xml.push_str(&xml_escape(&s3_encode_key(&upload.key, encoding_url)));
                xml.push_str("</Key><UploadId>");
                xml.push_str(&xml_escape(&upload.upload_id));
                xml.push_str("</UploadId><Initiator><ID>rustio</ID><DisplayName>rustio</DisplayName></Initiator><Owner><ID>rustio</ID><DisplayName>rustio</DisplayName></Owner><StorageClass>STANDARD</StorageClass>");
                if let Some(algorithm) = upload.checksum_algorithm.as_deref() {
                    xml.push_str(&format!(
                        "<ChecksumAlgorithm>{}</ChecksumAlgorithm>",
                        xml_escape(algorithm)
                    ));
                }
                if let Some(checksum_type) = upload.checksum_type.as_deref() {
                    xml.push_str(&format!(
                        "<ChecksumType>{}</ChecksumType>",
                        xml_escape(checksum_type)
                    ));
                }
                xml.push_str("<Initiated>");
                xml.push_str(
                    &upload
                        .initiated_at
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                );
                xml.push_str("</Initiated></Upload>");
            }
            Err(common) => {
                xml.push_str("<CommonPrefixes><Prefix>");
                xml.push_str(&xml_escape(&s3_encode_key(common, encoding_url)));
                xml.push_str("</Prefix></CommonPrefixes>");
            }
        }
    }
    xml.push_str("</ListMultipartUploadsResult>");
    s3_xml_response(StatusCode::OK, xml)
}

pub(crate) async fn s3_list_buckets_xml(
    state: Arc<AppState>,
    prefix: &str,
    continuation_token: &str,
    max_buckets: usize,
) -> Response {
    let mut buckets = state
        .buckets
        .read()
        .await
        .keys()
        .filter(|name| name.starts_with(prefix))
        .cloned()
        .collect::<Vec<_>>();
    buckets.sort();

    // continuation-token 为上一页最后一个 bucket 名（明文 marker 语义）
    if !continuation_token.is_empty() {
        buckets.retain(|name| name.as_str() > continuation_token);
    }
    let is_truncated = buckets.len() > max_buckets;
    buckets.truncate(max_buckets);
    let next_token = if is_truncated {
        buckets.last().cloned()
    } else {
        None
    };

    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>rustio</ID><DisplayName>rustio</DisplayName></Owner><Buckets>"#,
    );
    for bucket in &buckets {
        // CreationDate 取 bucket 目录的 mtime/birth time（BucketSpec 未持久化创建时间）
        let creation_date = bucket_path(&state, bucket)
            .ok()
            .and_then(|path| std::fs::metadata(&path).ok())
            .and_then(|metadata| metadata.created().or_else(|_| metadata.modified()).ok())
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(Utc::now);
        xml.push_str("<Bucket><Name>");
        xml.push_str(&xml_escape(bucket));
        xml.push_str("</Name><CreationDate>");
        xml.push_str(&creation_date.to_rfc3339_opts(SecondsFormat::Secs, true));
        xml.push_str("</CreationDate></Bucket>");
    }
    xml.push_str("</Buckets>");
    if !prefix.is_empty() {
        xml.push_str("<Prefix>");
        xml.push_str(&xml_escape(prefix));
        xml.push_str("</Prefix>");
    }
    if let Some(token) = next_token {
        xml.push_str("<ContinuationToken>");
        xml.push_str(&xml_escape(&token));
        xml.push_str("</ContinuationToken>");
    }
    xml.push_str("</ListAllMyBucketsResult>");
    s3_xml_response(StatusCode::OK, xml)
}

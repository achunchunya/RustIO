//! 桶对象列举与站点复制

use super::*;

pub(crate) async fn list_bucket_objects(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Query(query): Query<BucketObjectQuery>,
) -> Result<Json<ApiEnvelope<Vec<BucketObjectEntry>>>, AppError> {
    auth.require(Permission::BucketRead)?;

    let bucket_dir = bucket_path(&state, &name)
        .map_err(|_| AppError::bad_request("存储桶名称无效 / invalid bucket name"))?;
    if !tokio::fs::try_exists(&bucket_dir).await.unwrap_or(false) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }

    let mut objects = Vec::new();
    collect_objects(&bucket_dir, &bucket_dir, &mut objects).map_err(|err| {
        AppError::internal(format!(
            "列出存储桶对象失败 / failed to list bucket objects: {err}"
        ))
    })?;

    let prefix = query.prefix.unwrap_or_default();
    let mut result = objects
        .into_iter()
        .filter(|entry| entry.key.starts_with(&prefix))
        .map(|entry| BucketObjectEntry {
            key: entry.key.clone(),
            size: entry.size,
            etag: entry.etag,
            last_modified: entry.last_modified,
            storage_class: entry.storage_class,
            version_id: None,
            retention_until: None,
            legal_hold: false,
        })
        .collect::<Vec<_>>();
    result.sort_by(|left, right| left.key.cmp(&right.key));

    for item in &mut result {
        let meta = read_current_object_meta(&state, &name, &item.key)
            .await
            .map_err(|_| {
                AppError::internal("读取对象元数据失败 / failed to read object metadata")
            })?;
        if let Some(meta) = meta {
            item.version_id = Some(meta.version_id.clone());
            item.legal_hold = meta.legal_hold;
            item.storage_class = object_storage_class(&meta).to_string();
            item.retention_until = meta
                .retention_until
                .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true));
        }
    }

    Ok(wrap(result))
}

pub(crate) async fn list_bucket_object_versions(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Query(query): Query<BucketObjectVersionsQuery>,
) -> Result<Json<ApiEnvelope<Vec<BucketObjectVersionEntry>>>, AppError> {
    auth.require(Permission::BucketRead)?;

    let bucket_dir = bucket_path(&state, &name)
        .map_err(|_| AppError::bad_request("存储桶名称无效 / invalid bucket name"))?;
    if !tokio::fs::try_exists(&bucket_dir).await.unwrap_or(false) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }

    if query.key.is_empty() {
        return Err(AppError::bad_request(
            "对象键不能为空 / object key cannot be empty",
        ));
    }
    if is_reserved_internal_key(&query.key) {
        return Err(AppError::bad_request(
            "对象键使用了保留命名空间 / object key uses reserved namespace",
        ));
    }

    let versions = list_object_versions(&state, &name, &query.key)
        .await
        .map_err(|_| AppError::internal("列出对象版本失败 / failed to list object versions"))?;
    if versions.is_empty() {
        return Err(AppError::not_found("对象不存在 / object not found"));
    }

    let latest_version_id = versions.first().map(|item| item.version_id.clone());
    let entries = versions
        .into_iter()
        .map(|meta| {
            let storage_class = object_storage_class(&meta).to_string();
            let is_latest = latest_version_id
                .as_ref()
                .map(|value| value == &meta.version_id)
                .unwrap_or(false);
            BucketObjectVersionEntry {
                key: meta.key,
                size: meta.size,
                etag: meta.etag,
                last_modified: meta.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                storage_class,
                delete_marker: meta.delete_marker,
                legal_hold: meta.legal_hold,
                retention_until: meta
                    .retention_until
                    .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true)),
                is_latest,
                version_id: meta.version_id,
            }
        })
        .collect::<Vec<_>>();

    Ok(wrap(entries))
}

pub(crate) async fn put_bucket_object(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path((name, key)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::BucketWrite)?;

    let bucket_dir = bucket_path(&state, &name)
        .map_err(|_| AppError::bad_request("存储桶名称无效 / invalid bucket name"))?;
    if !tokio::fs::try_exists(&bucket_dir).await.unwrap_or(false) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }

    if is_reserved_internal_key(&key) {
        return Err(AppError::bad_request(
            "对象键使用了保留命名空间 / object key uses reserved namespace",
        ));
    }

    let current_meta = read_current_object_meta(&state, &name, &key)
        .await
        .map_err(|_| {
            AppError::internal("读取当前对象元数据失败 / failed to read current object metadata")
        })?;
    if let Some(current_meta) = current_meta.as_ref() {
        if current_meta.legal_hold {
            state
                .append_audit(
                    &auth.username,
                    "bucket.object.put",
                    &format!("bucket/{name}/{key}"),
                    "denied",
                    None,
                    json!({
                        "reason": "legal_hold",
                        "version_id": current_meta.version_id,
                    }),
                )
                .await;
            return Err(AppError::forbidden(
                "对象处于法律保留状态，禁止覆盖 / object is under legal hold and cannot be overwritten",
            ));
        }
        if current_meta
            .retention_until
            .map(|value| value > Utc::now())
            .unwrap_or(false)
        {
            state
                .append_audit(
                    &auth.username,
                    "bucket.object.put",
                    &format!("bucket/{name}/{key}"),
                    "denied",
                    None,
                    json!({
                        "reason": "retention_active",
                        "version_id": current_meta.version_id,
                        "retention_until": current_meta.retention_until,
                    }),
                )
                .await;
            return Err(AppError::forbidden(
                "对象保留期尚未到期，禁止覆盖 / object retention period has not expired; overwrite denied",
            ));
        }
    }

    let versioning_enabled = state
        .buckets
        .read()
        .await
        .get(&name)
        .map(|item| item.versioning)
        .unwrap_or(true);
    if versioning_enabled {
        if let Some(ref meta) = current_meta {
            archive_object_version(&state, &name, &key, meta)
                .await
                .map_err(|_| {
                    AppError::internal(
                        "归档上一个对象版本失败 / failed to archive previous object version",
                    )
                })?;
        }
    }

    let target = object_path(&bucket_dir, &key)
        .map_err(|_| AppError::bad_request("对象键路径无效 / invalid object key path"))?;
    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|err| {
            AppError::internal(format!(
                "创建对象目录失败 / failed to create object dir: {err}"
            ))
        })?;
    }
    tokio::fs::write(&target, &body).await.map_err(|err| {
        AppError::internal(format!("写入对象失败 / failed to write object: {err}"))
    })?;

    let etag = weak_etag(&body);
    let meta = build_object_meta_for_current_version(
        &state,
        &name,
        &key,
        body.len() as u64,
        etag.clone(),
        false,
    )
    .await;
    persist_current_object_meta(&state, meta.clone())
        .await
        .map_err(|_| {
            AppError::internal("持久化对象元数据失败 / failed to persist object metadata")
        })?;
    if !versioning_enabled {
        if let Some(previous_meta) = current_meta.as_ref() {
            remove_remote_tier_payload_for_meta(&state, previous_meta)
                .await
                .map_err(|_| {
                    AppError::internal(
                        "清理旧远端层对象失败 / failed to cleanup previous remote tier object",
                    )
                })?;
        }
    }
    emit_bucket_object_event_best_effort(
        &state,
        &name,
        &key,
        "s3:ObjectCreated:Put",
        Some(&meta),
        "admin-api",
    )
    .await;

    state
        .append_audit(
            &auth.username,
            "bucket.object.put",
            &format!("bucket/{name}/{key}"),
            "success",
            None,
            json!({ "size": body.len(), "version_id": meta.version_id }),
        )
        .await;
    Ok(wrap(
        json!({ "bucket": name, "key": key, "size": body.len(), "version_id": meta.version_id }),
    ))
}

pub(crate) async fn get_bucket_object(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path((name, key)): Path<(String, String)>,
    Query(query): Query<BucketObjectVersionQuery>,
) -> Result<Response, AppError> {
    auth.require(Permission::BucketRead)?;

    let bucket_dir = bucket_path(&state, &name)
        .map_err(|_| AppError::bad_request("存储桶名称无效 / invalid bucket name"))?;
    if !tokio::fs::try_exists(&bucket_dir).await.unwrap_or(false) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }

    if is_reserved_internal_key(&key) {
        return Err(AppError::bad_request(
            "对象键使用了保留命名空间 / object key uses reserved namespace",
        ));
    }

    let current_meta = read_current_object_meta(&state, &name, &key)
        .await
        .map_err(|_| {
            AppError::internal("读取当前对象元数据失败 / failed to read current object metadata")
        })?;
    let resolved = if let Some(version_id) = query.version_id.clone() {
        resolve_object_version_meta(&state, &name, &key, &version_id, current_meta)
            .await
            .map_err(|_| AppError::internal("解析对象版本失败 / failed to resolve object version"))?
            .ok_or_else(|| AppError::not_found("对象版本不存在 / object version not found"))?
    } else {
        let current =
            current_meta.ok_or_else(|| AppError::not_found("对象不存在 / object not found"))?;
        (current, true)
    };
    let (meta, is_current) = resolved;
    if meta.delete_marker {
        return Err(AppError::not_found(
            "对象版本是删除标记 / object version is a delete marker",
        ));
    }

    let bytes = if is_current {
        read_current_object_payload(&state, &name, &key, Some(&meta))
            .await
            .map_err(|_| AppError::internal("读取对象失败 / failed to read object"))?
            .ok_or_else(|| AppError::not_found("对象不存在 / object not found"))?
    } else {
        read_archived_object_payload(&state, &name, &key, &meta.version_id)
            .await
            .map_err(|_| {
                AppError::internal("读取归档对象版本失败 / failed to read archived object version")
            })?
            .ok_or_else(|| {
                AppError::not_found("对象版本数据不存在 / object version payload not found")
            })?
    };
    touch_object_access_heat(&state, &name, &key).await;

    let file_name = key
        .split('/')
        .next_back()
        .unwrap_or("object.bin")
        .to_string();
    let mut response = (StatusCode::OK, bytes).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{}\"", file_name))
            .map_err(|_| {
                AppError::internal(
                    "content-disposition 请求头无效 / invalid content-disposition header",
                )
            })?,
    );
    response.headers_mut().insert(
        axum::http::header::HeaderName::from_static("x-rustio-version-id"),
        axum::http::HeaderValue::from_str(&meta.version_id)
            .map_err(|_| AppError::internal("version 请求头无效 / invalid version header"))?,
    );
    Ok(response)
}

pub(crate) async fn delete_bucket_object(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path((name, key)): Path<(String, String)>,
    Query(query): Query<BucketObjectVersionQuery>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::BucketWrite)?;

    let bucket_dir = bucket_path(&state, &name)
        .map_err(|_| AppError::bad_request("存储桶名称无效 / invalid bucket name"))?;
    if !tokio::fs::try_exists(&bucket_dir).await.unwrap_or(false) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }

    if is_reserved_internal_key(&key) {
        return Err(AppError::bad_request(
            "对象键使用了保留命名空间 / object key uses reserved namespace",
        ));
    }

    if let Some(version_id) = query.version_id {
        let removed = delete_object_version(&state, &name, &key, &version_id)
            .await
            .map_err(|_| {
                AppError::internal("删除对象版本失败 / failed to delete object version")
            })?;
        if !removed {
            return Err(AppError::not_found(
                "对象版本不存在 / object version not found",
            ));
        }
        state
            .append_audit(
                &auth.username,
                "bucket.object.version.delete",
                &format!("bucket/{name}/{key}"),
                "success",
                None,
                json!({ "version_id": version_id }),
            )
            .await;
        return Ok(wrap(json!({
            "bucket": name,
            "key": key,
            "deleted": true,
            "version_id": version_id
        })));
    }

    let current_meta = read_current_object_meta(&state, &name, &key)
        .await
        .map_err(|_| {
            AppError::internal("读取当前对象元数据失败 / failed to read current object metadata")
        })?;
    let current_meta =
        current_meta.ok_or_else(|| AppError::not_found("对象不存在 / object not found"))?;

    if current_meta.legal_hold {
        return Err(AppError::forbidden(
            "对象处于法律保留状态 / object is under legal hold",
        ));
    }
    if current_meta
        .retention_until
        .map(|value| value > Utc::now())
        .unwrap_or(false)
    {
        return Err(AppError::forbidden(
            "对象保留期尚未到期 / object retention period has not expired",
        ));
    }

    let versioning_enabled = state
        .buckets
        .read()
        .await
        .get(&name)
        .map(|item| item.versioning)
        .unwrap_or(true);

    if versioning_enabled {
        archive_object_version(&state, &name, &key, &current_meta)
            .await
            .map_err(|_| {
                AppError::internal(
                    "归档当前对象版本失败 / failed to archive current object version",
                )
            })?;
    }

    remove_current_hot_object_payload(&state, &name, &key)
        .await
        .map_err(|_| AppError::internal("删除对象失败 / failed to delete object"))?;

    let mut response_body = json!({ "bucket": name, "key": key, "deleted": true });
    let notification_meta = if versioning_enabled {
        let marker =
            build_object_meta_for_current_version(&state, &name, &key, 0, String::new(), true)
                .await;
        persist_current_object_meta(&state, marker.clone())
            .await
            .map_err(|_| {
                AppError::internal(
                    "持久化删除标记元数据失败 / failed to persist delete marker metadata",
                )
            })?;
        response_body["version_id"] = json!(marker.version_id.clone());
        response_body["delete_marker"] = json!(true);
        marker
    } else {
        remove_current_object_meta(&state, &name, &key)
            .await
            .map_err(|_| {
                AppError::internal("删除对象元数据失败 / failed to remove object metadata")
            })?;
        remove_remote_tier_payload_for_meta(&state, &current_meta)
            .await
            .map_err(|_| {
                AppError::internal("删除远端层对象失败 / failed to remove remote tier object")
            })?;
        current_meta.clone()
    };
    emit_bucket_object_event_best_effort(
        &state,
        &name,
        &key,
        "s3:ObjectRemoved:Delete",
        Some(&notification_meta),
        "admin-api",
    )
    .await;

    state
        .append_audit(
            &auth.username,
            "bucket.object.delete",
            &format!("bucket/{name}/{key}"),
            "success",
            None,
            response_body.clone(),
        )
        .await;
    Ok(wrap(response_body))
}

pub(crate) async fn update_bucket_governance(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<BucketGovernanceUpdate>,
) -> Result<Json<ApiEnvelope<BucketSpec>>, AppError> {
    auth.require(Permission::BucketWrite)?;
    let BucketGovernanceUpdate {
        versioning,
        object_lock,
        ilm_policy,
        replication_policy,
    } = body;
    let mut buckets = state.buckets.write().await;
    let bucket = buckets
        .get_mut(&name)
        .ok_or_else(|| AppError::not_found("存储桶不存在 / bucket not found"))?;

    if let Some(v) = versioning {
        bucket.versioning = v;
    }
    if let Some(v) = object_lock {
        bucket.object_lock = v;
    }
    if let Some(v) = ilm_policy {
        bucket.ilm_policy = Some(v);
    }
    if let Some(v) = replication_policy {
        bucket.replication_policy = Some(v);
    }

    let snapshot = bucket.clone();
    drop(buckets);

    if let Some(enabled) = object_lock {
        let mut object_locks = state.bucket_object_locks.write().await;
        let config = object_locks
            .entry(name.clone())
            .or_insert_with(|| default_object_lock_config(&snapshot));
        config.enabled = enabled;
    }
    state
        .append_audit(
            &auth.username,
            "bucket.governance.update",
            &format!("bucket/{}", name),
            "success",
            None,
            json!({
                "versioning": snapshot.versioning,
                "object_lock": snapshot.object_lock,
            }),
        )
        .await;
    Ok(wrap(snapshot))
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateReplicationRequest {
    #[serde(default)]
    pub(crate) rule_id: Option<String>,
    pub(crate) target_site: String,
    #[serde(default)]
    pub(crate) rule_name: Option<String>,
    #[serde(default)]
    pub(crate) endpoint: Option<String>,
    #[serde(default)]
    pub(crate) prefix: Option<String>,
    #[serde(default)]
    pub(crate) suffix: Option<String>,
    #[serde(default)]
    pub(crate) tags: Option<Vec<BucketTag>>,
    #[serde(default)]
    pub(crate) priority: Option<i32>,
    #[serde(default)]
    pub(crate) replicate_existing: Option<bool>,
    #[serde(default)]
    pub(crate) sync_deletes: Option<bool>,
    pub(crate) enabled: bool,
}

pub(crate) fn normalize_replication_optional_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn normalize_replication_prefix(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .map(|value| value.trim_start_matches('/'))
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn normalize_batch_object_key(value: Option<&str>) -> Option<String> {
    normalize_replication_prefix(value)
}

pub(crate) fn normalize_replication_suffix(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn normalize_replication_filter_tags(
    tags: Vec<BucketTag>,
) -> Result<Vec<BucketTag>, AppError> {
    let mut normalized = normalize_s3_tagset(tags, true).map_err(|message| {
        AppError::bad_request(format!(
            "复制标签过滤条件无效：{message} / invalid replication tag filter: {message}"
        ))
    })?;
    normalized.sort_by(|left, right| left.key.cmp(&right.key).then(left.value.cmp(&right.value)));
    Ok(normalized)
}

pub(crate) fn validate_replication_endpoint(
    endpoint: Option<&str>,
) -> Result<Option<String>, AppError> {
    let endpoint = normalize_replication_optional_text(endpoint);
    if let Some(endpoint) = endpoint.as_deref() {
        if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
            return Err(AppError::bad_request(
                "复制站点端点必须以 http:// 或 https:// 开头 / replication site endpoint must start with http:// or https://",
            ));
        }
    }
    Ok(endpoint)
}

pub(crate) fn replication_rule_matches_key(rule: &ReplicationStatus, key: &str) -> bool {
    let prefix_matches = rule
        .prefix
        .as_deref()
        .map(|prefix| key.starts_with(prefix))
        .unwrap_or(true);
    let suffix_matches = rule
        .suffix
        .as_deref()
        .map(|suffix| key.ends_with(suffix))
        .unwrap_or(true);
    prefix_matches && suffix_matches
}

pub(crate) fn replication_rule_matches_tags(rule: &ReplicationStatus, tags: &[BucketTag]) -> bool {
    if rule.tags.is_empty() {
        return true;
    }
    rule.tags.iter().all(|expected| {
        tags.iter()
            .any(|actual| actual.key == expected.key && actual.value == expected.value)
    })
}

pub(crate) fn replication_rule_matches_meta(
    rule: &ReplicationStatus,
    key: &str,
    meta: Option<&S3ObjectMeta>,
) -> bool {
    if !replication_rule_matches_key(rule, key) {
        return false;
    }
    if rule.tags.is_empty() {
        return true;
    }
    meta.map(|meta| replication_rule_matches_tags(rule, &meta.tags))
        .unwrap_or(false)
}

pub(crate) fn replication_rule_allows_operation(rule: &ReplicationStatus, operation: &str) -> bool {
    if operation.eq_ignore_ascii_case("delete") {
        rule.sync_deletes
    } else {
        true
    }
}

pub(crate) fn validate_replication_site_endpoint_consistency(
    rules: &[ReplicationStatus],
    source_bucket: &str,
    rule_id: Option<&str>,
    target_site: &str,
    endpoint: Option<&str>,
) -> Result<(), AppError> {
    let Some(endpoint) = endpoint else {
        return Ok(());
    };
    let conflict = rules.iter().find(|rule| {
        rule.target_site == target_site
            && rule.rule_id != rule_id.unwrap_or_default()
            && rule.endpoint.as_deref().is_some()
            && rule.endpoint.as_deref() != Some(endpoint)
    });
    if conflict.is_some() {
        return Err(AppError::bad_request(format!(
            "复制站点 {target_site} 的端点必须保持一致，当前桶 {source_bucket} 提供的端点与现有规则冲突 / replication site {target_site} endpoint must stay consistent; bucket {source_bucket} endpoint conflicts with an existing rule"
        )));
    }
    Ok(())
}

pub(crate) async fn update_bucket_replication(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<UpdateReplicationRequest>,
) -> Result<Json<ApiEnvelope<ReplicationStatus>>, AppError> {
    auth.require(Permission::ReplicationWrite)?;
    if !state.buckets.read().await.contains_key(&name) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }
    let target_site = body.target_site.trim().to_string();
    if target_site.is_empty() {
        return Err(AppError::bad_request(
            "复制目标站点不能为空 / replication target site cannot be empty",
        ));
    }
    let endpoint = validate_replication_endpoint(body.endpoint.as_deref())?;
    let prefix = normalize_replication_prefix(body.prefix.as_deref());
    let suffix = normalize_replication_suffix(body.suffix.as_deref());
    let tags = normalize_replication_filter_tags(body.tags.unwrap_or_default())?;
    let rule_name = normalize_replication_optional_text(body.rule_name.as_deref());
    let priority = body.priority.unwrap_or(100).clamp(0, 1_000);
    let replicate_existing = body.replicate_existing.unwrap_or(true);
    let sync_deletes = body.sync_deletes.unwrap_or(true);
    let mut rules = state.replications.write().await;
    let normalized_rule_id = normalize_replication_optional_text(body.rule_id.as_deref());
    let effective_rule_id = normalized_rule_id.clone().or_else(|| {
        rules
            .iter()
            .find(|rule| {
                rule.source_bucket == name
                    && rule.target_site == target_site
                    && rule.prefix == prefix
                    && rule.suffix == suffix
                    && rule.tags == tags
            })
            .map(|rule| rule.rule_id.clone())
    });
    validate_replication_site_endpoint_consistency(
        &rules,
        &name,
        effective_rule_id.as_deref(),
        &target_site,
        endpoint.as_deref(),
    )?;
    let (status, should_catch_up) = if let Some(rule_id) = normalized_rule_id {
        let rule = rules
            .iter_mut()
            .find(|rule| rule.source_bucket == name && rule.rule_id == rule_id)
            .ok_or_else(|| AppError::not_found("复制规则不存在 / replication rule not found"))?;
        let was_paused = rule.status == "paused";
        let previous_prefix = rule.prefix.clone();
        let previous_suffix = rule.suffix.clone();
        let previous_target_site = rule.target_site.clone();
        let previous_tags = rule.tags.clone();
        let previous_replicate_existing = rule.replicate_existing;
        rule.target_site = target_site.clone();
        rule.rule_name = rule_name.clone();
        rule.endpoint = endpoint.clone();
        rule.prefix = prefix.clone();
        rule.suffix = suffix.clone();
        rule.tags = tags.clone();
        rule.priority = priority;
        rule.replicate_existing = replicate_existing;
        rule.sync_deletes = sync_deletes;
        rule.status = if body.enabled {
            "healthy".to_string()
        } else {
            "paused".to_string()
        };
        let should_catch_up = body.enabled
            && replicate_existing
            && (was_paused
                || previous_prefix != rule.prefix
                || previous_suffix != rule.suffix
                || previous_target_site != rule.target_site
                || previous_tags != rule.tags
                || !previous_replicate_existing);
        (rule.clone(), should_catch_up)
    } else if let Some(rule) = rules.iter_mut().find(|rule| {
        rule.source_bucket == name
            && rule.target_site == target_site
            && rule.prefix == prefix
            && rule.suffix == suffix
            && rule.tags == tags
    }) {
        let was_paused = rule.status == "paused";
        let previous_replicate_existing = rule.replicate_existing;
        rule.rule_name = rule_name.clone();
        rule.endpoint = endpoint.clone();
        rule.suffix = suffix.clone();
        rule.tags = tags.clone();
        rule.priority = priority;
        rule.replicate_existing = replicate_existing;
        rule.sync_deletes = sync_deletes;
        rule.status = if body.enabled {
            "healthy".to_string()
        } else {
            "paused".to_string()
        };
        let should_catch_up =
            body.enabled && replicate_existing && (was_paused || !previous_replicate_existing);
        (rule.clone(), should_catch_up)
    } else {
        let created = ReplicationStatus {
            rule_id: Uuid::new_v4().to_string(),
            source_bucket: name.clone(),
            target_site,
            rule_name,
            endpoint,
            prefix,
            suffix,
            tags,
            priority,
            replicate_existing,
            sync_deletes,
            lag_seconds: 0,
            status: if body.enabled {
                "healthy".to_string()
            } else {
                "paused".to_string()
            },
        };
        let should_catch_up = body.enabled && created.replicate_existing;
        rules.push(created.clone());
        (created, should_catch_up)
    };
    drop(rules);

    if should_catch_up {
        enqueue_bucket_replication_catch_up(&state, &status).await;
    }
    sync_site_replication_from_rules(&state).await;

    state
        .append_audit(
            &auth.username,
            "replication.rule.update",
            &format!("bucket/{name}"),
            "success",
            None,
            json!({
                "rule_id": status.rule_id.clone(),
                "rule_name": status.rule_name.clone(),
                "target_site": status.target_site.clone(),
                "endpoint": status.endpoint.clone(),
                "prefix": status.prefix.clone(),
                "suffix": status.suffix.clone(),
                "tags": status.tags.clone(),
                "priority": status.priority,
                "replicate_existing": status.replicate_existing,
                "sync_deletes": status.sync_deletes,
                "status": status.status.clone()
            }),
        )
        .await;
    Ok(wrap(status))
}

pub(crate) async fn delete_bucket_replication(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path((name, rule_id)): Path<(String, String)>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::ReplicationWrite)?;
    if !state.buckets.read().await.contains_key(&name) {
        return Err(AppError::not_found("存储桶不存在 / bucket not found"));
    }

    let removed = {
        let mut rules = state.replications.write().await;
        let before = rules.len();
        rules.retain(|rule| !(rule.source_bucket == name && rule.rule_id == rule_id));
        before != rules.len()
    };
    if !removed {
        return Err(AppError::not_found(
            "复制规则不存在 / replication rule not found",
        ));
    }

    {
        let mut backlog = state.replication_backlog.write().await;
        backlog.retain(|item| {
            if item.rule_id.as_deref() != Some(rule_id.as_str()) {
                return true;
            }
            !matches!(item.status.as_str(), "pending" | "failed" | "dead_letter")
        });
    }
    state.persist_replication_runtime_state().await;
    sync_site_replication_from_rules(&state).await;
    state
        .append_audit(
            &auth.username,
            "replication.rule.delete",
            &format!("bucket/{name}/replication/{rule_id}"),
            "success",
            None,
            json!({ "rule_id": rule_id.clone() }),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "rule_id": rule_id })))
}

pub(crate) async fn replication_status(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<ReplicationStatus>>>, AppError> {
    auth.require(Permission::ReplicationRead)?;
    Ok(wrap(state.replications.read().await.clone()))
}

pub(crate) async fn enqueue_bucket_replication_catch_up(
    state: &Arc<AppState>,
    rule: &ReplicationStatus,
) {
    let items = state
        .object_meta
        .read()
        .await
        .iter()
        .filter(|((source_bucket, _), meta)| {
            source_bucket == &rule.source_bucket
                && !meta.delete_marker
                && !meta.version_id.is_empty()
                && replication_rule_matches_meta(rule, &meta.key, Some(meta))
        })
        .map(|((_, key), meta)| (key.clone(), Some(meta.version_id.clone())))
        .collect::<Vec<_>>();
    for (key, version_id) in items {
        state
            .enqueue_replication_task(
                &rule.source_bucket,
                &rule.target_site,
                &key,
                Some(rule.rule_id.clone()),
                rule.priority,
                "put",
                version_id,
            )
            .await;
    }
}

pub(crate) async fn enqueue_replication_for_object(
    state: &AppState,
    bucket: &str,
    key: &str,
    operation: &str,
    version_id: Option<String>,
    meta: Option<&S3ObjectMeta>,
) {
    let mut rules = state
        .replications
        .read()
        .await
        .iter()
        .filter(|rule| {
            rule.source_bucket == bucket
                && rule.status != "paused"
                && replication_rule_matches_meta(rule, key, meta)
                && replication_rule_allows_operation(rule, operation)
        })
        .cloned()
        .collect::<Vec<_>>();
    rules.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.target_site.cmp(&right.target_site))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    for rule in rules {
        state
            .enqueue_replication_task(
                bucket,
                &rule.target_site,
                key,
                Some(rule.rule_id.clone()),
                rule.priority,
                operation,
                version_id.clone(),
            )
            .await;
    }
}

pub(crate) async fn emit_bucket_object_event_best_effort(
    state: &AppState,
    bucket: &str,
    key: &str,
    event_name: &str,
    object_meta: Option<&S3ObjectMeta>,
    origin: &str,
) {
    if let Err(err) = state
        .emit_bucket_object_event(bucket, key, event_name, object_meta, origin)
        .await
    {
        state
            .push_event(
                "bucket.notification.failed",
                "bucket-notification-worker",
                json!({
                    "bucket": bucket,
                    "key": key,
                    "event": event_name,
                    "origin": origin,
                    "error": err,
                }),
            )
            .await;
    }
}

pub(crate) async fn expire_current_object_for_lifecycle(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<Option<S3ObjectMeta>, String> {
    let current_meta = read_current_object_meta(state, bucket, key)
        .await
        .map_err(|_| {
            "读取当前对象元数据失败 / failed to read current object metadata".to_string()
        })?;
    let Some(current_meta) = current_meta else {
        return Ok(None);
    };
    if current_meta.delete_marker
        || current_meta.legal_hold
        || current_meta
            .retention_until
            .map(|value| value > Utc::now())
            .unwrap_or(false)
    {
        return Ok(None);
    }

    let versioning_enabled = state
        .buckets
        .read()
        .await
        .get(bucket)
        .map(|item| item.versioning)
        .unwrap_or(true);

    if versioning_enabled {
        archive_object_version(state, bucket, key, &current_meta)
            .await
            .map_err(|_| {
                "归档生命周期到期对象版本失败 / failed to archive lifecycle-expired object version"
                    .to_string()
            })?;
    }

    remove_current_hot_object_payload(state, bucket, key)
        .await
        .map_err(|_| {
            "删除生命周期到期对象失败 / failed to remove lifecycle-expired object".to_string()
        })?;
    if !versioning_enabled {
        remove_remote_tier_payload_for_meta(state, &current_meta)
            .await
            .map_err(|_| {
                "删除生命周期到期远端层对象失败 / failed to remove lifecycle-expired remote tier object"
                    .to_string()
            })?;
    }

    let removed_meta = if versioning_enabled {
        let marker =
            build_object_meta_for_current_version(state, bucket, key, 0, String::new(), true).await;
        persist_current_object_meta(state, marker.clone())
            .await
            .map_err(|_| {
                "持久化生命周期删除标记失败 / failed to persist lifecycle delete marker".to_string()
            })?;
        enqueue_replication_for_object(
            state,
            bucket,
            key,
            "delete",
            Some(marker.version_id.clone()),
            Some(&current_meta),
        )
        .await;
        marker
    } else {
        remove_current_object_meta(state, bucket, key)
            .await
            .map_err(|_| {
                "删除生命周期对象元数据失败 / failed to remove lifecycle object metadata"
                    .to_string()
            })?;
        current_meta.clone()
    };

    if !versioning_enabled {
        enqueue_replication_for_object(state, bucket, key, "delete", None, Some(&current_meta))
            .await;
    }
    Ok(Some(removed_meta))
}

pub(crate) async fn expire_noncurrent_object_version_for_lifecycle(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<bool, String> {
    let archived_meta = read_archived_object_meta(state, bucket, key, version_id)
        .await
        .map_err(|_| {
            "读取非当前版本元数据失败 / failed to read noncurrent version metadata".to_string()
        })?;
    let Some(archived_meta) = archived_meta else {
        return Ok(false);
    };
    if archived_meta.legal_hold
        || archived_meta
            .retention_until
            .map(|value| value > Utc::now())
            .unwrap_or(false)
    {
        return Ok(false);
    }
    remove_archived_object_version(state, bucket, key, version_id)
        .await
        .map_err(|_| {
            "删除非当前版本失败 / failed to remove noncurrent object version".to_string()
        })?;
    Ok(true)
}

pub(crate) async fn transition_current_object_for_lifecycle(
    state: &AppState,
    bucket: &str,
    key: &str,
    tier_name: &str,
) -> Result<Option<S3ObjectMeta>, String> {
    let current_meta = read_current_object_meta(state, bucket, key)
        .await
        .map_err(|_| {
            "读取当前对象元数据失败 / failed to read current object metadata".to_string()
        })?;
    let Some(mut current_meta) = current_meta else {
        return Ok(None);
    };
    if current_meta.delete_marker {
        return Ok(None);
    }
    if current_meta
        .remote_tier
        .as_ref()
        .map(|item| normalize_remote_tier_name(&item.tier) == normalize_remote_tier_name(tier_name))
        .unwrap_or(false)
    {
        return Ok(Some(current_meta));
    }

    let tier_config = lookup_remote_tier_config(state, tier_name).await?;
    let payload = read_current_object_payload(state, bucket, key, Some(&current_meta))
        .await
        .map_err(|_| "读取当前对象内容失败 / failed to read current object payload".to_string())?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let previous_remote = current_meta.remote_tier.clone();
    current_meta.storage_class = tier_config.storage_class.clone();
    current_meta.remote_tier = Some(ObjectRemoteTierStatus {
        tier: tier_config.name.clone(),
        storage_class: tier_config.storage_class.clone(),
        transitioned_at: Utc::now(),
    });
    current_meta.restore = None;
    persist_remote_tier_object(state, &tier_config, &current_meta, &payload).await?;
    remove_current_hot_object_payload(state, bucket, key)
        .await
        .map_err(|_| "删除本地热点对象失败 / failed to remove local hot object".to_string())?;
    if previous_remote.is_some() {
        let mut previous_meta = current_meta.clone();
        previous_meta.remote_tier = previous_remote;
        remove_remote_tier_payload_for_meta(state, &previous_meta)
            .await
            .map_err(|_| {
                "删除旧远端层对象失败 / failed to remove previous remote tier object".to_string()
            })?;
    }
    persist_current_object_meta(state, current_meta.clone())
        .await
        .map_err(|_| {
            "持久化转层元数据失败 / failed to persist transitioned object metadata".to_string()
        })?;
    Ok(Some(current_meta))
}

pub(crate) async fn transition_noncurrent_object_version_for_lifecycle(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: &str,
    tier_name: &str,
) -> Result<bool, String> {
    let archived_meta = read_archived_object_meta(state, bucket, key, version_id)
        .await
        .map_err(|_| {
            "读取非当前版本元数据失败 / failed to read noncurrent version metadata".to_string()
        })?;
    let Some(mut archived_meta) = archived_meta else {
        return Ok(false);
    };
    if archived_meta
        .remote_tier
        .as_ref()
        .map(|item| normalize_remote_tier_name(&item.tier) == normalize_remote_tier_name(tier_name))
        .unwrap_or(false)
    {
        return Ok(true);
    }
    let tier_config = lookup_remote_tier_config(state, tier_name).await?;
    let payload = read_archived_object_payload_by_meta(state, &archived_meta)
        .await
        .map_err(|_| {
            "读取非当前版本内容失败 / failed to read noncurrent version payload".to_string()
        })?;
    let Some(payload) = payload else {
        return Ok(false);
    };
    let previous_remote = archived_meta.remote_tier.clone();
    archived_meta.storage_class = tier_config.storage_class.clone();
    archived_meta.remote_tier = Some(ObjectRemoteTierStatus {
        tier: tier_config.name.clone(),
        storage_class: tier_config.storage_class.clone(),
        transitioned_at: Utc::now(),
    });
    archived_meta.restore = None;
    persist_remote_tier_object(state, &tier_config, &archived_meta, &payload).await?;
    let bucket_root = bucket_path(state, bucket)
        .map_err(|_| "存储桶名称无效 / invalid bucket name".to_string())?;
    let payload_path = object_version_payload_path(&bucket_root, key, version_id)
        .map_err(|_| "对象版本路径无效 / invalid object version path".to_string())?;
    match tokio::fs::remove_file(&payload_path).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "删除本地非当前版本失败 / failed to remove local noncurrent version: {err}"
            ));
        }
    }
    if previous_remote.is_some() {
        let mut previous_meta = archived_meta.clone();
        previous_meta.remote_tier = previous_remote;
        remove_remote_tier_payload_for_meta(state, &previous_meta)
            .await
            .map_err(|_| {
                "删除旧远端层对象失败 / failed to remove previous remote tier object".to_string()
            })?;
    }
    persist_archived_object_meta(state, &archived_meta)
        .await
        .map_err(|_| {
            "持久化转层非当前版本元数据失败 / failed to persist transitioned noncurrent metadata"
                .to_string()
        })?;
    Ok(true)
}

pub(crate) async fn sync_site_replication_from_rules(state: &Arc<AppState>) {
    let rules = state.replications.read().await.clone();
    let backlog = state.replication_backlog.read().await.clone();
    let mut managed_bucket_sets: HashMap<String, HashSet<String>> = HashMap::new();
    let mut max_lag_seconds: HashMap<String, u64> = HashMap::new();
    let mut pending_resync_items: HashMap<String, u64> = HashMap::new();
    let mut endpoints_by_site: HashMap<String, String> = HashMap::new();

    for rule in rules {
        managed_bucket_sets
            .entry(rule.target_site.clone())
            .or_default()
            .insert(rule.source_bucket.clone());
        max_lag_seconds
            .entry(rule.target_site.clone())
            .and_modify(|current| {
                *current = (*current).max(rule.lag_seconds);
            })
            .or_insert(rule.lag_seconds);
        if let Some(endpoint) = rule.endpoint.as_ref() {
            endpoints_by_site
                .entry(rule.target_site)
                .or_insert_with(|| endpoint.clone());
        }
    }

    for item in backlog
        .iter()
        .filter(|item| item.status != "done" && item.status != "completed")
    {
        pending_resync_items
            .entry(item.target_site.clone())
            .and_modify(|current| *current += 1)
            .or_insert(1);
        max_lag_seconds
            .entry(item.target_site.clone())
            .and_modify(|current| *current = (*current).max(1))
            .or_insert(1);
    }

    let now = Utc::now();
    let mut sites = state.site_replications.write().await;
    let known_sites = sites
        .iter()
        .map(|site| site.site_id.clone())
        .collect::<HashSet<_>>();
    for site_id in managed_bucket_sets.keys() {
        if known_sites.contains(site_id) {
            continue;
        }
        let lag = max_lag_seconds.get(site_id).copied().unwrap_or(0);
        sites.push(SiteReplicationStatus {
            site_id: site_id.clone(),
            endpoint: endpoints_by_site
                .get(site_id)
                .cloned()
                .unwrap_or_else(|| format!("https://{site_id}.example.internal")),
            role: "secondary".to_string(),
            preferred_primary: false,
            state: "healthy".to_string(),
            lag_seconds: lag,
            managed_buckets: managed_bucket_sets
                .get(site_id)
                .map(|items| items.len())
                .unwrap_or(0) as u32,
            last_sync_at: now - Duration::seconds(lag as i64),
            bootstrap_state: "discovered".to_string(),
            joined_at: None,
            last_resync_at: None,
            last_reconcile_at: None,
            pending_resync_items: pending_resync_items.get(site_id).copied().unwrap_or(0),
            drifted_buckets: 0,
            topology_version: 1,
            last_error: None,
        });
    }

    for site in sites.iter_mut() {
        let managed = managed_bucket_sets
            .get(&site.site_id)
            .map(|items| items.len())
            .unwrap_or(0) as u32;
        site.managed_buckets = managed;
        site.pending_resync_items = pending_resync_items
            .get(&site.site_id)
            .copied()
            .unwrap_or(0);
        if let Some(endpoint) = endpoints_by_site.get(&site.site_id) {
            site.endpoint = endpoint.clone();
        }
        if site.role == "primary" {
            site.lag_seconds = 0;
            site.last_sync_at = now;
            site.pending_resync_items = 0;
            site.last_error = None;
            continue;
        }
        site.lag_seconds = max_lag_seconds.get(&site.site_id).copied().unwrap_or(0);
        if site.state != "offline" {
            site.state = if site.pending_resync_items > 0 {
                "resyncing".to_string()
            } else {
                "healthy".to_string()
            };
        }
        if managed == 0 {
            site.last_error = None;
        }
        site.last_sync_at = now - Duration::seconds(site.lag_seconds as i64);
    }
}

pub(crate) fn valid_site_replication_id(site_id: &str) -> bool {
    let trimmed = site_id.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 128
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) fn normalize_site_replication_endpoint(endpoint: &str) -> Result<String, AppError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(AppError::bad_request(
            "站点 endpoint 不能为空 / site endpoint cannot be empty",
        ));
    }
    let normalized = endpoint.trim_end_matches('/').to_string();
    let lower = normalized.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return Err(AppError::bad_request(
            "站点 endpoint 必须是 HTTP(S) 地址 / site endpoint must be an HTTP(S) URL",
        ));
    }
    Ok(normalized)
}

pub(crate) async fn enqueue_site_governance_job(
    state: &Arc<AppState>,
    kind: &str,
    site_id: String,
    operator: &str,
    reason: String,
    extra_payload: Value,
) -> Result<JobStatus, AppError> {
    let now = Utc::now();
    let dedupe_key = format!("{kind}:{site_id}");
    let mut payload = serde_json::Map::new();
    payload.insert("operator".to_string(), json!(operator));
    payload.insert("reason".to_string(), json!(reason));
    payload.insert("dedupe_key".to_string(), json!(dedupe_key));
    if let Value::Object(extra) = extra_payload {
        for (key, value) in extra {
            payload.insert(key, value);
        }
    }
    let job = JobStatus {
        id: format!("job-{kind}-{}", Uuid::new_v4().simple()),
        kind: kind.to_string(),
        status: "pending".to_string(),
        priority: 0,
        bucket: None,
        object_key: None,
        site_id: Some(site_id.clone()),
        idempotency_key: format!("{kind}:{site_id}:{}", now.timestamp_millis()),
        attempt: 0,
        lease_owner: None,
        lease_until: None,
        checkpoint: None,
        last_error: None,
        payload: Value::Object(payload),
        progress: 0.0,
        created_at: now,
        updated_at: now,
        key: None,
        version_id: None,
        target: None,
        affected_disks: vec![],
        missing_shards: 0,
        corrupted_shards: 0,
        started_at: None,
        finished_at: None,
        attempts: 0,
        max_attempts: 0,
        next_attempt_at: None,
        error: None,
        dedupe_key: Some(dedupe_key),
        source: Some("manual".to_string()),
        details: Value::Null,
    };
    state
        .enqueue_switch_job(job)
        .await
        .map_err(AppError::bad_request)
}

pub(crate) async fn bootstrap_site_replication(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<SiteReplicationBootstrapRequest>,
) -> Result<Json<ApiEnvelope<JobStatus>>, AppError> {
    auth.require(Permission::ReplicationWrite)?;
    ensure_confirm_header(&headers)?;
    let site_id = body.site_id.trim().to_string();
    if !valid_site_replication_id(&site_id) {
        return Err(AppError::bad_request(
            "复制站点 ID 无效 / invalid replication site id",
        ));
    }
    let endpoint = normalize_site_replication_endpoint(&body.endpoint)?;
    let reason = body.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    if state
        .site_replications
        .read()
        .await
        .iter()
        .any(|site| site.site_id == site_id)
    {
        return Err(AppError::bad_request(
            "复制站点已存在 / replication site already exists",
        ));
    }

    let job = enqueue_site_governance_job(
        &state,
        "site-bootstrap",
        site_id.clone(),
        &auth.username,
        reason.clone(),
        json!({
            "endpoint": endpoint,
            "preferred_primary": body.preferred_primary,
        }),
    )
    .await?;
    state
        .append_audit(
            &auth.username,
            "replication.site.bootstrap.enqueue",
            &format!("replication/site/{site_id}"),
            "success",
            Some(reason),
            json!({
                "job_id": job.id,
                "site_id": site_id,
            }),
        )
        .await;
    Ok(wrap(job))
}

pub(crate) async fn join_site_replication(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SiteReplicationJoinRequest>,
) -> Result<Json<ApiEnvelope<JobStatus>>, AppError> {
    auth.require(Permission::ReplicationWrite)?;
    ensure_confirm_header(&headers)?;
    if !valid_site_replication_id(&site_id) {
        return Err(AppError::bad_request(
            "复制站点 ID 无效 / invalid replication site id",
        ));
    }
    let reason = body.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    let endpoint = match body.endpoint.as_deref() {
        Some(value) => Some(normalize_site_replication_endpoint(value)?),
        None => None,
    };
    let job = enqueue_site_governance_job(
        &state,
        "site-join",
        site_id.clone(),
        &auth.username,
        reason.clone(),
        json!({
            "endpoint": endpoint,
        }),
    )
    .await?;
    state
        .append_audit(
            &auth.username,
            "replication.site.join.enqueue",
            &format!("replication/site/{site_id}"),
            "success",
            Some(reason),
            json!({
                "job_id": job.id,
                "site_id": site_id,
            }),
        )
        .await;
    Ok(wrap(job))
}

pub(crate) async fn resync_site_replication(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<JobStatus>>, AppError> {
    auth.require(Permission::ReplicationWrite)?;
    ensure_confirm_header(&headers)?;
    sync_site_replication_from_rules(&state).await;
    let reason = body.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    if !state
        .site_replications
        .read()
        .await
        .iter()
        .any(|site| site.site_id == site_id)
    {
        return Err(AppError::not_found(
            "复制站点不存在 / replication site not found",
        ));
    }
    let job = enqueue_site_governance_job(
        &state,
        "site-resync",
        site_id.clone(),
        &auth.username,
        reason.clone(),
        Value::Null,
    )
    .await?;
    state
        .append_audit(
            &auth.username,
            "replication.site.resync.enqueue",
            &format!("replication/site/{site_id}"),
            "success",
            Some(reason),
            json!({
                "job_id": job.id,
                "site_id": site_id,
            }),
        )
        .await;
    Ok(wrap(job))
}

pub(crate) async fn reconcile_site_replication(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<JobStatus>>, AppError> {
    auth.require(Permission::ReplicationWrite)?;
    ensure_confirm_header(&headers)?;
    sync_site_replication_from_rules(&state).await;
    let reason = body.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    if !state
        .site_replications
        .read()
        .await
        .iter()
        .any(|site| site.site_id == site_id)
    {
        return Err(AppError::not_found(
            "复制站点不存在 / replication site not found",
        ));
    }
    let drift_report =
        build_site_replication_drift_report(&state, &site_id, "dry-run-reconcile").await?;
    if !drift_report.guardrails.safe_to_reconcile {
        return Err(AppError::bad_request(
            "复制站点收敛预检失败，请先查看 drift 预检阻塞原因 / replication site reconcile preflight failed, inspect drift guardrail blocking reasons first",
        ));
    }
    let job = enqueue_site_governance_job(
        &state,
        "site-reconcile",
        site_id.clone(),
        &auth.username,
        reason.clone(),
        Value::Null,
    )
    .await?;
    state
        .append_audit(
            &auth.username,
            "replication.site.reconcile.enqueue",
            &format!("replication/site/{site_id}"),
            "success",
            Some(reason),
            json!({
                "job_id": job.id,
                "site_id": site_id,
            }),
        )
        .await;
    Ok(wrap(job))
}

pub(crate) async fn preview_site_replication_reconcile(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(site_id): Path<String>,
) -> Result<Json<ApiEnvelope<SiteReplicationDriftReport>>, AppError> {
    auth.require(Permission::ReplicationRead)?;
    Ok(wrap(
        build_site_replication_drift_report(&state, &site_id, "dry-run-reconcile").await?,
    ))
}

pub(crate) async fn get_site_replication_drift(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(site_id): Path<String>,
) -> Result<Json<ApiEnvelope<SiteReplicationDriftReport>>, AppError> {
    auth.require(Permission::ReplicationRead)?;
    Ok(wrap(
        build_site_replication_drift_report(&state, &site_id, "inspect").await?,
    ))
}

pub(crate) async fn list_site_replications(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<SiteReplicationStatus>>>, AppError> {
    auth.require(Permission::ReplicationRead)?;
    sync_site_replication_from_rules(&state).await;
    let mut sites = state.site_replications.read().await.clone();
    sites.sort_by(|left, right| {
        let left_order = if left.role == "primary" { 0 } else { 1 };
        let right_order = if right.role == "primary" { 0 } else { 1 };
        left_order
            .cmp(&right_order)
            .then_with(|| left.site_id.cmp(&right.site_id))
    });
    Ok(wrap(sites))
}

pub(crate) async fn failover_site_replication(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<JobStatus>>, AppError> {
    auth.require(Permission::ReplicationWrite)?;
    ensure_confirm_header(&headers)?;
    sync_site_replication_from_rules(&state).await;
    let reason = body.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }

    {
        let sites = state.site_replications.read().await;
        let target = sites
            .iter()
            .find(|site| site.site_id == site_id)
            .ok_or_else(|| AppError::not_found("复制站点不存在 / replication site not found"))?;
        if target.role == "primary" {
            return Err(AppError::bad_request(
                "目标站点已是主站 / selected site is already primary",
            ));
        }
    }

    let now = Utc::now();
    let checkpoint = state
        .replication_checkpoints
        .read()
        .await
        .get(&site_id)
        .copied();
    let job = JobStatus {
        id: format!("job-failover-{}", Uuid::new_v4().simple()),
        kind: "failover".to_string(),
        status: "pending".to_string(),
        priority: 0,
        bucket: None,
        object_key: None,
        site_id: Some(site_id.clone()),
        idempotency_key: format!("failover:{}:{}", site_id, now.timestamp_millis()),
        attempt: 0,
        lease_owner: None,
        lease_until: None,
        checkpoint,
        last_error: None,
        payload: json!({
            "operator": auth.username,
            "reason": reason,
            "dedupe_key": format!("failover:{site_id}"),
        }),
        progress: 0.0,
        created_at: now,
        updated_at: now,
        key: None,
        version_id: None,
        target: None,
        affected_disks: vec![],
        missing_shards: 0,
        corrupted_shards: 0,
        started_at: None,
        finished_at: None,
        attempts: 0,
        max_attempts: 0,
        next_attempt_at: None,
        error: None,
        dedupe_key: Some(format!("failover:{site_id}")),
        source: Some("manual".to_string()),
        details: Value::Null,
    };
    let job = state
        .enqueue_switch_job(job)
        .await
        .map_err(AppError::bad_request)?;

    state
        .append_audit(
            &auth.username,
            "replication.site.failover.enqueue",
            &format!("replication/site/{site_id}"),
            "success",
            Some(reason.clone()),
            json!({
                "job_id": job.id,
                "to": site_id,
            }),
        )
        .await;
    state
        .push_event(
            "replication.site.failover.enqueued",
            "replication-site-manager",
            json!({
                "to": site_id,
                "operator": auth.username,
                "job_id": job.id,
            }),
        )
        .await;
    Ok(wrap(job))
}

pub(crate) async fn failback_site_replication(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<JobStatus>>, AppError> {
    auth.require(Permission::ReplicationWrite)?;
    ensure_confirm_header(&headers)?;
    sync_site_replication_from_rules(&state).await;
    let reason = body.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }

    {
        let sites = state.site_replications.read().await;
        let target = sites
            .iter()
            .find(|site| site.site_id == site_id)
            .cloned()
            .ok_or_else(|| AppError::not_found("复制站点不存在 / replication site not found"))?;
        if !target.preferred_primary {
            return Err(AppError::bad_request(
                "failback 目标必须是首选主站 / failback target must be preferred primary site",
            ));
        }
        let previous_primary = sites
            .iter()
            .find(|site| site.role == "primary")
            .map(|site| site.site_id.clone())
            .unwrap_or_else(|| "unknown".to_string());
        if previous_primary == site_id {
            return Err(AppError::bad_request(
                "目标站点已是主站 / selected site is already primary",
            ));
        }
    }

    let now = Utc::now();
    let checkpoint = state
        .replication_checkpoints
        .read()
        .await
        .get(&site_id)
        .copied();
    let job = JobStatus {
        id: format!("job-failback-{}", Uuid::new_v4().simple()),
        kind: "failback".to_string(),
        status: "pending".to_string(),
        priority: 0,
        bucket: None,
        object_key: None,
        site_id: Some(site_id.clone()),
        idempotency_key: format!("failback:{}:{}", site_id, now.timestamp_millis()),
        attempt: 0,
        lease_owner: None,
        lease_until: None,
        checkpoint,
        last_error: None,
        payload: json!({
            "operator": auth.username,
            "reason": reason,
            "dedupe_key": format!("failback:{site_id}"),
        }),
        progress: 0.0,
        created_at: now,
        updated_at: now,
        key: None,
        version_id: None,
        target: None,
        affected_disks: vec![],
        missing_shards: 0,
        corrupted_shards: 0,
        started_at: None,
        finished_at: None,
        attempts: 0,
        max_attempts: 0,
        next_attempt_at: None,
        error: None,
        dedupe_key: Some(format!("failback:{site_id}")),
        source: Some("manual".to_string()),
        details: Value::Null,
    };
    let job = state
        .enqueue_switch_job(job)
        .await
        .map_err(AppError::bad_request)?;
    state
        .append_audit(
            &auth.username,
            "replication.site.failback.enqueue",
            &format!("replication/site/{site_id}"),
            "success",
            Some(reason.clone()),
            json!({
                "to": site_id,
                "job_id": job.id,
            }),
        )
        .await;
    state
        .push_event(
            "replication.site.failback.enqueued",
            "replication-site-manager",
            json!({
                "to": site_id,
                "operator": auth.username,
                "job_id": job.id,
            }),
        )
        .await;
    Ok(wrap(job))
}

pub(crate) async fn get_security(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<rustio_core::SecurityConfig>>, AppError> {
    auth.require(Permission::SecurityRead)?;
    Ok(wrap(state.security.read().await.clone()))
}

pub(crate) async fn get_kms_status(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<SystemKmsMetricsSummary>>, AppError> {
    auth.require(Permission::SecurityRead)?;
    let security = state.security.read().await.clone();
    Ok(wrap(build_system_kms_metrics(&security)))
}

pub(crate) async fn update_security(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<SecurityUpdate>,
) -> Result<Json<ApiEnvelope<rustio_core::SecurityConfig>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    let mut security = state.security.write().await;
    let previous_snapshot = security.clone();
    if let Some(enabled) = body.oidc_enabled {
        security.oidc_enabled = enabled;
    }
    if let Some(enabled) = body.ldap_enabled {
        security.ldap_enabled = enabled;
    }
    if let Some(value) = body.oidc_discovery_url {
        security.oidc_discovery_url = value;
    }
    if let Some(value) = body.oidc_issuer {
        security.oidc_issuer = value;
    }
    if let Some(value) = body.oidc_client_id {
        security.oidc_client_id = value;
    }
    if let Some(value) = body.oidc_jwks_url {
        security.oidc_jwks_url = value;
    }
    if let Some(value) = body.oidc_allowed_algs {
        security.oidc_allowed_algs = value;
    }
    if let Some(value) = body.oidc_username_claim {
        security.oidc_username_claim = value;
    }
    if let Some(value) = body.oidc_groups_claim {
        security.oidc_groups_claim = value;
    }
    if let Some(value) = body.oidc_role_claim {
        security.oidc_role_claim = value;
    }
    if let Some(value) = body.oidc_default_role {
        security.oidc_default_role = value;
    }
    if let Some(value) = body.oidc_group_role_map {
        security.oidc_group_role_map = value;
    }
    if let Some(value) = body.ldap_url {
        security.ldap_url = value;
    }
    if let Some(value) = body.ldap_bind_dn {
        security.ldap_bind_dn = value;
    }
    if let Some(value) = body.ldap_user_base_dn {
        security.ldap_user_base_dn = value;
    }
    if let Some(value) = body.ldap_user_filter {
        security.ldap_user_filter = value;
    }
    if let Some(value) = body.ldap_group_base_dn {
        security.ldap_group_base_dn = value;
    }
    if let Some(value) = body.ldap_group_filter {
        security.ldap_group_filter = value;
    }
    if let Some(value) = body.ldap_group_attribute {
        security.ldap_group_attribute = value;
    }
    if let Some(value) = body.ldap_group_name_attribute {
        security.ldap_group_name_attribute = value;
    }
    if let Some(value) = body.ldap_default_role {
        security.ldap_default_role = value;
    }
    if let Some(value) = body.ldap_group_role_map {
        security.ldap_group_role_map = value;
    }
    if let Some(endpoint) = body.kms_endpoint {
        security.kms_endpoint = endpoint;
    }
    if let Some(mode) = body.sse_mode {
        security.sse_mode = mode;
    }

    let snapshot = security.clone();
    drop(security);
    if snapshot == previous_snapshot {
        return Ok(wrap(snapshot));
    }
    AppState::persist_security_config_snapshot(&state.data_dir, &snapshot).map_err(|err| {
        AppError::internal(format!(
            "持久化安全配置失败 / failed to persist security config: {err}"
        ))
    })?;
    let cluster_payload = current_cluster_config_payload(&state).await;
    let cluster_snapshot = ClusterConfigSnapshot {
        version: format!("cfg-{}", Uuid::new_v4().simple()),
        updated_at: Utc::now(),
        updated_by: auth.username.clone(),
        source: "security-api".to_string(),
        reason: None,
        etag: cluster_config_etag(&cluster_payload)?,
        payload: cluster_payload,
    };
    let previous_version =
        append_cluster_config_history_snapshot(&state, cluster_snapshot.clone()).await?;
    state
        .sync_metadata_raft("security-config-update")
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "元数据 Raft 提交失败 / metadata raft commit failed: {err}"
            ))
        })?;
    state
        .append_audit(
            &auth.username,
            "security.config.update",
            "security/config",
            "success",
            None,
            json!({
                "oidc": snapshot.oidc_enabled,
                "ldap": snapshot.ldap_enabled,
                "oidc_discovery_url": snapshot.oidc_discovery_url,
                "oidc_issuer": snapshot.oidc_issuer,
                "oidc_client_id": snapshot.oidc_client_id,
                "oidc_jwks_url": snapshot.oidc_jwks_url,
                "oidc_allowed_algs": snapshot.oidc_allowed_algs,
                "oidc_username_claim": snapshot.oidc_username_claim,
                "oidc_groups_claim": snapshot.oidc_groups_claim,
                "oidc_role_claim": snapshot.oidc_role_claim,
                "oidc_default_role": snapshot.oidc_default_role,
                "oidc_group_role_map": snapshot.oidc_group_role_map,
                "ldap_url": snapshot.ldap_url,
                "ldap_bind_dn": snapshot.ldap_bind_dn,
                "ldap_user_base_dn": snapshot.ldap_user_base_dn,
                "ldap_user_filter": snapshot.ldap_user_filter,
                "ldap_group_base_dn": snapshot.ldap_group_base_dn,
                "ldap_group_filter": snapshot.ldap_group_filter,
                "ldap_group_attribute": snapshot.ldap_group_attribute,
                "ldap_group_name_attribute": snapshot.ldap_group_name_attribute,
                "ldap_default_role": snapshot.ldap_default_role,
                "ldap_group_role_map": snapshot.ldap_group_role_map,
                "kms_endpoint": snapshot.kms_endpoint,
                "sse_mode": snapshot.sse_mode,
                "cluster_config_version": cluster_snapshot.version,
                "previous_cluster_config_version": previous_version,
            }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn rotate_kms_keys(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<KmsRotationResult>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    ensure_confirm_header(&headers)?;
    let result = perform_kms_rotation(&state, &auth, body.reason, false, None).await?;
    Ok(wrap(result))
}

pub(crate) async fn retry_kms_rotation(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<KmsRotationResult>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    ensure_confirm_header(&headers)?;
    let result = perform_kms_rotation(&state, &auth, body.reason, true, None).await?;
    Ok(wrap(result))
}

pub(crate) fn kms_rotation_action(retry_only_failed: bool) -> &'static str {
    if retry_only_failed {
        "security.kms.rotate.retry"
    } else {
        "security.kms.rotate"
    }
}

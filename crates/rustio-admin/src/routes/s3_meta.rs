//! S3 对象元数据归档与读取

use super::*;

pub(crate) async fn archive_object_version(
    state: &AppState,
    bucket: &str,
    key: &str,
    meta: &S3ObjectMeta,
) -> Result<(), Response> {
    let mut archived_meta = meta.clone();
    archived_meta.restore = None;
    if !valid_version_id(&archived_meta.version_id) {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidVersionId",
            "The specified version id is not valid",
            key,
        ));
    }

    let bucket_root = bucket_path(state, bucket)?;
    let version_dir = object_versions_dir(&bucket_root, key);
    tokio::fs::create_dir_all(&version_dir)
        .await
        .map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create object version directory: {err}"),
                key,
            )
        })?;

    let archived_meta_path =
        object_version_meta_path(&bucket_root, key, &archived_meta.version_id)?;
    if !tokio::fs::try_exists(&archived_meta_path)
        .await
        .unwrap_or(false)
    {
        let bytes = serde_json::to_vec_pretty(&archived_meta).map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to serialize archived object metadata: {err}"),
                key,
            )
        })?;
        tokio::fs::write(&archived_meta_path, bytes)
            .await
            .map_err(|err| {
                s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to persist archived object metadata: {err}"),
                    key,
                )
            })?;
    }

    if !archived_meta.delete_marker {
        if archived_meta.remote_tier.is_some() {
            return Ok(());
        }
        let payload_path =
            object_version_payload_path(&bucket_root, key, &archived_meta.version_id)?;
        if !tokio::fs::try_exists(&payload_path).await.unwrap_or(false) {
            if let Some(payload) =
                read_current_object_payload(state, bucket, key, Some(&archived_meta), None).await?
            {
                tokio::fs::write(&payload_path, payload)
                    .await
                    .map_err(|err| {
                        s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &format!("Failed to archive object payload: {err}"),
                            key,
                        )
                    })?;
            }
        }
    }

    Ok(())
}

pub(crate) async fn read_archived_object_meta(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<Option<S3ObjectMeta>, Response> {
    let bucket_root = bucket_path(state, bucket)?;
    let meta_path = object_version_meta_path(&bucket_root, key, version_id)?;
    let bytes = match tokio::fs::read(&meta_path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to read archived object metadata: {err}"),
                key,
            ));
        }
    };
    let meta = serde_json::from_slice::<S3ObjectMeta>(&bytes).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to decode archived object metadata: {err}"),
            key,
        )
    })?;
    if meta.bucket != bucket || meta.key != key {
        return Ok(None);
    }
    Ok(Some(meta))
}

pub(crate) async fn read_archived_object_payload(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<Option<Vec<u8>>, Response> {
    let archived_meta = read_archived_object_meta(state, bucket, key, version_id).await?;
    let Some(meta) = archived_meta else {
        return Ok(None);
    };
    read_archived_object_payload_by_meta(state, &meta).await
}

pub(crate) async fn read_archived_object_payload_by_meta(
    state: &AppState,
    meta: &S3ObjectMeta,
) -> Result<Option<Vec<u8>>, Response> {
    if object_restore_is_active(meta) {
        if let Some(bytes) = read_archived_local_object_payload_by_meta(state, meta).await? {
            return Ok(Some(bytes));
        }
    }
    if let Some(bytes) = read_remote_tier_payload_for_meta(state, meta).await? {
        return Ok(Some(bytes));
    }
    read_archived_local_object_payload_by_meta(state, meta).await
}

pub(crate) async fn read_archived_local_object_payload_by_meta(
    state: &AppState,
    meta: &S3ObjectMeta,
) -> Result<Option<Vec<u8>>, Response> {
    let bucket_root = bucket_path(state, &meta.bucket)?;
    let payload_path = object_version_payload_path(&bucket_root, &meta.key, &meta.version_id)?;
    let bytes = match tokio::fs::read(&payload_path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to read archived object payload: {err}"),
                &meta.key,
            ));
        }
    };
    Ok(Some(bytes))
}

pub(crate) async fn persist_restored_archived_object_payload(
    state: &AppState,
    meta: &S3ObjectMeta,
    payload: &[u8],
) -> Result<(), Response> {
    let bucket_root = bucket_path(state, &meta.bucket)?;
    let version_dir = object_versions_dir(&bucket_root, &meta.key);
    tokio::fs::create_dir_all(&version_dir)
        .await
        .map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create archived restore directory: {err}"),
                &meta.key,
            )
        })?;
    let payload_path = object_version_payload_path(&bucket_root, &meta.key, &meta.version_id)?;
    tokio::fs::write(&payload_path, payload)
        .await
        .map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to restore archived object payload: {err}"),
                &meta.key,
            )
        })?;
    Ok(())
}

pub(crate) async fn admin_prewarm_remote_archived_object(
    state: &AppState,
    meta: &S3ObjectMeta,
    is_current: bool,
    restore_days: u32,
    requested_at: DateTime<Utc>,
) -> Result<bool, String> {
    if meta.remote_tier.is_none() {
        return Ok(false);
    }
    if object_restore_is_active(meta) {
        return Ok(false);
    }
    let payload = read_remote_tier_payload_for_meta(state, meta)
        .await
        .map_err(|_| {
            bilingual_text(
                "读取远端归档对象失败",
                "failed to read remote archived object payload",
            )
        })?
        .ok_or_else(|| {
            bilingual_text(
                "远端归档对象不存在",
                "remote archived object payload does not exist",
            )
        })?;

    if is_current {
        persist_restored_current_object_payload(state, meta, &payload)
            .await
            .map_err(|_| {
                bilingual_text(
                    "回温当前对象失败",
                    "failed to persist restored current object payload",
                )
            })?;
        let mut next = meta.clone();
        next.restore = Some(ObjectRestoreStatus {
            ongoing_request: false,
            requested_at: Some(requested_at),
            expiry_at: Some(requested_at + Duration::days(restore_days as i64)),
        });
        persist_current_object_meta(state, next)
            .await
            .map_err(|_| {
                bilingual_text(
                    "写入当前对象回温元数据失败",
                    "failed to persist current object restore metadata",
                )
            })?;
    } else {
        persist_restored_archived_object_payload(state, meta, &payload)
            .await
            .map_err(|_| {
                bilingual_text(
                    "回温历史版本失败",
                    "failed to persist restored archived object payload",
                )
            })?;
        let mut next = meta.clone();
        next.restore = Some(ObjectRestoreStatus {
            ongoing_request: false,
            requested_at: Some(requested_at),
            expiry_at: Some(requested_at + Duration::days(restore_days as i64)),
        });
        persist_archived_object_meta(state, &next)
            .await
            .map_err(|_| {
                bilingual_text(
                    "写入历史版本回温元数据失败",
                    "failed to persist archived object restore metadata",
                )
            })?;
    }
    Ok(true)
}

pub(crate) async fn read_archived_versions_for_key(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<Vec<S3ObjectMeta>, Response> {
    let bucket_root = bucket_path(state, bucket)?;
    let version_dir = object_versions_dir(&bucket_root, key);
    let mut output = Vec::new();

    let mut dir = match tokio::fs::read_dir(&version_dir).await {
        Ok(reader) => reader,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(output),
        Err(err) => {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to enumerate archived object versions: {err}"),
                key,
            ));
        }
    };

    while let Some(entry) = dir.next_entry().await.map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to read archived object version entry: {err}"),
            key,
        )
    })? {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }

        let bytes = tokio::fs::read(&path).await.map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to read archived object version metadata: {err}"),
                key,
            )
        })?;
        let meta = serde_json::from_slice::<S3ObjectMeta>(&bytes).map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to parse archived object version metadata: {err}"),
                key,
            )
        })?;
        if meta.bucket == bucket && meta.key == key {
            output.push(meta);
        }
    }

    output.sort_by_key(|entry| std::cmp::Reverse(entry.created_at));
    Ok(output)
}

pub(crate) async fn remove_archived_object_version(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<(), Response> {
    remove_archived_object_version_with_remote(state, bucket, key, version_id, true).await
}

pub(crate) async fn remove_archived_object_version_with_remote(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: &str,
    remove_remote_payload: bool,
) -> Result<(), Response> {
    let archived_meta = read_archived_object_meta(state, bucket, key, version_id).await?;
    let bucket_root = bucket_path(state, bucket)?;
    let meta_path = object_version_meta_path(&bucket_root, key, version_id)?;
    let payload_path = object_version_payload_path(&bucket_root, key, version_id)?;

    match tokio::fs::remove_file(&meta_path).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to remove archived version metadata: {err}"),
                key,
            ));
        }
    }

    match tokio::fs::remove_file(&payload_path).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to remove archived version payload: {err}"),
                key,
            ));
        }
    }

    if remove_remote_payload {
        if let Some(meta) = archived_meta.as_ref() {
            remove_remote_tier_payload_for_meta(state, meta).await?;
        }
    }

    if let Some(parent) = meta_path.parent() {
        let root = bucket_root.join(".rustio_versions");
        let _ = remove_empty_dirs_until(parent, &root);
    }
    Ok(())
}

pub(crate) async fn resolve_object_version_meta(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: &str,
    current_meta: Option<S3ObjectMeta>,
) -> Result<Option<(S3ObjectMeta, bool)>, Response> {
    if let Some(meta) = current_meta {
        if meta.version_id == version_id {
            return Ok(Some((meta, true)));
        }
    }

    let archived = read_archived_object_meta(state, bucket, key, version_id).await?;
    Ok(archived.map(|meta| (meta, false)))
}

pub(crate) async fn list_object_versions(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<Vec<S3ObjectMeta>, Response> {
    let mut output = Vec::new();
    if let Some(current) = read_current_object_meta(state, bucket, key).await? {
        output.push(current);
    }

    let archived = read_archived_versions_for_key(state, bucket, key).await?;
    for item in archived {
        if output
            .iter()
            .any(|existing| existing.version_id == item.version_id)
        {
            continue;
        }
        output.push(item);
    }

    if output.is_empty() {
        let bucket_root = bucket_path(state, bucket)?;
        let target = object_payload_path(&bucket_root, key)?;
        if let Ok(metadata) = tokio::fs::metadata(&target).await {
            let modified = metadata.modified().ok();
            let modified_at = modified.map(DateTime::<Utc>::from).unwrap_or_else(Utc::now);
            let modified_secs = modified
                .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|value| value.as_secs())
                .unwrap_or(0);
            output.push(S3ObjectMeta {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: "null".to_string(),
                size: metadata.len(),
                etag: format!("{:x}{:x}", metadata.len(), modified_secs),
                created_at: modified_at,
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
                content_type: None,
                cache_control: None,
                content_disposition: None,
                content_encoding: None,
                content_language: None,
                expires: None,
                website_redirect_location: None,
                checksum: None,
            });
        }
    }

    output.sort_by_key(|entry| std::cmp::Reverse(entry.created_at));
    Ok(output)
}

pub(crate) async fn promote_latest_archived_version(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<Option<S3ObjectMeta>, Response> {
    let mut archived = read_archived_versions_for_key(state, bucket, key).await?;
    archived.sort_by_key(|entry| std::cmp::Reverse(entry.created_at));
    let Some(mut next) = archived.first().cloned() else {
        return Ok(None);
    };
    next.restore = None;

    let bucket_root = bucket_path(state, bucket)?;
    if next.delete_marker {
        let current_path = object_payload_path(&bucket_root, key)?;
        let _ = tokio::fs::remove_file(current_path).await;
    } else if next.remote_tier.is_none() {
        let payload = read_archived_object_payload_by_meta(state, &next).await?;
        let payload = payload.ok_or_else(|| {
            s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchVersion",
                "The specified archived object version payload does not exist",
                key,
            )
        })?;
        let target = object_payload_path(&bucket_root, key)?;
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|err| {
                s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to recreate object directory: {err}"),
                    key,
                )
            })?;
        }
        tokio::fs::write(&target, &payload).await.map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to restore archived object payload: {err}"),
                key,
            )
        })?;
        write_ec_object(state, bucket, key, &payload, &mut next, None).await?;
    } else {
        let target = object_payload_path(&bucket_root, key)?;
        let _ = tokio::fs::remove_file(target).await;
        remove_ec_object(state, bucket, key).await?;
    }

    persist_current_object_meta(state, next.clone()).await?;
    remove_archived_object_version_with_remote(state, bucket, key, &next.version_id, false).await?;
    Ok(Some(next))
}

pub(crate) async fn delete_object_version(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: &str,
    bypass_governance: bool,
) -> Result<bool, Response> {
    let current_meta = read_current_object_meta(state, bucket, key).await?;

    if let Some(meta) = current_meta.clone() {
        if meta.version_id == version_id {
            if meta.legal_hold {
                return Err(s3_error(
                    StatusCode::FORBIDDEN,
                    "AccessDenied",
                    "Object is under legal hold",
                    key,
                ));
            }
            // GOVERNANCE 模式 + bypass 头可绕过;COMPLIANCE 不可。
            let governance_bypassed =
                meta.retention_mode.as_deref() == Some("GOVERNANCE") && bypass_governance;
            if meta
                .retention_until
                .map(|value| value > Utc::now())
                .unwrap_or(false)
                && !governance_bypassed
            {
                return Err(s3_error(
                    StatusCode::FORBIDDEN,
                    "AccessDenied",
                    "Object retention period has not expired",
                    key,
                ));
            }
            if !meta.delete_marker {
                remove_current_hot_object_payload(state, bucket, key).await?;
                remove_remote_tier_payload_for_meta(state, &meta).await?;
            }
            remove_current_object_meta(state, bucket, key).await?;
            let _ = promote_latest_archived_version(state, bucket, key).await?;
            return Ok(true);
        }
    }

    let Some(archived_meta) = read_archived_object_meta(state, bucket, key, version_id).await?
    else {
        return Ok(false);
    };
    if archived_meta.legal_hold {
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Object is under legal hold",
            key,
        ));
    }
    let archived_governance_bypassed =
        archived_meta.retention_mode.as_deref() == Some("GOVERNANCE") && bypass_governance;
    if archived_meta
        .retention_until
        .map(|value| value > Utc::now())
        .unwrap_or(false)
        && !archived_governance_bypassed
    {
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Object retention period has not expired",
            key,
        ));
    }

    remove_archived_object_version(state, bucket, key, version_id).await?;
    Ok(true)
}

pub(crate) async fn persist_archived_object_meta(
    state: &AppState,
    meta: &S3ObjectMeta,
) -> Result<(), Response> {
    let bucket_root = bucket_path(state, &meta.bucket)?;
    let meta_path = object_version_meta_path(&bucket_root, &meta.key, &meta.version_id)?;
    if let Some(parent) = meta_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create archived metadata directory: {err}"),
                &meta.key,
            )
        })?;
    }
    let bytes = serde_json::to_vec_pretty(meta).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to serialize archived object metadata: {err}"),
            &meta.key,
        )
    })?;
    atomic_write(&meta_path, &bytes).await.map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to persist archived object metadata: {err}"),
            &meta.key,
        )
    })?;
    Ok(())
}

pub(crate) async fn persist_current_object_meta(
    state: &AppState,
    meta: S3ObjectMeta,
) -> Result<(), Response> {
    // 对象元数据已完全下沉 redb(真相源 + LRU 缓存),不再写 .rustio_meta JSON——
    // list/versions/lifecycle/KMS 等扫描路径均已改 redb scan。
    // 未来分布式集群:在 MetaStore::put 处提交增量 op 到 openraft,复制到各节点本地 redb。
    state.meta_store.put(&meta).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to persist object metadata: {err}"),
            &meta.key,
        )
    })?;
    Ok(())
}

pub(crate) async fn read_current_object_meta(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<Option<S3ObjectMeta>, Response> {
    // 真相源已下沉 redb;MetaStore::get 内部 LRU 命中 / redb 点查回填。
    state.meta_store.get(bucket, key).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to read object metadata: {err}"),
            key,
        )
    })
}

pub(crate) async fn read_current_object_meta_from_disk(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<Option<S3ObjectMeta>, Response> {
    // 后台/绕缓存读:直查 redb 真相源,不暖 LRU(避免冷数据污染前台缓存)。
    state.meta_store.get_uncached(bucket, key).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to read object metadata: {err}"),
            key,
        )
    })
}

pub(crate) async fn remove_current_object_meta(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<(), Response> {
    // 对象元数据已完全下沉 redb,不再写/删 .rustio_meta JSON。
    state.meta_store.remove(bucket, key).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to remove object metadata: {err}"),
            key,
        )
    })?;
    Ok(())
}

pub(crate) async fn build_object_meta_for_current_version(
    state: &AppState,
    bucket: &str,
    key: &str,
    size: u64,
    etag: String,
    delete_marker: bool,
    system_meta: ObjectSystemMetadata,
) -> S3ObjectMeta {
    let now = Utc::now();
    let (versioning, object_lock_from_bucket) = state
        .buckets
        .read()
        .await
        .get(bucket)
        .map(|item| (item.versioning, item.object_lock))
        .unwrap_or((true, false));
    let version_id = if versioning || delete_marker {
        Uuid::new_v4().to_string()
    } else {
        "null".to_string()
    };

    let object_lock = state
        .bucket_object_locks
        .read()
        .await
        .get(bucket)
        .cloned()
        .unwrap_or(BucketObjectLockConfig {
            enabled: object_lock_from_bucket,
            mode: "GOVERNANCE".to_string(),
            default_retention_days: 30,
        });
    let retention = state
        .bucket_retentions
        .read()
        .await
        .get(bucket)
        .cloned()
        .unwrap_or_else(default_retention_config);
    let legal_hold = state
        .bucket_legal_holds
        .read()
        .await
        .get(bucket)
        .cloned()
        .unwrap_or_else(default_legal_hold_config)
        .enabled;

    let retention_until = if delete_marker {
        None
    } else if retention.enabled {
        Some(now + Duration::days(retention.duration_days as i64))
    } else if object_lock.enabled {
        Some(now + Duration::days(object_lock.default_retention_days as i64))
    } else {
        None
    };
    let retention_mode = if delete_marker {
        None
    } else if retention.enabled {
        Some(retention.mode)
    } else if object_lock.enabled {
        Some(object_lock.mode)
    } else {
        None
    };

    S3ObjectMeta {
        bucket: bucket.to_string(),
        key: key.to_string(),
        version_id,
        size,
        etag,
        created_at: now,
        storage_class: system_meta
            .storage_class
            .clone()
            .unwrap_or_else(default_storage_class),
        retention_mode,
        retention_until,
        legal_hold: if delete_marker { false } else { legal_hold },
        delete_marker,
        remote_tier: None,
        restore: None,
        tags: Vec::new(),
        user_metadata: HashMap::new(),
        encryption: S3ObjectEncryptionMeta::default(),
        content_type: system_meta.content_type,
        cache_control: system_meta.cache_control,
        content_disposition: system_meta.content_disposition,
        content_encoding: system_meta.content_encoding,
        content_language: system_meta.content_language,
        expires: system_meta.expires,
        website_redirect_location: system_meta.website_redirect_location,
        checksum: None,
    }
}

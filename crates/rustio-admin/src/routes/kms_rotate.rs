//! KMS 密钥轮换

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KmsRotationEntryKind {
    Current,
    Archived,
}

#[derive(Debug, Clone)]
pub(crate) struct KmsRotationEntry {
    pub(crate) meta: S3ObjectMeta,
    pub(crate) kind: KmsRotationEntryKind,
}

impl KmsRotationEntry {
    fn is_current(&self) -> bool {
        matches!(self.kind, KmsRotationEntryKind::Current)
    }

    fn object_identity(&self) -> String {
        format!(
            "{}/{}?versionId={}",
            self.meta.bucket, self.meta.key, self.meta.version_id
        )
    }
}

pub(crate) fn kms_rotation_retry_id(entry: &KmsRotationEntry) -> String {
    KmsRotationFailedObject {
        bucket: entry.meta.bucket.clone(),
        object_key: entry.meta.key.clone(),
        version_id: Some(entry.meta.version_id.clone()),
        is_current: entry.is_current(),
        kms_key_id: entry.meta.encryption.kms_key_id.clone(),
        retry_id: String::new(),
        stage: String::new(),
        message: String::new(),
    }
    .normalized_retry_id()
}

pub(crate) fn kms_rotation_matches_scope(
    entry: &KmsRotationEntry,
    scope: Option<&BatchRunScope>,
) -> bool {
    let Some(scope) = scope else {
        return true;
    };
    if scope.current_only && !entry.is_current() {
        return false;
    }
    if scope.noncurrent_only && entry.is_current() {
        return false;
    }
    let meta = &entry.meta;
    if scope
        .source_bucket
        .as_deref()
        .map(|bucket| meta.bucket != bucket)
        .unwrap_or(false)
    {
        return false;
    }
    if scope
        .object_prefix
        .as_deref()
        .map(|prefix| !meta.key.starts_with(prefix))
        .unwrap_or(false)
    {
        return false;
    }
    if scope
        .object_key
        .as_deref()
        .map(|key| meta.key != key)
        .unwrap_or(false)
    {
        return false;
    }
    if scope
        .version_id
        .as_deref()
        .map(|version_id| meta.version_id != version_id)
        .unwrap_or(false)
    {
        return false;
    }
    if scope
        .kms_key_id
        .as_deref()
        .map(|kms_key_id| meta.encryption.kms_key_id.as_deref() != Some(kms_key_id))
        .unwrap_or(false)
    {
        return false;
    }
    true
}

pub(crate) fn kms_rotation_retry_matches_scope(
    entry: &KmsRotationEntry,
    retry_targets: &HashSet<String>,
) -> bool {
    let full_identity = entry.object_identity();
    let retry_id = kms_rotation_retry_id(entry);
    let bucket_key_identity = format!("{}/{}", entry.meta.bucket, entry.meta.key);
    retry_targets.contains(&retry_id)
        || retry_targets.contains(&full_identity)
        || retry_targets.contains(&bucket_key_identity)
        || retry_targets.contains(&entry.meta.key)
}

pub(crate) async fn perform_kms_rotation(
    state: &Arc<AppState>,
    auth: &AuthContext,
    reason: String,
    retry_only_failed: bool,
    scope: Option<&BatchRunScope>,
) -> Result<KmsRotationResult, AppError> {
    let reason = reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }

    let retry_targets = if retry_only_failed {
        let security = state.security.read().await;
        security.kms_rotation_failed_objects.clone()
    } else {
        Vec::new()
    };
    if retry_only_failed && retry_targets.is_empty() {
        return Err(AppError::bad_request(
            "当前没有可重试的 KMS 失败对象 / no failed KMS rotation objects to retry",
        ));
    }

    let started_at = Utc::now();
    update_security_runtime(state.as_ref(), move |security| {
        security.kms_rotation_status = "running".to_string();
        security.kms_rotation_last_started_at = Some(started_at);
        security.kms_rotation_last_failure_reason = None;
        security.kms_rotation_scanned = 0;
        security.kms_rotation_rotated = 0;
        security.kms_rotation_skipped = 0;
        security.kms_rotation_failed = 0;
        security.kms_rotation_failed_objects.clear();
    })
    .await;

    let retry_target_set = retry_targets
        .into_iter()
        .flat_map(|item| {
            let retry_id = item.normalized_retry_id();
            let mut targets = vec![retry_id];
            if !item.bucket.trim().is_empty() && !item.object_key.trim().is_empty() {
                targets.push(format!("{}/{}", item.bucket.trim(), item.object_key.trim()));
            }
            if !item.object_key.trim().is_empty() {
                targets.push(item.object_key.trim().to_string());
            }
            targets
        })
        .collect::<HashSet<_>>();
    let mut entries = collect_object_meta_entries_for_kms_rotation(state)
        .await
        .into_iter()
        .filter(|entry| kms_rotation_matches_scope(entry, scope))
        .filter(|entry| {
            !retry_only_failed || kms_rotation_retry_matches_scope(entry, &retry_target_set)
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.meta
            .bucket
            .cmp(&right.meta.bucket)
            .then_with(|| left.meta.key.cmp(&right.meta.key))
            .then_with(|| left.meta.version_id.cmp(&right.meta.version_id))
            .then_with(|| left.is_current().cmp(&right.is_current()))
    });
    if let Some(limit) = scope.and_then(|item| item.limit) {
        entries.truncate(limit.min(entries.len()));
    }

    let scanned = entries.len() as u64;
    let mut rotated = 0u64;
    let mut skipped = 0u64;
    let mut failed_objects = Vec::<KmsRotationFailedObject>::new();
    let mut failure_reason = None;

    for entry in entries {
        let failed_object_base = KmsRotationFailedObject {
            bucket: entry.meta.bucket.clone(),
            object_key: entry.meta.key.clone(),
            version_id: Some(entry.meta.version_id.clone()),
            is_current: entry.is_current(),
            kms_key_id: entry.meta.encryption.kms_key_id.clone(),
            retry_id: String::new(),
            stage: String::new(),
            message: String::new(),
        };
        let is_current = entry.is_current();
        let mut meta = entry.meta;
        let key = meta.key.clone();

        if !encryption_enabled(&meta) || !meta.encryption.algorithm.eq_ignore_ascii_case("aws:kms")
        {
            skipped += 1;
            continue;
        }

        let data_key = if let Some(wrapped) = meta.encryption.wrapped_key_base64.clone() {
            match unwrap_object_data_key(state.as_ref(), &key, &meta, &wrapped, None).await {
                Ok(key_bytes) => key_bytes,
                Err(_) => {
                    let error_message = state
                        .security
                        .read()
                        .await
                        .kms_last_error
                        .clone()
                        .unwrap_or_else(|| {
                            "KMS 数据密钥解包失败 / failed to unwrap KMS data key".to_string()
                        });
                    if failure_reason.is_none() {
                        failure_reason = Some(error_message.clone());
                    }
                    failed_objects.push(
                        KmsRotationFailedObject {
                            stage: "unwrap".to_string(),
                            message: error_message,
                            ..failed_object_base.clone()
                        }
                        .normalized(),
                    );
                    continue;
                }
            }
        } else {
            derive_object_encryption_key(state.as_ref(), &meta)
        };

        meta.encryption.wrapped_key_base64 =
            match wrap_object_data_key(state.as_ref(), &key, &meta, &data_key, None).await {
                Ok(value) => Some(value),
                Err(_) => {
                    let error_message = state
                        .security
                        .read()
                        .await
                        .kms_last_error
                        .clone()
                        .unwrap_or_else(|| {
                            "KMS 数据密钥重新包裹失败 / failed to rewrap KMS data key".to_string()
                        });
                    if failure_reason.is_none() {
                        failure_reason = Some(error_message.clone());
                    }
                    failed_objects.push(
                        KmsRotationFailedObject {
                            stage: "rewrap".to_string(),
                            message: error_message,
                            ..failed_object_base.clone()
                        }
                        .normalized(),
                    );
                    continue;
                }
            };

        let persist_result = if is_current {
            persist_current_object_meta(state, meta).await
        } else {
            persist_archived_object_meta(state, &meta).await
        };
        if persist_result.is_err() {
            let error_message =
                "持久化对象元数据失败 / failed to persist object metadata".to_string();
            if failure_reason.is_none() {
                failure_reason = Some(error_message.clone());
            }
            failed_objects.push(
                KmsRotationFailedObject {
                    stage: "persist".to_string(),
                    message: error_message,
                    ..failed_object_base
                }
                .normalized(),
            );
            continue;
        }
        rotated += 1;
    }

    let completed_at = Utc::now();
    let failed = failed_objects.len() as u64;
    if failed > 0 && failure_reason.is_none() {
        failure_reason = Some("KMS 轮换存在失败对象 / KMS rotation has failed objects".to_string());
    }
    let status = if failed == 0 {
        "completed"
    } else if rotated == 0 {
        "failed"
    } else {
        "partial_failed"
    };
    let retry_recommended = failed > 0;
    let failed_preview = failed_objects.iter().take(20).cloned().collect::<Vec<_>>();
    let success_completed_at = if failed == 0 {
        Some(completed_at)
    } else {
        None
    };

    update_security_runtime(state.as_ref(), {
        let failed_objects = failed_objects.clone();
        let failure_reason = failure_reason.clone();
        move |security| {
            security.kms_rotation_status = status.to_string();
            security.kms_rotation_last_completed_at = Some(completed_at);
            if let Some(success_at) = success_completed_at {
                security.kms_rotation_last_success_at = Some(success_at);
            }
            security.kms_rotation_last_failure_reason = failure_reason.clone();
            security.kms_rotation_scanned = scanned;
            security.kms_rotation_rotated = rotated;
            security.kms_rotation_skipped = skipped;
            security.kms_rotation_failed = failed;
            security.kms_rotation_failed_objects = failed_objects;
            if failed == 0 {
                security.kms_last_error = None;
            }
        }
    })
    .await;

    let result = KmsRotationResult {
        status: status.to_string(),
        scanned,
        rotated,
        skipped,
        failed,
        failed_objects: failed_objects.clone(),
        failure_reason: failure_reason.clone(),
        retry_recommended,
        started_at,
        completed_at,
    };

    state
        .append_audit(
            &auth.username,
            kms_rotation_action(retry_only_failed),
            "security/kms",
            if failed == 0 {
                "success"
            } else {
                "partial_failed"
            },
            Some(reason.clone()),
            json!({
                "status": result.status,
                "retry_only_failed": retry_only_failed,
                "scope": scope.cloned(),
                "scanned": scanned,
                "rotated": rotated,
                "skipped": skipped,
                "failed": failed,
                "failed_objects_preview": failed_preview,
                "failure_reason": failure_reason,
            }),
        )
        .await;

    state
        .push_event(
            kms_rotation_action(retry_only_failed),
            "security-service",
            json!({
                "actor": auth.username,
                "status": result.status,
                "retry_only_failed": retry_only_failed,
                "scope": scope.cloned(),
                "scanned": scanned,
                "rotated": rotated,
                "skipped": skipped,
                "failed": failed,
                "failed_objects_preview": failed_preview,
            }),
        )
        .await;

    Ok(result)
}

pub(crate) async fn collect_object_meta_entries_for_kms_rotation(
    state: &Arc<AppState>,
) -> Vec<KmsRotationEntry> {
    let mut entries = state
        .object_meta
        .iter()
        .map(|entry| entry.value().clone())
        .map(|meta| KmsRotationEntry {
            meta,
            kind: KmsRotationEntryKind::Current,
        })
        .collect::<Vec<_>>();
    let mut known_current = entries
        .iter()
        .map(|entry| (entry.meta.bucket.clone(), entry.meta.key.clone()))
        .collect::<HashSet<_>>();
    let mut known_versions = entries
        .iter()
        .map(|entry| {
            (
                entry.meta.bucket.clone(),
                entry.meta.key.clone(),
                entry.meta.version_id.clone(),
            )
        })
        .collect::<HashSet<_>>();

    let buckets = state
        .buckets
        .read()
        .await
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for bucket in buckets {
        let bucket_root = match bucket_path(state, &bucket) {
            Ok(path) => path,
            Err(_) => continue,
        };
        for meta in scan_bucket_current_object_meta_from_disk(&bucket_root, &bucket).await {
            let current_identity = (meta.bucket.clone(), meta.key.clone());
            let version_identity = (
                meta.bucket.clone(),
                meta.key.clone(),
                meta.version_id.clone(),
            );
            if known_current.insert(current_identity) && known_versions.insert(version_identity) {
                entries.push(KmsRotationEntry {
                    meta,
                    kind: KmsRotationEntryKind::Current,
                });
            }
        }
        for meta in scan_bucket_archived_object_meta_from_disk(&bucket_root, &bucket).await {
            let version_identity = (
                meta.bucket.clone(),
                meta.key.clone(),
                meta.version_id.clone(),
            );
            if known_versions.insert(version_identity) {
                entries.push(KmsRotationEntry {
                    meta,
                    kind: KmsRotationEntryKind::Archived,
                });
            }
        }
    }

    entries
}

pub(crate) async fn scan_object_meta_root_from_disk(
    meta_root: PathBuf,
    bucket: &str,
) -> Vec<S3ObjectMeta> {
    if !tokio::fs::try_exists(&meta_root).await.unwrap_or(false) {
        return Vec::new();
    }

    let mut queue = VecDeque::new();
    queue.push_back(meta_root);
    let mut metas = Vec::new();
    let mut seen = HashSet::new();
    while let Some(directory) = queue.pop_front() {
        let Ok(mut entries) = tokio::fs::read_dir(&directory).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let Ok(file_type) = entry.file_type().await else {
                continue;
            };
            if file_type.is_dir() {
                queue.push_back(path);
                continue;
            }
            if !file_type.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("json")
            {
                continue;
            }
            let Ok(bytes) = tokio::fs::read(&path).await else {
                continue;
            };
            let Ok(meta) = serde_json::from_slice::<S3ObjectMeta>(&bytes) else {
                continue;
            };
            if meta.bucket != bucket || meta.key.is_empty() {
                continue;
            }
            let version_identity = (
                meta.bucket.clone(),
                meta.key.clone(),
                meta.version_id.clone(),
            );
            if seen.insert(version_identity) {
                metas.push(meta);
            }
        }
    }
    metas
}

pub(crate) async fn scan_bucket_current_object_meta_from_disk(
    bucket_root: &FsPath,
    bucket: &str,
) -> Vec<S3ObjectMeta> {
    scan_object_meta_root_from_disk(bucket_root.join(".rustio_meta"), bucket).await
}

pub(crate) async fn scan_bucket_archived_object_meta_from_disk(
    bucket_root: &FsPath,
    bucket: &str,
) -> Vec<S3ObjectMeta> {
    scan_object_meta_root_from_disk(bucket_root.join(".rustio_versions"), bucket).await
}

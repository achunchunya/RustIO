//! 存储扫描与治理

use super::*;

#[derive(Debug, Clone)]
pub(crate) struct StorageScanFinding {
    pub(crate) kind: String,
    pub(crate) target: String,
    pub(crate) bucket: Option<String>,
    pub(crate) key: Option<String>,
    pub(crate) version_id: Option<String>,
    pub(crate) affected_disks: Vec<String>,
    pub(crate) missing_shards: usize,
    pub(crate) corrupted_shards: usize,
    pub(crate) details: Value,
}

pub(crate) async fn mark_job_completed(
    state: &AppState,
    job_id: &str,
    details: Value,
) -> Option<JobStatus> {
    let mut jobs = state.jobs.write().await;
    let job = jobs.iter_mut().find(|item| item.id == job_id)?;
    job.status = "completed".to_string();
    job.progress = 1.0;
    job.updated_at = Utc::now();
    job.finished_at = Some(job.updated_at);
    job.error = None;
    job.details = details;
    Some(job.clone())
}

pub(crate) async fn mark_job_retrying(
    state: &AppState,
    job_id: &str,
    error: String,
    details: Value,
) -> Option<JobStatus> {
    let mut jobs = state.jobs.write().await;
    let job = jobs.iter_mut().find(|item| item.id == job_id)?;
    job.status = "retrying".to_string();
    job.progress = job.progress.max(0.2);
    job.updated_at = Utc::now();
    job.finished_at = None;
    job.error = Some(error);
    job.next_attempt_at = Some(job.updated_at + storage_job_retry_delay(job.attempts));
    job.details = details;
    Some(job.clone())
}

pub(crate) async fn mark_job_failed(
    state: &AppState,
    job_id: &str,
    error: String,
    details: Value,
) -> Option<JobStatus> {
    let mut jobs = state.jobs.write().await;
    let job = jobs.iter_mut().find(|item| item.id == job_id)?;
    job.status = "failed".to_string();
    job.progress = job.progress.max(0.2);
    job.updated_at = Utc::now();
    job.finished_at = Some(job.updated_at);
    job.error = Some(error);
    job.next_attempt_at = None;
    job.details = details;
    Some(job.clone())
}

pub(crate) async fn claim_next_storage_job(state: &AppState) -> Option<JobStatus> {
    {
        let runtime = state.storage_governance.read().await;
        if runtime.heal_running >= storage_job_concurrency_limit() {
            return None;
        }
    }

    let now = Utc::now();
    let mut jobs = state.jobs.write().await;
    let mut selected_index: Option<usize> = None;
    let mut selected_priority = i32::MIN;
    let mut selected_created_at = now;
    for (index, job) in jobs.iter().enumerate() {
        let kind = storage_job_kind_label(&job.kind);
        if !storage_job_is_storage_work(kind) {
            continue;
        }
        if !matches!(job.status.as_str(), "pending" | "retrying") {
            continue;
        }
        if job.status == "retrying"
            && job
                .next_attempt_at
                .map(|value| value > now)
                .unwrap_or(false)
        {
            continue;
        }
        if selected_index.is_none()
            || job.priority > selected_priority
            || (job.priority == selected_priority && job.created_at < selected_created_at)
        {
            selected_index = Some(index);
            selected_priority = job.priority;
            selected_created_at = job.created_at;
        }
    }
    let index = selected_index?;
    let job = jobs.get_mut(index)?;
    job.status = "running".to_string();
    job.progress = job.progress.max(0.15);
    job.updated_at = now;
    job.started_at.get_or_insert(now);
    job.attempts = job.attempts.saturating_add(1);
    job.next_attempt_at = None;
    job.error = None;
    let snapshot = job.clone();
    drop(jobs);

    let mut runtime = state.storage_governance.write().await;
    runtime.heal_running = runtime.heal_running.saturating_add(1);
    Some(snapshot)
}

pub(crate) async fn inspect_storage_manifest(
    state: &AppState,
    bucket: &str,
    manifest: &EcObjectManifest,
) -> StorageScanFinding {
    let total_shards = manifest.data_shards + manifest.parity_shards;
    let shard_map = manifest
        .shards
        .iter()
        .cloned()
        .map(|item| (item.shard_index, item))
        .collect::<HashMap<_, _>>();
    let mut missing_shards = 0usize;
    let mut corrupted_shards = 0usize;
    let mut affected_disks = HashSet::new();
    for shard_index in 0..total_shards {
        let shard = shard_map.get(&shard_index).cloned().or_else(|| {
            derived_ec_shard_path(state, bucket, &manifest.key, shard_index).map(
                |(disk_index, shard_path)| EcShardInfo {
                    shard_index,
                    disk_index,
                    path: shard_path,
                    checksum: String::new(),
                },
            )
        });
        let Some(shard) = shard else {
            missing_shards += 1;
            continue;
        };
        let disk_id = format!("disk-{}", shard.disk_index);
        match tokio::fs::read(&shard.path).await {
            Ok(bytes) => {
                let checksum_matches =
                    shard.checksum.is_empty() || sha256_hex(&bytes) == shard.checksum;
                if bytes.len() != manifest.shard_size || !checksum_matches {
                    corrupted_shards += 1;
                    affected_disks.insert(disk_id);
                }
            }
            Err(_) => {
                missing_shards += 1;
                affected_disks.insert(disk_id);
            }
        }
    }

    let current_meta = read_current_object_meta_from_disk(state, bucket, &manifest.key)
        .await
        .ok()
        .flatten();
    let available_shards = total_shards.saturating_sub(missing_shards + corrupted_shards);
    let kind = if available_shards < manifest.data_shards
        || missing_shards + corrupted_shards > manifest.parity_shards
    {
        "rebuild"
    } else if missing_shards > 0 {
        "heal"
    } else {
        "scrub"
    };

    StorageScanFinding {
        kind: kind.to_string(),
        target: format!("{bucket}/{}", manifest.key),
        bucket: Some(bucket.to_string()),
        key: Some(manifest.key.clone()),
        version_id: current_meta.map(|item| item.version_id),
        affected_disks: affected_disks.into_iter().collect(),
        missing_shards,
        corrupted_shards,
        details: json!({
            "bucket": bucket,
            "key": manifest.key,
            "missing_shards": missing_shards,
            "corrupted_shards": corrupted_shards,
        }),
    }
}

pub(crate) async fn inspect_storage_object_target(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<Option<StorageScanFinding>, String> {
    let bucket_root = bucket_path(state, bucket)
        .map_err(|_| "存储桶名称无效 / invalid bucket name".to_string())?;
    let manifest_path = ec_manifest_path(&bucket_root, key);
    let manifest_bytes = match tokio::fs::read(&manifest_path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "读取纠删码清单失败：{err} / failed to read erasure manifest: {err}"
            ))
        }
    };
    let manifest = serde_json::from_slice::<EcObjectManifest>(&manifest_bytes).map_err(|err| {
        format!("解析纠删码清单失败：{err} / failed to decode erasure manifest: {err}")
    })?;
    let finding = inspect_storage_manifest(state, bucket, &manifest).await;
    if finding.missing_shards == 0 && finding.corrupted_shards == 0 {
        return Ok(None);
    }
    Ok(Some(finding))
}

pub(crate) async fn collect_storage_scan_findings(
    state: &Arc<AppState>,
) -> Result<Vec<StorageScanFinding>, String> {
    let bucket_names = state
        .buckets
        .read()
        .await
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let mut findings = Vec::new();
    for bucket in bucket_names {
        let bucket_root = bucket_path(state, &bucket)
            .map_err(|_| "存储桶名称无效 / invalid bucket name".to_string())?;
        let manifest_dir = bucket_root.join(".rustio_ec_meta");
        let mut entries = match tokio::fs::read_dir(&manifest_dir).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(format!(
                    "读取纠删码目录失败：{err} / failed to read erasure manifest directory: {err}"
                ))
            }
        };
        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(err) => {
                    return Err(format!(
                        "遍历纠删码目录失败：{err} / failed to iterate erasure manifest directory: {err}"
                    ))
                }
            };
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let manifest_bytes = match tokio::fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(err) => {
                    return Err(format!(
                        "读取纠删码清单失败：{err} / failed to read erasure manifest: {err}"
                    ))
                }
            };
            match serde_json::from_slice::<EcObjectManifest>(&manifest_bytes) {
                Ok(manifest) => {
                    let finding =
                        inspect_storage_manifest(state.as_ref(), &bucket, &manifest).await;
                    if finding.missing_shards > 0 || finding.corrupted_shards > 0 {
                        findings.push(finding);
                    }
                }
                Err(err) => findings.push(StorageScanFinding {
                    kind: "scrub".to_string(),
                    target: path.display().to_string(),
                    bucket: Some(bucket.clone()),
                    key: Some(
                        path.file_name()
                            .and_then(|value| value.to_str())
                            .unwrap_or_default()
                            .to_string(),
                    ),
                    version_id: None,
                    affected_disks: vec![],
                    missing_shards: 0,
                    corrupted_shards: 0,
                    details: json!({
                        "bucket": bucket,
                        "manifest_path": path.display().to_string(),
                        "error": err.to_string(),
                    }),
                }),
            }
        }
    }
    Ok(findings)
}

pub(crate) fn storage_job_is_plan(kind: &str) -> bool {
    kind.contains(":plan")
}

pub(crate) fn storage_disk_index_from_id(
    disk_id: &str,
    disk_count: usize,
) -> Result<usize, String> {
    let Some(suffix) = disk_id.trim().strip_prefix("disk-") else {
        return Err("磁盘 ID 必须形如 disk-0 / disk id must look like disk-0".to_string());
    };
    let index = suffix
        .parse::<usize>()
        .map_err(|_| "磁盘 ID 非法 / invalid disk id".to_string())?;
    if index >= disk_count {
        return Err("磁盘 ID 超出范围 / disk id is out of range".to_string());
    }
    Ok(index)
}

pub(crate) async fn response_message(response: Response) -> String {
    let status = response.status();
    match to_bytes(response.into_body(), usize::MAX).await {
        Ok(bytes) => {
            let body = String::from_utf8_lossy(&bytes).trim().to_string();
            if body.is_empty() {
                format!("请求失败：{status} / request failed: {status}")
            } else {
                body
            }
        }
        Err(err) => format!("读取错误响应失败：{err} / failed to read error response: {err}"),
    }
}

pub(crate) async fn active_storage_disk_indices_for_write(
    state: &AppState,
    extra_avoid_disk_ids: &HashSet<String>,
) -> Result<Vec<usize>, String> {
    let runtime = state.storage_governance.read().await;
    let mut indices = Vec::new();
    for (index, path) in state.data_disks.iter().enumerate() {
        let disk_id = storage_disk_id(index);
        if extra_avoid_disk_ids.contains(&disk_id)
            || runtime.draining_disks.contains(&disk_id)
            || runtime.decommissioned_disks.contains(&disk_id)
        {
            continue;
        }
        if tokio::fs::try_exists(path).await.unwrap_or(false) {
            indices.push(index);
        }
    }
    Ok(indices)
}

pub(crate) fn preferred_disk_indices_for_key(
    key: &str,
    candidates: &[usize],
    total_shards: usize,
) -> Result<Vec<usize>, String> {
    if candidates.len() < total_shards {
        return Err(format!(
            "可用磁盘不足，至少需要 {total_shards} 个，当前只有 {} 个 / not enough writable disks: need at least {total_shards}, only {} available",
            candidates.len(),
            candidates.len()
        ));
    }
    if candidates.is_empty() {
        return Err("没有可用磁盘 / no writable disks available".to_string());
    }
    let digest = Sha256::digest(key.as_bytes());
    let mut seed_bytes = [0u8; 8];
    seed_bytes.copy_from_slice(&digest[..8]);
    let start = u64::from_le_bytes(seed_bytes) as usize % candidates.len();
    Ok((0..total_shards)
        .map(|offset| candidates[(start + offset) % candidates.len()])
        .collect())
}

pub(crate) async fn preferred_storage_disk_indices_for_key(
    state: &AppState,
    key: &str,
    total_shards: usize,
    extra_avoid_disk_ids: &HashSet<String>,
) -> Result<Vec<usize>, String> {
    let candidates = active_storage_disk_indices_for_write(state, extra_avoid_disk_ids).await?;
    preferred_disk_indices_for_key(key, &candidates, total_shards)
}

pub(crate) fn manifest_disk_index_for_shard(
    manifest: &EcObjectManifest,
    shard_index: usize,
) -> Option<usize> {
    manifest
        .shards
        .iter()
        .find(|shard| shard.shard_index == shard_index)
        .map(|shard| shard.disk_index)
}

pub(crate) fn manifest_disk_id_for_shard(
    manifest: &EcObjectManifest,
    shard_index: usize,
    disk_count: usize,
) -> String {
    manifest_disk_index_for_shard(manifest, shard_index)
        .map(storage_disk_id)
        .unwrap_or_else(|| storage_disk_id(shard_index % disk_count.max(1)))
}

pub(crate) fn manifest_disk_ids(manifest: &EcObjectManifest, disk_count: usize) -> Vec<String> {
    let total_shards = manifest.data_shards + manifest.parity_shards;
    (0..total_shards)
        .map(|shard_index| manifest_disk_id_for_shard(manifest, shard_index, disk_count))
        .collect()
}

pub(crate) async fn collect_storage_manifests(
    state: &Arc<AppState>,
) -> Result<Vec<EcObjectManifest>, String> {
    let bucket_names = state
        .buckets
        .read()
        .await
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let mut manifests = Vec::new();
    for bucket in bucket_names {
        let bucket_root = match bucket_path(state, &bucket) {
            Ok(path) => path,
            Err(response) => return Err(response_message(response).await),
        };
        let manifest_dir = bucket_root.join(".rustio_ec_meta");
        let mut entries = match tokio::fs::read_dir(&manifest_dir).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(format!(
                    "读取纠删码目录失败：{err} / failed to read erasure manifest directory: {err}"
                ))
            }
        };
        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(err) => {
                    return Err(format!(
                        "遍历纠删码目录失败：{err} / failed to iterate erasure manifest directory: {err}"
                    ))
                }
            };
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let manifest_bytes = tokio::fs::read(&path).await.map_err(|err| {
                format!("读取纠删码清单失败：{err} / failed to read erasure manifest: {err}")
            })?;
            let manifest =
                serde_json::from_slice::<EcObjectManifest>(&manifest_bytes).map_err(|err| {
                    format!("解析纠删码清单失败：{err} / failed to decode erasure manifest: {err}")
                })?;
            manifests.push(manifest);
        }
    }
    Ok(manifests)
}

pub(crate) fn union_disk_ids(left: &[String], right: &[String]) -> Vec<String> {
    let mut merged = left
        .iter()
        .chain(right.iter())
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    merged.sort();
    merged
}

pub(crate) async fn plan_storage_migration_jobs(
    state: &Arc<AppState>,
    job_label: &str,
    source_disk_ids: &[String],
    extra_avoid_disk_ids: &[String],
) -> Result<(usize, usize), String> {
    let manifests = collect_storage_manifests(state).await?;
    let source_set = source_disk_ids.iter().cloned().collect::<HashSet<_>>();
    let extra_avoid = extra_avoid_disk_ids.iter().cloned().collect::<HashSet<_>>();
    let mut queued = 0usize;
    let mut skipped = 0usize;
    for manifest in manifests {
        let total_shards = manifest.data_shards + manifest.parity_shards;
        if total_shards == 0 {
            skipped += 1;
            continue;
        }
        let current_disk_ids = manifest_disk_ids(&manifest, state.data_disks.len());
        if !source_set.is_empty()
            && !current_disk_ids
                .iter()
                .any(|disk_id| source_set.contains(disk_id))
        {
            skipped += 1;
            continue;
        }
        let desired_disk_indices = preferred_storage_disk_indices_for_key(
            state,
            &manifest.key,
            total_shards,
            &extra_avoid,
        )
        .await?;
        let desired_disk_ids = desired_disk_indices
            .into_iter()
            .map(storage_disk_id)
            .collect::<Vec<_>>();
        if current_disk_ids == desired_disk_ids {
            skipped += 1;
            continue;
        }
        let affected_disks = union_disk_ids(&current_disk_ids, &desired_disk_ids);
        let _ = upsert_storage_job(
            state.as_ref(),
            StorageJobDraft {
                kind: job_label.to_string(),
                target: format!("{}/{}", manifest.bucket, manifest.key),
                bucket: Some(manifest.bucket.clone()),
                key: Some(manifest.key.clone()),
                version_id: None,
                priority: Some(if job_label == "decommission" {
                    2100
                } else {
                    1800
                }),
                affected_disks,
                missing_shards: 0,
                corrupted_shards: 0,
                source: format!("{job_label}_plan"),
                details: json!({
                    "desired_disks": desired_disk_ids,
                    "source_disks": source_disk_ids,
                    "bucket": manifest.bucket,
                    "key": manifest.key,
                }),
            },
            "pending",
        )
        .await;
        queued += 1;
    }
    Ok((queued, skipped))
}

pub(crate) async fn load_manifest_shard_bytes(
    manifest: &EcObjectManifest,
) -> Result<Vec<(EcShardInfo, Vec<u8>)>, String> {
    let mut items = manifest.shards.clone();
    items.sort_by_key(|item| item.shard_index);
    let mut shards = Vec::with_capacity(items.len());
    for shard in items {
        let bytes = tokio::fs::read(&shard.path)
            .await
            .map_err(|err| format!("读取分片失败：{err} / failed to read shard file: {err}"))?;
        if !shard.checksum.is_empty() && sha256_hex(&bytes) != shard.checksum {
            return Err("分片校验和不匹配 / shard checksum mismatch".to_string());
        }
        shards.push((shard, bytes));
    }
    Ok(shards)
}

pub(crate) async fn execute_storage_migration_job(
    state: &Arc<AppState>,
    job: &JobStatus,
    job_label: &str,
) -> Result<Value, String> {
    let bucket = job
        .bucket
        .as_deref()
        .ok_or_else(|| "缺少存储桶信息 / missing bucket".to_string())?;
    let key = job
        .key
        .as_deref()
        .ok_or_else(|| "缺少对象键 / missing object key".to_string())?;
    let desired_disk_ids = job
        .details
        .get("desired_disks")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if desired_disk_ids.is_empty() {
        return Err("缺少目标磁盘布局 / missing desired disk layout".to_string());
    }
    let desired_disk_indices = desired_disk_ids
        .iter()
        .map(|disk_id| storage_disk_index_from_id(disk_id, state.data_disks.len()))
        .collect::<Result<Vec<_>, _>>()?;

    let current_meta = match read_current_object_meta(state, bucket, key).await {
        Ok(meta) => meta,
        Err(response) => return Err(response_message(response).await),
    };
    if let Err(response) = read_ec_object(state, bucket, key, current_meta.as_ref(), None).await {
        return Err(response_message(response).await);
    }

    let bucket_root = match bucket_path(state, bucket) {
        Ok(path) => path,
        Err(response) => return Err(response_message(response).await),
    };
    let manifest_path = ec_manifest_path(&bucket_root, key);
    let manifest_bytes = tokio::fs::read(&manifest_path).await.map_err(|err| {
        format!("读取纠删码清单失败：{err} / failed to read erasure manifest: {err}")
    })?;
    let mut manifest =
        serde_json::from_slice::<EcObjectManifest>(&manifest_bytes).map_err(|err| {
            format!("解析纠删码清单失败：{err} / failed to decode erasure manifest: {err}")
        })?;
    let total_shards = manifest.data_shards + manifest.parity_shards;
    if desired_disk_indices.len() != total_shards {
        return Err(format!(
            "目标磁盘布局长度非法：期望 {total_shards}，实际 {} / invalid desired disk layout length: expected {total_shards}, got {}",
            desired_disk_indices.len(),
            desired_disk_indices.len()
        ));
    }

    let current_disk_ids = manifest_disk_ids(&manifest, state.data_disks.len());
    let shard_payloads = load_manifest_shard_bytes(&manifest).await?;
    let object_hash = sha256_hex(key.as_bytes());
    let current_paths = manifest
        .shards
        .iter()
        .map(|shard| (shard.shard_index, shard.path.clone()))
        .collect::<HashMap<_, _>>();
    let mut rewritten_paths = Vec::new();
    let mut next_shards = Vec::with_capacity(total_shards);

    for (shard, bytes) in shard_payloads {
        let desired_disk_index = *desired_disk_indices.get(shard.shard_index).ok_or_else(|| {
            "目标磁盘布局缺少分片位置 / desired disk layout missing shard slot".to_string()
        })?;
        let desired_path = state.data_disks[desired_disk_index]
            .join(bucket)
            .join(".rustio_ec")
            .join(&object_hash)
            .join(format!("{}.bin", shard.shard_index));
        if desired_path != shard.path {
            if let Some(parent) = desired_path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|err| {
                    format!(
                        "创建目标分片目录失败：{err} / failed to create target shard directory: {err}"
                    )
                })?;
            }
            tokio::fs::write(&desired_path, &bytes)
                .await
                .map_err(|err| {
                    format!("写入目标分片失败：{err} / failed to write target shard: {err}")
                })?;
            rewritten_paths.push(desired_path.clone());
        }
        next_shards.push(EcShardInfo {
            shard_index: shard.shard_index,
            disk_index: desired_disk_index,
            path: desired_path,
            checksum: sha256_hex(&bytes),
        });
    }

    manifest.shards = next_shards.clone();
    manifest.updated_at = Utc::now();
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|err| {
        format!("编码纠删码清单失败：{err} / failed to encode erasure manifest: {err}")
    })?;
    if let Err(err) = tokio::fs::write(&manifest_path, manifest_bytes).await {
        for path in rewritten_paths {
            let _ = tokio::fs::remove_file(path).await;
        }
        return Err(format!(
            "写入纠删码清单失败：{err} / failed to persist erasure manifest: {err}"
        ));
    }

    let next_paths = next_shards
        .iter()
        .map(|shard| shard.path.clone())
        .collect::<HashSet<_>>();
    for path in current_paths.values() {
        if !next_paths.contains(path) {
            let _ = tokio::fs::remove_file(path).await;
        }
    }

    Ok(json!({
        "bucket": bucket,
        "key": key,
        "operation": job_label,
        "from_disks": current_disk_ids,
        "to_disks": desired_disk_ids,
        "moved_shards": next_shards
            .iter()
            .enumerate()
            .filter(|(index, shard)| current_disk_ids.get(*index) != Some(&storage_disk_id(shard.disk_index)))
            .count(),
    }))
}

pub(crate) async fn refresh_decommission_completion(
    state: &Arc<AppState>,
) -> Result<Vec<String>, String> {
    let draining = state.storage_governance.read().await.draining_disks.clone();
    if draining.is_empty() {
        return Ok(Vec::new());
    }
    let manifests = collect_storage_manifests(state).await?;
    let draining_indices = draining
        .iter()
        .map(|disk_id| storage_disk_index_from_id(disk_id, state.data_disks.len()))
        .collect::<Result<HashSet<_>, _>>()?;
    let mut referenced = HashSet::new();
    for manifest in &manifests {
        for shard in &manifest.shards {
            if draining_indices.contains(&shard.disk_index) {
                referenced.insert(storage_disk_id(shard.disk_index));
            }
        }
    }
    let active_jobs = state.jobs.read().await;
    let busy_disks = active_jobs
        .iter()
        .filter(|job| {
            storage_job_kind_label(&job.kind) == "decommission"
                && !storage_job_is_terminal(&job.status)
        })
        .flat_map(|job| job.affected_disks.clone())
        .collect::<HashSet<_>>();
    drop(active_jobs);

    let finalized = draining
        .iter()
        .filter(|disk_id| !referenced.contains(*disk_id) && !busy_disks.contains(*disk_id))
        .cloned()
        .collect::<Vec<_>>();
    if finalized.is_empty() {
        return Ok(finalized);
    }

    {
        let mut runtime = state.storage_governance.write().await;
        for disk_id in &finalized {
            runtime.draining_disks.remove(disk_id);
            runtime.decommissioned_disks.insert(disk_id.clone());
            runtime.last_decommission_at = Some(Utc::now());
        }
    }

    for disk_id in &finalized {
        state
            .append_runtime_audit(
                "system",
                "storage.governance.decommission.complete",
                &format!("storage/disk/{disk_id}"),
                "success",
                None,
                json!({ "disk_id": disk_id }),
            )
            .await;
        state
            .push_event(
                "storage.governance.decommission.completed",
                "storage-governance",
                json!({ "disk_id": disk_id }),
            )
            .await;
    }

    Ok(finalized)
}

pub(crate) async fn enqueue_storage_scan_findings(
    state: &AppState,
    findings: &[StorageScanFinding],
    source: &str,
) -> usize {
    let mut queued = 0usize;
    for finding in findings {
        let _ = upsert_storage_job(
            state,
            StorageJobDraft {
                kind: finding.kind.clone(),
                target: finding.target.clone(),
                bucket: finding.bucket.clone(),
                key: finding.key.clone(),
                version_id: finding.version_id.clone(),
                priority: None,
                affected_disks: finding.affected_disks.clone(),
                missing_shards: finding.missing_shards,
                corrupted_shards: finding.corrupted_shards,
                source: source.to_string(),
                details: finding.details.clone(),
            },
            "pending",
        )
        .await;
        queued += 1;
    }
    queued
}

pub(crate) async fn execute_storage_job(
    state: &Arc<AppState>,
    job: &JobStatus,
) -> Result<Value, String> {
    let kind = storage_job_kind_label(&job.kind);
    if kind == "scan" {
        let findings = collect_storage_scan_findings(state).await?;
        let filtered = findings
            .into_iter()
            .filter(|finding| {
                job.bucket
                    .as_deref()
                    .map(|bucket| finding.bucket.as_deref() == Some(bucket))
                    .unwrap_or(true)
                    && job
                        .key
                        .as_deref()
                        .map(|key| finding.key.as_deref() == Some(key))
                        .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        let queued = enqueue_storage_scan_findings(state.as_ref(), &filtered, "manual_scan").await;
        return Ok(json!({
            "result": if filtered.is_empty() { "healthy" } else { "degraded" },
            "findings": filtered.len(),
            "queued": queued,
        }));
    }
    if kind == "rebalance" && storage_job_is_plan(&job.kind) {
        let disk_ids = job
            .details
            .get("disk_ids")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let runtime = state.storage_governance.read().await;
        let mut avoid_disk_ids = runtime
            .draining_disks
            .iter()
            .chain(runtime.decommissioned_disks.iter())
            .cloned()
            .collect::<Vec<_>>();
        drop(runtime);
        for disk_id in &disk_ids {
            if !avoid_disk_ids.contains(disk_id) {
                avoid_disk_ids.push(disk_id.clone());
            }
        }
        let (queued, skipped) =
            plan_storage_migration_jobs(state, "rebalance", &disk_ids, &avoid_disk_ids).await?;
        return Ok(json!({
            "operation": "rebalance",
            "queued": queued,
            "skipped": skipped,
            "disk_ids": disk_ids,
        }));
    }
    if kind == "decommission" && storage_job_is_plan(&job.kind) {
        let disk_ids = job
            .details
            .get("disk_ids")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if disk_ids.is_empty() {
            return Err("退役计划缺少磁盘 ID / decommission plan is missing disk ids".to_string());
        }
        {
            let mut runtime = state.storage_governance.write().await;
            for disk_id in &disk_ids {
                if runtime.decommissioned_disks.contains(disk_id) {
                    return Err(format!(
                        "磁盘已退役：{disk_id} / disk is already decommissioned: {disk_id}"
                    ));
                }
                runtime.draining_disks.insert(disk_id.clone());
            }
        }
        let (queued, skipped) =
            match plan_storage_migration_jobs(state, "decommission", &disk_ids, &disk_ids).await {
                Ok(result) => result,
                Err(err) => {
                    let mut runtime = state.storage_governance.write().await;
                    for disk_id in &disk_ids {
                        runtime.draining_disks.remove(disk_id);
                    }
                    return Err(err);
                }
            };
        let finalized = refresh_decommission_completion(state).await?;
        return Ok(json!({
            "operation": "decommission",
            "queued": queued,
            "skipped": skipped,
            "disk_ids": disk_ids,
            "finalized_disks": finalized,
        }));
    }
    if kind == "rebalance" {
        return execute_storage_migration_job(state, job, "rebalance").await;
    }
    if kind == "decommission" {
        return execute_storage_migration_job(state, job, "decommission").await;
    }

    let Some(bucket) = job.bucket.as_deref() else {
        let findings = collect_storage_scan_findings(state).await?;
        let queued =
            enqueue_storage_scan_findings(state.as_ref(), &findings, "manual_orchestration").await;
        return Ok(json!({
            "result": "orchestrated",
            "findings": findings.len(),
            "queued": queued,
        }));
    };
    let Some(key) = job.key.as_deref() else {
        return Err("缺少对象键，无法执行修复 / missing object key for storage heal".to_string());
    };
    let meta = read_current_object_meta(state, bucket, key)
        .await
        .map_err(|_| {
            "读取对象元数据失败 / failed to read object metadata for background heal".to_string()
        })?;
    let repaired = read_ec_object(state, bucket, key, meta.as_ref(), None)
        .await
        .map_err(|_| "后台修复执行失败 / background heal execution failed".to_string())?;
    if repaired.is_none() {
        return Err("对象未启用纠删码 / object is not stored with erasure coding".to_string());
    }
    let remaining = inspect_storage_object_target(state, bucket, key).await?;
    if let Some(remaining) = remaining {
        return Err(format!(
            "对象仍存在异常：缺失 {}，损坏 {} / object still has anomalies: missing {}, corrupted {}",
            remaining.missing_shards,
            remaining.corrupted_shards,
            remaining.missing_shards,
            remaining.corrupted_shards
        ));
    }
    Ok(json!({
        "bucket": bucket,
        "key": key,
        "kind": kind,
        "missing_shards": job.missing_shards,
        "corrupted_shards": job.corrupted_shards,
        "repaired": true,
    }))
}

pub async fn process_storage_governance_scan_once(state: &Arc<AppState>) -> Result<(), String> {
    {
        let mut runtime = state.storage_governance.write().await;
        if runtime.scan_running {
            return Ok(());
        }
        runtime.scan_running = true;
    }

    let started = Instant::now();
    let scan_job = upsert_storage_job(
        state.as_ref(),
        StorageJobDraft {
            kind: "scan".to_string(),
            target: "cluster".to_string(),
            bucket: None,
            key: None,
            version_id: None,
            priority: Some(0),
            affected_disks: vec![],
            missing_shards: 0,
            corrupted_shards: 0,
            source: "background_scan".to_string(),
            details: json!({ "auto": true }),
        },
        "running",
    )
    .await;

    let findings = collect_storage_scan_findings(state).await;
    let finished_at = Utc::now();
    let duration = started.elapsed().as_secs_f64();
    match &findings {
        Ok(items) => {
            let queued =
                enqueue_storage_scan_findings(state.as_ref(), items, "background_scan").await;
            let _ = mark_job_completed(
                state.as_ref(),
                &scan_job.id,
                json!({
                    "auto": true,
                    "result": if items.is_empty() { "healthy" } else { "degraded" },
                    "findings": items.len(),
                    "queued": queued,
                }),
            )
            .await;
            let mut runtime = state.storage_governance.write().await;
            runtime.last_scan_at = Some(finished_at);
            runtime.last_scan_duration_seconds = duration;
            runtime.last_scan_result = if items.is_empty() {
                "healthy".to_string()
            } else {
                "degraded".to_string()
            };
            runtime.scan_runs_total = runtime.scan_runs_total.saturating_add(1);
            runtime.scan_running = false;
            for finding in items {
                for disk in &finding.affected_disks {
                    runtime
                        .disk_last_anomaly_at
                        .insert(disk.clone(), finished_at);
                }
            }
        }
        Err(err) => {
            let _ = mark_job_failed(
                state.as_ref(),
                &scan_job.id,
                err.clone(),
                json!({ "auto": true, "result": "failed" }),
            )
            .await;
            let mut runtime = state.storage_governance.write().await;
            runtime.last_scan_at = Some(finished_at);
            runtime.last_scan_duration_seconds = duration;
            runtime.last_scan_result = "failed".to_string();
            runtime.scan_runs_total = runtime.scan_runs_total.saturating_add(1);
            runtime.scan_failures_total = runtime.scan_failures_total.saturating_add(1);
            runtime.scan_running = false;
        }
    }

    Ok(())
}

pub async fn process_storage_governance_heal_queue_once(
    state: &Arc<AppState>,
) -> Result<(), String> {
    let Some(job) = claim_next_storage_job(state.as_ref()).await else {
        return Ok(());
    };

    let started = Instant::now();
    let kind = storage_job_kind_label(&job.kind).to_string();
    let is_plan = storage_job_is_plan(&job.kind);
    let result = execute_storage_job(state, &job).await;
    let finished_at = Utc::now();
    match result {
        Ok(details) => {
            let _ = mark_job_completed(state.as_ref(), &job.id, details).await;
            let mut runtime = state.storage_governance.write().await;
            runtime.heal_running = runtime.heal_running.saturating_sub(1);
            match kind.as_str() {
                "heal" | "rebuild" if !is_plan => {
                    runtime.last_heal_at = Some(finished_at);
                    runtime.last_heal_duration_seconds = started.elapsed().as_secs_f64();
                    runtime.heal_objects_total = runtime.heal_objects_total.saturating_add(1);
                }
                "rebalance" if !is_plan => {
                    runtime.last_rebalance_at = Some(finished_at);
                    runtime.rebalance_objects_total =
                        runtime.rebalance_objects_total.saturating_add(1);
                }
                "decommission" if !is_plan => {
                    runtime.last_decommission_at = Some(finished_at);
                    runtime.decommission_objects_total =
                        runtime.decommission_objects_total.saturating_add(1);
                }
                _ => {}
            }
            drop(runtime);
            if kind == "decommission" {
                let _ = refresh_decommission_completion(state).await;
            }
        }
        Err(err) => {
            let details = json!({
                "kind": kind,
                "bucket": job.bucket,
                "key": job.key,
            });
            if job.attempts < job.max_attempts && kind != "scan" {
                let _ = mark_job_retrying(state.as_ref(), &job.id, err.clone(), details).await;
            } else {
                let _ = mark_job_failed(state.as_ref(), &job.id, err.clone(), details).await;
                if kind != "scan" {
                    let mut runtime = state.storage_governance.write().await;
                    match kind.as_str() {
                        "heal" | "rebuild" if !is_plan => {
                            runtime.heal_failures_total =
                                runtime.heal_failures_total.saturating_add(1);
                        }
                        "rebalance" if !is_plan => {
                            runtime.rebalance_failures_total =
                                runtime.rebalance_failures_total.saturating_add(1);
                        }
                        "decommission" if !is_plan => {
                            runtime.decommission_failures_total =
                                runtime.decommission_failures_total.saturating_add(1);
                        }
                        _ => {}
                    }
                }
            }
            let mut runtime = state.storage_governance.write().await;
            runtime.heal_running = runtime.heal_running.saturating_sub(1);
            drop(runtime);
            if kind == "decommission" {
                let _ = refresh_decommission_completion(state).await;
            }
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
pub(crate) struct StreamTokenQuery {
    pub(crate) token: Option<String>,
}

pub(crate) async fn events_stream(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<StreamTokenQuery>,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, std::convert::Infallible>>>, AppError> {
    let token = extract_access_token(&headers, query.token)
        .ok_or_else(|| AppError::unauthorized("缺少事件流令牌 / missing event stream token"))?;
    let claims = validate_access_token(&token, state.as_ref()).await?;
    if !claims.has_permission(Permission::ClusterRead) {
        return Err(AppError::forbidden(
            "缺少权限 cluster:read / missing permission cluster:read",
        ));
    }

    let mut rx = state.events.subscribe();

    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(runtime_event) => {
                    let event_name = runtime_event.topic.clone();
                    let payload = serde_json::to_string(&runtime_event)
                        .unwrap_or_else(|_| "{}".to_string());
                    yield Ok(Event::default().event(event_name).data(payload));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(10))))
}

//! 任务处理（存储、异步、批量、复制积压）

use super::*;

#[derive(Debug, Deserialize, Default)]
pub(crate) struct StorageJobRequest {
    pub(crate) target: Option<String>,
    pub(crate) kind: Option<String>,
    pub(crate) bucket: Option<String>,
    pub(crate) key: Option<String>,
    pub(crate) version_id: Option<String>,
    pub(crate) priority: Option<i32>,
}

#[derive(Debug, Clone)]
pub(crate) struct StorageJobDraft {
    pub(crate) kind: String,
    pub(crate) target: String,
    pub(crate) bucket: Option<String>,
    pub(crate) key: Option<String>,
    pub(crate) version_id: Option<String>,
    pub(crate) priority: Option<i32>,
    pub(crate) affected_disks: Vec<String>,
    pub(crate) missing_shards: usize,
    pub(crate) corrupted_shards: usize,
    pub(crate) source: String,
    pub(crate) details: Value,
}

pub(crate) fn storage_job_max_attempts() -> usize {
    std::env::var("RUSTIO_STORAGE_JOB_MAX_ATTEMPTS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(3)
        .clamp(1, 10)
}

pub(crate) fn storage_job_retry_delay(attempts: usize) -> Duration {
    let seconds = 2_i64
        .saturating_pow(attempts.saturating_sub(1).min(6) as u32)
        .clamp(1, 300);
    Duration::seconds(seconds)
}

pub(crate) fn storage_job_concurrency_limit() -> usize {
    std::env::var("RUSTIO_STORAGE_HEAL_MAX_RUNNING")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, 16)
}

pub(crate) fn normalize_storage_disk_ids(
    disk_ids: &[String],
    disk_count: usize,
) -> Result<Vec<String>, AppError> {
    let mut normalized = disk_ids
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| {
            let Some(suffix) = item.strip_prefix("disk-") else {
                return Err(AppError::bad_request(
                    "磁盘 ID 必须形如 disk-0 / disk id must look like disk-0",
                ));
            };
            let index = suffix
                .parse::<usize>()
                .map_err(|_| AppError::bad_request("磁盘 ID 非法 / invalid disk id"))?;
            if index >= disk_count {
                return Err(AppError::bad_request(
                    "磁盘 ID 超出范围 / disk id is out of range",
                ));
            }
            Ok(storage_disk_id(index))
        })
        .collect::<Result<HashSet<_>, _>>()?
        .into_iter()
        .collect::<Vec<_>>();
    normalized.sort();
    Ok(normalized)
}

pub(crate) fn normalize_storage_job_kind_request(kind: Option<&str>) -> Result<String, AppError> {
    let normalized = kind.unwrap_or("heal").trim().to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "scan" | "scrub" | "heal" | "rebuild" | "rebalance" | "decommission"
    ) {
        return Ok(normalized);
    }
    Err(AppError::bad_request(
        "任务类型必须是 scan / scrub / heal / rebuild / rebalance / decommission / job kind must be scan, scrub, heal, rebuild, rebalance or decommission",
    ))
}

pub(crate) fn storage_job_target_display(
    target: &str,
    bucket: Option<&str>,
    key: Option<&str>,
) -> String {
    if let (Some(bucket), Some(key)) = (bucket, key) {
        return format!("{bucket}/{key}");
    }
    if target.trim().is_empty() {
        return "cluster".to_string();
    }
    target.to_string()
}

pub(crate) fn storage_job_dedupe_key(
    kind: &str,
    target: &str,
    bucket: Option<&str>,
    key: Option<&str>,
    version_id: Option<&str>,
) -> Option<String> {
    if kind == "scan" && bucket.is_none() && key.is_none() && target == "cluster" {
        return None;
    }
    Some(format!(
        "{kind}:{target}:{}:{}:{}",
        bucket.unwrap_or("-"),
        key.unwrap_or("-"),
        version_id.unwrap_or("-")
    ))
}

pub(crate) fn storage_job_priority_score(
    kind: &str,
    source: &str,
    missing_shards: usize,
    corrupted_shards: usize,
    heat: u64,
    explicit_priority: Option<i32>,
) -> i32 {
    let kind = storage_job_kind_label(kind);
    let mut score = explicit_priority.unwrap_or_default();
    if source == "read_failure" {
        score += 1000;
    }
    if kind == "rebuild" {
        score += 800;
    } else if kind == "decommission" {
        score += 700;
    } else if kind == "rebalance" {
        score += 500;
    }
    if missing_shards > 0 {
        score += 500 + (missing_shards as i32 * 25);
    }
    if corrupted_shards > 0 {
        score += 250 + (corrupted_shards as i32 * 10);
    }
    score + heat.min(250) as i32
}

pub(crate) fn prune_jobs_locked(jobs: &mut Vec<JobStatus>) {
    const MAX_JOBS: usize = 256;
    if jobs.len() <= MAX_JOBS {
        return;
    }
    let removable = jobs
        .iter()
        .enumerate()
        .filter(|(_, job)| storage_job_is_terminal(&job.status))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let mut remove_count = jobs.len().saturating_sub(MAX_JOBS);
    for index in removable.into_iter().rev() {
        if remove_count == 0 {
            break;
        }
        jobs.remove(index);
        remove_count -= 1;
    }
}

pub(crate) async fn touch_object_access_heat(state: &AppState, bucket: &str, key: &str) {
    let mut heat = state.object_access_heat.write().await;
    let entry = heat
        .entry((bucket.to_string(), key.to_string()))
        .or_insert(0);
    *entry = entry.saturating_add(1);
}

pub(crate) async fn current_object_heat(state: &AppState, bucket: &str, key: &str) -> u64 {
    state
        .object_access_heat
        .read()
        .await
        .get(&(bucket.to_string(), key.to_string()))
        .copied()
        .unwrap_or_default()
}

pub(crate) async fn upsert_storage_job(
    state: &AppState,
    draft: StorageJobDraft,
    initial_status: &str,
) -> JobStatus {
    let now = Utc::now();
    let heat = match (draft.bucket.as_deref(), draft.key.as_deref()) {
        (Some(bucket), Some(key)) => current_object_heat(state, bucket, key).await,
        _ => 0,
    };
    let priority = storage_job_priority_score(
        &draft.kind,
        &draft.source,
        draft.missing_shards,
        draft.corrupted_shards,
        heat,
        draft.priority,
    );
    let dedupe_key = storage_job_dedupe_key(
        &draft.kind,
        &draft.target,
        draft.bucket.as_deref(),
        draft.key.as_deref(),
        draft.version_id.as_deref(),
    );

    let mut jobs = state.jobs.write().await;
    if let Some(dedupe_key) = dedupe_key.as_deref() {
        if let Some(existing) = jobs.iter_mut().find(|job| {
            job.dedupe_key.as_deref() == Some(dedupe_key) && !storage_job_is_terminal(&job.status)
        }) {
            existing.priority = existing.priority.max(priority);
            existing.affected_disks = draft.affected_disks.clone();
            existing.missing_shards = existing.missing_shards.max(draft.missing_shards);
            existing.corrupted_shards = existing.corrupted_shards.max(draft.corrupted_shards);
            existing.updated_at = now;
            existing.details = draft.details.clone();
            return existing.clone();
        }
    }

    let target_display =
        storage_job_target_display(&draft.target, draft.bucket.as_deref(), draft.key.as_deref());
    let draft_key = draft.key.clone();
    let dedupe_key_value = dedupe_key.clone();
    let details_payload = draft.details.clone();
    let job = JobStatus {
        id: Uuid::new_v4().to_string(),
        kind: if target_display == draft.kind {
            draft.kind.clone()
        } else {
            format!("{}:{target_display}", draft.kind)
        },
        status: initial_status.to_string(),
        progress: if initial_status == "running" {
            0.1
        } else {
            0.0
        },
        created_at: now,
        updated_at: now,
        bucket: draft.bucket,
        object_key: draft_key.clone(),
        site_id: None,
        idempotency_key: dedupe_key_value.clone().unwrap_or_default(),
        attempt: 0,
        lease_owner: None,
        lease_until: None,
        checkpoint: None,
        last_error: None,
        payload: details_payload.clone(),
        key: draft_key,
        version_id: draft.version_id,
        target: Some(draft.target),
        priority,
        affected_disks: draft.affected_disks,
        missing_shards: draft.missing_shards,
        corrupted_shards: draft.corrupted_shards,
        started_at: (initial_status == "running").then_some(now),
        finished_at: None,
        attempts: 0,
        max_attempts: if storage_job_kind_label(&draft.kind) == "scan"
            || draft.kind.contains(":plan")
        {
            1
        } else {
            storage_job_max_attempts()
        },
        next_attempt_at: None,
        error: None,
        dedupe_key,
        source: Some(draft.source),
        details: details_payload,
    };
    jobs.push(job.clone());
    prune_jobs_locked(&mut jobs);
    job
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct AsyncJobQuery {
    pub(crate) kind: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) bucket: Option<String>,
    pub(crate) site_id: Option<String>,
    pub(crate) object_prefix: Option<String>,
    pub(crate) keyword: Option<String>,
    pub(crate) limit: Option<usize>,
    pub(crate) include_terminal: Option<bool>,
    pub(crate) cursor: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct AsyncJobBulkRequest {
    #[serde(default)]
    pub(crate) job_ids: Vec<String>,
}

pub(crate) fn batch_job_internal_kind(kind: &str) -> String {
    format!("batch:{kind}")
}

#[derive(Debug, Clone)]
pub(crate) struct BatchExecutionResult {
    pub(crate) status: String,
    pub(crate) matched: usize,
    pub(crate) enqueued: usize,
    pub(crate) skipped: usize,
    pub(crate) failed: usize,
    pub(crate) last_error: Option<String>,
    pub(crate) failed_objects_preview: Vec<KmsRotationFailedObject>,
}

pub(crate) fn batch_kind_from_job(kind: &str) -> Option<&str> {
    kind.strip_prefix("batch:")
}

pub(crate) fn batch_payload_usize(job: &JobStatus, key: &str) -> usize {
    job.payload
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| value.min(usize::MAX as u64) as usize)
        .unwrap_or(0)
}

pub(crate) fn batch_scope_from_job(job: &JobStatus) -> BatchRunScope {
    job.payload
        .get("scope")
        .cloned()
        .and_then(|value| serde_json::from_value::<BatchRunScope>(value).ok())
        .unwrap_or_default()
}

pub(crate) fn batch_failed_objects_preview_from_job(
    job: &JobStatus,
) -> Vec<KmsRotationFailedObject> {
    job.payload
        .get("failed_objects_preview")
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<KmsRotationFailedObject>>(value).ok())
        .unwrap_or_default()
}

pub(crate) fn job_to_batch_run(job: &JobStatus) -> Option<BatchRunStatus> {
    let kind = batch_kind_from_job(&job.kind)?;
    Some(BatchRunStatus {
        id: job.id.clone(),
        kind: kind.to_string(),
        status: job.status.clone(),
        scope: batch_scope_from_job(job),
        matched: batch_payload_usize(job, "matched"),
        enqueued: batch_payload_usize(job, "enqueued"),
        skipped: batch_payload_usize(job, "skipped"),
        failed: batch_payload_usize(job, "failed"),
        last_error: job
            .last_error
            .clone()
            .filter(|value| !value.trim().is_empty()),
        failed_objects_preview: batch_failed_objects_preview_from_job(job),
        created_at: job.created_at,
        updated_at: async_job_updated_at(job.created_at, job.updated_at),
    })
}

pub(crate) fn normalize_batch_statuses(statuses: &[String]) -> Vec<String> {
    let mut normalized = statuses
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

pub(crate) fn normalize_batch_run_request(
    body: BatchRunRequest,
) -> Result<(String, BatchRunScope), AppError> {
    let kind = body.kind.trim().to_ascii_lowercase();
    let object_prefix = normalize_replication_prefix(body.object_prefix.as_deref());
    let object_key = normalize_batch_object_key(body.object_key.as_deref());
    if kind.is_empty() {
        return Err(AppError::bad_request(
            "批处理类型不能为空 / batch run kind cannot be empty",
        ));
    }
    if matches!(body.limit, Some(0)) {
        return Err(AppError::bad_request(
            "批处理 limit 必须大于 0 / batch run limit must be greater than 0",
        ));
    }
    if body.current_only && body.noncurrent_only {
        return Err(AppError::bad_request(
            "批处理不能同时指定 current_only 与 noncurrent_only / batch run cannot set both current_only and noncurrent_only",
        ));
    }
    if let (Some(prefix), Some(key)) = (object_prefix.as_deref(), object_key.as_deref()) {
        if !key.starts_with(prefix) {
            return Err(AppError::bad_request(
                "object_key 必须落在 object_prefix 范围内 / object_key must be within object_prefix",
            ));
        }
    }
    Ok((
        kind,
        BatchRunScope {
            source_bucket: normalize_replication_optional_text(body.source_bucket.as_deref()),
            target_site: normalize_replication_optional_text(body.target_site.as_deref()),
            rule_id: normalize_replication_optional_text(body.rule_id.as_deref()),
            object_prefix,
            object_key,
            version_id: normalize_replication_optional_text(body.version_id.as_deref()),
            kms_key_id: normalize_replication_optional_text(body.kms_key_id.as_deref()),
            statuses: normalize_batch_statuses(&body.statuses),
            retry_only_failed: body.retry_only_failed,
            current_only: body.current_only,
            noncurrent_only: body.noncurrent_only,
            limit: body.limit,
        },
    ))
}

pub(crate) fn batch_run_payload(
    scope: &BatchRunScope,
    matched: usize,
    enqueued: usize,
    skipped: usize,
    failed: usize,
    failed_objects_preview: &[KmsRotationFailedObject],
) -> Result<Value, AppError> {
    let scope = serde_json::to_value(scope).map_err(|_| {
        AppError::internal("序列化批处理范围失败 / failed to serialize batch run scope")
    })?;
    let failed_objects_preview = serde_json::to_value(failed_objects_preview).map_err(|_| {
        AppError::internal(
            "序列化批处理失败对象预览失败 / failed to serialize batch failed objects preview",
        )
    })?;
    Ok(json!({
        "scope": scope,
        "matched": matched,
        "enqueued": enqueued,
        "skipped": skipped,
        "failed": failed,
        "failed_objects_preview": failed_objects_preview,
    }))
}

pub(crate) fn build_batch_run_job(
    kind: &str,
    scope: &BatchRunScope,
) -> Result<JobStatus, AppError> {
    let now = Utc::now();
    let payload = batch_run_payload(scope, 0, 0, 0, 0, &[])?;
    Ok(JobStatus {
        id: format!(
            "job-batch-{}-{}",
            kind.replace(':', "-"),
            Uuid::new_v4().simple()
        ),
        kind: batch_job_internal_kind(kind),
        status: "running".to_string(),
        priority: 1,
        bucket: scope.source_bucket.clone(),
        object_key: scope.object_key.clone().or(scope.object_prefix.clone()),
        site_id: scope.target_site.clone(),
        idempotency_key: format!("batch:{kind}:{}", Uuid::new_v4().simple()),
        attempt: 1,
        lease_owner: None,
        lease_until: None,
        checkpoint: None,
        last_error: None,
        payload,
        progress: 0.05,
        created_at: now,
        updated_at: now,
        key: None,
        version_id: scope.version_id.clone(),
        target: None,
        affected_disks: vec![],
        missing_shards: 0,
        corrupted_shards: 0,
        started_at: Some(now),
        finished_at: None,
        attempts: 1,
        max_attempts: 1,
        next_attempt_at: None,
        error: None,
        dedupe_key: None,
        source: None,
        details: Value::Null,
    })
}

pub(crate) fn update_batch_job_locked(
    jobs: &mut [JobStatus],
    job_id: &str,
    status: &str,
    progress: f32,
    last_error: Option<String>,
    payload: Value,
) -> Option<BatchRunStatus> {
    let now = Utc::now();
    let job = jobs.iter_mut().find(|job| job.id == job_id)?;
    job.status = status.to_string();
    job.progress = progress.clamp(0.0, 1.0);
    job.last_error = last_error;
    job.payload = payload;
    job.updated_at = now;
    job.finished_at = matches!(
        status,
        "completed" | "failed" | "dead_letter" | "cancelled" | "partial_failed"
    )
    .then_some(now);
    job_to_batch_run(job)
}

pub(crate) async fn collect_batch_runs(state: &AppState) -> Vec<BatchRunStatus> {
    let mut items = state
        .jobs
        .read()
        .await
        .iter()
        .filter_map(job_to_batch_run)
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        right
            .updated_at
            .cmp(&left.updated_at)
            .then_with(|| right.created_at.cmp(&left.created_at))
            .then_with(|| right.id.cmp(&left.id))
    });
    items
}

pub(crate) async fn execute_replication_requeue_batch(
    state: &Arc<AppState>,
    scope: &BatchRunScope,
) -> Result<(usize, usize, usize), String> {
    let source_bucket = scope.source_bucket.as_deref().ok_or_else(|| {
        "复制批处理必须提供源桶 / replication batch run requires source bucket".to_string()
    })?;
    let rules = state
        .replications
        .read()
        .await
        .iter()
        .filter(|rule| {
            rule.source_bucket == source_bucket
                && rule.status != "paused"
                && scope
                    .target_site
                    .as_deref()
                    .map(|site| rule.target_site == site)
                    .unwrap_or(true)
                && scope
                    .rule_id
                    .as_deref()
                    .map(|rule_id| rule.rule_id == rule_id)
                    .unwrap_or(true)
        })
        .cloned()
        .collect::<Vec<_>>();
    if rules.is_empty() {
        return Err(
            "未找到匹配的启用复制规则 / no enabled replication rule matched this batch run"
                .to_string(),
        );
    }

    // 按 source_bucket 前缀 scan_bucket(redb range,非全表)。
    let metas = state
        .meta_store
        .scan_bucket(source_bucket)
        .unwrap_or_default()
        .into_iter()
        .filter(|meta| {
            !meta.delete_marker
                && !meta.version_id.is_empty()
                && scope
                    .object_prefix
                    .as_deref()
                    .map(|prefix| meta.key.starts_with(prefix))
                    .unwrap_or(true)
        })
        .map(|meta| (meta.key.clone(), meta))
        .collect::<Vec<_>>();

    let backlog = state.replication_backlog.read().await.clone();
    let status_filter =
        (!scope.statuses.is_empty()).then(|| scope.statuses.iter().collect::<HashSet<_>>());
    let failed_only = scope.retry_only_failed;
    let mut unique_targets = HashSet::<(String, String)>::new();
    let mut candidates = Vec::<(String, String, String, i32, Option<String>)>::new();

    for (key, meta) in metas {
        let mut matched_rules = rules
            .iter()
            .filter(|rule| replication_rule_matches_meta(rule, &key, Some(&meta)))
            .collect::<Vec<_>>();
        matched_rules.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left.target_site.cmp(&right.target_site))
                .then_with(|| left.rule_id.cmp(&right.rule_id))
        });

        for rule in matched_rules {
            let target_key = (rule.target_site.clone(), key.clone());
            if !unique_targets.insert(target_key.clone()) {
                continue;
            }

            if let Some(statuses) = status_filter.as_ref() {
                let has_status_match = backlog.iter().any(|entry| {
                    entry.source_bucket == source_bucket
                        && entry.target_site == target_key.0
                        && entry.object_key == target_key.1
                        && statuses.contains(&entry.status)
                });
                if !has_status_match {
                    continue;
                }
            }

            if failed_only {
                let has_failed_match = backlog.iter().any(|entry| {
                    entry.source_bucket == source_bucket
                        && entry.target_site == target_key.0
                        && entry.object_key == target_key.1
                        && matches!(entry.status.as_str(), "failed" | "dead_letter")
                });
                if !has_failed_match {
                    continue;
                }
            }

            candidates.push((
                rule.target_site.clone(),
                key.clone(),
                rule.rule_id.clone(),
                rule.priority,
                Some(meta.version_id.clone()),
            ));
        }
    }

    candidates.sort_by(|left, right| {
        left.3
            .cmp(&right.3)
            .then_with(|| left.0.cmp(&right.0))
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });

    let matched = candidates.len();
    let selected = scope.limit.unwrap_or(matched).min(matched);
    for (target_site, key, rule_id, priority, version_id) in candidates.into_iter().take(selected) {
        state
            .enqueue_replication_task(
                source_bucket,
                &target_site,
                &key,
                Some(rule_id),
                priority,
                "put",
                version_id,
            )
            .await;
    }

    Ok((matched, selected, matched.saturating_sub(selected)))
}

pub(crate) async fn list_batch_runs(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<BatchRunStatus>>>, AppError> {
    auth.require(Permission::JobsRead)?;
    Ok(wrap(collect_batch_runs(&state).await))
}

pub(crate) async fn get_batch_run(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<ApiEnvelope<BatchRunStatus>>, AppError> {
    auth.require(Permission::JobsRead)?;
    let run = state
        .jobs
        .read()
        .await
        .iter()
        .find(|job| job.id == id)
        .and_then(job_to_batch_run)
        .ok_or_else(|| AppError::not_found("批处理任务不存在 / batch run not found"))?;
    Ok(wrap(run))
}

pub(crate) async fn create_batch_run(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<BatchRunRequest>,
) -> Result<Json<ApiEnvelope<BatchRunStatus>>, AppError> {
    auth.require(Permission::JobsWrite)?;
    let (kind, scope) = normalize_batch_run_request(body)?;
    match kind.as_str() {
        "replication-requeue" => {
            auth.require(Permission::ReplicationWrite)?;
            let bucket = scope.source_bucket.as_deref().ok_or_else(|| {
                AppError::bad_request(
                    "复制批处理必须提供 source_bucket / replication batch run requires source_bucket",
                )
            })?;
            if !state.buckets.read().await.contains_key(bucket) {
                return Err(AppError::not_found("存储桶不存在 / bucket not found"));
            }
            if scope.object_key.is_some() {
                return Err(AppError::bad_request(
                    "复制批处理不支持 object_key 过滤 / replication batch run does not support object_key filter",
                ));
            }
            if scope.version_id.is_some() {
                return Err(AppError::bad_request(
                    "复制批处理不支持 version_id 过滤 / replication batch run does not support version_id filter",
                ));
            }
            if scope.kms_key_id.is_some() {
                return Err(AppError::bad_request(
                    "复制批处理不支持 kms_key_id 过滤 / replication batch run does not support kms_key_id filter",
                ));
            }
        }
        "lifecycle-requeue" => {
            auth.require(Permission::BucketWrite)?;
            let bucket = scope.source_bucket.as_deref().ok_or_else(|| {
                AppError::bad_request(
                    "生命周期批处理必须提供 source_bucket / lifecycle batch run requires source_bucket",
                )
            })?;
            if !state.buckets.read().await.contains_key(bucket) {
                return Err(AppError::not_found("存储桶不存在 / bucket not found"));
            }
            if scope.target_site.is_some() {
                return Err(AppError::bad_request(
                    "生命周期批处理不支持 target_site 过滤 / lifecycle batch run does not support target_site filter",
                ));
            }
            if scope.object_key.is_some() {
                return Err(AppError::bad_request(
                    "生命周期批处理不支持 object_key 过滤 / lifecycle batch run does not support object_key filter",
                ));
            }
            if scope.version_id.is_some() {
                return Err(AppError::bad_request(
                    "生命周期批处理不支持 version_id 过滤 / lifecycle batch run does not support version_id filter",
                ));
            }
            if scope.kms_key_id.is_some() {
                return Err(AppError::bad_request(
                    "生命周期批处理不支持 kms_key_id 过滤 / lifecycle batch run does not support kms_key_id filter",
                ));
            }
        }
        "kms-rotate" => {
            auth.require(Permission::SecurityWrite)?;
            if let Some(bucket) = scope.source_bucket.as_deref() {
                if !state.buckets.read().await.contains_key(bucket) {
                    return Err(AppError::not_found("存储桶不存在 / bucket not found"));
                }
            }
            if scope.target_site.is_some() {
                return Err(AppError::bad_request(
                    "KMS 批处理不支持 target_site 过滤 / KMS batch run does not support target_site filter",
                ));
            }
            if scope.rule_id.is_some() {
                return Err(AppError::bad_request(
                    "KMS 批处理不支持 rule_id 过滤 / KMS batch run does not support rule_id filter",
                ));
            }
            if !scope.statuses.is_empty() {
                return Err(AppError::bad_request(
                    "KMS 批处理不支持 statuses 过滤 / KMS batch run does not support statuses filter",
                ));
            }
        }
        _ => {
            return Err(AppError::bad_request(format!(
                "暂不支持的批处理类型 {kind} / unsupported batch run kind {kind}"
            )));
        }
    }

    let job = build_batch_run_job(&kind, &scope)?;
    let job_id = job.id.clone();
    {
        let mut jobs = state.jobs.write().await;
        jobs.push(job);
        prune_jobs_locked(&mut jobs);
    }

    let result: Result<BatchExecutionResult, String> =
        match kind.as_str() {
            "replication-requeue" => execute_replication_requeue_batch(&state, &scope).await.map(
                |(matched, enqueued, skipped)| BatchExecutionResult {
                    status: "completed".to_string(),
                    matched,
                    enqueued,
                    skipped,
                    failed: 0,
                    last_error: None,
                    failed_objects_preview: Vec::new(),
                },
            ),
            "lifecycle-requeue" => state.enqueue_lifecycle_batch_run(&scope).await.map(
                |(matched, enqueued, skipped)| BatchExecutionResult {
                    status: "completed".to_string(),
                    matched,
                    enqueued,
                    skipped,
                    failed: 0,
                    last_error: None,
                    failed_objects_preview: Vec::new(),
                },
            ),
            "kms-rotate" => perform_kms_rotation(
                &state,
                &auth,
                format!("批处理任务 {job_id} KMS 轮换 / batch run {job_id} KMS rotation"),
                scope.retry_only_failed,
                Some(&scope),
            )
            .await
            .map(|result| BatchExecutionResult {
                status: result.status,
                matched: result.scanned as usize,
                enqueued: result.rotated as usize,
                skipped: result.skipped as usize,
                failed: result.failed as usize,
                last_error: result.failure_reason,
                failed_objects_preview: result.failed_objects.iter().take(20).cloned().collect(),
            })
            .map_err(|err| err.message),
            _ => unreachable!(),
        };

    let response = match result {
        Ok(result) => {
            let payload = batch_run_payload(
                &scope,
                result.matched,
                result.enqueued,
                result.skipped,
                result.failed,
                &result.failed_objects_preview,
            )?;
            let run = {
                let mut jobs = state.jobs.write().await;
                update_batch_job_locked(
                    &mut jobs,
                    &job_id,
                    &result.status,
                    1.0,
                    result.last_error.clone(),
                    payload,
                )
            }
            .ok_or_else(|| AppError::internal("批处理任务写回失败 / failed to update batch run"))?;
            state
                .append_audit(
                    &auth.username,
                    "jobs.batch.create",
                    &format!("jobs/batch/{job_id}"),
                    if result.failed == 0 {
                        "success"
                    } else {
                        "partial_failed"
                    },
                    result.last_error.clone(),
                    json!({
                        "kind": run.kind.clone(),
                        "scope": run.scope.clone(),
                        "matched": run.matched,
                        "enqueued": run.enqueued,
                        "skipped": run.skipped,
                        "failed": run.failed,
                        "failed_objects_preview": run.failed_objects_preview.clone(),
                        "status": run.status.clone(),
                    }),
                )
                .await;
            run
        }
        Err(err) => {
            let payload = batch_run_payload(&scope, 0, 0, 0, 0, &[])?;
            let run = {
                let mut jobs = state.jobs.write().await;
                update_batch_job_locked(
                    &mut jobs,
                    &job_id,
                    "failed",
                    1.0,
                    Some(err.clone()),
                    payload,
                )
            }
            .ok_or_else(|| AppError::internal("批处理任务写回失败 / failed to update batch run"))?;
            state
                .append_audit(
                    &auth.username,
                    "jobs.batch.create",
                    &format!("jobs/batch/{job_id}"),
                    "error",
                    Some(err.clone()),
                    json!({
                        "kind": run.kind.clone(),
                        "scope": run.scope.clone(),
                    }),
                )
                .await;
            run
        }
    };

    Ok(wrap(response))
}

pub(crate) fn normalize_async_job_kind(kind: &str) -> String {
    let normalized = kind.trim().to_ascii_lowercase();
    if normalized.starts_with("batch:") {
        normalized
    } else if normalized.starts_with("heal") {
        "heal".to_string()
    } else if normalized.contains("failover") {
        "failover".to_string()
    } else if normalized.contains("failback") {
        "failback".to_string()
    } else if normalized.contains("lifecycle") {
        "lifecycle".to_string()
    } else if normalized.contains("notification") || normalized.contains("alert") {
        "notification".to_string()
    } else {
        normalized
    }
}

pub(crate) fn async_job_priority_for_kind(kind: &str) -> u8 {
    match kind {
        "failover" | "failback" => 0,
        "replication" | "lifecycle" => 1,
        "notification" => 2,
        _ => 3,
    }
}

pub(crate) fn async_job_retryable(kind: &str, status: &str) -> bool {
    matches!(
        kind,
        "replication" | "notification" | "lifecycle" | "failover" | "failback"
    ) && matches!(status, "failed" | "dead_letter")
}

pub(crate) fn async_job_terminal(kind: &str, status: &str) -> bool {
    match status {
        "done" | "completed" | "success" | "cancelled" | "dead_letter" | "skipped"
        | "partial_failed" => true,
        "failed" => !async_job_retryable(kind, status),
        _ => false,
    }
}

pub(crate) fn async_job_progress(status: &str, current: f32, attempt: u32) -> f32 {
    if current > 0.0 {
        return current.clamp(0.0, 1.0);
    }
    match status {
        "done" | "completed" | "success" | "skipped" | "partial_failed" => 1.0,
        "in_progress" | "running" => 0.5,
        "failed" | "dead_letter" => (attempt as f32 / 10.0).clamp(0.1, 0.95),
        _ => 0.0,
    }
}

pub(crate) fn async_job_updated_at(
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> DateTime<Utc> {
    if updated_at < created_at {
        created_at
    } else {
        updated_at
    }
}

pub(crate) fn job_status_to_async_job(job: &JobStatus) -> Option<AsyncJobStatus> {
    if job.status == "idle" {
        return None;
    }
    let kind = normalize_async_job_kind(&job.kind);
    let retryable = async_job_retryable(&kind, &job.status);
    Some(AsyncJobStatus {
        job_id: job.id.clone(),
        kind: kind.clone(),
        status: job.status.clone(),
        priority: if job.priority == 0 {
            async_job_priority_for_kind(&kind)
        } else {
            job.priority.clamp(0, u8::MAX as i32) as u8
        },
        bucket: job.bucket.clone(),
        object_key: job.object_key.clone(),
        site_id: job.site_id.clone(),
        idempotency_key: job.idempotency_key.clone(),
        attempt: job.attempt,
        lease_owner: job.lease_owner.clone(),
        lease_until: job.lease_until,
        checkpoint: job.checkpoint,
        last_error: job
            .last_error
            .clone()
            .filter(|value| !value.trim().is_empty()),
        progress: async_job_progress(&job.status, job.progress, job.attempt),
        retryable,
        terminal: async_job_terminal(&kind, &job.status),
        created_at: job.created_at,
        updated_at: async_job_updated_at(job.created_at, job.updated_at),
    })
}

pub(crate) fn replication_item_to_async_job(item: &ReplicationBacklogItem) -> AsyncJobStatus {
    let kind = "replication".to_string();
    AsyncJobStatus {
        job_id: item.id.clone(),
        kind: kind.clone(),
        status: item.status.clone(),
        priority: item.priority.clamp(0, u8::MAX as i32) as u8,
        bucket: Some(item.source_bucket.clone()),
        object_key: Some(item.object_key.clone()),
        site_id: Some(item.target_site.clone()),
        idempotency_key: item.idempotency_key.clone(),
        attempt: item.attempts,
        lease_owner: item.lease_owner.clone(),
        lease_until: item.lease_until,
        checkpoint: Some(item.checkpoint),
        last_error: (!item.last_error.trim().is_empty()).then(|| item.last_error.clone()),
        progress: async_job_progress(&item.status, 0.0, item.attempts),
        retryable: async_job_retryable(&kind, &item.status),
        terminal: async_job_terminal(&kind, &item.status),
        created_at: item.queued_at,
        updated_at: async_job_updated_at(item.queued_at, item.last_attempt_at),
    }
}

pub(crate) fn alert_delivery_item_to_async_job(item: &AlertDeliveryItem) -> AsyncJobStatus {
    let kind = "notification".to_string();
    let bucket = item
        .payload
        .get("bucket")
        .and_then(Value::as_str)
        .map(|value| value.to_string());
    let object_key = item
        .payload
        .get("key")
        .and_then(Value::as_str)
        .map(|value| value.to_string());
    let updated_at = item.last_attempt_at.unwrap_or(item.queued_at);
    AsyncJobStatus {
        job_id: item.id.clone(),
        kind: kind.clone(),
        status: item.status.clone(),
        priority: async_job_priority_for_kind(&kind),
        bucket,
        object_key,
        site_id: None,
        idempotency_key: item.idempotency_key.clone(),
        attempt: item.attempts,
        lease_owner: item.lease_owner.clone(),
        lease_until: item.lease_until,
        checkpoint: None,
        last_error: (!item.last_error.trim().is_empty()).then(|| item.last_error.clone()),
        progress: async_job_progress(&item.status, 0.0, item.attempts),
        retryable: async_job_retryable(&kind, &item.status),
        terminal: async_job_terminal(&kind, &item.status),
        created_at: item.queued_at,
        updated_at: async_job_updated_at(item.queued_at, updated_at),
    }
}

pub(crate) async fn collect_async_jobs(state: &Arc<AppState>) -> Vec<AsyncJobStatus> {
    let jobs = state.jobs.read().await.clone();
    let replication_backlog = state.replication_backlog.read().await.clone();
    let alert_delivery_queue = state.alert_delivery_queue.read().await.clone();

    let mut items = replication_backlog
        .iter()
        .map(replication_item_to_async_job)
        .collect::<Vec<_>>();
    items.extend(
        alert_delivery_queue
            .iter()
            .map(alert_delivery_item_to_async_job),
    );
    items.extend(jobs.iter().filter_map(job_status_to_async_job));
    items.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.job_id.cmp(&left.job_id))
    });
    items
}

pub(crate) fn parse_async_job_cursor(
    cursor: Option<&str>,
) -> Result<Option<(i64, String)>, AppError> {
    let Some(raw) = cursor else {
        return Ok(None);
    };
    let mut parts = raw.splitn(2, ':');
    let ts = parts
        .next()
        .ok_or_else(|| AppError::bad_request("任务游标格式无效 / invalid async job cursor format"))?
        .parse::<i64>()
        .map_err(|_| {
            AppError::bad_request("任务游标时间戳无效 / invalid async job cursor timestamp")
        })?;
    let id = parts
        .next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::bad_request("任务游标对象无效 / invalid async job cursor id"))?;
    Ok(Some((ts, id.to_string())))
}

pub(crate) fn async_job_cursor_value(item: &AsyncJobStatus) -> String {
    format!("{}:{}", item.created_at.timestamp_millis(), item.job_id)
}

pub(crate) fn async_job_after_cursor(item: &AsyncJobStatus, cursor: &(i64, String)) -> bool {
    let ts = item.created_at.timestamp_millis();
    ts < cursor.0 || (ts == cursor.0 && item.job_id < cursor.1)
}

pub(crate) fn async_job_matches_query(
    item: &AsyncJobStatus,
    query: &AsyncJobQuery,
    kind_filter: Option<&str>,
    status_filter: Option<&str>,
    keyword_filter: Option<&str>,
) -> bool {
    if let Some(kind) = kind_filter {
        if item.kind.to_ascii_lowercase() != kind {
            return false;
        }
    }
    if let Some(status) = status_filter {
        if item.status.to_ascii_lowercase() != status {
            return false;
        }
    }
    if let Some(bucket) = query
        .bucket
        .as_ref()
        .map(|value| value.to_ascii_lowercase())
    {
        let matches_bucket = item
            .bucket
            .as_ref()
            .map(|value| value.to_ascii_lowercase() == bucket)
            .unwrap_or(false);
        if !matches_bucket {
            return false;
        }
    }
    if let Some(site_id) = query
        .site_id
        .as_ref()
        .map(|value| value.to_ascii_lowercase())
    {
        let matches_site = item
            .site_id
            .as_ref()
            .map(|value| value.to_ascii_lowercase() == site_id)
            .unwrap_or(false);
        if !matches_site {
            return false;
        }
    }
    if let Some(prefix) = query.object_prefix.as_ref() {
        let matches_prefix = item
            .object_key
            .as_ref()
            .map(|value| value.starts_with(prefix))
            .unwrap_or(false);
        if !matches_prefix {
            return false;
        }
    }
    if !query.include_terminal.unwrap_or(true) && item.terminal {
        return false;
    }
    if let Some(keyword) = keyword_filter {
        let mut haystacks = Vec::new();
        haystacks.push(item.kind.to_ascii_lowercase());
        haystacks.push(item.status.to_ascii_lowercase());
        if let Some(value) = item.bucket.as_ref() {
            haystacks.push(value.to_ascii_lowercase());
        }
        if let Some(value) = item.object_key.as_ref() {
            haystacks.push(value.to_ascii_lowercase());
        }
        if let Some(value) = item.site_id.as_ref() {
            haystacks.push(value.to_ascii_lowercase());
        }
        if let Some(value) = item.last_error.as_ref() {
            haystacks.push(value.to_ascii_lowercase());
        }
        if !haystacks.iter().any(|value| value.contains(keyword)) {
            return false;
        }
    }
    true
}

pub(crate) fn filter_async_jobs(
    mut items: Vec<AsyncJobStatus>,
    query: &AsyncJobQuery,
) -> Result<Vec<AsyncJobStatus>, AppError> {
    let kind_filter = query
        .kind
        .as_ref()
        .map(|value| normalize_async_job_kind(value));
    let status_filter = query
        .status
        .as_ref()
        .map(|value| value.to_ascii_lowercase());
    let keyword_filter = query
        .keyword
        .as_ref()
        .map(|value| value.to_ascii_lowercase());
    let cursor = parse_async_job_cursor(query.cursor.as_deref())?;
    items.retain(|item| {
        async_job_matches_query(
            item,
            query,
            kind_filter.as_deref(),
            status_filter.as_deref(),
            keyword_filter.as_deref(),
        )
    });
    if let Some(cursor) = cursor.as_ref() {
        items.retain(|item| async_job_after_cursor(item, cursor));
    }
    Ok(items)
}

pub(crate) fn record_async_job_summary(
    summary: &mut AsyncJobSummary,
    by_kind: &mut HashMap<String, AsyncJobKindSummary>,
    kind: &str,
    status: &str,
    retryable: bool,
) {
    let entry = by_kind
        .entry(kind.to_string())
        .or_insert_with(|| AsyncJobKindSummary {
            kind: kind.to_string(),
            total: 0,
            pending: 0,
            in_progress: 0,
            completed: 0,
            failed: 0,
            dead_letter: 0,
            retryable: 0,
        });
    entry.total += 1;
    if retryable {
        summary.retryable += 1;
        entry.retryable += 1;
    }
    match status {
        "pending" | "queued" => {
            summary.pending += 1;
            entry.pending += 1;
        }
        "in_progress" | "running" => {
            summary.in_progress += 1;
            entry.in_progress += 1;
        }
        "done" | "completed" | "success" | "skipped" => {
            summary.completed += 1;
            entry.completed += 1;
        }
        "partial_failed" | "failed" => {
            summary.failed += 1;
            entry.failed += 1;
        }
        "dead_letter" => {
            summary.dead_letter += 1;
            entry.dead_letter += 1;
        }
        _ => {}
    }
}

pub(crate) fn finalize_async_job_summary(
    mut summary: AsyncJobSummary,
    by_kind: HashMap<String, AsyncJobKindSummary>,
) -> AsyncJobSummary {
    summary.kinds = by_kind.into_values().collect::<Vec<_>>();
    summary
        .kinds
        .sort_by(|left, right| left.kind.cmp(&right.kind));
    summary
}

pub(crate) fn summarize_async_job_sources(
    jobs: &[JobStatus],
    replication_backlog: &[ReplicationBacklogItem],
    alert_delivery_queue: &[AlertDeliveryItem],
) -> AsyncJobSummary {
    let mut by_kind = HashMap::<String, AsyncJobKindSummary>::new();
    let mut summary = AsyncJobSummary {
        generated_at: Utc::now(),
        total: replication_backlog.len()
            + alert_delivery_queue.len()
            + jobs.iter().filter(|job| job.status != "idle").count(),
        pending: 0,
        in_progress: 0,
        completed: 0,
        failed: 0,
        dead_letter: 0,
        retryable: 0,
        kinds: Vec::new(),
    };

    for item in replication_backlog {
        let kind = "replication";
        record_async_job_summary(
            &mut summary,
            &mut by_kind,
            kind,
            &item.status,
            async_job_retryable(kind, &item.status),
        );
    }

    for item in alert_delivery_queue {
        let kind = "notification";
        record_async_job_summary(
            &mut summary,
            &mut by_kind,
            kind,
            &item.status,
            async_job_retryable(kind, &item.status),
        );
    }

    for job in jobs {
        if job.status == "idle" {
            continue;
        }
        let kind = normalize_async_job_kind(&job.kind);
        let retryable = async_job_retryable(&kind, &job.status);
        record_async_job_summary(&mut summary, &mut by_kind, &kind, &job.status, retryable);
    }

    finalize_async_job_summary(summary, by_kind)
}

pub(crate) fn summarize_async_jobs(items: &[AsyncJobStatus]) -> AsyncJobSummary {
    let mut by_kind = HashMap::<String, AsyncJobKindSummary>::new();
    let mut summary = AsyncJobSummary {
        generated_at: Utc::now(),
        total: items.len(),
        pending: 0,
        in_progress: 0,
        completed: 0,
        failed: 0,
        dead_letter: 0,
        retryable: 0,
        kinds: Vec::new(),
    };

    for item in items {
        record_async_job_summary(
            &mut summary,
            &mut by_kind,
            &item.kind,
            &item.status,
            item.retryable,
        );
    }
    finalize_async_job_summary(summary, by_kind)
}

pub(crate) async fn list_async_jobs(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<AsyncJobQuery>,
) -> Result<Json<ApiEnvelope<Vec<AsyncJobStatus>>>, AppError> {
    auth.require(Permission::JobsRead)?;
    let mut items = filter_async_jobs(collect_async_jobs(&state).await, &query)?;
    let limit = query.limit.unwrap_or(200).clamp(1, 500);
    items.truncate(limit);
    Ok(wrap(items))
}

pub(crate) async fn async_jobs_page(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<AsyncJobQuery>,
) -> Result<Json<ApiEnvelope<AsyncJobPage>>, AppError> {
    auth.require(Permission::JobsRead)?;
    let mut items = filter_async_jobs(collect_async_jobs(&state).await, &query)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let has_more = items.len() > limit;
    items.truncate(limit);
    let next_cursor = if has_more {
        items.last().map(async_job_cursor_value)
    } else {
        None
    };
    Ok(wrap(AsyncJobPage { items, next_cursor }))
}

pub(crate) async fn async_jobs_summary(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<AsyncJobQuery>,
) -> Result<Json<ApiEnvelope<AsyncJobSummary>>, AppError> {
    auth.require(Permission::JobsRead)?;
    let items = filter_async_jobs(collect_async_jobs(&state).await, &query)?;
    Ok(wrap(summarize_async_jobs(&items)))
}

pub(crate) async fn export_async_jobs(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<AsyncJobQuery>,
) -> Result<impl IntoResponse, AppError> {
    auth.require(Permission::JobsRead)?;
    let items = filter_async_jobs(collect_async_jobs(&state).await, &query)?;
    let body = serde_json::to_string_pretty(&items).map_err(|err| {
        AppError::internal(format!(
            "序列化统一任务导出失败 / failed to serialize async jobs export: {err}"
        ))
    })?;
    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )],
        body,
    ))
}

pub(crate) async fn collect_bulk_async_job_targets(
    state: &Arc<AppState>,
    query: &AsyncJobQuery,
    body: &AsyncJobBulkRequest,
) -> Result<Vec<AsyncJobStatus>, AppError> {
    let mut items = filter_async_jobs(collect_async_jobs(state).await, query)?;
    if !body.job_ids.is_empty() {
        let ids = body.job_ids.iter().cloned().collect::<HashSet<String>>();
        items.retain(|item| ids.contains(&item.job_id));
    }
    Ok(items)
}

pub(crate) async fn retry_async_jobs(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<AsyncJobQuery>,
    Json(body): Json<AsyncJobBulkRequest>,
) -> Result<Json<ApiEnvelope<AsyncJobBulkOperationResult>>, AppError> {
    auth.require(Permission::JobsWrite)?;
    let items = collect_bulk_async_job_targets(&state, &query, &body).await?;
    let matched = items.len();
    let ids = items
        .iter()
        .map(|item| item.job_id.clone())
        .collect::<HashSet<_>>();
    let now = Utc::now();
    let mut updated = 0usize;
    let mut skipped = 0usize;

    {
        let mut backlog = state.replication_backlog.write().await;
        for entry in backlog.iter_mut().filter(|entry| ids.contains(&entry.id)) {
            if async_job_retryable("replication", &entry.status) {
                entry.status = "pending".to_string();
                entry.attempts = 0;
                entry.last_error.clear();
                entry.lease_owner = None;
                entry.lease_until = None;
                entry.last_attempt_at = now;
                updated += 1;
            } else {
                skipped += 1;
            }
        }
    }

    {
        let mut queue = state.alert_delivery_queue.write().await;
        for entry in queue.iter_mut().filter(|entry| ids.contains(&entry.id)) {
            if async_job_retryable("notification", &entry.status) {
                entry.status = "pending".to_string();
                entry.attempts = 0;
                entry.last_error.clear();
                entry.lease_owner = None;
                entry.lease_until = None;
                entry.last_attempt_at = None;
                entry.next_attempt_at = now;
                updated += 1;
            } else {
                skipped += 1;
            }
        }
    }

    {
        let mut jobs = state.jobs.write().await;
        for job in jobs.iter_mut().filter(|job| ids.contains(&job.id)) {
            let kind = normalize_async_job_kind(&job.kind);
            if async_job_retryable(&kind, &job.status) {
                job.status = "pending".to_string();
                job.attempt = 0;
                job.progress = 0.0;
                job.last_error = None;
                job.lease_owner = None;
                job.lease_until = None;
                job.updated_at = now;
                updated += 1;
            } else {
                skipped += 1;
            }
        }
    }

    state.persist_replication_runtime_state().await;
    let remaining = collect_async_jobs(&state).await.len();
    state
        .append_audit(
            &auth.username,
            "jobs.async.retry",
            "jobs/async",
            "success",
            None,
            json!({
                "matched": matched,
                "updated": updated,
                "skipped": skipped,
            }),
        )
        .await;
    Ok(wrap(AsyncJobBulkOperationResult {
        matched,
        updated,
        removed: 0,
        skipped,
        remaining,
    }))
}

pub(crate) async fn cleanup_async_jobs(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<AsyncJobQuery>,
    Json(body): Json<AsyncJobBulkRequest>,
) -> Result<Json<ApiEnvelope<AsyncJobBulkOperationResult>>, AppError> {
    auth.require(Permission::JobsWrite)?;
    let items = collect_bulk_async_job_targets(&state, &query, &body).await?;
    let matched = items.len();
    let targets = items
        .iter()
        .map(|item| (item.job_id.clone(), item.terminal))
        .collect::<HashMap<_, _>>();
    let mut removed = 0usize;
    let mut skipped = 0usize;
    let replication_changed = {
        let before = state.replication_backlog.read().await.len();
        let mut backlog = state.replication_backlog.write().await;
        backlog.retain(|entry| {
            let Some(terminal) = targets.get(&entry.id) else {
                return true;
            };
            if *terminal {
                removed += 1;
                false
            } else {
                skipped += 1;
                true
            }
        });
        before != backlog.len()
    };
    if replication_changed {
        state.persist_replication_runtime_state().await;
    }

    {
        let mut queue = state.alert_delivery_queue.write().await;
        queue.retain(|entry| {
            let Some(terminal) = targets.get(&entry.id) else {
                return true;
            };
            if *terminal {
                removed += 1;
                false
            } else {
                skipped += 1;
                true
            }
        });
    }

    {
        let mut jobs = state.jobs.write().await;
        jobs.retain(|job| {
            let Some(terminal) = targets.get(&job.id) else {
                return true;
            };
            if *terminal {
                removed += 1;
                false
            } else {
                skipped += 1;
                true
            }
        });
    }

    let remaining = collect_async_jobs(&state).await.len();
    state
        .append_audit(
            &auth.username,
            "jobs.async.cleanup",
            "jobs/async",
            "success",
            None,
            json!({
                "matched": matched,
                "removed": removed,
                "skipped": skipped,
            }),
        )
        .await;
    Ok(wrap(AsyncJobBulkOperationResult {
        matched,
        updated: 0,
        removed,
        skipped,
        remaining,
    }))
}

pub(crate) async fn skip_async_jobs(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<AsyncJobQuery>,
    Json(body): Json<AsyncJobBulkRequest>,
) -> Result<Json<ApiEnvelope<AsyncJobBulkOperationResult>>, AppError> {
    auth.require(Permission::JobsWrite)?;
    let items = collect_bulk_async_job_targets(&state, &query, &body).await?;
    let matched = items.len();
    let ids = items
        .iter()
        .map(|item| item.job_id.clone())
        .collect::<HashSet<_>>();
    let now = Utc::now();
    let mut updated = 0usize;
    let mut skipped = 0usize;

    {
        let mut backlog = state.replication_backlog.write().await;
        for entry in backlog.iter_mut().filter(|entry| ids.contains(&entry.id)) {
            if async_job_terminal("replication", &entry.status) {
                skipped += 1;
                continue;
            }
            entry.status = "skipped".to_string();
            entry.last_error = "人工跳过 / skipped by operator".to_string();
            entry.lease_owner = None;
            entry.lease_until = None;
            entry.last_attempt_at = now;
            updated += 1;
        }
    }

    {
        let mut queue = state.alert_delivery_queue.write().await;
        for entry in queue.iter_mut().filter(|entry| ids.contains(&entry.id)) {
            if async_job_terminal("notification", &entry.status) {
                skipped += 1;
                continue;
            }
            entry.status = "skipped".to_string();
            entry.last_error = "人工跳过 / skipped by operator".to_string();
            entry.lease_owner = None;
            entry.lease_until = None;
            entry.last_attempt_at = Some(now);
            entry.next_attempt_at = now;
            updated += 1;
        }
    }

    {
        let mut jobs = state.jobs.write().await;
        for job in jobs.iter_mut().filter(|job| ids.contains(&job.id)) {
            let kind = normalize_async_job_kind(&job.kind);
            if async_job_terminal(&kind, &job.status) {
                skipped += 1;
                continue;
            }
            job.status = "skipped".to_string();
            job.progress = 1.0;
            job.last_error = Some("人工跳过 / skipped by operator".to_string());
            job.lease_owner = None;
            job.lease_until = None;
            job.updated_at = now;
            updated += 1;
        }
    }

    state.persist_replication_runtime_state().await;
    let remaining = collect_async_jobs(&state).await.len();
    state
        .append_audit(
            &auth.username,
            "jobs.async.skip",
            "jobs/async",
            "success",
            None,
            json!({
                "matched": matched,
                "updated": updated,
                "skipped": skipped,
            }),
        )
        .await;
    Ok(wrap(AsyncJobBulkOperationResult {
        matched,
        updated,
        removed: 0,
        skipped,
        remaining,
    }))
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct ReplicationBacklogQuery {
    pub(crate) status: Option<String>,
    pub(crate) source_bucket: Option<String>,
    pub(crate) target_site: Option<String>,
    pub(crate) object_prefix: Option<String>,
    pub(crate) limit: Option<usize>,
    pub(crate) include_terminal: Option<bool>,
    pub(crate) cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReplicationBacklogMetrics {
    pub(crate) total: usize,
    pub(crate) pending: usize,
    pub(crate) in_progress: usize,
    pub(crate) failed: usize,
    pub(crate) dead_letter: usize,
    pub(crate) done: usize,
    pub(crate) retryable: usize,
    pub(crate) non_terminal: usize,
    pub(crate) sites: Vec<ReplicationBacklogSiteMetrics>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReplicationBacklogSiteMetrics {
    pub(crate) site_id: String,
    pub(crate) total: usize,
    pub(crate) pending: usize,
    pub(crate) in_progress: usize,
    pub(crate) failed: usize,
    pub(crate) dead_letter: usize,
    pub(crate) done: usize,
    pub(crate) retryable: usize,
    pub(crate) non_terminal: usize,
    pub(crate) stale_pending: usize,
    pub(crate) max_pending_age_seconds: u64,
    pub(crate) sla_status: String,
    pub(crate) sla_thresholds: ReplicationBacklogSlaThresholds,
    pub(crate) sla_breach_reasons: Vec<String>,
    pub(crate) firing_alerts: usize,
    pub(crate) alert_history_count: usize,
    pub(crate) last_alert_triggered_at: Option<DateTime<Utc>>,
    pub(crate) last_alert_resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReplicationBacklogSlaThresholds {
    pub(crate) failed: usize,
    pub(crate) dead_letter: usize,
    pub(crate) pending_age_seconds: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReplicationBacklogPage {
    pub(crate) items: Vec<ReplicationBacklogItem>,
    pub(crate) next_cursor: Option<String>,
    pub(crate) has_more: bool,
    pub(crate) total: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReplicationBacklogBatchResult {
    pub(crate) matched: usize,
    pub(crate) updated: usize,
    pub(crate) removed: usize,
    pub(crate) skipped: usize,
    pub(crate) remaining: usize,
}

pub(crate) fn replication_status_terminal(status: &str) -> bool {
    matches!(status, "done" | "dead_letter")
}

pub(crate) fn replication_sla_alert_source(site_id: &str) -> String {
    format!("replication-backlog-sla-watchdog:{site_id}")
}

pub(crate) fn replication_json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

pub(crate) fn replication_json_usize(value: &Value, key: &str) -> Option<usize> {
    replication_json_u64(value, key).map(|raw| raw.min(usize::MAX as u64) as usize)
}

pub(crate) fn replication_push_sla_breach_reason(reasons: &mut Vec<String>, reason: &str) {
    if matches!(reason, "failed" | "dead_letter" | "pending_age")
        && !reasons.iter().any(|value| value == reason)
    {
        reasons.push(reason.to_string());
    }
}

pub(crate) fn replication_sla_breach_reasons_from_thresholds(
    failed: usize,
    dead_letter: usize,
    stale_pending: usize,
    max_pending_age_seconds: u64,
    failed_threshold: usize,
    dead_letter_threshold: usize,
    pending_age_threshold_seconds: u64,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if failed_threshold > 0 && failed >= failed_threshold {
        replication_push_sla_breach_reason(&mut reasons, "failed");
    }
    if dead_letter_threshold > 0 && dead_letter >= dead_letter_threshold {
        replication_push_sla_breach_reason(&mut reasons, "dead_letter");
    }
    if pending_age_threshold_seconds > 0
        && stale_pending > 0
        && max_pending_age_seconds >= pending_age_threshold_seconds
    {
        replication_push_sla_breach_reason(&mut reasons, "pending_age");
    }
    reasons
}

pub(crate) fn replication_sla_breach_reasons_from_details(details: &Value) -> Vec<String> {
    let mut reasons = Vec::new();
    if let Some(items) = details.get("breaches").and_then(Value::as_array) {
        for item in items {
            if let Some(reason) = item.as_str() {
                replication_push_sla_breach_reason(&mut reasons, reason);
            }
        }
    }
    if !reasons.is_empty() {
        return reasons;
    }
    let failed = replication_json_usize(details, "failed").unwrap_or(0);
    let dead_letter = replication_json_usize(details, "dead_letter").unwrap_or(0);
    let stale_pending = replication_json_usize(details, "stale_pending").unwrap_or(0);
    let max_pending_age_seconds =
        replication_json_u64(details, "max_pending_age_seconds").unwrap_or(0);
    let failed_threshold = replication_json_usize(details, "failed_threshold").unwrap_or(0);
    let dead_letter_threshold =
        replication_json_usize(details, "dead_letter_threshold").unwrap_or(0);
    let pending_age_threshold_seconds =
        replication_json_u64(details, "pending_age_threshold_seconds").unwrap_or(0);
    replication_sla_breach_reasons_from_thresholds(
        failed,
        dead_letter,
        stale_pending,
        max_pending_age_seconds,
        failed_threshold,
        dead_letter_threshold,
        pending_age_threshold_seconds,
    )
}

pub(crate) fn replication_backlog_sort_desc(backlog: &mut [ReplicationBacklogItem]) {
    backlog.sort_by(|left, right| {
        right
            .queued_at
            .cmp(&left.queued_at)
            .then_with(|| right.id.cmp(&left.id))
    });
}

pub(crate) fn parse_replication_backlog_cursor(
    cursor: Option<&str>,
) -> Result<Option<(i64, String)>, AppError> {
    let Some(raw) = cursor else {
        return Ok(None);
    };
    let token = raw.trim();
    if token.is_empty() {
        return Ok(None);
    }
    let mut parts = token.splitn(2, '|');
    let Some(ts_raw) = parts.next() else {
        return Err(AppError::bad_request(
            "复制游标格式无效 / invalid replication cursor format",
        ));
    };
    let Some(id_raw) = parts.next() else {
        return Err(AppError::bad_request(
            "复制游标格式无效 / invalid replication cursor format",
        ));
    };
    let ts = ts_raw.parse::<i64>().map_err(|_| {
        AppError::bad_request("复制游标时间戳无效 / invalid replication cursor timestamp")
    })?;
    let id = id_raw.trim().to_string();
    if id.is_empty() {
        return Err(AppError::bad_request(
            "复制游标对象无效 / invalid replication cursor id",
        ));
    }
    Ok(Some((ts, id)))
}

pub(crate) fn replication_backlog_cursor_value(item: &ReplicationBacklogItem) -> String {
    format!("{}|{}", item.queued_at.timestamp_millis(), item.id)
}

pub(crate) fn replication_backlog_after_cursor(
    item: &ReplicationBacklogItem,
    cursor: &(i64, String),
) -> bool {
    let ts = item.queued_at.timestamp_millis();
    ts < cursor.0 || (ts == cursor.0 && item.id < cursor.1)
}

pub(crate) fn parse_replication_status_filter(
    status: Option<&str>,
) -> Result<Option<HashSet<String>>, AppError> {
    let Some(raw) = status else {
        return Ok(None);
    };
    let mut set = HashSet::new();
    for token in raw.split(',') {
        let item = token.trim().to_ascii_lowercase();
        if item.is_empty() {
            continue;
        }
        if !matches!(
            item.as_str(),
            "pending" | "in_progress" | "failed" | "dead_letter" | "done"
        ) {
            return Err(AppError::bad_request(
                "复制状态过滤参数无效 / invalid replication status filter",
            ));
        }
        set.insert(item);
    }
    Ok(Some(set))
}

pub(crate) fn replication_backlog_match_query(
    item: &ReplicationBacklogItem,
    query: &ReplicationBacklogQuery,
    status_filter: Option<&HashSet<String>>,
) -> bool {
    if query.include_terminal == Some(false) && replication_status_terminal(&item.status) {
        return false;
    }
    if let Some(filter) = status_filter {
        if !filter.contains(&item.status) {
            return false;
        }
    }
    if let Some(bucket) = query.source_bucket.as_deref() {
        if item.source_bucket != bucket {
            return false;
        }
    }
    if let Some(site) = query.target_site.as_deref() {
        if item.target_site != site {
            return false;
        }
    }
    if let Some(prefix) = query.object_prefix.as_deref() {
        if !item.object_key.starts_with(prefix) {
            return false;
        }
    }
    true
}

#[derive(Default)]
pub(crate) struct ReplicationBacklogSiteAgg {
    pub(crate) total: usize,
    pub(crate) pending: usize,
    pub(crate) in_progress: usize,
    pub(crate) failed: usize,
    pub(crate) dead_letter: usize,
    pub(crate) done: usize,
    pub(crate) retryable: usize,
    pub(crate) non_terminal: usize,
    pub(crate) stale_pending: usize,
    pub(crate) max_pending_age_seconds: u64,
}

pub(crate) fn compute_replication_backlog_metrics(
    backlog: &[ReplicationBacklogItem],
    alert_history: &[AlertHistoryEntry],
    site_replications: &[SiteReplicationStatus],
    query: &ReplicationBacklogQuery,
    status_filter: Option<&HashSet<String>>,
    now: DateTime<Utc>,
) -> ReplicationBacklogMetrics {
    let (failed_threshold, dead_letter_threshold, pending_age_threshold_seconds) =
        AppState::replication_backlog_alert_threshold_snapshot();
    let site_ids = site_replications
        .iter()
        .map(|site| site.site_id.clone())
        .collect::<HashSet<_>>();
    let mut metrics = ReplicationBacklogMetrics {
        total: 0,
        pending: 0,
        in_progress: 0,
        failed: 0,
        dead_letter: 0,
        done: 0,
        retryable: 0,
        non_terminal: 0,
        sites: Vec::new(),
    };
    let mut per_site = HashMap::<String, ReplicationBacklogSiteAgg>::new();
    for item in backlog {
        if !replication_backlog_match_query(item, query, status_filter) {
            continue;
        }
        let site = per_site.entry(item.target_site.clone()).or_default();
        metrics.total += 1;
        site.total += 1;
        match item.status.as_str() {
            "pending" => {
                metrics.pending += 1;
                metrics.retryable += 1;
                metrics.non_terminal += 1;
                site.pending += 1;
                site.retryable += 1;
                site.non_terminal += 1;
                let age = now
                    .signed_duration_since(item.queued_at)
                    .num_seconds()
                    .max(0) as u64;
                site.max_pending_age_seconds = site.max_pending_age_seconds.max(age);
                if pending_age_threshold_seconds > 0 && age >= pending_age_threshold_seconds {
                    site.stale_pending += 1;
                }
            }
            "in_progress" => {
                metrics.in_progress += 1;
                metrics.non_terminal += 1;
                site.in_progress += 1;
                site.non_terminal += 1;
            }
            "failed" => {
                metrics.failed += 1;
                metrics.retryable += 1;
                metrics.non_terminal += 1;
                site.failed += 1;
                site.retryable += 1;
                site.non_terminal += 1;
            }
            "dead_letter" => {
                metrics.dead_letter += 1;
                site.dead_letter += 1;
            }
            "done" => {
                metrics.done += 1;
                site.done += 1;
            }
            _ => {
                metrics.non_terminal += 1;
                site.non_terminal += 1;
            }
        }
    }

    let mut site_keys = per_site
        .keys()
        .cloned()
        .chain(site_ids)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    site_keys.sort();

    for site_id in site_keys {
        let source = replication_sla_alert_source(&site_id);
        let site_agg = per_site.remove(&site_id).unwrap_or_default();
        let mut firing_alerts = 0usize;
        let mut alert_history_count = 0usize;
        let mut last_alert_triggered_at = None::<DateTime<Utc>>;
        let mut last_alert_resolved_at = None::<DateTime<Utc>>;
        let mut latest_firing_triggered_at = None::<DateTime<Utc>>;
        let mut sla_breach_reasons = Vec::<String>::new();
        for entry in alert_history.iter().filter(|entry| entry.source == source) {
            alert_history_count += 1;
            if entry.status == "firing" && entry.resolved_at.is_none() {
                firing_alerts += 1;
                if latest_firing_triggered_at
                    .map(|value| entry.triggered_at > value)
                    .unwrap_or(true)
                {
                    sla_breach_reasons =
                        replication_sla_breach_reasons_from_details(&entry.details);
                    latest_firing_triggered_at = Some(entry.triggered_at);
                }
            }
            if last_alert_triggered_at
                .map(|value| entry.triggered_at > value)
                .unwrap_or(true)
            {
                last_alert_triggered_at = Some(entry.triggered_at);
            }
            if let Some(resolved_at) = entry.resolved_at {
                if last_alert_resolved_at
                    .map(|value| resolved_at > value)
                    .unwrap_or(true)
                {
                    last_alert_resolved_at = Some(resolved_at);
                }
            }
        }
        if firing_alerts > 0 && sla_breach_reasons.is_empty() {
            sla_breach_reasons = replication_sla_breach_reasons_from_thresholds(
                site_agg.failed,
                site_agg.dead_letter,
                site_agg.stale_pending,
                site_agg.max_pending_age_seconds,
                failed_threshold,
                dead_letter_threshold,
                pending_age_threshold_seconds,
            );
        }
        metrics.sites.push(ReplicationBacklogSiteMetrics {
            site_id,
            total: site_agg.total,
            pending: site_agg.pending,
            in_progress: site_agg.in_progress,
            failed: site_agg.failed,
            dead_letter: site_agg.dead_letter,
            done: site_agg.done,
            retryable: site_agg.retryable,
            non_terminal: site_agg.non_terminal,
            stale_pending: site_agg.stale_pending,
            max_pending_age_seconds: site_agg.max_pending_age_seconds,
            sla_status: if firing_alerts > 0 {
                "firing".to_string()
            } else {
                "healthy".to_string()
            },
            sla_thresholds: ReplicationBacklogSlaThresholds {
                failed: failed_threshold,
                dead_letter: dead_letter_threshold,
                pending_age_seconds: pending_age_threshold_seconds,
            },
            sla_breach_reasons,
            firing_alerts,
            alert_history_count,
            last_alert_triggered_at,
            last_alert_resolved_at,
        });
    }

    metrics
        .sites
        .sort_by(|left, right| left.site_id.cmp(&right.site_id));
    metrics
}

pub(crate) async fn list_replication_backlog(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<ReplicationBacklogQuery>,
) -> Result<Json<ApiEnvelope<Vec<ReplicationBacklogItem>>>, AppError> {
    auth.require(Permission::ReplicationRead)?;
    let status_filter = parse_replication_status_filter(query.status.as_deref())?;
    let cursor = parse_replication_backlog_cursor(query.cursor.as_deref())?;
    let limit = query.limit.unwrap_or(500).clamp(1, 5000);
    let mut backlog = state.replication_backlog.read().await.clone();
    backlog.retain(|item| replication_backlog_match_query(item, &query, status_filter.as_ref()));
    if let Some(cursor) = cursor.as_ref() {
        backlog.retain(|item| replication_backlog_after_cursor(item, cursor));
    }
    replication_backlog_sort_desc(&mut backlog);
    backlog.truncate(limit);
    Ok(wrap(backlog))
}

pub(crate) async fn replication_backlog_page(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<ReplicationBacklogQuery>,
) -> Result<Json<ApiEnvelope<ReplicationBacklogPage>>, AppError> {
    auth.require(Permission::ReplicationRead)?;
    let status_filter = parse_replication_status_filter(query.status.as_deref())?;
    let cursor = parse_replication_backlog_cursor(query.cursor.as_deref())?;
    let limit = query.limit.unwrap_or(100).clamp(1, 2000);
    let mut backlog = state.replication_backlog.read().await.clone();
    backlog.retain(|item| replication_backlog_match_query(item, &query, status_filter.as_ref()));
    if let Some(cursor) = cursor.as_ref() {
        backlog.retain(|item| replication_backlog_after_cursor(item, cursor));
    }
    replication_backlog_sort_desc(&mut backlog);
    let total = backlog.len();
    let has_more = total > limit;
    backlog.truncate(limit);
    let next_cursor = if has_more {
        backlog.last().map(replication_backlog_cursor_value)
    } else {
        None
    };
    Ok(wrap(ReplicationBacklogPage {
        items: backlog,
        next_cursor,
        has_more,
        total,
    }))
}

pub(crate) async fn replication_backlog_metrics(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<ReplicationBacklogQuery>,
) -> Result<Json<ApiEnvelope<ReplicationBacklogMetrics>>, AppError> {
    auth.require(Permission::ReplicationRead)?;
    let now = Utc::now();
    let status_filter = parse_replication_status_filter(query.status.as_deref())?;
    let backlog = state.replication_backlog.read().await.clone();
    let alert_history = state.alert_history.read().await.clone();
    let site_replications = state.site_replications.read().await.clone();
    Ok(wrap(compute_replication_backlog_metrics(
        &backlog,
        &alert_history,
        &site_replications,
        &query,
        status_filter.as_ref(),
        now,
    )))
}

pub(crate) async fn retry_matched_replication_backlog(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<ReplicationBacklogQuery>,
) -> Result<Json<ApiEnvelope<ReplicationBacklogBatchResult>>, AppError> {
    auth.require(Permission::ReplicationWrite)?;
    let status_filter = parse_replication_status_filter(query.status.as_deref())?;
    let cursor = parse_replication_backlog_cursor(query.cursor.as_deref())?;
    let limit = query.limit.unwrap_or(500).clamp(1, 5000);

    let mut backlog = state.replication_backlog.write().await;
    let mut indexed = backlog
        .iter()
        .enumerate()
        .filter(|(_, item)| replication_backlog_match_query(item, &query, status_filter.as_ref()))
        .filter(|(_, item)| {
            cursor
                .as_ref()
                .map(|cursor| replication_backlog_after_cursor(item, cursor))
                .unwrap_or(true)
        })
        .map(|(index, item)| (index, item.queued_at, item.id.clone()))
        .collect::<Vec<_>>();
    indexed.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| right.2.cmp(&left.2)));
    indexed.truncate(limit);

    let matched = indexed.len();
    let mut updated = 0usize;
    let mut skipped = 0usize;
    for (index, _, _) in indexed {
        let Some(item) = backlog.get_mut(index) else {
            continue;
        };
        if item.status == "failed" || item.status == "in_progress" || item.status == "dead_letter" {
            item.status = "pending".to_string();
            item.attempts = 0;
            item.last_error.clear();
            item.last_attempt_at = Utc::now();
            updated += 1;
        } else {
            skipped += 1;
        }
    }
    let remaining = backlog.len();
    drop(backlog);
    state.persist_replication_runtime_state().await;

    state
        .append_audit(
            &auth.username,
            "replication.backlog.retry_matched",
            "replication/backlog",
            "success",
            None,
            json!({
                "matched": matched,
                "updated": updated,
                "skipped": skipped,
                "remaining": remaining,
            }),
        )
        .await;

    Ok(wrap(ReplicationBacklogBatchResult {
        matched,
        updated,
        removed: 0,
        skipped,
        remaining,
    }))
}

pub(crate) async fn cleanup_replication_backlog(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<ReplicationBacklogQuery>,
) -> Result<Json<ApiEnvelope<ReplicationBacklogBatchResult>>, AppError> {
    auth.require(Permission::ReplicationWrite)?;
    let status_filter = parse_replication_status_filter(query.status.as_deref())?;
    let cursor = parse_replication_backlog_cursor(query.cursor.as_deref())?;
    let limit = query.limit.unwrap_or(500).clamp(1, 5000);

    let mut backlog = state.replication_backlog.write().await;
    let mut indexed = backlog
        .iter()
        .enumerate()
        .filter(|(_, item)| replication_backlog_match_query(item, &query, status_filter.as_ref()))
        .filter(|(_, item)| {
            cursor
                .as_ref()
                .map(|cursor| replication_backlog_after_cursor(item, cursor))
                .unwrap_or(true)
        })
        .map(|(index, item)| (index, item.queued_at, item.id.clone()))
        .collect::<Vec<_>>();
    indexed.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| right.2.cmp(&left.2)));
    indexed.truncate(limit);

    let matched = indexed.len();
    let selected_ids = indexed
        .iter()
        .filter_map(|(index, _, _)| backlog.get(*index).map(|item| item.id.clone()))
        .collect::<HashSet<_>>();

    let mut removed = 0usize;
    let mut skipped = 0usize;
    backlog.retain(|item| {
        if !selected_ids.contains(&item.id) {
            return true;
        }
        if item.status == "done" || item.status == "dead_letter" {
            removed += 1;
            return false;
        }
        skipped += 1;
        true
    });

    let remaining = backlog.len();
    drop(backlog);
    state.persist_replication_runtime_state().await;

    state
        .append_audit(
            &auth.username,
            "replication.backlog.cleanup",
            "replication/backlog",
            "success",
            None,
            json!({
                "matched": matched,
                "removed": removed,
                "skipped": skipped,
                "remaining": remaining,
            }),
        )
        .await;

    Ok(wrap(ReplicationBacklogBatchResult {
        matched,
        updated: 0,
        removed,
        skipped,
        remaining,
    }))
}

pub(crate) async fn retry_replication_backlog_item(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::ReplicationWrite)?;

    let mut backlog = state.replication_backlog.write().await;
    let item = backlog
        .iter_mut()
        .find(|entry| entry.id == id)
        .ok_or_else(|| {
            AppError::not_found("复制积压项不存在 / replication backlog item not found")
        })?;
    item.status = "pending".to_string();
    item.attempts = 0;
    item.last_error.clear();
    item.last_attempt_at = Utc::now();
    let snapshot = item.clone();
    let remaining = backlog.len();
    drop(backlog);
    state.persist_replication_runtime_state().await;

    state
        .append_audit(
            &auth.username,
            "replication.backlog.retry",
            &format!("replication/backlog/{id}"),
            "success",
            None,
            json!({
                "source_bucket": snapshot.source_bucket,
                "target_site": snapshot.target_site,
                "object_key": snapshot.object_key,
                "attempts": snapshot.attempts,
                "remaining": remaining,
            }),
        )
        .await;
    state
        .push_event(
            "replication.backlog.retried",
            "replication-engine",
            json!({ "id": id, "remaining": remaining }),
        )
        .await;

    Ok(wrap(
        json!({ "retried": true, "id": id, "remaining": remaining }),
    ))
}

pub(crate) async fn retry_all_replication_backlog(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::ReplicationWrite)?;

    let mut backlog = state.replication_backlog.write().await;
    let mut retried = 0usize;
    for item in backlog.iter_mut() {
        if item.status == "failed" || item.status == "in_progress" || item.status == "dead_letter" {
            item.status = "pending".to_string();
            item.attempts = 0;
            item.last_error.clear();
            item.last_attempt_at = Utc::now();
            retried += 1;
        }
    }
    drop(backlog);
    state.persist_replication_runtime_state().await;

    state
        .append_audit(
            &auth.username,
            "replication.backlog.retry_all",
            "replication/backlog",
            "success",
            None,
            json!({ "retried": retried }),
        )
        .await;
    state
        .push_event(
            "replication.backlog.retried_all",
            "replication-engine",
            json!({ "retried": retried }),
        )
        .await;

    Ok(wrap(json!({ "retried": retried })))
}

pub(crate) async fn start_heal_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<StorageJobRequest>,
) -> Result<Json<ApiEnvelope<JobStatus>>, AppError> {
    auth.require(Permission::JobsWrite)?;
    let kind = normalize_storage_job_kind_request(body.kind.as_deref())?;
    let target = body.target.clone().unwrap_or_else(|| {
        storage_job_target_display("cluster", body.bucket.as_deref(), body.key.as_deref())
    });
    let job = upsert_storage_job(
        state.as_ref(),
        StorageJobDraft {
            kind: kind.clone(),
            target: target.clone(),
            bucket: body.bucket.clone(),
            key: body.key.clone(),
            version_id: body.version_id.clone(),
            priority: body.priority,
            affected_disks: vec![],
            missing_shards: 0,
            corrupted_shards: 0,
            source: "manual".to_string(),
            details: json!({
                "requested_kind": kind,
                "requested_target": target,
            }),
        },
        "pending",
    )
    .await;

    state
        .append_audit(
            &auth.username,
            &format!("job.{}.start", storage_job_kind_label(&job.kind)),
            &format!("jobs/{}", storage_job_kind_label(&job.kind)),
            "success",
            None,
            json!({
                "target": target,
                "job_id": job.id,
                "bucket": job.bucket,
                "key": job.key,
                "version_id": job.version_id,
                "priority": job.priority,
            }),
        )
        .await;
    state
        .push_event(
            "job.storage.queued",
            "job-orchestrator",
            json!({
                "job_id": job.id,
                "kind": storage_job_kind_label(&job.kind),
                "target": job.target,
            }),
        )
        .await;

    Ok(wrap(job))
}

pub(crate) async fn cancel_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<JobStatus>>, AppError> {
    auth.require(Permission::JobsWrite)?;
    ensure_confirm_header(&headers)?;

    let mut jobs = state.jobs.write().await;
    let job = jobs
        .iter_mut()
        .find(|j| j.id == id)
        .ok_or_else(|| AppError::not_found("作业不存在 / job not found"))?;
    job.status = "cancelled".to_string();
    job.updated_at = Utc::now();
    job.finished_at = Some(job.updated_at);
    let snapshot = job.clone();

    state
        .append_audit(
            &auth.username,
            "job.cancel",
            &format!("job/{}", snapshot.id),
            "success",
            Some(body.reason),
            json!({}),
        )
        .await;

    Ok(wrap(snapshot))
}

pub(crate) async fn retry_job(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<ApiEnvelope<JobStatus>>, AppError> {
    auth.require(Permission::JobsWrite)?;
    let mut jobs = state.jobs.write().await;
    let job = jobs
        .iter_mut()
        .find(|item| item.id == id)
        .ok_or_else(|| AppError::not_found("作业不存在 / job not found"))?;
    if !matches!(job.status.as_str(), "failed" | "cancelled" | "completed") {
        return Err(AppError::bad_request(
            "只有失败、已取消或已完成的任务可以重试 / only failed, cancelled or completed jobs can be retried",
        ));
    }
    job.status = "pending".to_string();
    job.progress = 0.0;
    job.updated_at = Utc::now();
    job.finished_at = None;
    job.next_attempt_at = None;
    job.error = None;
    let snapshot = job.clone();
    drop(jobs);

    state
        .append_audit(
            &auth.username,
            "job.retry",
            &format!("job/{}", snapshot.id),
            "success",
            None,
            json!({
                "kind": snapshot.kind,
                "target": snapshot.target,
            }),
        )
        .await;
    state
        .push_event(
            "job.storage.retried",
            "job-orchestrator",
            json!({ "job_id": snapshot.id }),
        )
        .await;
    Ok(wrap(snapshot))
}

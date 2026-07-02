//! 托管异步任务、生命周期与站点复制作业执行

use super::*;

impl AppState {
    pub(crate) fn managed_async_job_worker_interval() -> std::time::Duration {
        let millis = std::env::var("RUSTIO_ASYNC_JOB_WORKER_INTERVAL_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(200);
        std::time::Duration::from_millis(millis)
    }

    pub(crate) fn managed_async_job_lease_interval() -> std::time::Duration {
        let millis = std::env::var("RUSTIO_ASYNC_JOB_LEASE_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(5_000);
        std::time::Duration::from_millis(millis)
    }

    pub(crate) fn managed_async_job_max_attempts() -> u32 {
        std::env::var("RUSTIO_ASYNC_JOB_MAX_ATTEMPTS")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(3)
    }

    pub(crate) fn managed_async_job_kind(kind: &str) -> Option<&'static str> {
        let normalized = kind.trim().to_ascii_lowercase();
        if normalized.starts_with("batch:") {
            None
        } else if normalized.contains("lifecycle") {
            Some("lifecycle")
        } else if normalized.contains("site-bootstrap") || normalized.contains("bootstrap") {
            Some("site-bootstrap")
        } else if normalized.contains("site-join") || normalized.contains("join") {
            Some("site-join")
        } else if normalized.contains("site-resync") || normalized.contains("resync") {
            Some("site-resync")
        } else if normalized.contains("site-reconcile") || normalized.contains("reconcile") {
            Some("site-reconcile")
        } else if normalized.contains("failover") {
            Some("failover")
        } else if normalized.contains("failback") {
            Some("failback")
        } else {
            None
        }
    }

    pub(crate) fn managed_async_job_dedupe_key(job: &JobStatus) -> String {
        job.payload
            .get("dedupe_key")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.to_string())
            .unwrap_or_else(|| job.idempotency_key.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_managed_async_job(
        &self,
        kind: &str,
        priority: u8,
        bucket: Option<String>,
        object_key: Option<String>,
        site_id: Option<String>,
        idempotency_key: String,
        checkpoint: Option<u64>,
        payload: Value,
    ) -> JobStatus {
        let now = Utc::now();
        let mut payload_map = payload.as_object().cloned().unwrap_or_default();
        payload_map
            .entry("dedupe_key".to_string())
            .or_insert_with(|| Value::String(idempotency_key.clone()));
        JobStatus {
            id: format!("job-{}-{}", kind.replace(':', "-"), Uuid::new_v4().simple()),
            kind: kind.to_string(),
            status: "pending".to_string(),
            priority: i32::from(priority),
            bucket,
            object_key,
            site_id,
            idempotency_key,
            attempt: 0,
            lease_owner: None,
            lease_until: None,
            checkpoint,
            last_error: None,
            payload: Value::Object(payload_map),
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
            dedupe_key: None,
            source: None,
            details: Value::Null,
        }
    }

    pub(crate) async fn mutate_job<F>(&self, job_id: &str, mutator: F) -> Option<JobStatus>
    where
        F: FnOnce(&mut JobStatus),
    {
        let mut jobs = self.jobs.write().await;
        let job = jobs.iter_mut().find(|job| job.id == job_id)?;
        mutator(job);
        Some(job.clone())
    }

    pub(crate) async fn enqueue_lifecycle_job_if_absent(&self, job: JobStatus) -> bool {
        let dedupe_key = Self::managed_async_job_dedupe_key(&job);
        let mut blocked = false;
        let mut jobs = self.jobs.write().await;
        jobs.retain(|existing| {
            if Self::managed_async_job_kind(&existing.kind) != Some("lifecycle")
                || Self::managed_async_job_dedupe_key(existing) != dedupe_key
            {
                return true;
            }
            match existing.status.as_str() {
                "pending" => false,
                "in_progress" | "running" | "failed" | "dead_letter" => {
                    blocked = true;
                    true
                }
                _ => true,
            }
        });
        if blocked {
            return false;
        }
        jobs.push(job);
        true
    }

    pub(crate) fn lifecycle_job_matches_existing_filters(
        existing_jobs: &[JobStatus],
        dedupe_key: &str,
        statuses: Option<&HashSet<String>>,
        retry_only_failed: bool,
    ) -> bool {
        if statuses.is_none() && !retry_only_failed {
            return true;
        }
        existing_jobs.iter().any(|job| {
            if Self::managed_async_job_kind(&job.kind) != Some("lifecycle") {
                return false;
            }
            if Self::managed_async_job_dedupe_key(job) != dedupe_key {
                return false;
            }
            let normalized_status = job.status.trim().to_ascii_lowercase();
            if retry_only_failed && !matches!(normalized_status.as_str(), "failed" | "dead_letter")
            {
                return false;
            }
            statuses
                .map(|filter| filter.contains(&normalized_status))
                .unwrap_or(true)
        })
    }

    pub(crate) fn lifecycle_current_job_draft(
        &self,
        bucket: &str,
        meta: &S3ObjectMeta,
        active_rules: &[BucketLifecycleRule],
        remote_tiers: &HashMap<String, RemoteTierConfig>,
        now: DateTime<Utc>,
    ) -> Option<LifecycleJobDraft> {
        let transition_tier = active_rules.iter().find_map(|rule| {
            if !Self::lifecycle_rule_matches(rule, &meta.key) {
                return None;
            }
            let tier = Self::lifecycle_current_transition_target(rule, meta, now)?;
            remote_tiers
                .get(&tier)
                .filter(|config| config.enabled)
                .map(|_| tier)
        });
        if let Some(tier) = transition_tier {
            let idempotency_key = format!(
                "lifecycle:transition-current:{}:{}:{}:{}",
                bucket, meta.key, meta.version_id, tier
            );
            return Some(LifecycleJobDraft {
                kind: "lifecycle:transition-current".to_string(),
                bucket: bucket.to_string(),
                object_key: meta.key.clone(),
                idempotency_key: idempotency_key.clone(),
                payload: json!({
                    "mode": "transition-current",
                    "version_id": meta.version_id,
                    "tier": tier,
                    "dedupe_key": idempotency_key,
                }),
            });
        }

        let should_expire = active_rules.iter().any(|rule| {
            Self::lifecycle_rule_matches(rule, &meta.key)
                && rule
                    .expiration_days
                    .map(|days| {
                        now.signed_duration_since(meta.created_at) >= Duration::days(days as i64)
                    })
                    .unwrap_or(false)
        });
        if !should_expire {
            return None;
        }

        let idempotency_key = format!(
            "lifecycle:current:{}:{}:{}",
            bucket, meta.key, meta.version_id
        );
        Some(LifecycleJobDraft {
            kind: "lifecycle:current".to_string(),
            bucket: bucket.to_string(),
            object_key: meta.key.clone(),
            idempotency_key: idempotency_key.clone(),
            payload: json!({
                "mode": "current",
                "version_id": meta.version_id,
                "dedupe_key": idempotency_key,
            }),
        })
    }

    pub(crate) fn lifecycle_noncurrent_job_draft(
        &self,
        bucket: &str,
        meta: &S3ObjectMeta,
        active_rules: &[BucketLifecycleRule],
        remote_tiers: &HashMap<String, RemoteTierConfig>,
        now: DateTime<Utc>,
    ) -> Option<LifecycleJobDraft> {
        let transition_tier = active_rules.iter().find_map(|rule| {
            if !Self::lifecycle_rule_matches(rule, &meta.key) {
                return None;
            }
            let tier = Self::lifecycle_noncurrent_transition_target(rule, meta, now)?;
            remote_tiers
                .get(&tier)
                .filter(|config| config.enabled)
                .map(|_| tier)
        });
        if let Some(tier) = transition_tier {
            let idempotency_key = format!(
                "lifecycle:transition-noncurrent:{}:{}:{}:{}",
                bucket, meta.key, meta.version_id, tier
            );
            return Some(LifecycleJobDraft {
                kind: "lifecycle:transition-noncurrent".to_string(),
                bucket: bucket.to_string(),
                object_key: meta.key.clone(),
                idempotency_key: idempotency_key.clone(),
                payload: json!({
                    "mode": "transition-noncurrent",
                    "version_id": meta.version_id,
                    "tier": tier,
                    "dedupe_key": idempotency_key,
                }),
            });
        }

        let should_expire = active_rules.iter().any(|rule| {
            Self::lifecycle_rule_matches(rule, &meta.key)
                && rule
                    .noncurrent_expiration_days
                    .map(|days| {
                        now.signed_duration_since(meta.created_at) >= Duration::days(days as i64)
                    })
                    .unwrap_or(false)
        });
        if !should_expire {
            return None;
        }

        let idempotency_key = format!(
            "lifecycle:noncurrent:{}:{}:{}",
            bucket, meta.key, meta.version_id
        );
        Some(LifecycleJobDraft {
            kind: "lifecycle:noncurrent".to_string(),
            bucket: bucket.to_string(),
            object_key: meta.key.clone(),
            idempotency_key: idempotency_key.clone(),
            payload: json!({
                "mode": "noncurrent",
                "version_id": meta.version_id,
                "dedupe_key": idempotency_key,
            }),
        })
    }

    pub(crate) fn build_lifecycle_job_from_draft(&self, draft: &LifecycleJobDraft) -> JobStatus {
        let checkpoint = self.next_replication_checkpoint();
        self.build_managed_async_job(
            &draft.kind,
            1,
            Some(draft.bucket.clone()),
            Some(draft.object_key.clone()),
            None,
            draft.idempotency_key.clone(),
            Some(checkpoint),
            draft.payload.clone(),
        )
    }

    pub(crate) async fn enqueue_lifecycle_batch_job(&self, draft: &LifecycleJobDraft) -> bool {
        let job = self.build_lifecycle_job_from_draft(draft);
        let dedupe_key = Self::managed_async_job_dedupe_key(&job);
        let mut blocked = false;
        let mut jobs = self.jobs.write().await;
        jobs.retain(|existing| {
            if Self::managed_async_job_kind(&existing.kind) != Some("lifecycle")
                || Self::managed_async_job_dedupe_key(existing) != dedupe_key
            {
                return true;
            }
            if matches!(existing.status.as_str(), "in_progress" | "running") {
                blocked = true;
                return true;
            }
            false
        });
        if blocked {
            return false;
        }
        jobs.push(job);
        true
    }

    pub async fn enqueue_lifecycle_batch_run(
        &self,
        scope: &BatchRunScope,
    ) -> Result<(usize, usize, usize), String> {
        let bucket = scope.source_bucket.as_deref().ok_or_else(|| {
            bilingual_runtime_error(
                "生命周期批处理必须提供源桶",
                "lifecycle batch run requires source bucket",
            )
        })?;
        let rules = self
            .bucket_lifecycle_rules
            .read()
            .await
            .get(bucket)
            .cloned()
            .unwrap_or_default();
        let active_rules = rules
            .into_iter()
            .filter(|rule| {
                rule.status.eq_ignore_ascii_case("enabled")
                    && scope
                        .rule_id
                        .as_deref()
                        .map(|rule_id| rule.id == rule_id)
                        .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        if active_rules.is_empty() {
            return Err(bilingual_runtime_error(
                "未找到匹配的启用生命周期规则",
                "no enabled lifecycle rule matched this batch run",
            ));
        }

        let remote_tiers = self.remote_tiers.read().await.clone();
        let existing_jobs = self.jobs.read().await.clone();
        let status_filter = (!scope.statuses.is_empty())
            .then(|| scope.statuses.iter().cloned().collect::<HashSet<String>>());
        let now = Utc::now();
        let bucket_root = self.lifecycle_bucket_root(bucket).await;
        let archived_meta_root = bucket_root.join(".rustio_versions");
        // current 已下沉 redb,直接 scan_bucket;archived 仍是 .rustio_versions JSON。
        let current_metas = self.meta_store.scan_bucket(bucket).unwrap_or_default();
        let archived_metas = Self::lifecycle_scan_object_metas(&archived_meta_root, bucket);
        let mut candidates = Vec::<LifecycleJobDraft>::new();

        if !scope.noncurrent_only {
            for meta in current_metas {
                if meta.delete_marker {
                    continue;
                }
                if scope
                    .object_prefix
                    .as_deref()
                    .map(|prefix| !meta.key.starts_with(prefix))
                    .unwrap_or(false)
                {
                    continue;
                }
                let Some(draft) = self.lifecycle_current_job_draft(
                    bucket,
                    &meta,
                    &active_rules,
                    &remote_tiers,
                    now,
                ) else {
                    continue;
                };
                if !Self::lifecycle_job_matches_existing_filters(
                    &existing_jobs,
                    &draft.idempotency_key,
                    status_filter.as_ref(),
                    scope.retry_only_failed,
                ) {
                    continue;
                }
                candidates.push(draft);
            }
        }

        if !scope.current_only {
            for meta in archived_metas {
                if scope
                    .object_prefix
                    .as_deref()
                    .map(|prefix| !meta.key.starts_with(prefix))
                    .unwrap_or(false)
                {
                    continue;
                }
                let Some(draft) = self.lifecycle_noncurrent_job_draft(
                    bucket,
                    &meta,
                    &active_rules,
                    &remote_tiers,
                    now,
                ) else {
                    continue;
                };
                if !Self::lifecycle_job_matches_existing_filters(
                    &existing_jobs,
                    &draft.idempotency_key,
                    status_filter.as_ref(),
                    scope.retry_only_failed,
                ) {
                    continue;
                }
                candidates.push(draft);
            }
        }

        candidates.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.object_key.cmp(&right.object_key))
                .then_with(|| left.idempotency_key.cmp(&right.idempotency_key))
        });

        let matched = candidates.len();
        let selected = scope.limit.unwrap_or(matched).min(matched);
        let mut enqueued = 0usize;
        for draft in candidates.into_iter().take(selected) {
            if self.enqueue_lifecycle_batch_job(&draft).await {
                enqueued += 1;
            }
        }

        Ok((matched, enqueued, matched.saturating_sub(enqueued)))
    }

    pub async fn enqueue_switch_job(&self, job: JobStatus) -> Result<JobStatus, String> {
        let dedupe_key = Self::managed_async_job_dedupe_key(&job);
        let kind = Self::managed_async_job_kind(&job.kind).unwrap_or("switch");
        let mut jobs = self.jobs.write().await;
        if jobs.iter().any(|existing| {
            Self::managed_async_job_kind(&existing.kind) == Some(kind)
                && Self::managed_async_job_dedupe_key(existing) == dedupe_key
                && matches!(
                    existing.status.as_str(),
                    "pending" | "in_progress" | "running"
                )
        }) {
            return Err(bilingual_runtime_error(
                "切换任务已存在",
                format!("{kind} task is already pending or running"),
            ));
        }
        jobs.retain(|existing| {
            !(Self::managed_async_job_kind(&existing.kind) == Some(kind)
                && Self::managed_async_job_dedupe_key(existing) == dedupe_key
                && matches!(
                    existing.status.as_str(),
                    "failed" | "dead_letter" | "skipped"
                ))
        });
        jobs.push(job.clone());
        Ok(job)
    }

    pub(crate) fn lifecycle_interval() -> std::time::Duration {
        let millis = std::env::var("RUSTIO_LIFECYCLE_INTERVAL_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(60_000);
        std::time::Duration::from_millis(millis)
    }

    pub(crate) async fn lifecycle_bucket_root(&self, bucket: &str) -> PathBuf {
        let sites = self.site_replications.read().await.clone();
        if let Some(active_site) = sites
            .iter()
            .find(|site| site.role == "primary" && !site.preferred_primary)
            .map(|site| site.site_id.clone())
        {
            let rules = self.replications.read().await.clone();
            if rules.iter().any(|rule| {
                rule.source_bucket == bucket
                    && rule.target_site == active_site
                    && rule.status != "paused"
            }) {
                return self
                    .data_dir
                    .join(".rustio_sites")
                    .join(active_site)
                    .join("data")
                    .join(bucket);
            }
        }
        self.data_dir.join(bucket)
    }

    pub(crate) fn lifecycle_collect_json_files(root: &std::path::Path, output: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                Self::lifecycle_collect_json_files(&path, output);
                continue;
            }
            if file_type.is_file()
                && path.extension().and_then(|value| value.to_str()) == Some("json")
            {
                output.push(path);
            }
        }
    }

    pub(crate) fn lifecycle_scan_object_metas(
        root: &std::path::Path,
        bucket: &str,
    ) -> Vec<S3ObjectMeta> {
        let mut files = Vec::new();
        Self::lifecycle_collect_json_files(root, &mut files);
        let mut metas = Vec::new();
        let mut seen = HashSet::new();
        for path in files {
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let Ok(meta) = serde_json::from_slice::<S3ObjectMeta>(&bytes) else {
                continue;
            };
            if meta.bucket != bucket || meta.key.is_empty() {
                continue;
            }
            let dedupe_key = format!("{}:{}", meta.key, meta.version_id);
            if seen.insert(dedupe_key) {
                metas.push(meta);
            }
        }
        metas
    }

    pub(crate) fn lifecycle_rule_matches(rule: &BucketLifecycleRule, key: &str) -> bool {
        rule.status.eq_ignore_ascii_case("enabled")
            && rule
                .prefix
                .as_deref()
                .map(|prefix| key.starts_with(prefix))
                .unwrap_or(true)
    }

    pub(crate) fn lifecycle_current_transition_target(
        rule: &BucketLifecycleRule,
        meta: &S3ObjectMeta,
        now: DateTime<Utc>,
    ) -> Option<String> {
        let tier = rule.transition_tier.as_deref()?.trim();
        if tier.is_empty() || meta.delete_marker || meta.remote_tier.is_some() {
            return None;
        }
        let days = rule.transition_days?;
        (now.signed_duration_since(meta.created_at) >= Duration::days(days as i64))
            .then(|| tier.to_string())
    }

    pub(crate) fn lifecycle_noncurrent_transition_target(
        rule: &BucketLifecycleRule,
        meta: &S3ObjectMeta,
        now: DateTime<Utc>,
    ) -> Option<String> {
        let tier = rule.noncurrent_transition_tier.as_deref()?.trim();
        if tier.is_empty() || meta.remote_tier.is_some() {
            return None;
        }
        let days = rule.noncurrent_transition_days?;
        (now.signed_duration_since(meta.created_at) >= Duration::days(days as i64))
            .then(|| tier.to_string())
    }

    pub(crate) async fn process_bucket_lifecycle_once(&self) -> Result<usize, String> {
        let buckets = self.bucket_lifecycle_rules.read().await.clone();
        let remote_tiers = self.remote_tiers.read().await.clone();
        let mut enqueued = 0usize;
        let now = Utc::now();

        for (bucket, rules) in buckets {
            let active_rules = rules
                .into_iter()
                .filter(|rule| rule.status.eq_ignore_ascii_case("enabled"))
                .collect::<Vec<_>>();
            if active_rules.is_empty() {
                continue;
            }

            let bucket_root = self.lifecycle_bucket_root(&bucket).await;
            let archived_meta_root = bucket_root.join(".rustio_versions");
            // current 已下沉 redb,直接 scan_bucket;archived 仍是 .rustio_versions JSON。
            let current_metas = self.meta_store.scan_bucket(&bucket).unwrap_or_default();
            let archived_metas = Self::lifecycle_scan_object_metas(&archived_meta_root, &bucket);

            for meta in current_metas {
                if meta.delete_marker {
                    continue;
                }
                let transition_tier = active_rules.iter().find_map(|rule| {
                    if !Self::lifecycle_rule_matches(rule, &meta.key) {
                        return None;
                    }
                    let tier = Self::lifecycle_current_transition_target(rule, &meta, now)?;
                    remote_tiers
                        .get(&tier)
                        .filter(|config| config.enabled)
                        .map(|_| tier)
                });
                if let Some(tier) = transition_tier {
                    let checkpoint = self.next_replication_checkpoint();
                    let idempotency_key = format!(
                        "lifecycle:transition-current:{}:{}:{}:{}",
                        bucket, meta.key, meta.version_id, tier
                    );
                    let job = self.build_managed_async_job(
                        "lifecycle:transition-current",
                        1,
                        Some(bucket.clone()),
                        Some(meta.key.clone()),
                        None,
                        idempotency_key.clone(),
                        Some(checkpoint),
                        json!({
                            "mode": "transition-current",
                            "version_id": meta.version_id,
                            "tier": tier,
                            "dedupe_key": idempotency_key,
                        }),
                    );
                    if self.enqueue_lifecycle_job_if_absent(job).await {
                        enqueued += 1;
                    }
                    continue;
                }
                let should_expire = active_rules.iter().any(|rule| {
                    Self::lifecycle_rule_matches(rule, &meta.key)
                        && rule
                            .expiration_days
                            .map(|days| {
                                now.signed_duration_since(meta.created_at)
                                    >= Duration::days(days as i64)
                            })
                            .unwrap_or(false)
                });
                if !should_expire {
                    continue;
                }
                let checkpoint = self.next_replication_checkpoint();
                let idempotency_key = format!(
                    "lifecycle:current:{}:{}:{}",
                    bucket, meta.key, meta.version_id
                );
                let job = self.build_managed_async_job(
                    "lifecycle:current",
                    1,
                    Some(bucket.clone()),
                    Some(meta.key.clone()),
                    None,
                    idempotency_key.clone(),
                    Some(checkpoint),
                    json!({
                        "mode": "current",
                        "version_id": meta.version_id,
                        "dedupe_key": idempotency_key,
                    }),
                );
                if self.enqueue_lifecycle_job_if_absent(job).await {
                    enqueued += 1;
                }
            }

            for meta in archived_metas {
                let transition_tier = active_rules.iter().find_map(|rule| {
                    if !Self::lifecycle_rule_matches(rule, &meta.key) {
                        return None;
                    }
                    let tier = Self::lifecycle_noncurrent_transition_target(rule, &meta, now)?;
                    remote_tiers
                        .get(&tier)
                        .filter(|config| config.enabled)
                        .map(|_| tier)
                });
                if let Some(tier) = transition_tier {
                    let checkpoint = self.next_replication_checkpoint();
                    let idempotency_key = format!(
                        "lifecycle:transition-noncurrent:{}:{}:{}:{}",
                        bucket, meta.key, meta.version_id, tier
                    );
                    let job = self.build_managed_async_job(
                        "lifecycle:transition-noncurrent",
                        1,
                        Some(bucket.clone()),
                        Some(meta.key.clone()),
                        None,
                        idempotency_key.clone(),
                        Some(checkpoint),
                        json!({
                            "mode": "transition-noncurrent",
                            "version_id": meta.version_id,
                            "tier": tier,
                            "dedupe_key": idempotency_key,
                        }),
                    );
                    if self.enqueue_lifecycle_job_if_absent(job).await {
                        enqueued += 1;
                    }
                    continue;
                }
                let should_expire = active_rules.iter().any(|rule| {
                    Self::lifecycle_rule_matches(rule, &meta.key)
                        && rule
                            .noncurrent_expiration_days
                            .map(|days| {
                                now.signed_duration_since(meta.created_at)
                                    >= Duration::days(days as i64)
                            })
                            .unwrap_or(false)
                });
                if !should_expire {
                    continue;
                }
                let checkpoint = self.next_replication_checkpoint();
                let idempotency_key = format!(
                    "lifecycle:noncurrent:{}:{}:{}",
                    bucket, meta.key, meta.version_id
                );
                let job = self.build_managed_async_job(
                    "lifecycle:noncurrent",
                    1,
                    Some(bucket.clone()),
                    Some(meta.key.clone()),
                    None,
                    idempotency_key.clone(),
                    Some(checkpoint),
                    json!({
                        "mode": "noncurrent",
                        "version_id": meta.version_id,
                        "dedupe_key": idempotency_key,
                    }),
                );
                if self.enqueue_lifecycle_job_if_absent(job).await {
                    enqueued += 1;
                }
            }
        }

        Ok(enqueued)
    }

    pub(crate) async fn ensure_site_bucket_roots(&self, site_id: &str) {
        let buckets = self
            .replications
            .read()
            .await
            .iter()
            .filter(|rule| rule.target_site == site_id)
            .map(|rule| rule.source_bucket.clone())
            .collect::<HashSet<_>>();
        for bucket in buckets {
            let path = self
                .data_dir
                .join(".rustio_sites")
                .join(site_id)
                .join("data")
                .join(bucket);
            let _ = tokio::fs::create_dir_all(path).await;
        }
    }

    pub(crate) fn site_bucket_root_path(&self, site_id: &str, bucket: &str) -> PathBuf {
        self.data_dir
            .join(".rustio_sites")
            .join(site_id)
            .join("data")
            .join(bucket)
    }

    pub(crate) async fn site_managed_buckets(&self, site_id: &str) -> HashSet<String> {
        self.replications
            .read()
            .await
            .iter()
            .filter(|rule| rule.target_site == site_id)
            .map(|rule| rule.source_bucket.clone())
            .collect::<HashSet<_>>()
    }

    pub(crate) async fn count_site_bucket_root_drift(&self, site_id: &str) -> u32 {
        let buckets = self.site_managed_buckets(site_id).await;
        let mut missing = 0u32;
        for bucket in buckets {
            if !tokio::fs::try_exists(self.site_bucket_root_path(site_id, &bucket))
                .await
                .unwrap_or(false)
            {
                missing += 1;
            }
        }
        missing
    }

    pub(crate) async fn copy_directory_tree(
        &self,
        source_root: &std::path::Path,
        target_root: &std::path::Path,
    ) -> Result<u64, String> {
        let mut queue = VecDeque::new();
        let mut copied_files = 0u64;
        queue.push_back((source_root.to_path_buf(), target_root.to_path_buf()));

        while let Some((source_dir, target_dir)) = queue.pop_front() {
            let mut entries = tokio::fs::read_dir(&source_dir).await.map_err(|err| {
                bilingual_runtime_error(
                    "读取回迁目录失败",
                    format!("failed to read recovery directory: {err}"),
                )
            })?;
            tokio::fs::create_dir_all(&target_dir)
                .await
                .map_err(|err| {
                    bilingual_runtime_error(
                        "创建回迁目录失败",
                        format!("failed to create recovery directory: {err}"),
                    )
                })?;

            while let Some(entry) = entries.next_entry().await.map_err(|err| {
                bilingual_runtime_error(
                    "遍历回迁目录失败",
                    format!("failed to iterate recovery directory: {err}"),
                )
            })? {
                let source_path = entry.path();
                let target_path = target_dir.join(entry.file_name());
                let file_type = entry.file_type().await.map_err(|err| {
                    bilingual_runtime_error(
                        "读取文件类型失败",
                        format!("failed to read file type: {err}"),
                    )
                })?;
                if file_type.is_dir() {
                    queue.push_back((source_path, target_path));
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                if let Some(parent) = target_path.parent() {
                    tokio::fs::create_dir_all(parent).await.map_err(|err| {
                        bilingual_runtime_error(
                            "创建目标目录失败",
                            format!("failed to create target directory: {err}"),
                        )
                    })?;
                }
                tokio::fs::copy(&source_path, &target_path)
                    .await
                    .map_err(|err| {
                        bilingual_runtime_error(
                            "复制文件失败",
                            format!("failed to copy file during recovery: {err}"),
                        )
                    })?;
                copied_files += 1;
            }
        }

        Ok(copied_files)
    }

    pub(crate) async fn recover_failback_object_space(
        &self,
        source_site_id: &str,
    ) -> Result<u64, String> {
        if source_site_id.trim().is_empty() || source_site_id == "unknown" {
            return Ok(0);
        }

        let buckets = self
            .replications
            .read()
            .await
            .iter()
            .filter(|rule| rule.target_site == source_site_id)
            .map(|rule| rule.source_bucket.clone())
            .collect::<HashSet<_>>();
        let mut recovered_files = 0u64;
        for bucket in buckets {
            let source_root = self
                .data_dir
                .join(".rustio_sites")
                .join(source_site_id)
                .join("data")
                .join(&bucket);
            if !tokio::fs::try_exists(&source_root).await.unwrap_or(false) {
                continue;
            }
            let target_root = self.data_dir.join(&bucket);
            tokio::fs::create_dir_all(&target_root)
                .await
                .map_err(|err| {
                    bilingual_runtime_error(
                        "创建主站存储桶目录失败",
                        format!("failed to create primary bucket directory: {err}"),
                    )
                })?;
            recovered_files += self.copy_directory_tree(&source_root, &target_root).await?;
        }
        Ok(recovered_files)
    }

    pub(crate) async fn execute_lifecycle_job(&self, job: &JobStatus) -> Result<(), String> {
        let bucket = job.bucket.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error("生命周期任务缺少桶名", "lifecycle job missing bucket")
        })?;
        let object_key = job.object_key.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error("生命周期任务缺少对象键", "lifecycle job missing object key")
        })?;
        let mode = job
            .payload
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("current");

        match mode {
            "current" => {
                if let Some(result_meta) =
                    expire_current_object_for_lifecycle(self, &bucket, &object_key).await?
                {
                    if let Err(err) = self
                        .emit_bucket_object_event(
                            &bucket,
                            &object_key,
                            "s3:ObjectRemoved:Delete",
                            Some(&result_meta),
                            "lifecycle-expiration",
                        )
                        .await
                    {
                        self.push_event(
                            "bucket.notification.failed",
                            "bucket-notification-worker",
                            json!({
                                "bucket": bucket,
                                "key": object_key,
                                "event": "s3:ObjectRemoved:Delete",
                                "origin": "lifecycle-expiration",
                                "error": err,
                            }),
                        )
                        .await;
                    }
                    self.append_audit(
                        "system",
                        "bucket.lifecycle.expire.current",
                        &format!("bucket/{bucket}/{object_key}"),
                        "success",
                        Some("生命周期到期自动删除 / lifecycle automatic expiration".to_string()),
                        json!({
                            "bucket": bucket,
                            "key": object_key,
                            "version_id": result_meta.version_id,
                            "job_id": job.id,
                        }),
                    )
                    .await;
                }
            }
            "noncurrent" => {
                let version_id = job
                    .payload
                    .get("version_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        bilingual_runtime_error(
                            "生命周期任务缺少版本号",
                            "lifecycle noncurrent job missing version id",
                        )
                    })?
                    .to_string();
                if expire_noncurrent_object_version_for_lifecycle(
                    self,
                    &bucket,
                    &object_key,
                    &version_id,
                )
                .await?
                {
                    self.append_audit(
                        "system",
                        "bucket.lifecycle.expire.noncurrent",
                        &format!("bucket/{bucket}/{object_key}?versionId={version_id}"),
                        "success",
                        Some(
                            "生命周期到期自动删除非当前版本 / lifecycle automatic noncurrent expiration"
                                .to_string(),
                        ),
                        json!({
                            "bucket": bucket,
                            "key": object_key,
                            "version_id": version_id,
                            "job_id": job.id,
                        }),
                    )
                    .await;
                }
            }
            "transition-current" => {
                let tier = job
                    .payload
                    .get("tier")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        bilingual_runtime_error(
                            "生命周期转层任务缺少目标层",
                            "lifecycle transition job missing target tier",
                        )
                    })?
                    .to_string();
                if let Some(result_meta) =
                    transition_current_object_for_lifecycle(self, &bucket, &object_key, &tier)
                        .await?
                {
                    self.append_audit(
                        "system",
                        "bucket.lifecycle.transition.current",
                        &format!("bucket/{bucket}/{object_key}"),
                        "success",
                        Some(
                            "生命周期转层当前版本 / lifecycle transition current object"
                                .to_string(),
                        ),
                        json!({
                            "bucket": bucket,
                            "key": object_key,
                            "version_id": result_meta.version_id,
                            "tier": tier,
                            "job_id": job.id,
                        }),
                    )
                    .await;
                }
            }
            "transition-noncurrent" => {
                let version_id = job
                    .payload
                    .get("version_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        bilingual_runtime_error(
                            "生命周期转层任务缺少版本号",
                            "lifecycle transition noncurrent job missing version id",
                        )
                    })?
                    .to_string();
                let tier = job
                    .payload
                    .get("tier")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        bilingual_runtime_error(
                            "生命周期转层任务缺少目标层",
                            "lifecycle transition job missing target tier",
                        )
                    })?
                    .to_string();
                if transition_noncurrent_object_version_for_lifecycle(
                    self,
                    &bucket,
                    &object_key,
                    &version_id,
                    &tier,
                )
                .await?
                {
                    self.append_audit(
                        "system",
                        "bucket.lifecycle.transition.noncurrent",
                        &format!("bucket/{bucket}/{object_key}?versionId={version_id}"),
                        "success",
                        Some(
                            "生命周期转层非当前版本 / lifecycle transition noncurrent object"
                                .to_string(),
                        ),
                        json!({
                            "bucket": bucket,
                            "key": object_key,
                            "version_id": version_id,
                            "tier": tier,
                            "job_id": job.id,
                        }),
                    )
                    .await;
                }
            }
            _ => {
                return Err(bilingual_runtime_error(
                    "生命周期任务模式无效",
                    format!("unsupported lifecycle job mode: {mode}"),
                ));
            }
        }
        Ok(())
    }

    pub(crate) async fn execute_site_bootstrap_job(&self, job: &JobStatus) -> Result<(), String> {
        let site_id = job.site_id.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error(
                "Bootstrap 任务缺少站点 ID",
                "site bootstrap job missing site id",
            )
        })?;
        let operator = job
            .payload
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("system");
        let reason = job
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let endpoint = job
            .payload
            .get("endpoint")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                bilingual_runtime_error(
                    "Bootstrap 任务缺少 endpoint",
                    "site bootstrap job missing endpoint",
                )
            })?
            .to_string();
        let preferred_primary = job
            .payload
            .get("preferred_primary")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.25);
                entry.updated_at = Utc::now();
            })
            .await;

        let managed_buckets = self.site_managed_buckets(&site_id).await.len() as u32;
        self.ensure_site_bucket_roots(&site_id).await;
        let now = Utc::now();
        let role = {
            let mut sites = self.site_replications.write().await;
            if sites.iter().any(|site| site.site_id == site_id) {
                return Err(bilingual_runtime_error(
                    "复制站点已存在",
                    format!("replication site {site_id} already exists"),
                ));
            }
            let has_primary = sites.iter().any(|site| site.role == "primary");
            let role = if preferred_primary && !has_primary {
                "primary".to_string()
            } else {
                "secondary".to_string()
            };
            sites.push(SiteReplicationStatus {
                site_id: site_id.clone(),
                endpoint: endpoint.clone(),
                role: role.clone(),
                preferred_primary,
                state: "healthy".to_string(),
                lag_seconds: 0,
                managed_buckets,
                last_sync_at: now,
                bootstrap_state: "bootstrapped".to_string(),
                joined_at: Some(now),
                last_resync_at: Some(now),
                last_reconcile_at: Some(now),
                pending_resync_items: 0,
                drifted_buckets: 0,
                topology_version: 1,
                last_error: None,
            });
            role
        };
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.8);
                entry.updated_at = Utc::now();
            })
            .await;
        self.append_audit(
            operator,
            "replication.site.bootstrap",
            &format!("replication/site/{site_id}"),
            "success",
            reason.clone(),
            json!({
                "site_id": site_id,
                "endpoint": endpoint,
                "role": role,
                "preferred_primary": preferred_primary,
                "job_id": job.id,
            }),
        )
        .await;
        self.push_event(
            "replication.site.bootstrap",
            "replication-site-manager",
            json!({
                "site_id": site_id,
                "endpoint": endpoint,
                "operator": operator,
                "job_id": job.id,
            }),
        )
        .await;
        Ok(())
    }

    pub(crate) async fn execute_site_join_job(&self, job: &JobStatus) -> Result<(), String> {
        let site_id = job.site_id.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error("Join 任务缺少站点 ID", "site join job missing site id")
        })?;
        let operator = job
            .payload
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("system");
        let reason = job
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let endpoint = job
            .payload
            .get("endpoint")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.25);
                entry.updated_at = Utc::now();
            })
            .await;

        let managed_buckets = self.site_managed_buckets(&site_id).await.len() as u32;
        self.ensure_site_bucket_roots(&site_id).await;
        let now = Utc::now();
        let (created, effective_endpoint) = {
            let mut sites = self.site_replications.write().await;
            if let Some(site) = sites.iter_mut().find(|site| site.site_id == site_id) {
                if let Some(endpoint) = endpoint.clone() {
                    site.endpoint = endpoint;
                }
                site.state = "healthy".to_string();
                site.bootstrap_state = "joined".to_string();
                site.joined_at.get_or_insert(now);
                site.last_sync_at = now;
                site.last_error = None;
                site.managed_buckets = managed_buckets;
                site.topology_version += 1;
                (false, site.endpoint.clone())
            } else {
                // 路由层(join_site_replication)已要求新站点必须带 endpoint;这里作为纵深防御
                // 再次校验,缺失时中止任务而不是回退到占位值。
                let Some(effective_endpoint) = endpoint.clone() else {
                    return Err(bilingual_runtime_error(
                        "加入新站点缺少 endpoint,任务已中止",
                        "join job for a new site is missing endpoint, aborting",
                    ));
                };
                sites.push(SiteReplicationStatus {
                    site_id: site_id.clone(),
                    endpoint: effective_endpoint.clone(),
                    role: "secondary".to_string(),
                    preferred_primary: false,
                    state: "healthy".to_string(),
                    lag_seconds: 0,
                    managed_buckets,
                    last_sync_at: now,
                    bootstrap_state: "joined".to_string(),
                    joined_at: Some(now),
                    last_resync_at: None,
                    last_reconcile_at: None,
                    pending_resync_items: 0,
                    drifted_buckets: 0,
                    topology_version: 1,
                    last_error: None,
                });
                (true, effective_endpoint)
            }
        };
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.8);
                entry.updated_at = Utc::now();
            })
            .await;
        self.append_audit(
            operator,
            "replication.site.join",
            &format!("replication/site/{site_id}"),
            "success",
            reason.clone(),
            json!({
                "site_id": site_id,
                "endpoint": effective_endpoint,
                "created": created,
                "job_id": job.id,
            }),
        )
        .await;
        self.push_event(
            "replication.site.join",
            "replication-site-manager",
            json!({
                "site_id": site_id,
                "endpoint": effective_endpoint,
                "created": created,
                "operator": operator,
                "job_id": job.id,
            }),
        )
        .await;
        Ok(())
    }

    pub(crate) async fn execute_site_resync_job(&self, job: &JobStatus) -> Result<(), String> {
        let site_id = job.site_id.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error("Resync 任务缺少站点 ID", "site resync job missing site id")
        })?;
        let operator = job
            .payload
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("system");
        let reason = job
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.25);
                entry.updated_at = Utc::now();
            })
            .await;

        let pending_items = self
            .replication_backlog
            .read()
            .await
            .iter()
            .filter(|item| {
                item.target_site == site_id && item.status != "done" && item.status != "completed"
            })
            .count() as u64;
        let checkpoint = self
            .replication_checkpoints
            .read()
            .await
            .get(&site_id)
            .copied();
        if let Some(value) = checkpoint {
            self.write_replication_checkpoint(&site_id, value).await;
        }
        self.ensure_site_bucket_roots(&site_id).await;
        let now = Utc::now();
        {
            let mut sites = self.site_replications.write().await;
            let site = sites
                .iter_mut()
                .find(|site| site.site_id == site_id)
                .ok_or_else(|| {
                    bilingual_runtime_error(
                        "复制站点不存在",
                        format!("replication site {site_id} not found"),
                    )
                })?;
            site.last_resync_at = Some(now);
            site.pending_resync_items = pending_items;
            site.state = if pending_items > 0 {
                "resyncing".to_string()
            } else {
                "healthy".to_string()
            };
            if pending_items == 0 {
                site.lag_seconds = 0;
                site.last_sync_at = now;
                site.last_error = None;
            }
        }
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.8);
                entry.updated_at = Utc::now();
                entry.checkpoint = checkpoint;
            })
            .await;
        self.append_audit(
            operator,
            "replication.site.resync",
            &format!("replication/site/{site_id}"),
            "success",
            reason.clone(),
            json!({
                "site_id": site_id,
                "pending_resync_items": pending_items,
                "job_id": job.id,
                "checkpoint": checkpoint,
            }),
        )
        .await;
        self.push_event(
            "replication.site.resync",
            "replication-site-manager",
            json!({
                "site_id": site_id,
                "pending_resync_items": pending_items,
                "operator": operator,
                "job_id": job.id,
                "checkpoint": checkpoint,
            }),
        )
        .await;
        Ok(())
    }

    pub(crate) async fn execute_site_reconcile_job(&self, job: &JobStatus) -> Result<(), String> {
        let site_id = job.site_id.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error(
                "Reconcile 任务缺少站点 ID",
                "site reconcile job missing site id",
            )
        })?;
        let operator = job
            .payload
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("system");
        let reason = job
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.25);
                entry.updated_at = Utc::now();
            })
            .await;

        let drifted_before = self.count_site_bucket_root_drift(&site_id).await;
        self.ensure_site_bucket_roots(&site_id).await;
        let drifted_after = self.count_site_bucket_root_drift(&site_id).await;
        let managed_buckets = self.site_managed_buckets(&site_id).await.len() as u32;
        let now = Utc::now();
        {
            let mut sites = self.site_replications.write().await;
            let site = sites
                .iter_mut()
                .find(|site| site.site_id == site_id)
                .ok_or_else(|| {
                    bilingual_runtime_error(
                        "复制站点不存在",
                        format!("replication site {site_id} not found"),
                    )
                })?;
            site.managed_buckets = managed_buckets;
            site.drifted_buckets = drifted_after;
            site.last_reconcile_at = Some(now);
            if drifted_after == 0 {
                site.last_error = None;
                if site.state != "offline" {
                    site.state = if site.pending_resync_items > 0 {
                        "resyncing".to_string()
                    } else {
                        "healthy".to_string()
                    };
                }
            } else {
                site.state = "degraded".to_string();
            }
            site.topology_version += 1;
        }
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.8);
                entry.updated_at = Utc::now();
            })
            .await;
        self.append_audit(
            operator,
            "replication.site.reconcile",
            &format!("replication/site/{site_id}"),
            "success",
            reason.clone(),
            json!({
                "site_id": site_id,
                "managed_buckets": managed_buckets,
                "drifted_before": drifted_before,
                "drifted_after": drifted_after,
                "job_id": job.id,
            }),
        )
        .await;
        self.push_event(
            "replication.site.reconcile",
            "replication-site-manager",
            json!({
                "site_id": site_id,
                "managed_buckets": managed_buckets,
                "drifted_before": drifted_before,
                "drifted_after": drifted_after,
                "operator": operator,
                "job_id": job.id,
            }),
        )
        .await;
        Ok(())
    }

    pub(crate) async fn execute_failover_job(&self, job: &JobStatus) -> Result<(), String> {
        let site_id = job.site_id.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error("Failover 任务缺少站点 ID", "failover job missing site id")
        })?;
        let operator = job
            .payload
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("system");
        let reason = job
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.35);
                entry.updated_at = Utc::now();
            })
            .await;

        let now = Utc::now();
        let previous_primary = {
            let mut sites = self.site_replications.write().await;
            let target_exists = sites.iter().any(|site| site.site_id == site_id);
            if !target_exists {
                return Err(bilingual_runtime_error(
                    "复制站点不存在",
                    format!("replication site {site_id} not found"),
                ));
            }
            let previous_primary = sites
                .iter()
                .find(|site| site.role == "primary")
                .map(|site| site.site_id.clone())
                .unwrap_or_else(|| "unknown".to_string());
            if previous_primary == site_id {
                return Err(bilingual_runtime_error(
                    "目标站点已是主站",
                    "selected site is already primary",
                ));
            }
            for site in sites.iter_mut() {
                if site.site_id == site_id {
                    site.role = "primary".to_string();
                    site.state = "healthy".to_string();
                    site.lag_seconds = 0;
                    site.last_sync_at = now;
                    site.last_error = None;
                } else {
                    site.role = "secondary".to_string();
                    if site.state != "offline" {
                        site.state = "healthy".to_string();
                    }
                    site.last_sync_at = now;
                }
            }
            previous_primary
        };
        let checkpoint = self
            .replication_checkpoints
            .read()
            .await
            .get(&site_id)
            .copied();
        if let Some(value) = checkpoint {
            self.write_replication_checkpoint(&site_id, value).await;
        }
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.8);
                entry.updated_at = Utc::now();
                entry.checkpoint = checkpoint;
            })
            .await;
        self.ensure_site_bucket_roots(&site_id).await;
        self.append_audit(
            operator,
            "replication.site.failover",
            &format!("replication/site/{site_id}"),
            "success",
            reason.clone(),
            json!({
                "from": previous_primary,
                "to": site_id,
                "job_id": job.id,
                "checkpoint": checkpoint,
            }),
        )
        .await;
        self.push_event(
            "replication.site.failover",
            "replication-site-manager",
            json!({
                "from": previous_primary,
                "to": site_id,
                "operator": operator,
                "job_id": job.id,
                "checkpoint": checkpoint,
            }),
        )
        .await;
        Ok(())
    }

    pub(crate) async fn execute_failback_job(&self, job: &JobStatus) -> Result<(), String> {
        let site_id = job.site_id.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error("Failback 任务缺少站点 ID", "failback job missing site id")
        })?;
        let operator = job
            .payload
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("system");
        let reason = job
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let previous_primary = {
            let sites = self.site_replications.read().await;
            let target = sites
                .iter()
                .find(|site| site.site_id == site_id)
                .cloned()
                .ok_or_else(|| {
                    bilingual_runtime_error(
                        "复制站点不存在",
                        format!("replication site {site_id} not found"),
                    )
                })?;
            if !target.preferred_primary {
                return Err(bilingual_runtime_error(
                    "Failback 目标必须是首选主站",
                    "failback target must be preferred primary site",
                ));
            }
            let previous_primary = sites
                .iter()
                .find(|site| site.role == "primary")
                .map(|site| site.site_id.clone())
                .unwrap_or_else(|| "unknown".to_string());
            if previous_primary == site_id {
                return Err(bilingual_runtime_error(
                    "目标站点已是主站",
                    "selected site is already primary",
                ));
            }
            previous_primary
        };
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.35);
                entry.updated_at = Utc::now();
            })
            .await;
        let recovered_files = self
            .recover_failback_object_space(&previous_primary)
            .await?;
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.7);
                entry.updated_at = Utc::now();
            })
            .await;

        let now = Utc::now();
        {
            let mut sites = self.site_replications.write().await;
            for site in sites.iter_mut() {
                if site.site_id == site_id {
                    site.role = "primary".to_string();
                    site.state = "healthy".to_string();
                    site.lag_seconds = 0;
                    site.last_sync_at = now;
                    site.last_error = None;
                } else {
                    site.role = "secondary".to_string();
                    if site.state != "offline" {
                        site.state = "healthy".to_string();
                    }
                    site.last_sync_at = now;
                }
            }
        }
        let checkpoint = self
            .replication_checkpoints
            .read()
            .await
            .get(&site_id)
            .copied();
        if let Some(value) = checkpoint {
            self.write_replication_checkpoint(&site_id, value).await;
        }
        self.ensure_site_bucket_roots(&site_id).await;
        self.append_audit(
            operator,
            "replication.site.failback",
            &format!("replication/site/{site_id}"),
            "success",
            reason.clone(),
            json!({
                "from": previous_primary,
                "to": site_id,
                "recovered_files": recovered_files,
                "job_id": job.id,
                "checkpoint": checkpoint,
            }),
        )
        .await;
        self.push_event(
            "replication.site.failback",
            "replication-site-manager",
            json!({
                "from": previous_primary,
                "to": site_id,
                "recovered_files": recovered_files,
                "operator": operator,
                "job_id": job.id,
                "checkpoint": checkpoint,
            }),
        )
        .await;
        Ok(())
    }

    pub(crate) async fn execute_managed_async_job(&self, job: &JobStatus) -> Result<(), String> {
        match Self::managed_async_job_kind(&job.kind) {
            Some("lifecycle") => self.execute_lifecycle_job(job).await,
            Some("site-bootstrap") => self.execute_site_bootstrap_job(job).await,
            Some("site-join") => self.execute_site_join_job(job).await,
            Some("site-resync") => self.execute_site_resync_job(job).await,
            Some("site-reconcile") => self.execute_site_reconcile_job(job).await,
            Some("failover") => self.execute_failover_job(job).await,
            Some("failback") => self.execute_failback_job(job).await,
            _ => Err(bilingual_runtime_error(
                "不支持的统一任务类型",
                format!("unsupported managed async job kind: {}", job.kind),
            )),
        }
    }

    pub async fn process_managed_async_jobs_once(&self, worker_id: &str) -> usize {
        let now = Utc::now();
        let lease_until = now
            + Duration::from_std(Self::managed_async_job_lease_interval())
                .unwrap_or_else(|_| Duration::seconds(5));
        let next_job = {
            let mut jobs = self.jobs.write().await;
            let mut picked_index = None::<usize>;
            let mut picked_priority = i32::MAX;
            let mut picked_checkpoint = u64::MAX;
            let mut picked_created_at = i64::MAX;

            for (index, job) in jobs.iter().enumerate() {
                if Self::managed_async_job_kind(&job.kind).is_none() {
                    continue;
                }
                let lease_expired = job.lease_until.map(|value| value <= now).unwrap_or(true);
                let ready =
                    job.status == "pending" || (job.status == "in_progress" && lease_expired);
                if !ready {
                    continue;
                }
                let checkpoint = job.checkpoint.unwrap_or(u64::MAX);
                let created_at = job.created_at.timestamp_millis();
                if job.priority < picked_priority
                    || (job.priority == picked_priority && checkpoint < picked_checkpoint)
                    || (job.priority == picked_priority
                        && checkpoint == picked_checkpoint
                        && created_at < picked_created_at)
                {
                    picked_index = Some(index);
                    picked_priority = job.priority;
                    picked_checkpoint = checkpoint;
                    picked_created_at = created_at;
                }
            }

            let Some(index) = picked_index else {
                return 0;
            };
            let Some(job) = jobs.get_mut(index) else {
                return 0;
            };
            job.status = "in_progress".to_string();
            job.attempt += 1;
            job.lease_owner = Some(worker_id.to_string());
            job.lease_until = Some(lease_until);
            job.progress = job.progress.max(0.1);
            job.updated_at = now;
            job.clone()
        };

        let result = self.execute_managed_async_job(&next_job).await;
        let max_attempts = Self::managed_async_job_max_attempts();
        let completed_at = Utc::now();
        match result {
            Ok(()) => {
                let _ = self
                    .mutate_job(&next_job.id, |job| {
                        job.status = "completed".to_string();
                        job.progress = 1.0;
                        job.last_error = None;
                        job.lease_owner = None;
                        job.lease_until = None;
                        job.updated_at = completed_at;
                    })
                    .await;
            }
            Err(err) => {
                let decorated_error = format!(
                    "{err}；可通过统一任务重试并检查回滚提示 / retry via unified async jobs and review rollback guidance"
                );
                let _ = self
                    .mutate_job(&next_job.id, |job| {
                        job.last_error = Some(decorated_error.clone());
                        job.lease_owner = None;
                        job.lease_until = None;
                        job.updated_at = completed_at;
                        if job.attempt >= max_attempts {
                            job.status = "dead_letter".to_string();
                            job.progress = job.progress.max(0.95);
                        } else {
                            job.status = "failed".to_string();
                            job.progress = job.progress.max(0.4);
                        }
                    })
                    .await;
            }
        }
        1
    }
}

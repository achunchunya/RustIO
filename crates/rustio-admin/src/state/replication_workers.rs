//! 复制队列处理、后台 worker 与架构对齐报告

use super::*;

impl AppState {
    pub(crate) fn replication_item_matches_target(
        item: &ReplicationBacklogItem,
        source_bucket: &str,
        target_site: &str,
        object_key: &str,
    ) -> bool {
        item.source_bucket == source_bucket
            && item.target_site == target_site
            && item.object_key == object_key
    }

    pub(crate) fn replication_items_same_target(
        left: &ReplicationBacklogItem,
        right: &ReplicationBacklogItem,
    ) -> bool {
        Self::replication_item_matches_target(
            left,
            &right.source_bucket,
            &right.target_site,
            &right.object_key,
        )
    }

    pub(crate) fn replication_target_blocked(
        backlog: &[ReplicationBacklogItem],
        candidate_index: usize,
        now: &DateTime<Utc>,
    ) -> bool {
        let Some(candidate) = backlog.get(candidate_index) else {
            return true;
        };
        backlog.iter().enumerate().any(|(index, item)| {
            if index == candidate_index || !Self::replication_items_same_target(item, candidate) {
                return false;
            }
            let lease_active = item.lease_until.map(|value| value > *now).unwrap_or(false);
            if item.status == "in_progress" && lease_active {
                return true;
            }
            Self::replication_item_supersedable(&item.status)
                && item.checkpoint < candidate.checkpoint
        })
    }

    pub(crate) fn replication_remote_response_summary(body: &str) -> String {
        let normalized = body.split_whitespace().collect::<Vec<_>>().join(" ");
        if normalized.len() <= 240 {
            normalized
        } else {
            format!("{}...", &normalized[..240])
        }
    }

    pub(crate) fn replication_remote_failure_retryable(status: reqwest::StatusCode) -> bool {
        status.is_server_error()
            || status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status == reqwest::StatusCode::REQUEST_TIMEOUT
    }

    pub async fn enqueue_replication_task(
        &self,
        source_bucket: &str,
        target_site: &str,
        object_key: &str,
        rule_id: Option<String>,
        priority: i32,
        operation: &str,
        version_id: Option<String>,
    ) -> ReplicationBacklogItem {
        let now = Utc::now();
        let checkpoint = self.next_replication_checkpoint();
        let idempotency_key = format!(
            "{}:{}:{}:{}",
            source_bucket, target_site, object_key, checkpoint
        );
        let item = ReplicationBacklogItem {
            id: Uuid::new_v4().to_string(),
            source_bucket: source_bucket.to_string(),
            target_site: target_site.to_string(),
            object_key: object_key.to_string(),
            rule_id,
            priority,
            operation: operation.to_string(),
            checkpoint,
            idempotency_key,
            version_id,
            attempts: 0,
            status: "pending".to_string(),
            last_error: String::new(),
            lease_owner: None,
            lease_until: None,
            queued_at: now,
            last_attempt_at: now,
        };
        {
            let mut backlog = self.replication_backlog.write().await;
            backlog.retain(|entry| {
                if !Self::replication_item_matches_target(
                    entry,
                    source_bucket,
                    target_site,
                    object_key,
                ) {
                    return true;
                }
                !Self::replication_item_supersedable(&entry.status)
            });
            backlog.push(item.clone());
        }
        self.persist_replication_runtime_state().await;
        tracing::debug!(
            target_site = %target_site,
            bucket = %source_bucket,
            key = %object_key,
            operation = %operation,
            checkpoint,
            "复制任务入队 / replication task enqueued"
        );
        item
    }

    pub(crate) fn safe_object_path(bucket_root: &std::path::Path, key: &str) -> Option<PathBuf> {
        if key.is_empty() {
            return None;
        }
        let key_path = std::path::Path::new(key);
        for component in key_path.components() {
            match component {
                std::path::Component::Normal(_) => {}
                _ => return None,
            }
        }
        Some(bucket_root.join(key_path))
    }

    pub(crate) fn valid_replication_version_id(version_id: &str) -> bool {
        !version_id.is_empty()
            && version_id.len() <= 128
            && version_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
            })
    }

    pub(crate) fn object_meta_file_path(
        bucket_root: &std::path::Path,
        key: &str,
    ) -> Option<PathBuf> {
        let mut meta_key = key.to_string();
        meta_key.push_str(".json");
        Self::safe_object_path(&bucket_root.join(".rustio_meta"), &meta_key)
    }

    pub(crate) fn object_versions_dir(bucket_root: &std::path::Path, key: &str) -> PathBuf {
        bucket_root
            .join(".rustio_versions")
            .join(sha256_hex(key.as_bytes()))
    }

    pub(crate) fn object_version_meta_file_path(
        bucket_root: &std::path::Path,
        key: &str,
        version_id: &str,
    ) -> Option<PathBuf> {
        if !Self::valid_replication_version_id(version_id) {
            return None;
        }
        Some(Self::object_versions_dir(bucket_root, key).join(format!("{version_id}.json")))
    }

    pub(crate) fn object_version_payload_file_path(
        bucket_root: &std::path::Path,
        key: &str,
        version_id: &str,
    ) -> Option<PathBuf> {
        if !Self::valid_replication_version_id(version_id) {
            return None;
        }
        Some(Self::object_versions_dir(bucket_root, key).join(format!("{version_id}.bin")))
    }

    pub(crate) fn write_pretty_json_file(
        path: &std::path::Path,
        value: &S3ObjectMeta,
    ) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                bilingual_runtime_error(
                    "创建复制元数据目录失败",
                    format!("create replication metadata directory failed: {err}"),
                )
            })?;
        }
        let bytes = serde_json::to_vec_pretty(value).map_err(|err| {
            bilingual_runtime_error(
                "序列化复制元数据失败",
                format!("serialize replication metadata failed: {err}"),
            )
        })?;
        std::fs::write(path, bytes).map_err(|err| {
            bilingual_runtime_error(
                "写入复制元数据失败",
                format!("write replication metadata failed: {err}"),
            )
        })?;
        Ok(())
    }

    pub(crate) fn persist_replication_snapshot(
        site_root: &std::path::Path,
        key: &str,
        payload: Option<&[u8]>,
        object_meta: Option<&S3ObjectMeta>,
    ) -> Result<(), String> {
        if let Some(meta) = object_meta {
            if let Some(current_meta_path) = Self::object_meta_file_path(site_root, key) {
                Self::write_pretty_json_file(&current_meta_path, meta)?;
            }
            if let Some(version_path) =
                Self::object_version_meta_file_path(site_root, key, &meta.version_id)
            {
                Self::write_pretty_json_file(&version_path, meta)?;
            }
            if !meta.delete_marker {
                if let (Some(payload), Some(payload_path)) = (
                    payload,
                    Self::object_version_payload_file_path(site_root, key, &meta.version_id),
                ) {
                    if let Some(parent) = payload_path.parent() {
                        std::fs::create_dir_all(parent).map_err(|err| {
                            bilingual_runtime_error(
                                "创建复制版本目录失败",
                                format!("create replication version directory failed: {err}"),
                            )
                        })?;
                    }
                    std::fs::write(payload_path, payload).map_err(|err| {
                        bilingual_runtime_error(
                            "写入复制版本对象失败",
                            format!("write replication version payload failed: {err}"),
                        )
                    })?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn write_replication_object_payload(
        root: &std::path::Path,
        key: &str,
        payload: &[u8],
    ) -> Result<(), String> {
        let target_path = Self::safe_object_path(root, key).ok_or_else(|| {
            bilingual_runtime_error("目标对象路径无效", "invalid target object key")
        })?;
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                bilingual_runtime_error(
                    "创建目标目录失败",
                    format!("create target directory failed: {err}"),
                )
            })?;
        }
        std::fs::write(&target_path, payload).map_err(|err| {
            bilingual_runtime_error(
                "写入目标对象失败",
                format!("write target object failed: {err}"),
            )
        })?;
        Ok(())
    }

    pub(crate) fn delete_replication_object_payload(
        root: &std::path::Path,
        key: &str,
    ) -> Result<(), String> {
        let target_path = Self::safe_object_path(root, key).ok_or_else(|| {
            bilingual_runtime_error("复制对象路径无效", "invalid replication object key")
        })?;
        let _ = std::fs::remove_file(target_path);
        Ok(())
    }

    pub(crate) fn load_replication_payload(
        &self,
        item: &ReplicationBacklogItem,
    ) -> Result<Option<Vec<u8>>, String> {
        if item.operation == "delete" {
            return Ok(None);
        }
        let source_bucket_root = self.data_dir.join(&item.source_bucket);
        if let Some(version_id) = item.version_id.as_deref() {
            if let Some(version_payload_path) = Self::object_version_payload_file_path(
                &source_bucket_root,
                &item.object_key,
                version_id,
            ) {
                match std::fs::read(&version_payload_path) {
                    Ok(bytes) => return Ok(Some(bytes)),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(bilingual_runtime_error(
                            "读取源版本对象失败",
                            format!("read source version payload failed: {err}"),
                        ));
                    }
                }
            }
        }

        let source_path = Self::safe_object_path(&source_bucket_root, &item.object_key)
            .ok_or_else(|| {
                bilingual_runtime_error("源对象路径无效", "invalid source object key")
            })?;
        let payload = std::fs::read(&source_path).map_err(|err| {
            bilingual_runtime_error(
                "读取源对象失败",
                format!("read source object failed: {err}"),
            )
        })?;
        Ok(Some(payload))
    }

    pub(crate) async fn load_replication_object_meta(
        &self,
        item: &ReplicationBacklogItem,
    ) -> Result<Option<S3ObjectMeta>, String> {
        let cached = self
            .meta_store
            .get_uncached(&item.source_bucket, &item.object_key)
            .ok()
            .flatten();
        if let Some(version_id) = item.version_id.as_deref() {
            if let Some(meta) = cached.clone() {
                if meta.version_id == version_id {
                    return Ok(Some(meta));
                }
            }

            let source_bucket_root = self.data_dir.join(&item.source_bucket);
            if let Some(version_meta_path) = Self::object_version_meta_file_path(
                &source_bucket_root,
                &item.object_key,
                version_id,
            ) {
                match std::fs::read(&version_meta_path) {
                    Ok(bytes) => {
                        let meta =
                            serde_json::from_slice::<S3ObjectMeta>(&bytes).map_err(|err| {
                                bilingual_runtime_error(
                                    "解析源版本元数据失败",
                                    format!("decode source version metadata failed: {err}"),
                                )
                            })?;
                        return Ok(Some(meta));
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(bilingual_runtime_error(
                            "读取源版本元数据失败",
                            format!("read source version metadata failed: {err}"),
                        ));
                    }
                }
            }
            if let Some(meta_path) =
                Self::object_meta_file_path(&source_bucket_root, &item.object_key)
            {
                match std::fs::read(&meta_path) {
                    Ok(bytes) => {
                        let meta =
                            serde_json::from_slice::<S3ObjectMeta>(&bytes).map_err(|err| {
                                bilingual_runtime_error(
                                    "解析源对象元数据失败",
                                    format!("decode source object metadata failed: {err}"),
                                )
                            })?;
                        if meta.version_id == version_id {
                            return Ok(Some(meta));
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(bilingual_runtime_error(
                            "读取源对象元数据失败",
                            format!("read source object metadata failed: {err}"),
                        ));
                    }
                }
            }
            return Ok(None);
        }

        if cached.is_some() {
            return Ok(cached);
        }

        let source_bucket_root = self.data_dir.join(&item.source_bucket);
        let Some(meta_path) = Self::object_meta_file_path(&source_bucket_root, &item.object_key)
        else {
            return Ok(None);
        };
        match std::fs::read(meta_path) {
            Ok(bytes) => {
                let meta = serde_json::from_slice::<S3ObjectMeta>(&bytes).map_err(|err| {
                    bilingual_runtime_error(
                        "解析源对象元数据失败",
                        format!("decode source object metadata failed: {err}"),
                    )
                })?;
                Ok(Some(meta))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(bilingual_runtime_error(
                "读取源对象元数据失败",
                format!("read source object metadata failed: {err}"),
            )),
        }
    }

    pub(crate) async fn write_replication_checkpoint(&self, site_id: &str, checkpoint: u64) {
        {
            let mut checkpoints = self.replication_checkpoints.write().await;
            checkpoints
                .entry(site_id.to_string())
                .and_modify(|current| *current = (*current).max(checkpoint))
                .or_insert(checkpoint);
        }

        let checkpoint_path = self
            .replication_root_dir()
            .join("checkpoints")
            .join(format!("{site_id}.json"));
        if let Some(parent) = checkpoint_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let value = json!({
            "site_id": site_id,
            "checkpoint": checkpoint,
            "updated_at": Utc::now(),
        });
        let _ = std::fs::write(
            checkpoint_path,
            serde_json::to_vec_pretty(&value).unwrap_or_default(),
        );
        self.persist_replication_runtime_state().await;
    }

    pub(crate) async fn replication_site_endpoint(&self, site_id: &str) -> Option<String> {
        self.site_replications
            .read()
            .await
            .iter()
            .find(|site| site.site_id == site_id)
            .map(|site| site.endpoint.clone())
    }

    #[tracing::instrument(
        name = "replication_apply_remote",
        skip(self, item, payload_base64, object_meta),
        fields(
            target_site = %item.target_site,
            bucket = %item.source_bucket,
            key = %item.object_key,
            operation = %item.operation
        )
    )]
    pub(crate) async fn apply_replication_item_remote(
        &self,
        item: &ReplicationBacklogItem,
        payload_base64: Option<String>,
        object_meta: Option<S3ObjectMeta>,
    ) -> Result<bool, String> {
        if !Self::replication_remote_enabled() {
            return Ok(false);
        }
        let Some(endpoint) = self.replication_site_endpoint(&item.target_site).await else {
            return Ok(false);
        };
        let endpoint = endpoint.trim().trim_end_matches('/');
        if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
            return Ok(false);
        }

        let request = InternalReplicationApplyRequest {
            source_bucket: item.source_bucket.clone(),
            target_site: item.target_site.clone(),
            object_key: item.object_key.clone(),
            operation: item.operation.clone(),
            checkpoint: item.checkpoint,
            idempotency_key: item.idempotency_key.clone(),
            version_id: item.version_id.clone(),
            payload_base64,
            object_meta,
        };

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|err| err.to_string())?;
        let response = client
            .post(format!("{endpoint}/api/v1/internal/replication/apply"))
            .header("x-rustio-internal-token", Self::internal_control_token())
            .json(&request)
            .send()
            .await
            .map_err(|err| {
                bilingual_runtime_error(
                    "远端复制请求失败",
                    format!("remote replication request failed: {err}"),
                )
            })?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let body_summary = Self::replication_remote_response_summary(&body);
            let detail = if body_summary.is_empty() {
                format!("remote replication status: {}", status)
            } else {
                format!(
                    "remote replication status: {}, body: {}",
                    status, body_summary
                )
            };
            let err = bilingual_runtime_error("远端复制请求失败", detail);
            let retryable = Self::replication_remote_failure_retryable(status);
            tracing::warn!(
                %status,
                retryable,
                "远端复制请求失败 / remote replication request failed"
            );
            if retryable {
                return Err(err);
            }
            return Err(Self::replication_mark_non_retryable(err));
        }
        tracing::info!(%endpoint, "远端复制应用成功 / remote replication applied");
        Ok(true)
    }

    #[tracing::instrument(
        name = "replication_apply",
        skip(self, item),
        fields(
            target_site = %item.target_site,
            bucket = %item.source_bucket,
            key = %item.object_key,
            operation = %item.operation,
            checkpoint = item.checkpoint
        )
    )]
    pub(crate) async fn apply_replication_item(
        &self,
        item: &ReplicationBacklogItem,
    ) -> Result<(), String> {
        let site_root = self
            .replication_root_dir()
            .join("sites")
            .join(&item.target_site)
            .join(&item.source_bucket);
        let object_space_root =
            self.replication_object_space_root(&item.target_site, &item.source_bucket);
        let marker_path = site_root
            .join(".applied")
            .join(format!("{}.done", item.idempotency_key));

        if marker_path.exists() {
            self.write_replication_checkpoint(&item.target_site, item.checkpoint)
                .await;
            return Ok(());
        }

        let object_meta = self.load_replication_object_meta(item).await?;
        let payload = self.load_replication_payload(item)?;
        let payload_base64 = payload.as_ref().map(|bytes| BASE64.encode(bytes));

        if self
            .apply_replication_item_remote(item, payload_base64, object_meta.clone())
            .await?
        {
            if let Some(parent) = marker_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&marker_path, item.checkpoint.to_string()).map_err(|err| {
                bilingual_runtime_error(
                    "写入复制幂等标记失败",
                    format!("write replication marker failed: {err}"),
                )
            })?;
            self.write_replication_checkpoint(&item.target_site, item.checkpoint)
                .await;
            return Ok(());
        }

        if item.operation == "delete" {
            if let Some(meta_path) = Self::object_meta_file_path(&site_root, &item.object_key) {
                let _ = std::fs::remove_file(meta_path);
            }
            if let Some(version_id) = item.version_id.as_deref() {
                if let Some(version_meta_path) =
                    Self::object_version_meta_file_path(&site_root, &item.object_key, version_id)
                {
                    let _ = std::fs::remove_file(version_meta_path);
                }
                if let Some(version_payload_path) =
                    Self::object_version_payload_file_path(&site_root, &item.object_key, version_id)
                {
                    let _ = std::fs::remove_file(version_payload_path);
                }
            }
            Self::delete_replication_object_payload(&site_root, &item.object_key)?;
            Self::delete_replication_object_payload(&object_space_root, &item.object_key)?;
            if object_meta
                .as_ref()
                .map(|meta| meta.delete_marker)
                .unwrap_or(false)
            {
                Self::persist_replication_snapshot(
                    &site_root,
                    &item.object_key,
                    None,
                    object_meta.as_ref(),
                )?;
                Self::persist_replication_snapshot(
                    &object_space_root,
                    &item.object_key,
                    None,
                    object_meta.as_ref(),
                )?;
            }
        } else {
            let payload = payload.as_deref().ok_or_else(|| {
                bilingual_runtime_error("源对象内容缺失", "replication source payload missing")
            })?;
            Self::write_replication_object_payload(&site_root, &item.object_key, payload)?;
            Self::write_replication_object_payload(&object_space_root, &item.object_key, payload)?;
            Self::persist_replication_snapshot(
                &site_root,
                &item.object_key,
                Some(payload),
                object_meta.as_ref(),
            )?;
            Self::persist_replication_snapshot(
                &object_space_root,
                &item.object_key,
                Some(payload),
                object_meta.as_ref(),
            )?;
        }

        if let Some(parent) = marker_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&marker_path, item.checkpoint.to_string()).map_err(|err| {
            bilingual_runtime_error(
                "写入复制幂等标记失败",
                format!("write replication marker failed: {err}"),
            )
        })?;
        self.write_replication_checkpoint(&item.target_site, item.checkpoint)
            .await;
        Ok(())
    }

    pub(crate) async fn process_replication_backlog_sla_watchdog_once(&self) -> Result<(), String> {
        #[derive(Default)]
        struct SiteStats {
            total: usize,
            failed: usize,
            dead_letter: usize,
            stale_pending: usize,
            max_pending_age_seconds: u64,
        }

        let now = Utc::now();
        let (failed_threshold, dead_letter_threshold, pending_age_threshold_secs) =
            Self::replication_backlog_alert_threshold_snapshot();
        let suppress_interval = Self::replication_backlog_alert_suppress_interval();
        let suppress_interval_chrono =
            Duration::from_std(suppress_interval).unwrap_or_else(|_| Duration::seconds(0));

        let backlog = self.replication_backlog.read().await.clone();
        let mut per_site = HashMap::<String, SiteStats>::new();
        for item in &backlog {
            let stats = per_site.entry(item.target_site.clone()).or_default();
            stats.total += 1;
            match item.status.as_str() {
                "failed" => stats.failed += 1,
                "dead_letter" => stats.dead_letter += 1,
                "pending" => {
                    let age = now
                        .signed_duration_since(item.queued_at)
                        .num_seconds()
                        .max(0) as u64;
                    stats.max_pending_age_seconds = stats.max_pending_age_seconds.max(age);
                    if pending_age_threshold_secs > 0 && age >= pending_age_threshold_secs {
                        stats.stale_pending += 1;
                    }
                }
                _ => {}
            }
        }

        let mut breached_sites = HashMap::<String, (String, String, Value, String)>::new();
        for (site, stats) in &per_site {
            let mut reasons_zh = Vec::new();
            let mut reasons_en = Vec::new();
            let mut breach_kinds = Vec::new();
            if failed_threshold > 0 && stats.failed >= failed_threshold {
                reasons_zh.push(format!(
                    "失败任务 {} >= 阈值 {}",
                    stats.failed, failed_threshold
                ));
                reasons_en.push(format!(
                    "failed backlog {} >= threshold {}",
                    stats.failed, failed_threshold
                ));
                breach_kinds.push("failed".to_string());
            }
            if dead_letter_threshold > 0 && stats.dead_letter >= dead_letter_threshold {
                reasons_zh.push(format!(
                    "死信任务 {} >= 阈值 {}",
                    stats.dead_letter, dead_letter_threshold
                ));
                reasons_en.push(format!(
                    "dead-letter backlog {} >= threshold {}",
                    stats.dead_letter, dead_letter_threshold
                ));
                breach_kinds.push("dead_letter".to_string());
            }
            if pending_age_threshold_secs > 0
                && stats.stale_pending > 0
                && stats.max_pending_age_seconds >= pending_age_threshold_secs
            {
                reasons_zh.push(format!(
                    "超时 pending 任务 {} 个（最老 {}s >= 阈值 {}s）",
                    stats.stale_pending, stats.max_pending_age_seconds, pending_age_threshold_secs
                ));
                reasons_en.push(format!(
                    "stale pending items {} (oldest {}s >= threshold {}s)",
                    stats.stale_pending, stats.max_pending_age_seconds, pending_age_threshold_secs
                ));
                breach_kinds.push("pending_age".to_string());
            }
            if reasons_zh.is_empty() {
                continue;
            }
            let message_zh = format!(
                "站点 {site} 复制 backlog SLA 超阈值：{}",
                reasons_zh.join("；")
            );
            let message_en = format!(
                "replication backlog SLA breached on site {site}: {}",
                reasons_en.join("; ")
            );
            let fingerprint = json!({
                "site_id": site,
                "breaches": breach_kinds,
                "failed_threshold": failed_threshold,
                "dead_letter_threshold": dead_letter_threshold,
                "pending_age_threshold_seconds": pending_age_threshold_secs,
            });
            let breach_hash = Self::hash_json(&fingerprint).unwrap_or_else(|_| {
                format!(
                    "{site}:{failed_threshold}:{dead_letter_threshold}:{pending_age_threshold_secs}"
                )
            });
            let details = json!({
                "site_id": site,
                "failed": stats.failed,
                "dead_letter": stats.dead_letter,
                "stale_pending": stats.stale_pending,
                "max_pending_age_seconds": stats.max_pending_age_seconds,
                "failed_threshold": failed_threshold,
                "dead_letter_threshold": dead_letter_threshold,
                "pending_age_threshold_seconds": pending_age_threshold_secs,
                "breaches": fingerprint["breaches"].clone(),
                "breach_hash": breach_hash.clone(),
                "total": stats.total,
            });
            breached_sites.insert(site.clone(), (message_zh, message_en, details, breach_hash));
        }

        let mut history = self.alert_history.write().await;

        for entry in history.iter_mut() {
            let Some(site) = Self::replication_backlog_alert_site(&entry.source) else {
                continue;
            };
            if entry.status != "firing" || entry.resolved_at.is_some() {
                continue;
            }
            if breached_sites.contains_key(site) {
                continue;
            }
            entry.status = "resolved".to_string();
            entry.resolved_by = Some("system".to_string());
            entry.resolved_at = Some(now);
            entry.message = bilingual_runtime_error(
                &format!("站点 {site} 复制 backlog SLA 已恢复"),
                format!("replication backlog SLA recovered on site {site}"),
            );
        }

        for (site, (message_zh, message_en, details, breach_hash)) in breached_sites {
            let source = Self::replication_backlog_alert_source(&site);
            let already_firing = history.iter().any(|entry| {
                entry.source == source && entry.status == "firing" && entry.resolved_at.is_none()
            });
            if already_firing {
                continue;
            }
            let last_same_hash_triggered = history
                .iter()
                .filter(|entry| {
                    entry.source == source
                        && Self::replication_backlog_alert_breach_hash(&entry.details)
                            == Some(breach_hash.as_str())
                })
                .map(|entry| entry.triggered_at)
                .max();
            if let Some(last) = last_same_hash_triggered {
                if now.signed_duration_since(last) < suppress_interval_chrono {
                    continue;
                }
            }
            let last_triggered = history
                .iter()
                .filter(|entry| entry.source == source)
                .map(|entry| entry.triggered_at)
                .max();
            if let Some(last) = last_triggered {
                if now.signed_duration_since(last) < suppress_interval_chrono {
                    continue;
                }
            }
            history.push(AlertHistoryEntry {
                id: format!("history-{}", Uuid::new_v4().simple()),
                rule_id: None,
                rule_name: Some("复制 backlog SLA 超阈值".to_string()),
                severity: "warning".to_string(),
                status: "firing".to_string(),
                message: bilingual_runtime_error(&message_zh, message_en),
                triggered_at: now,
                source,
                assignee: None,
                claimed_at: None,
                acknowledged_by: None,
                acknowledged_at: None,
                resolved_by: None,
                resolved_at: None,
                details,
            });
        }
        Ok(())
    }

    #[tracing::instrument(name = "replication_queue", skip(self), fields(worker_id = %worker_id))]
    pub async fn process_replication_queue_once(&self, worker_id: &str) -> usize {
        let now = Utc::now();
        let max_attempts = Self::replication_max_attempts();
        let lease_until = now
            + Duration::from_std(Self::replication_lease_interval())
                .unwrap_or_else(|_| Duration::seconds(1));
        let next_item = {
            let mut backlog = self.replication_backlog.write().await;
            let mut picked = None::<ReplicationBacklogItem>;
            let mut picked_index = None::<usize>;
            let mut picked_priority = i32::MAX;
            let mut picked_operation_priority = u8::MAX;
            let mut picked_checkpoint = u64::MAX;
            for (index, entry) in backlog.iter().enumerate() {
                let retry_ready = Self::replication_retry_ready(entry, &now);
                let lease_expired = entry.lease_until.map(|value| value <= now).unwrap_or(true);
                let ready = entry.status == "pending"
                    || retry_ready
                    || (entry.status == "in_progress" && lease_expired);
                if !ready {
                    continue;
                }
                if Self::replication_target_blocked(&backlog, index, &now) {
                    continue;
                }
                let operation_priority = Self::replication_operation_priority(&entry.operation);
                if entry.priority < picked_priority
                    || (entry.priority == picked_priority
                        && operation_priority < picked_operation_priority)
                    || (entry.priority == picked_priority
                        && operation_priority == picked_operation_priority
                        && entry.checkpoint < picked_checkpoint)
                {
                    picked_index = Some(index);
                    picked_priority = entry.priority;
                    picked_operation_priority = operation_priority;
                    picked_checkpoint = entry.checkpoint;
                }
            }
            if let Some(index) = picked_index {
                if let Some(entry) = backlog.get_mut(index) {
                    entry.status = "in_progress".to_string();
                    entry.attempts += 1;
                    entry.last_attempt_at = now;
                    entry.lease_owner = Some(worker_id.to_string());
                    entry.lease_until = Some(lease_until);
                    picked = Some(entry.clone());
                }
            }
            picked
        };
        let Some(item) = next_item else {
            return 0;
        };

        let result = self.apply_replication_item(&item).await;
        let mut backlog = self.replication_backlog.write().await;
        if let Some(entry) = backlog.iter_mut().find(|entry| entry.id == item.id) {
            match result {
                Ok(_) => {
                    entry.status = "done".to_string();
                    entry.last_error.clear();
                    entry.lease_owner = None;
                    entry.lease_until = None;
                }
                Err(err) => {
                    let non_retryable = Self::replication_error_is_non_retryable(&err);
                    let err = Self::replication_error_message(&err);
                    if non_retryable {
                        entry.status = "dead_letter".to_string();
                        entry.lease_owner = None;
                        entry.lease_until = None;
                        entry.last_error = Self::replication_dead_letter_non_retryable_error(&err);
                        tracing::error!(
                            target_site = %item.target_site,
                            bucket = %item.source_bucket,
                            key = %item.object_key,
                            reason = "non_retryable",
                            "复制任务进入死信队列 / replication item dead-lettered"
                        );
                    } else if entry.attempts >= max_attempts {
                        entry.status = "dead_letter".to_string();
                        entry.lease_owner = None;
                        entry.lease_until = None;
                        entry.last_error =
                            Self::replication_dead_letter_error(entry.attempts, max_attempts, &err);
                        tracing::error!(
                            target_site = %item.target_site,
                            bucket = %item.source_bucket,
                            key = %item.object_key,
                            attempts = entry.attempts,
                            max_attempts,
                            reason = "max_attempts_exceeded",
                            "复制任务进入死信队列 / replication item dead-lettered"
                        );
                    } else {
                        entry.status = "failed".to_string();
                        entry.lease_owner = None;
                        entry.lease_until = None;
                        entry.last_error = err;
                    }
                }
            }
        }
        backlog.retain(|entry| {
            if entry.id == item.id {
                return true;
            }
            if !Self::replication_items_same_target(entry, &item) {
                return true;
            }
            if !Self::replication_item_supersedable(&entry.status) {
                return true;
            }
            entry.checkpoint > item.checkpoint
        });
        drop(backlog);
        self.persist_replication_runtime_state().await;
        1
    }

    /// 探测一轮集群 peer 健康(GET `/minio/health/live`),更新 `peer_health`。
    ///
    /// 仅集群模式(`local_node_id > 0`)生效。任一 peer 由在线跳变为离线时,触发一次
    /// 远程感知扫描——离线节点上的分片会被识别为缺失并自动排出重建任务。
    pub(crate) async fn process_peer_health_probe_once(self: &Arc<Self>) -> Result<(), String> {
        if self.local_node_id == 0 {
            return Ok(());
        }
        let peers = {
            let guard = self.cluster_peers.read().await;
            guard
                .values()
                .filter(|peer| peer.node_id != self.local_node_id)
                .map(|peer| (peer.node_id, peer.api_addr.clone()))
                .collect::<Vec<_>>()
        };
        if peers.is_empty() {
            return Ok(());
        }
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .map_err(|err| err.to_string())?;

        let mut went_offline = false;
        for (node_id, api_addr) in peers {
            let now = Utc::now();
            let healthy = client
                .get(format!("{api_addr}/minio/health/live"))
                .send()
                .await
                .map(|resp| resp.status().is_success())
                .unwrap_or(false);

            let mut runtime = self.storage_governance.write().await;
            let was_online = runtime
                .peer_health
                .get(&node_id)
                .map(|state| state.online)
                .unwrap_or(true);
            let entry = runtime
                .peer_health
                .entry(node_id)
                .or_insert_with(|| PeerHealthState {
                    online: true,
                    last_check_at: now,
                    last_ok_at: None,
                    consecutive_failures: 0,
                });
            entry.online = healthy;
            entry.last_check_at = now;
            if healthy {
                entry.last_ok_at = Some(now);
                entry.consecutive_failures = 0;
            } else {
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            }
            drop(runtime);

            if was_online && !healthy {
                went_offline = true;
                tracing::warn!(
                    node_id,
                    node = %api_addr,
                    "集群节点离线,触发重建扫描 / cluster peer offline, triggering rebuild scan"
                );
            }
        }

        if went_offline {
            let state = Arc::clone(self);
            let _ = process_storage_governance_scan_once(&state).await;
        }
        Ok(())
    }

    pub(crate) fn start_background_workers(self: &Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        for _ in 0..Self::replication_worker_concurrency() {
            let state = Arc::clone(self);
            let worker_id = format!("replication-worker-{}", Uuid::new_v4().simple());
            handle.spawn(async move {
                loop {
                    let _ = state.process_replication_queue_once(&worker_id).await;
                    tokio::time::sleep(Self::replication_worker_interval()).await;
                }
            });
        }
        let replication_alert_state = Arc::clone(self);
        handle.spawn(async move {
            loop {
                let _ = replication_alert_state
                    .process_replication_backlog_sla_watchdog_once()
                    .await;
                tokio::time::sleep(Self::replication_backlog_alert_interval()).await;
            }
        });
        let alert_rule_state = Arc::clone(self);
        handle.spawn(async move {
            loop {
                let _ = alert_rule_state.process_alert_rules_once().await;
                tokio::time::sleep(Self::alert_rule_eval_interval()).await;
            }
        });
        let alert_delivery_state = Arc::clone(self);
        let alert_delivery_worker_id = format!("alert-worker-{}", Uuid::new_v4().simple());
        handle.spawn(async move {
            loop {
                let _ = alert_delivery_state
                    .process_alert_delivery_queue_once(&alert_delivery_worker_id)
                    .await;
                tokio::time::sleep(Self::alert_delivery_interval()).await;
            }
        });
        let lifecycle_state = Arc::clone(self);
        handle.spawn(async move {
            loop {
                let _ = lifecycle_state.process_bucket_lifecycle_once().await;
                tokio::time::sleep(Self::lifecycle_interval()).await;
            }
        });
        let storage_scan_state = Arc::clone(self);
        handle.spawn(async move {
            loop {
                let _ = process_storage_governance_scan_once(&storage_scan_state).await;
                tokio::time::sleep(Self::storage_scan_interval()).await;
            }
        });
        let storage_heal_state = Arc::clone(self);
        handle.spawn(async move {
            loop {
                let _ = process_storage_governance_heal_queue_once(&storage_heal_state).await;
                tokio::time::sleep(Self::storage_heal_worker_interval()).await;
            }
        });
        if self.local_node_id > 0 {
            let peer_health_state = Arc::clone(self);
            handle.spawn(async move {
                loop {
                    let _ = peer_health_state.process_peer_health_probe_once().await;
                    tokio::time::sleep(Self::peer_health_probe_interval()).await;
                }
            });
        }
        let managed_async_state = Arc::clone(self);
        let managed_async_worker_id = format!("async-worker-{}", Uuid::new_v4().simple());
        handle.spawn(async move {
            loop {
                let _ = managed_async_state
                    .process_managed_async_jobs_once(&managed_async_worker_id)
                    .await;
                tokio::time::sleep(Self::managed_async_job_worker_interval()).await;
            }
        });
        let memory_trim_state = Arc::clone(self);
        handle.spawn(async move {
            loop {
                tokio::time::sleep(Self::memory_trim_interval()).await;
                memory_trim_state.maybe_trim_memory();
            }
        });
    }

    pub async fn architecture_alignment_report(&self) -> ArchitectureAlignmentReport {
        let required_planes = [
            "control-plane",
            "metadata-plane",
            "data-plane",
            "worker-plane",
        ];
        let topology = self.architecture.clone();
        let plane_ids: HashSet<&str> = topology
            .planes
            .iter()
            .map(|plane| plane.id.as_str())
            .collect();
        let missing_planes: Vec<String> = required_planes
            .iter()
            .filter(|plane| !plane_ids.contains(*plane))
            .map(|plane| plane.to_string())
            .collect();

        let credential_count = self.credentials.read().await.len();
        let user_count = self.users.read().await.len();
        let group_count = self.groups.read().await.len();
        let policy_count = self.policies.read().await.len();
        let cluster_config_count = self.cluster_config_history.read().await.len();
        let bucket_count = self.buckets.read().await.len();
        let bucket_object_lock_count = self.bucket_object_locks.read().await.len();
        let site_replication_count = self.site_replications.read().await.len();
        let job_count = self.jobs.read().await.len();
        let alert_rule_count = self.alert_rules.read().await.len();
        let alert_channel_count = self.alert_channels.read().await.len();
        let replication_checkpoint_count = self.replication_checkpoints.read().await.len();
        let raft_status = self.metadata_raft_status().await;
        let data_disk_ready = self.data_disks.iter().filter(|path| path.exists()).count();
        let data_dir_ready = self.data_dir.exists();
        let s3_credential_ready = !self.s3_access_key.is_empty() && !self.s3_secret_key.is_empty();
        let jwt_ready = !self.jwt_secret.is_empty();

        let planes: Vec<PlaneAlignmentStatus> = topology
            .planes
            .iter()
            .map(|plane| {
                let mut checks = Vec::new();
                let mut component_ready = 0usize;

                for component in &plane.components {
                    let ready = match component.id.as_str() {
                        "admin-api" => cluster_config_count > 0,
                        "auth-service" => jwt_ready && credential_count > 0 && user_count > 0,
                        "audit-service" => user_count > 0,
                        "bucket-metadata-store" => {
                            bucket_object_lock_count >= bucket_count
                                && raft_status.online_peers >= raft_status.quorum
                        }
                        "iam-metadata-store" => {
                            user_count > 0
                                && group_count > 0
                                && policy_count > 0
                                && raft_status.online_peers >= raft_status.quorum
                        }
                        "cluster-config-history" => {
                            cluster_config_count > 0 && raft_status.commit_index > 0
                        }
                        "s3-gateway" => s3_credential_ready && data_disk_ready >= 3,
                        "object-store" => data_dir_ready && data_disk_ready >= 3,
                        "multipart-store" => data_dir_ready && data_disk_ready >= 3,
                        "replication-worker" => {
                            site_replication_count > 0
                                && replication_checkpoint_count <= site_replication_count
                        }
                        "job-orchestrator" => job_count > 0,
                        "alert-worker" => alert_rule_count > 0 && alert_channel_count > 0,
                        _ => false,
                    };
                    if ready {
                        component_ready += 1;
                    }
                    checks.push(format!(
                        "{}={}",
                        component.id,
                        if ready { "ready" } else { "missing" }
                    ));
                }

                let status = if component_ready == plane.components.len() {
                    "aligned"
                } else {
                    "degraded"
                };

                PlaneAlignmentStatus {
                    plane_id: plane.id.clone(),
                    plane_name: plane.name.clone(),
                    status: status.to_string(),
                    component_total: plane.components.len(),
                    component_ready,
                    checks,
                }
            })
            .collect();

        let all_planes_aligned = planes.iter().all(|plane| plane.status == "aligned");
        let overall_status = if missing_planes.is_empty() && all_planes_aligned {
            "aligned"
        } else {
            "degraded"
        };

        ArchitectureAlignmentReport {
            version: topology.version,
            generated_at: Utc::now(),
            overall_status: overall_status.to_string(),
            missing_planes,
            planes,
        }
    }
}

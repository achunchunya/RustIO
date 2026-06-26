//! 集群级 rebalance:对象 EC 重编码迁移原语(migrate_ec_object_layout) +
//! leader 集中编排器(run_cluster_rebalance) + graceful decommission / force remove / 加节点摊匀。
//!
//! 对象迁移的幂等性保证:按 SHA-256(key) 从当前 cluster_peers 重新推导期望布局,
//! 若 manifest 已与期望一致则 Skip(重入安全)。迁移采用「还原存储态 payload → 新布局重写」
//! 方式,直接复用 write_ec_object_streaming / read_ec_object 等既有 EC 原语,加密对象无需解密。

use super::*;
use crate::state::AppState;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::warn;

// ── 错误信息构建 ──

/// 构建双语错误:简体中文在前,英文随后(与现有错误风格对齐)。
fn bilingual(cn: &str, en: &str) -> String {
    format!("{cn} / {en}")
}

// ── 迁移结果 ──

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) enum MigrateOutcome {
    /// 布局已与期望一致,无需迁移(幂等跳过)。
    Skipped,
    /// 迁移成功(重编码 + manifest 更新 + 旧分片清理)。
    Migrated { rewritten_shards: usize, cleared_shards: usize },
}

// ── 核心迁移原语 ──

/// 对单个对象执行 EC 布局重编码迁移。
///
/// - 从 manifest quorum 读取当前 manifest,按 cluster_peers 推导期望布局与放置;
/// - 一致则 Skipped(幂等);
/// - 不一致则:还原存储态 payload(流式)→新布局 write_ec_object_streaming 重写→清理旧分片→
///   覆盖旧副本节点 stale manifest。
/// - 失败时旧 manifest/分片原封未动,可重试(无半态)。
pub(crate) async fn migrate_ec_object_layout(
    state: &Arc<AppState>,
    bucket: &str,
    key: &str,
) -> Result<MigrateOutcome, String> {
    // 1) 取当前 manifest。
    let bucket_root = match bucket_path(state, bucket) {
        Ok(path) => path,
        Err(response) => return Err(response_message(response).await),
    };
    let manifest = match read_manifest_quorum(state, &bucket_root, bucket, key).await {
        Some(m) => m,
        None => return Err(bilingual("manifest 无任何副本", "no manifest replica found")),
    };
    if manifest.data_shards == 0 {
        return Err(bilingual("manifest 破损(零 data 分片)", "broken manifest: zero data shards"));
    }

    let total_size = manifest.total_size as usize;

    // 2) 推导期望布局与放置;一致则幂等跳过。
    // 优先使用 manifest 中记录的 group_id(组感知),旧 manifest 无 group_id 时退化全局。
    let (exp_data, exp_parity) = if manifest.group_id.is_empty() {
        ec_layout_for(state).await
    } else {
        ec_layout_for_in_group(state, &manifest.group_id).await
    };
    let exp_total = exp_data + exp_parity;
    let expected_placement = if manifest.group_id.is_empty() {
        resolve_shard_placements(state, key, exp_total).await?
    } else {
        resolve_shard_placements_in_group(state, key, exp_total, &manifest.group_id).await?
    };

    // 检查是否已一致:分片数与归属节点完全匹配。
    // 归一化口径:manifest 中本节点分片 node_id=None(写入时 is_remote=false 不记 node_id),
    // 而 resolve_shard_placements 对本节点分片返回真实 node_id。比较时统一把
    // 「本节点 / 0 / None」折叠为 0,避免本地分片被误判为需迁移。
    let normalize = |node_id: u64| -> u64 {
        if node_id == state.local_node_id {
            0
        } else {
            node_id
        }
    };
    let mut layout_matches = exp_data == manifest.data_shards && exp_parity == manifest.parity_shards;
    if layout_matches {
        for shard in &manifest.shards {
            let exp_place = expected_placement.get(shard.shard_index);
            let expected_node = normalize(exp_place.map(|p| p.node_id).unwrap_or(0));
            let current_node = normalize(shard.node_id.unwrap_or(0));
            if current_node != expected_node {
                layout_matches = false;
                break;
            }
        }
    }
    if layout_matches {
        return Ok(MigrateOutcome::Skipped);
    }

    let manifest_before_updated = manifest.updated_at;
    let object_hash = sha256_hex(key.as_bytes());

    // 3) 还原「存储态 payload」到临时文件(流式,防 OOM)。
    let tmp_dir = state.data_dir.join(".rebalance_tmp");
    let _ = tokio::fs::create_dir_all(&tmp_dir).await;
    let u = uuid::Uuid::new_v4();
    let tmp_path = tmp_dir.join(format!("{u}.bin"));

    let restore_result = restore_storage_payload(state, &manifest, bucket, key, &object_hash, &tmp_path).await;
    match restore_result {
        Ok(actual_size) => {
            if actual_size != total_size {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(bilingual(
                    &format!("还原 payload 大小不匹配:期望 {total_size},实际 {actual_size}"),
                    &format!("restored payload size mismatch: expected {total_size}, got {actual_size}"),
                ));
            }
        }
        Err(err) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(err);
        }
    }

    // 4) 并发写防护:重写前确认 manifest 未被客户端覆盖(覆盖则放弃,客户端新写已按当前布局落盘)。
    //    检查→重写窗口内的并发覆盖与现状 S3 last-writer-wins 语义一致。
    if let Some(latest) = read_manifest_quorum(state, &bucket_root, bucket, key).await {
        if latest.updated_at > manifest_before_updated {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Ok(MigrateOutcome::Skipped);
        }
    }

    // 5) 用新布局重写:write_ec_object_streaming 自动用 ec_layout_for + resolve_shard_placements
    //    产生新 manifest 并 quorum 写副本。
    if let Err(response) =
        write_ec_object_streaming(state, bucket, key, &tmp_path, total_size as u64).await
    {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(format!("重写新布局失败: {}", response_message(response).await));
    }
    let _ = tokio::fs::remove_file(&tmp_path).await;

    // 6) 读回新 manifest,据其清理旧分片。
    let new_manifest = match read_manifest_quorum(state, &bucket_root, bucket, key).await {
        Some(m) => m,
        None => return Err(bilingual("新 manifest 读取失败", "new manifest read failed")),
    };

    // 7) 清理:删除不再被新 manifest 引用的旧分片。
    //    远程分片 manifest 的 path 为空,不能用 path 判断引用关系;改用物理位置三元组
    //    (拥有节点, disk_index, shard_index) 唯一标识分片落点。本节点分片 node_id=None
    //    归一为 local_node_id,与新 manifest 同口径比较。
    let phys_key = |shard: &EcShardInfo| -> (u64, usize, usize) {
        (
            shard.node_id.unwrap_or(state.local_node_id),
            shard.disk_index,
            shard.shard_index,
        )
    };
    let new_keys: HashSet<(u64, usize, usize)> =
        new_manifest.shards.iter().map(phys_key).collect();
    let mut cleared = 0usize;
    for shard in &manifest.shards {
        if new_keys.contains(&phys_key(shard)) {
            continue; // 新布局仍占用同一落点,保留。
        }
        if shard_is_remote(shard, state.local_node_id) {
            let node_addr = shard.node_addr.as_deref().unwrap_or_default();
            let _ = delete_remote_shard(
                node_addr,
                bucket,
                &object_hash,
                shard.disk_index,
                shard.shard_index,
            )
            .await;
            cleared += 1;
        } else if !shard.path.as_os_str().is_empty() {
            let _ = tokio::fs::remove_file(&shard.path).await;
            cleared += 1;
        }
    }

    // 7) 覆盖 stale manifest 副本:把新 manifest 推送到旧 manifest 各分片节点全集,
    //    防止 read_manifest_quorum 本地快路径读到旧 manifest(该路径不比版本)。
    let old_node_set: HashSet<u64> = manifest
        .shards
        .iter()
        .filter_map(|s| if s.node_id.unwrap_or(0) != 0 { s.node_id } else { Some(state.local_node_id) })
        .collect();
    let new_bytes = serde_json::to_vec_pretty(&new_manifest).map_err(|e| e.to_string())?;
    for node_id in old_node_set {
        if node_id == state.local_node_id {
            continue; // 本节点 manifest 已由 write_manifest_quorum 写好。
        }
        let Some(addr) = state
            .cluster_peers
            .read()
            .await
            .get(&node_id)
            .map(|p| p.api_addr.clone())
            .filter(|a| !a.is_empty())
        else {
            continue;
        };
        let _ = put_remote_manifest(&addr, bucket, &object_hash, new_bytes.clone()).await;
    }

    let rewritten = new_manifest.shards.len();
    Ok(MigrateOutcome::Migrated {
        rewritten_shards: rewritten,
        cleared_shards: cleared,
    })
}

// ── 存储态 payload 还原(流式) ──

/// 从 manifest 分片中还原「存储态」payload(未解密,即为 write_ec_object_streaming 能直接
/// 消费的格式)到临时文件。
///
/// 快路径:逐个 data 分片顺序写入临时文件,truncate 到 total_size;
/// 回退路径:任一 data 分片缺失/损坏 → RS 重建(收集可用分片字节 → reconstruct → 仅取 data)。
async fn restore_storage_payload(
    state: &AppState,
    manifest: &EcObjectManifest,
    bucket: &str,
    _key: &str,
    object_hash: &str,
    out_path: &PathBuf,
) -> Result<usize, String> {
    let total_size = manifest.total_size as usize;
    let shard_size = manifest.shard_size;
    let data_shards = manifest.data_shards;
    let parity_shards = manifest.parity_shards;
    let total_shards = data_shards + parity_shards;

    // 快路径:尝试逐个 data 分片直接写入。
    let fast_ok = atomic_stream_data_shards(state, bucket, object_hash, manifest, out_path, total_size).await;

    if fast_ok {
        let meta = tokio::fs::metadata(out_path)
            .await
            .map_err(|e| format!("stat tmp: {e}"))?;
        return Ok(meta.len() as usize);
    }

    // 回退路径:RS 重建(兼容 force remove 后存活分片场景)。
    let reed = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|e| bilingual(&format!("RS 初始化失败: {e}"), &format!("RS init failed: {e}")))?;
    let mut loaded: Vec<Option<Vec<u8>>> = vec![None; total_shards];

    for shard in &manifest.shards {
        if shard.shard_index >= total_shards {
            continue;
        }
        let bytes = if shard_is_remote(shard, state.local_node_id) {
            let addr = shard.node_addr.as_deref().unwrap_or_default();
            get_remote_shard(addr, bucket, object_hash, shard.disk_index, shard.shard_index)
                .await
                .ok()
        } else {
            tokio::fs::read(&shard.path).await.ok()
        };
        if let Some(bytes) = bytes {
            if bytes.len() == shard_size {
                loaded[shard.shard_index] = Some(bytes);
            }
        }
    }

    reed.reconstruct(&mut loaded)
        .map_err(|e| bilingual(&format!("RS 重建失败: {e}"), &format!("RS reconstruct failed: {e}")))?;

    let mut file = tokio::fs::File::create(out_path)
        .await
        .map_err(|e| format!("create tmp file: {e}"))?;
    let mut written = 0usize;
    for bytes in loaded.iter().take(data_shards).flatten() {
        let take = bytes.len().min(total_size.saturating_sub(written));
        if take > 0 {
            file.write_all(&bytes[..take]).await.map_err(|e| format!("write tmp: {e}"))?;
            written += take;
        }
    }
    file.sync_all().await.map_err(|e| format!("sync tmp: {e}"))?;
    Ok(written)
}

/// 流式快路径:逐个 data 分片顺序读(本地/远程)写到临时文件。
/// 返回 true 表示全部 data 分片成功读取并写入(无遗漏/无损坏)。
async fn atomic_stream_data_shards(
    state: &AppState,
    bucket: &str,
    object_hash: &str,
    manifest: &EcObjectManifest,
    out_path: &PathBuf,
    total_size: usize,
) -> bool {
    let data_shards = manifest.data_shards;
    let mut shards_by_index: Vec<Option<&EcShardInfo>> = vec![None; data_shards];
    for shard in &manifest.shards {
        if shard.shard_index < data_shards {
            shards_by_index[shard.shard_index] = Some(shard);
        }
    }

    let mut file = match tokio::fs::File::create(out_path).await {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut written = 0usize;

    for idx in 0..data_shards {
        let Some(shard) = shards_by_index.get(idx).and_then(|s| *s) else {
            return false;
        };
        let bytes = if shard_is_remote(shard, state.local_node_id) {
            let addr = shard.node_addr.as_deref().unwrap_or_default();
            match get_remote_shard(addr, bucket, object_hash, shard.disk_index, shard.shard_index).await {
                Ok(b) => b,
                Err(_) => return false,
            }
        } else {
            match tokio::fs::read(&shard.path).await {
                Ok(b) => b,
                Err(_) => return false,
            }
        };
        if bytes.len() != manifest.shard_size {
            return false;
        }
        let take = bytes.len().min(total_size.saturating_sub(written));
        if take == 0 {
            break;
        }
        if tokio::io::AsyncWriteExt::write_all(&mut file, &bytes[..take])
            .await
            .is_err()
        {
            return false;
        }
        written += take;
    }
    if file.sync_all().await.is_err() {
        return false;
    }
    written == total_size
}

// ── manifest 枚举 RPC 端点(leader 集中编排用) ──

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ManifestEntry {
    pub(crate) bucket: String,
    pub(crate) key: String,
    pub(crate) updated_at: String, // RFC3339
    #[serde(default)]
    pub(crate) node_ids: Vec<u64>, // 分片所在节点(用于 scope 过滤)
}

/// internal RPC:GET /api/v1/internal/ec/manifest-list?bucket=&cursor=&limit=
/// 扫描本节点各 bucket `.rustio_ec_meta/`,分页返回 manifest 条目清单。
pub(crate) async fn internal_ec_manifest_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<ManifestListParams>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    let limit = params.limit.map(|v| v.clamp(1, 2000)).unwrap_or(200);
    let cursor_bucket = params.cursor.as_deref().unwrap_or("");
    let filter_bucket = params.bucket.as_deref().filter(|b| !b.is_empty());
    let (entries, next_cursor) =
        scan_manifest_entries_paged(&state, cursor_bucket, limit, filter_bucket).await;
    (StatusCode::OK, Json(json!({ "entries": entries, "next_cursor": next_cursor }))).into_response()
}

/// 分页扫描本节点 manifest 清单(handler 与本地枚举共用,可独立单测)。
///
/// 分页语义:游标 = 已完整返回的最后一个 bucket 名。`limit` 是 **bucket 边界对齐的软上限**——
/// 单个 bucket 始终一次性完整返回(不中途截断,避免大 bucket 超出 limit 的对象被漏枚举导致
/// rebalance 丢对象),达到 limit 后在 bucket 边界停止,下一页从下一个 bucket 续。
/// bucket 列表排序后遍历,保证跨 RPC 调用游标稳定有效。返回 `(entries, next_cursor)`,
/// next_cursor 为空表示已枚举到末尾。
pub(crate) async fn scan_manifest_entries_paged(
    state: &AppState,
    cursor_bucket: &str,
    limit: usize,
    filter_bucket: Option<&str>,
) -> (Vec<ManifestEntry>, String) {
    // 排序保证跨 RPC 顺序稳定(HashMap.keys() 顺序不确定会使游标失效)。
    let mut bucket_names = state
        .buckets
        .read()
        .await
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    bucket_names.sort();
    let mut entries: Vec<ManifestEntry> = Vec::new();
    let mut next_cursor = String::new();
    let mut started = cursor_bucket.is_empty();

    for bucket_name in &bucket_names {
        if filter_bucket.is_some_and(|fb| bucket_name.as_str() != fb) {
            continue;
        }
        if !started {
            // 跳过游标及之前的 bucket(上一页已完整返回)。
            if bucket_name.as_str() == cursor_bucket {
                started = true;
            }
            continue;
        }

        let bucket_root = match bucket_path(state, bucket_name) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let manifest_dir = bucket_root.join(".rustio_ec_meta");
        let mut dir = match tokio::fs::read_dir(&manifest_dir).await {
            Ok(d) => d,
            Err(_) => {
                // 该 bucket 无 manifest 目录:仍视为"已完整处理",游标推进。
                next_cursor = bucket_name.clone();
                if entries.len() >= limit {
                    break;
                }
                continue;
            }
        };

        // 完整扫描该 bucket 的所有 manifest(不中途截断,保证不丢对象)。
        loop {
            let Some(entry) = dir.next_entry().await.unwrap_or(None) else {
                break;
            };
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let bytes = match tokio::fs::read(&path).await {
                Ok(b) => b,
                Err(_) => continue,
            };
            let manifest: EcObjectManifest = match serde_json::from_slice(&bytes) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let node_ids: Vec<u64> = manifest
                .shards
                .iter()
                .filter_map(|s| s.node_id)
                .chain(std::iter::once(state.local_node_id))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            entries.push(ManifestEntry {
                bucket: manifest.bucket.clone(),
                key: manifest.key.clone(),
                updated_at: manifest.updated_at.to_rfc3339(),
                node_ids,
            });
        }
        // 该 bucket 已完整返回,游标推进到它;达到软上限则在 bucket 边界停止。
        next_cursor = bucket_name.clone();
        if entries.len() >= limit {
            break;
        }
    }

    // 自然遍历完所有 bucket(未因 limit 提前 break)→ 清空游标表示结束。
    if entries.len() < limit {
        next_cursor = String::new();
    }

    (entries, next_cursor)
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct ManifestListParams {
    bucket: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}

// ── leader 集中编排器 ──

/// rebalance 范围。
#[derive(Debug, Clone)]
pub(crate) enum RebalanceScope {
    /// 全量摊匀:所有存量对象重编码到当前 cluster_peers 布局。
    All,
    /// 仅迁移引用指定节点(分片所在)的对象(decommission / force remove)。
    Node(u64),
}

impl RebalanceScope {
    fn to_job_kind(&self) -> String {
        match self {
            Self::All => "cluster-rebalance:all".to_string(),
            Self::Node(id) => format!("cluster-rebalance:node-{id}"),
        }
    }

    fn to_label(&self) -> String {
        match self {
            Self::All => "rebalance".to_string(),
            Self::Node(_) => "decommission".to_string(),
        }
    }
}

/// leader 集中编排:枚举各节点 manifest → 去重 → 限并发逐对象迁移 → jobs 进度跟踪。
///
/// 仅 leader 调用(调用方确保)。
/// - `scope`:全量摊匀 / 仅某 node 迁移。
/// - 幂等重入:重新发起同一 scope 时,已迁对象 migrate_ec_object_layout 返回 Skipped。
/// - 中断恢复:job checkpoint 记录最后一个成功迁移的 (bucket,key),重新发起从 checkpoitn 继续
///   (需配合 manifest-list 游标;当前简化:重入时全量重枚举,幂等跳过已迁对象)。
pub(crate) async fn run_cluster_rebalance(
    state: &Arc<AppState>,
    scope: RebalanceScope,
    reason: &str,
) -> Result<(usize, usize, usize), String> {
    let job_kind = scope.to_job_kind();
    let job_label = scope.to_label();

    // 创建/覆盖 job
    let job = upsert_storage_job(
        state.as_ref(),
        StorageJobDraft {
            kind: job_kind.clone(),
            target: match &scope {
                RebalanceScope::All => "cluster".to_string(),
                RebalanceScope::Node(id) => format!("node-{id}"),
            },
            bucket: None,
            key: None,
            version_id: None,
            priority: Some(if job_label == "decommission" { 2100 } else { 1500 }),
            affected_disks: vec![],
            missing_shards: 0,
            corrupted_shards: 0,
            source: "manual".to_string(),
            details: json!({ "scope": job_label, "reason": reason }),
        },
        "running",
    )
    .await;

    // 1) 枚举:并发从所有 peer 拉 manifest 清单。
    let all_entries = enumerate_cluster_manifests(state).await?;
    let total = all_entries.len();

    // 2) 根据 scope 过滤。
    let filtered: Vec<&ManifestEntry> = match &scope {
        RebalanceScope::All => all_entries.iter().collect(),
        RebalanceScope::Node(node_id) => all_entries
            .iter()
            .filter(|e| e.node_ids.contains(node_id))
            .collect(),
    };

    let parallelism = std::env::var("RUSTIO_REBALANCE_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2)
        .max(1);

    let throttle_ms = std::env::var("RUSTIO_REBALANCE_THROTTLE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let mut migrated = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;

    // 3) 限并发,逐对象迁移。
    let chunks: Vec<&[&ManifestEntry]> = filtered.chunks(parallelism).collect();
    for chunk in chunks {
        // 检查取消。
        {
            let jobs = state.jobs.read().await;
            if let Some(j) = jobs.iter().find(|j| j.id == job.id) {
                if j.status == "cancelled" {
                    return Err(bilingual(
                        &format!("rebalance 已取消:已迁移 {migrated},跳过 {skipped},失败 {failed}"),
                        &format!("rebalance cancelled: migrated {migrated}, skipped {skipped}, failed {failed}"),
                    ));
                }
            }
        }

        let mut tasks = Vec::new();
        for entry in chunk {
            let s = Arc::clone(state);
            let bucket = entry.bucket.clone();
            let key = entry.key.clone();
            tasks.push(tokio::spawn(async move {
                migrate_ec_object_layout(&s, &bucket, &key).await
            }));
        }

        for task in tasks {
            match task.await {
                Ok(Ok(MigrateOutcome::Migrated { .. })) => migrated += 1,
                Ok(Ok(MigrateOutcome::Skipped)) => skipped += 1,
                Ok(Err(err)) => {
                    warn!("对象迁移失败: {err}");
                    failed += 1;
                }
                Err(join_err) => {
                    warn!("迁移 task join 异常: {join_err}");
                    failed += 1;
                }
            }
        }

        // 更新 job 进度。
        let progress = if filtered.is_empty() { 0.95 } else { (migrated + skipped + failed) as f32 / filtered.len() as f32 };
        let _ = state.mutate_job(&job.id, |j| {
            j.progress = progress;
            let detail = json!({
                "scope": job_label,
                "migrated": migrated,
                "skipped": skipped,
                "failed": failed,
                "total_in_scope": filtered.len(),
                "total_cluster": total,
            });
            // details 为内部字段,payload 为 API(/api/v1/jobs)暴露字段,两者同步更新。
            j.details = detail.clone();
            j.payload = detail;
        })
        .await;

        if throttle_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(throttle_ms)).await;
        }
    }

    // 4) 整轮完成状态。
    if failed > 0 {
        let _ = state.mutate_job(&job.id, |j| {
            j.status = "failed".to_string();
            j.progress = 0.99;
        })
        .await;
        return Err(bilingual(
            &format!("rebalance 完成但有 {failed} 个对象失败(已迁移 {migrated},跳过 {skipped})"),
            &format!("rebalance done with {failed} failures (migrated {migrated}, skipped {skipped})"),
        ));
    }
    let _ = state.mutate_job(&job.id, |j| {
        j.status = "completed".to_string();
        j.progress = 1.0;
    })
    .await;
    Ok((migrated, skipped, failed))
}

/// 并发从全集群 peer 枚举 manifest 清单,按 (bucket,key) 去重取 updated_at 最新者。
async fn enumerate_cluster_manifests(state: &Arc<AppState>) -> Result<Vec<ManifestEntry>, String> {
    let token = AppState::internal_control_token();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("构建 client: {e}"))?;

    // 本地扫。
    let local = collect_local_manifest_entries(state).await?;

    // 远程并发拉。
    let peers: Vec<(u64, String)> = {
        let guard = state.cluster_peers.read().await;
        guard
            .values()
            .filter(|p| p.node_id != state.local_node_id && !p.api_addr.is_empty())
            .map(|p| (p.node_id, p.api_addr.clone()))
            .collect()
    };

    let mut remote_futs = Vec::new();
    for (_id, addr) in &peers {
        let addr = addr.clone();
        let tok = token.clone();
        let cl = client.clone();
        remote_futs.push(tokio::spawn(async move {
            fetch_remote_manifest_list(&cl, &addr, &tok).await
        }));
    }

    let mut all = local;
    for fut in remote_futs {
        match fut.await {
            Ok(Ok(entries)) => all.extend(entries),
            Ok(Err(e)) => warn!("远程 manifest 枚举失败: {e}"),
            Err(e) => warn!("远程 manifest 枚举 task join 异常: {e}"),
        }
    }

    // 按 (bucket,key) 去重,取 updated_at 最新。
    let mut dedup: std::collections::HashMap<(String, String), ManifestEntry> = std::collections::HashMap::new();
    for entry in all {
        let key = (entry.bucket.clone(), entry.key.clone());
        dedup
            .entry(key)
            .and_modify(|existing| {
                if entry.updated_at > existing.updated_at {
                    *existing = entry.clone();
                }
            })
            .or_insert_with(|| entry);
    }
    Ok(dedup.into_values().collect())
}

/// 本地扫描全部 manifest 条目(无分页,复用分页扫描逻辑的全量形式)。
async fn collect_local_manifest_entries(state: &AppState) -> Result<Vec<ManifestEntry>, String> {
    let (entries, _) = scan_manifest_entries_paged(state, "", usize::MAX, None).await;
    Ok(entries)
}

/// RPC 从远程节点拉 manifest 清单(分页)。
async fn fetch_remote_manifest_list(
    client: &reqwest::Client,
    addr: &str,
    token: &str,
) -> Result<Vec<ManifestEntry>, String> {
    let mut all = Vec::new();
    let mut cursor = String::new();
    loop {
        let mut url = format!("{addr}/api/v1/internal/ec/manifest-list?limit=500");
        if !cursor.is_empty() {
            url.push_str(&format!("&cursor={cursor}"));
        }
        let resp = client
            .get(&url)
            .header("x-rustio-internal-token", token)
            .send()
            .await
            .map_err(|e| format!("manifest-list RPC 失败: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("manifest-list HTTP {}", resp.status()));
        }
        let body: serde_json::Value = resp.json().await.map_err(|e| format!("decode: {e}"))?;
        let entries: Vec<ManifestEntry> = serde_json::from_value(
            body.get("entries").cloned().unwrap_or(serde_json::Value::Array(vec![])),
        )
        .map_err(|e| format!("parse entries: {e}"))?;
        all.extend(entries);
        cursor = body
            .get("next_cursor")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if cursor.is_empty() {
            break;
        }
    }
    Ok(all)
}

// ── 管理端点:集群级 rebalance ──

#[derive(Debug, serde::Deserialize)]
pub(crate) struct ClusterRebalanceRequest {
    pub(crate) reason: String,
}

/// POST /api/v1/storage/governance/cluster-rebalance — 全量存量摊匀(leader 集中编排)。
/// 非 leader 自动转发 leader;后台 tokio::spawn 执行,立即返回 job 视图。
pub(crate) async fn start_cluster_rebalance(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<ClusterRebalanceRequest>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request("原因不能为空 / reason cannot be empty"));
    }

    // 集群模式下编排在 leader 执行;非 leader 转发。
    if state.local_node_id > 0 && !state.is_metadata_leader() {
        let Some(leader_addr) = state.metadata_leader_addr() else {
            return Err(AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                "当前无已知 leader,无法发起 rebalance / no known leader".to_string(),
            ));
        };
        forward_cluster_rebalance_to_leader(&leader_addr, &body.reason).await?;
        return Ok(wrap(json!({ "forwarded_to": leader_addr })));
    }

    let reason = body.reason.clone();
    spawn_cluster_rebalance(&state, RebalanceScope::All, reason.clone());

    state
        .append_audit(
            &auth.username,
            "storage.governance.cluster-rebalance.start",
            "storage/governance/cluster-rebalance",
            "success",
            Some(reason),
            json!({ "scope": "all" }),
        )
        .await;
    state
        .push_event(
            "storage.governance.cluster-rebalance.started",
            "storage-governance",
            json!({ "scope": "all" }),
        )
        .await;
    Ok(wrap(json!({ "started": true, "scope": "all" })))
}

/// POST /api/v1/storage/governance/cluster-rebalance/cancel — 取消进行中的集群 rebalance。
pub(crate) async fn cancel_cluster_rebalance(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;

    let mut cancelled = 0usize;
    {
        let mut jobs = state.jobs.write().await;
        for job in jobs.iter_mut() {
            if job.kind.starts_with("cluster-rebalance:")
                && matches!(job.status.as_str(), "running" | "pending")
            {
                job.status = "cancelled".to_string();
                job.updated_at = Utc::now();
                cancelled += 1;
            }
        }
    }
    state
        .append_audit(
            &auth.username,
            "storage.governance.cluster-rebalance.cancel",
            "storage/governance/cluster-rebalance",
            "success",
            None,
            json!({ "cancelled": cancelled }),
        )
        .await;
    Ok(wrap(json!({ "cancelled": cancelled })))
}

/// 后台运行集群 rebalance(panic 防护,完成/失败记日志与事件)。
pub(crate) fn spawn_cluster_rebalance(state: &Arc<AppState>, scope: RebalanceScope, reason: String) {
    let state = Arc::clone(state);
    tokio::spawn(async move {
        use futures::FutureExt;
        let scope_label = scope.to_job_kind();
        let run = std::panic::AssertUnwindSafe(run_cluster_rebalance(&state, scope, &reason))
            .catch_unwind()
            .await;
        match run {
            Ok(Ok((migrated, skipped, failed))) => {
                tracing::info!(scope = %scope_label, migrated, skipped, failed, "集群 rebalance 完成");
                state
                    .push_event(
                        "storage.governance.cluster-rebalance.completed",
                        "storage-governance",
                        json!({ "scope": scope_label, "migrated": migrated, "skipped": skipped, "failed": failed }),
                    )
                    .await;
            }
            Ok(Err(err)) => {
                tracing::warn!(scope = %scope_label, error = %err, "集群 rebalance 失败");
                state
                    .push_event(
                        "storage.governance.cluster-rebalance.failed",
                        "storage-governance",
                        json!({ "scope": scope_label, "error": err }),
                    )
                    .await;
            }
            Err(_) => {
                tracing::error!(scope = %scope_label, "集群 rebalance panic,已捕获");
            }
        }
    });
}

/// 把集群 rebalance 请求转发到 leader。
async fn forward_cluster_rebalance_to_leader(leader_addr: &str, reason: &str) -> Result<(), AppError> {
    let url = format!("{leader_addr}/api/v1/internal/cluster/rebalance");
    let token = AppState::internal_control_token();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|err| AppError::internal(format!("构建转发 client 失败: {err}")))?;
    let resp = client
        .post(&url)
        .header("x-rustio-internal-token", &token)
        .json(&json!({ "reason": reason, "scope": "all" }))
        .send()
        .await
        .map_err(|err| AppError::internal(format!("转发 rebalance 到 leader 失败: {err}")))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(AppError::internal(format!("leader rebalance 返回 HTTP {}", resp.status())))
    }
}

/// internal:POST /api/v1/internal/cluster/rebalance — leader 侧接收转发的 rebalance 请求。
pub(crate) async fn internal_cluster_rebalance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    if !state.is_metadata_leader() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "not leader"})),
        )
            .into_response();
    }
    let reason = body
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("forwarded")
        .to_string();
    let scope = match body.get("scope").and_then(|v| v.as_str()) {
        Some(s) if s.starts_with("node-") => s
            .trim_start_matches("node-")
            .parse::<u64>()
            .map(RebalanceScope::Node)
            .unwrap_or(RebalanceScope::All),
        _ => RebalanceScope::All,
    };
    spawn_cluster_rebalance(&state, scope, reason);
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

// ── graceful decommission(优雅退役) ──

#[derive(Debug, serde::Deserialize)]
pub(crate) struct DecommissionRequest {
    pub(crate) node_id: u64,
    #[serde(default)]
    pub(crate) reason: Option<String>,
}

/// POST /api/v1/cluster/membership/decommission — 优雅退役在线节点。
/// 流程(leader-only,非 leader 转发):标记 draining(raft 复制)→ 后台 rebalance 迁出 →
/// 复核无残留 → raft_remove_member。中断可重入(draining 标记在 raft,重发端点续作)。
pub(crate) async fn decommission_cluster_member(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<DecommissionRequest>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;

    if state.local_node_id == 0 {
        return Err(AppError::bad_request(
            "单机模式不支持节点退役 / decommission unsupported in standalone mode",
        ));
    }
    if body.node_id == 0 {
        return Err(AppError::bad_request("node_id 必须 > 0 / node_id must be > 0"));
    }

    // 非 leader:转发 leader。
    if !state.is_metadata_leader() {
        let Some(leader_addr) = state.metadata_leader_addr() else {
            return Err(AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                "当前无已知 leader / no known leader".to_string(),
            ));
        };
        forward_decommission_to_leader(&leader_addr, body.node_id, body.reason.as_deref()).await?;
        return Ok(wrap(json!({ "forwarded_to": leader_addr })));
    }

    // 前置校验:目标存在、非自身、剩余非 draining 节点数足够。
    {
        let peers = state.cluster_peers.read().await;
        if !peers.contains_key(&body.node_id) {
            return Err(AppError::not_found("节点不存在 / node not found"));
        }
        if body.node_id == state.local_node_id {
            return Err(AppError::bad_request(
                "不能退役 leader 自身;请在其他节点发起 / cannot decommission the leader itself",
            ));
        }
        // 退役后剩余非 draining 节点须 ≥ 2(集群 EC 布局最小镜像 1+1 需 2 节点)。
        let remaining = peers
            .values()
            .filter(|p| !p.draining && p.node_id != body.node_id)
            .count();
        if remaining < 2 {
            return Err(AppError::bad_request(
                "退役后剩余节点不足 2,无法保证 EC 布局 / fewer than 2 nodes would remain",
            ));
        }
    }

    let reason = body.reason.clone().unwrap_or_else(|| "decommission".to_string());
    spawn_decommission(&state, body.node_id, reason.clone());

    state
        .append_audit(
            &auth.username,
            "cluster.membership.decommission.start",
            &format!("node/{}", body.node_id),
            "success",
            Some(reason),
            json!({ "node_id": body.node_id }),
        )
        .await;
    state
        .push_event(
            "cluster.membership.decommission.started",
            "cluster-service",
            json!({ "node_id": body.node_id }),
        )
        .await;
    Ok(wrap(json!({ "started": true, "node_id": body.node_id })))
}

/// 后台执行退役全流程(panic 防护)。
pub(crate) fn spawn_decommission(state: &Arc<AppState>, node_id: u64, reason: String) {
    let state = Arc::clone(state);
    tokio::spawn(async move {
        use futures::FutureExt;
        let run = std::panic::AssertUnwindSafe(run_decommission(&state, node_id, &reason))
            .catch_unwind()
            .await;
        match run {
            Ok(Ok(())) => {
                tracing::info!(node_id, "节点优雅退役完成");
                state
                    .push_event(
                        "cluster.membership.decommissioned",
                        "cluster-service",
                        json!({ "node_id": node_id }),
                    )
                    .await;
            }
            Ok(Err(err)) => {
                tracing::warn!(node_id, error = %err, "节点退役失败");
                state
                    .push_event(
                        "cluster.membership.decommission.failed",
                        "cluster-service",
                        json!({ "node_id": node_id, "error": err }),
                    )
                    .await;
            }
            Err(_) => tracing::error!(node_id, "节点退役 panic,已捕获"),
        }
    });
}

/// 退役全流程:标记 draining → rebalance(scope=node)→ 复核残留 → 移除成员。
async fn run_decommission(state: &Arc<AppState>, node_id: u64, reason: &str) -> Result<(), String> {
    // 1) 标记 draining(经 raft 复制到各节点,新写入立即不再落该节点)。
    //    持成员变更锁做「校验剩余非 draining 节点 ≥ 2 + 标记」,与 force-remove 互斥:
    //    避免并发移除把可用节点数降到布局无法满足。
    {
        let _guard = state.membership_change_lock.lock().await;
        let remaining = state
            .cluster_peers
            .read()
            .await
            .values()
            .filter(|p| !p.draining && p.node_id != node_id)
            .count();
        if remaining < 2 {
            return Err(bilingual(
                "退役后剩余节点不足 2,无法保证 EC 布局",
                "fewer than 2 nodes would remain after decommission",
            ));
        }
        set_peer_draining(state, node_id, true).await?;
    }

    // 2) rebalance 迁出引用该节点的对象。
    let (migrated, skipped, failed) =
        run_cluster_rebalance(state, RebalanceScope::Node(node_id), reason).await?;
    tracing::info!(node_id, migrated, skipped, failed, "退役迁出完成");

    // 3) 复核:重新枚举确认无对象仍引用该节点(防迁移期间客户端新写漏网)。
    //    draining 已生效,新写不会落该节点;此处再跑一轮兜底。
    let residual = enumerate_cluster_manifests(state)
        .await?
        .into_iter()
        .filter(|e| e.node_ids.contains(&node_id))
        .count();
    if residual > 0 {
        tracing::info!(node_id, residual, "退役复核发现残留,再迁一轮");
        run_cluster_rebalance(state, RebalanceScope::Node(node_id), reason).await?;
    }

    // 4) 从 raft 成员集移除(收缩 voter + RemoveClusterPeer 拓扑)。
    //    该节点已 draining,locked_remove_member 不需 force 校验(剩余即非 draining 节点)。
    locked_remove_member(state, node_id, false).await?;
    Ok(())
}

/// 设置某节点 draining 标记并经 raft 复制(读现有拓扑 → 改标记 → UpsertClusterPeer)。
async fn set_peer_draining(state: &Arc<AppState>, node_id: u64, draining: bool) -> Result<(), String> {
    let mut peer = {
        let peers = state.cluster_peers.read().await;
        peers
            .get(&node_id)
            .cloned()
            .ok_or_else(|| bilingual("节点不存在", "node not found"))?
    };
    if peer.draining == draining {
        return Ok(()); // 幂等。
    }
    peer.draining = draining;
    state
        .submit_metadata_command(MetadataCommand::UpsertClusterPeer(Box::new(peer)))
        .await
}

/// 转发退役请求到 leader。
async fn forward_decommission_to_leader(
    leader_addr: &str,
    node_id: u64,
    reason: Option<&str>,
) -> Result<(), AppError> {
    let url = format!("{leader_addr}/api/v1/internal/cluster/decommission");
    let token = AppState::internal_control_token();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|err| AppError::internal(format!("构建转发 client 失败: {err}")))?;
    let resp = client
        .post(&url)
        .header("x-rustio-internal-token", &token)
        .json(&json!({ "node_id": node_id, "reason": reason }))
        .send()
        .await
        .map_err(|err| AppError::internal(format!("转发退役到 leader 失败: {err}")))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(AppError::internal(format!("leader 退役返回 HTTP {}", resp.status())))
    }
}

/// internal:POST /api/v1/internal/cluster/decommission — leader 侧接收转发的退役请求。
pub(crate) async fn internal_cluster_decommission(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(response) = ensure_internal_token(&headers) {
        return response;
    }
    if !state.is_metadata_leader() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "not leader"}))).into_response();
    }
    let Some(node_id) = body.get("node_id").and_then(|v| v.as_u64()) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "missing node_id"}))).into_response();
    };
    let reason = body
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("decommission")
        .to_string();
    spawn_decommission(&state, node_id, reason);
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

// ── 单测 ──


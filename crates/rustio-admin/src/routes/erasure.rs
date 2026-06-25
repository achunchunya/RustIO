//! 纠删码（EC）对象读写

use super::*;
use std::os::fd::AsRawFd;
use tokio::io::AsyncSeekExt;

/// 设置文件绕过/弱化 page cache，减少大对象分片读写的双重拷贝。
/// - macOS：`F_NOCACHE`（无对齐要求，直接绕过缓存）。
/// - Linux：**不用 `O_DIRECT`**（它要求缓冲区/IO 大小/偏移三重 4096 对齐，当前 `Vec<u8>`
///   缓冲区与非对齐分片尾块会触发 `EINVAL` 写损坏）；改在 I/O 结束后用
///   `posix_fadvise(DONTNEED)` 提示内核丢弃页缓存（顾问式，无对齐要求，不破坏写入）。
fn set_nocache(file: &tokio::fs::File) {
    let _fd = file.as_raw_fd();
    #[cfg(target_os = "macos")]
    unsafe {
        libc::fcntl(_fd, libc::F_NOCACHE, 1);
    }
}

/// I/O 结束后丢弃文件的页缓存（仅 Linux，顾问式，安全无对齐要求）。macOS 由 F_NOCACHE 处理。
fn drop_page_cache(file: &tokio::fs::File) {
    let _fd = file.as_raw_fd();
    #[cfg(target_os = "linux")]
    unsafe {
        libc::posix_fadvise(_fd, 0, 0, libc::POSIX_FADV_DONTNEED);
    }
}

/// 拼接远程 EC 分片端点 URL。
fn remote_shard_url(
    node_addr: &str,
    bucket: &str,
    object_hash: &str,
    disk_index: usize,
    shard_index: usize,
) -> String {
    format!("{node_addr}/api/v1/internal/ec/shard/{bucket}/{object_hash}/{disk_index}/{shard_index}")
}

/// 判断 manifest 中某分片是否落在远程节点(集群模式)。
pub(crate) fn shard_is_remote(shard: &EcShardInfo, local_node_id: u64) -> bool {
    matches!(shard.node_id, Some(id) if id != 0 && id != local_node_id)
}

/// 拼接远程 manifest 端点 URL。
fn remote_manifest_url(node_addr: &str, bucket: &str, object_hash: &str) -> String {
    format!("{node_addr}/api/v1/internal/ec/manifest/{bucket}/{object_hash}")
}

/// 将 manifest 字节 PUT 到远程节点副本。
pub(crate) async fn put_remote_manifest(
    node_addr: &str,
    bucket: &str,
    object_hash: &str,
    bytes: Vec<u8>,
) -> Result<(), String> {
    let url = remote_manifest_url(node_addr, bucket, object_hash);
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|err| err.to_string())?;
    let resp = client
        .put(&url)
        .header("x-rustio-internal-token", AppState::internal_control_token())
        .body(bytes)
        .send()
        .await
        .map_err(|err| format!("remote manifest put to {node_addr} failed: {err}"))?;
    if !resp.status().is_success() {
        return Err(format!("remote manifest put status {} from {node_addr}", resp.status()));
    }
    Ok(())
}

/// 从远程节点 GET manifest 原始字节(不存在返回 Ok(None))。
async fn get_remote_manifest(
    node_addr: &str,
    bucket: &str,
    object_hash: &str,
) -> Result<Option<Vec<u8>>, String> {
    let url = remote_manifest_url(node_addr, bucket, object_hash);
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|err| err.to_string())?;
    let resp = client
        .get(&url)
        .header("x-rustio-internal-token", AppState::internal_control_token())
        .send()
        .await
        .map_err(|err| format!("remote manifest get from {node_addr} failed: {err}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("remote manifest get status {} from {node_addr}", resp.status()));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|err| format!("remote manifest get read body from {node_addr}: {err}"))?;
    Ok(Some(bytes.to_vec()))
}

/// manifest 副本目标节点:(node_id, node_addr)。node_id=0 表示本地。
struct ManifestReplica {
    node_id: u64,
    node_addr: String,
}

/// 选 manifest 副本节点(对齐 MinIO 元数据多副本):
/// 单机(local_node_id=0)→ 仅本地一份;集群 → 取 manifest 各分片所属节点去重,
/// 取前 `parity_shards + 1` 个不同节点(与数据容错等级一致),保证本节点在内(读写本地快路径)。
fn manifest_replica_nodes(state: &AppState, manifest: &EcObjectManifest) -> Vec<ManifestReplica> {
    if state.local_node_id == 0 {
        return vec![ManifestReplica { node_id: 0, node_addr: String::new() }];
    }
    let want = manifest.parity_shards + 1;
    let mut replicas: Vec<ManifestReplica> = Vec::new();
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    // 本节点优先作为一份副本(本地读写快路径)。
    replicas.push(ManifestReplica { node_id: state.local_node_id, node_addr: String::new() });
    seen.insert(state.local_node_id);
    // 其余副本取分片所属的不同节点(确定性顺序:按 shard_index)。
    let mut shards: Vec<&EcShardInfo> = manifest.shards.iter().collect();
    shards.sort_by_key(|s| s.shard_index);
    for shard in shards {
        if replicas.len() >= want {
            break;
        }
        if let (Some(node_id), Some(addr)) = (shard.node_id, shard.node_addr.as_ref()) {
            if node_id != 0 && !addr.is_empty() && seen.insert(node_id) {
                replicas.push(ManifestReplica { node_id, node_addr: addr.clone() });
            }
        }
    }
    replicas
}

/// quorum 写 manifest 到多副本节点。floor(N/2)+1 成功才算成功。
/// 单机退化为本地单写。`local_manifest_path` 是本节点 manifest 落盘路径。
pub(crate) async fn write_manifest_quorum(
    state: &AppState,
    bucket: &str,
    object_hash: &str,
    local_manifest_path: &FsPath,
    manifest: &EcObjectManifest,
) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|err| err.to_string())?;
    let replicas = manifest_replica_nodes(state, manifest);
    let quorum = replicas.len() / 2 + 1;
    let mut ok = 0usize;
    for replica in &replicas {
        let result = if replica.node_id == 0 || replica.node_id == state.local_node_id {
            // 本地副本
            if let Some(parent) = local_manifest_path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            atomic_write(local_manifest_path, &bytes).await.map_err(|e| e.to_string())
        } else {
            put_remote_manifest(&replica.node_addr, bucket, object_hash, bytes.clone()).await
        };
        match result {
            Ok(()) => ok += 1,
            Err(message) => tracing::warn!(node = replica.node_id, error = %message, "manifest 副本写入失败"),
        }
    }
    if ok >= quorum {
        Ok(())
    } else {
        Err(format!("manifest 写未达 quorum({ok}/{quorum},共 {} 副本)", replicas.len()))
    }
}

/// 读 manifest:本地副本优先(快路径,零远程开销);本地缺失/损坏时并发查集群其他节点的副本,
/// 取 `updated_at` 最新者,并 inline healing 回写本地一份(下次本地命中)。
/// 这解决了 manifest 单副本单点:本节点没有该对象 manifest 时仍能从其他副本读到。
/// 返回 Ok(None) 表示所有已知副本都无该对象 manifest。
pub(crate) async fn read_manifest_quorum(
    state: &AppState,
    bucket_root: &FsPath,
    bucket: &str,
    key: &str,
) -> Option<EcObjectManifest> {
    let local_path = ec_manifest_path(bucket_root, key);
    // 快路径:本地副本命中。
    if let Ok(bytes) = tokio::fs::read(&local_path).await {
        if let Ok(manifest) = serde_json::from_slice::<EcObjectManifest>(&bytes) {
            return Some(manifest);
        }
    }
    // 单机无远程副本可查。
    if state.local_node_id == 0 {
        return None;
    }
    // 本地缺失/损坏:并发查集群其他节点副本,取 updated_at 最新者。
    let object_hash = sha256_hex(key.as_bytes());
    let peers: Vec<(u64, String)> = {
        let guard = state.cluster_peers.read().await;
        guard
            .values()
            .filter(|p| p.node_id != state.local_node_id && !p.api_addr.is_empty())
            .map(|p| (p.node_id, p.api_addr.clone()))
            .collect()
    };
    let mut best: Option<EcObjectManifest> = None;
    for (node_id, addr) in peers {
        match get_remote_manifest(&addr, bucket, &object_hash).await {
            Ok(Some(bytes)) => {
                if let Ok(manifest) = serde_json::from_slice::<EcObjectManifest>(&bytes) {
                    let newer = best
                        .as_ref()
                        .map(|b| manifest.updated_at > b.updated_at)
                        .unwrap_or(true);
                    if newer {
                        best = Some(manifest);
                    }
                }
            }
            Ok(None) => {}
            Err(message) => {
                tracing::debug!(node = node_id, error = %message, "读取远程 manifest 副本失败")
            }
        }
    }
    // inline healing:把从远程取到的最新 manifest 回写本地副本。
    if let Some(manifest) = &best {
        if let Ok(bytes) = serde_json::to_vec_pretty(manifest) {
            if let Some(parent) = local_path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            let _ = atomic_write(&local_path, &bytes).await;
        }
    }
    best
}

/// 将分片字节 PUT 到远程节点,返回远程计算的校验和。
async fn put_remote_shard(
    node_addr: &str,
    bucket: &str,
    object_hash: &str,
    disk_index: usize,
    shard_index: usize,
    bytes: Vec<u8>,
) -> Result<String, String> {
    let url = remote_shard_url(node_addr, bucket, object_hash, disk_index, shard_index);
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|err| err.to_string())?;
    let resp = client
        .put(&url)
        .header("x-rustio-internal-token", AppState::internal_control_token())
        .body(bytes)
        .send()
        .await
        .map_err(|err| format!("remote shard put to {node_addr} failed: {err}"))?;
    if !resp.status().is_success() {
        return Err(format!("remote shard put status {} from {node_addr}", resp.status()));
    }
    let value: Value = resp
        .json()
        .await
        .map_err(|err| format!("remote shard put decode from {node_addr}: {err}"))?;
    value
        .get("checksum")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("remote shard put missing checksum from {node_addr}"))
}

/// 以流式 body 将本地分片文件 PUT 到远程节点(内存恒定,供流式写入路径用)。
async fn put_remote_shard_file(
    node_addr: &str,
    bucket: &str,
    object_hash: &str,
    disk_index: usize,
    shard_index: usize,
    path: &FsPath,
) -> Result<(), String> {
    let url = remote_shard_url(node_addr, bucket, object_hash, disk_index, shard_index);
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|err| format!("open shard for remote put: {err}"))?;
    let stream = tokio_util::io::ReaderStream::new(file);
    let body = reqwest::Body::wrap_stream(stream);
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|err| err.to_string())?;
    let resp = client
        .put(&url)
        .header("x-rustio-internal-token", AppState::internal_control_token())
        .body(body)
        .send()
        .await
        .map_err(|err| format!("remote shard stream put to {node_addr} failed: {err}"))?;
    if !resp.status().is_success() {
        return Err(format!("remote shard stream put status {} from {node_addr}", resp.status()));
    }
    Ok(())
}

/// 从远程节点 GET 分片原始字节。
pub(crate) async fn get_remote_shard(
    node_addr: &str,
    bucket: &str,
    object_hash: &str,
    disk_index: usize,
    shard_index: usize,
) -> Result<Vec<u8>, String> {
    let url = remote_shard_url(node_addr, bucket, object_hash, disk_index, shard_index);
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|err| err.to_string())?;
    let resp = client
        .get(&url)
        .header("x-rustio-internal-token", AppState::internal_control_token())
        .send()
        .await
        .map_err(|err| format!("remote shard get from {node_addr} failed: {err}"))?;
    if !resp.status().is_success() {
        return Err(format!("remote shard get status {} from {node_addr}", resp.status()));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|err| format!("remote shard get read body from {node_addr}: {err}"))?;
    Ok(bytes.to_vec())
}

/// 远程分片探测结果(供治理扫描远程感知)。
pub(crate) struct RemoteShardStat {
    pub(crate) size: usize,
    pub(crate) checksum: String,
}

/// 探测远程节点上某分片的存在性与校验和(治理扫描用,不拉取分片字节)。
///
/// 返回 `Ok(None)` 表示远程明确报告分片不存在(`exists:false`);
/// `Ok(Some(_))` 表示存在并附大小/校验和;`Err` 表示 RPC/网络失败(扫描方按不可达=missing 处理)。
pub(crate) async fn stat_remote_shard(
    node_addr: &str,
    bucket: &str,
    object_hash: &str,
    disk_index: usize,
    shard_index: usize,
) -> Result<Option<RemoteShardStat>, String> {
    let url = format!(
        "{node_addr}/api/v1/internal/ec/shard-stat/{bucket}/{object_hash}/{disk_index}/{shard_index}"
    );
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|err| err.to_string())?;
    let resp = client
        .get(&url)
        .header("x-rustio-internal-token", AppState::internal_control_token())
        .send()
        .await
        .map_err(|err| format!("remote shard stat from {node_addr} failed: {err}"))?;
    if !resp.status().is_success() {
        return Err(format!("remote shard stat status {} from {node_addr}", resp.status()));
    }
    let value: Value = resp
        .json()
        .await
        .map_err(|err| format!("remote shard stat decode from {node_addr}: {err}"))?;
    if !value.get("exists").and_then(Value::as_bool).unwrap_or(false) {
        return Ok(None);
    }
    let size = value.get("size").and_then(Value::as_u64).unwrap_or(0) as usize;
    let checksum = value
        .get("checksum")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(Some(RemoteShardStat { size, checksum }))
}

/// 通知远程节点删除分片(对象删除 / 写入回滚)。
pub(crate) async fn delete_remote_shard(
    node_addr: &str,
    bucket: &str,
    object_hash: &str,
    disk_index: usize,
    shard_index: usize,
) -> Result<(), String> {
    let url = remote_shard_url(node_addr, bucket, object_hash, disk_index, shard_index);
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|err| err.to_string())?;
    let resp = client
        .delete(&url)
        .header("x-rustio-internal-token", AppState::internal_control_token())
        .send()
        .await
        .map_err(|err| format!("remote shard delete to {node_addr} failed: {err}"))?;
    if !resp.status().is_success() {
        return Err(format!("remote shard delete status {} from {node_addr}", resp.status()));
    }
    Ok(())
}

#[tracing::instrument(
    name = "ec_write",
    skip(state, payload, meta, customer_key),
    fields(bucket = %bucket, key = %key, size = payload.len())
)]
pub(crate) async fn write_ec_object(
    state: &AppState,
    bucket: &str,
    key: &str,
    payload: &[u8],
    meta: &mut S3ObjectMeta,
    customer_key: Option<&[u8; 32]>,
) -> Result<(), Response> {
    let payload = encrypt_payload_for_storage(state, key, payload, meta, customer_key).await?;
    let (data_shards, parity_shards) = ec_layout_for(state).await;
    let total_shards = data_shards + parity_shards;
    // 单机模式分片全部落本地盘,需本地盘数 ≥ total;集群模式由 resolve_shard_placements 校验全局磁盘池。
    if state.local_node_id == 0 && state.data_disks.len() < total_shards {
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "erasure disk count is not enough",
            key,
        ));
    }
    let placement = resolve_shard_placements(state, key, total_shards)
        .await
        .map_err(|message| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &message,
                key,
            )
        })?;

    let bucket_root = bucket_path(state, bucket)?;
    let shard_size = payload.len().div_ceil(data_shards).max(1);
    let mut shards = vec![vec![0u8; shard_size]; total_shards];
    for (index, byte) in payload.iter().enumerate() {
        let shard_index = index / shard_size;
        let offset = index % shard_size;
        if shard_index < data_shards {
            shards[shard_index][offset] = *byte;
        }
    }
    let reed_solomon = ReedSolomon::new(data_shards, parity_shards).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to create Reed-Solomon encoder: {err}"),
            key,
        )
    })?;
    reed_solomon.encode(&mut shards).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to encode Reed-Solomon shards: {err}"),
            key,
        )
    })?;

    let object_hash = sha256_hex(key.as_bytes());
    let mut shard_infos = Vec::with_capacity(total_shards);
    let mut successful_shards = 0usize;
    for shard_index in 0..total_shards {
        let place = &placement[shard_index];
        let disk_index = place.local_disk_index;
        let is_remote = place.node_id != 0 && place.node_id != state.local_node_id;
        let mut checksum = String::new();
        let mut write_ok = false;
        let shard_path;
        if is_remote {
            // 远程分片:RPC 发到目标节点落盘;manifest 仅记录节点信息,本地 path 留空。
            match put_remote_shard(
                &place.node_addr,
                bucket,
                &object_hash,
                disk_index,
                shard_index,
                shards[shard_index].clone(),
            )
            .await
            {
                Ok(remote_checksum) => {
                    checksum = remote_checksum;
                    successful_shards += 1;
                    write_ok = true;
                }
                Err(message) => {
                    tracing::warn!(
                        shard_index,
                        node = %place.node_addr,
                        error = %message,
                        "远程分片写入失败 / remote shard write failed"
                    );
                }
            }
            shard_path = PathBuf::new();
        } else {
            // 本地分片:落本地磁盘。
            let path = place
                .local_disk_path
                .join(bucket)
                .join(".rustio_ec")
                .join(&object_hash)
                .join(format!("{shard_index}.bin"));
            let mut write_failed = false;
            if let Some(parent) = path.parent() {
                if tokio::fs::create_dir_all(parent).await.is_err() {
                    write_failed = true;
                }
            } else {
                write_failed = true;
            }
            if !write_failed && atomic_write(&path, &shards[shard_index]).await.is_ok() {
                checksum = sha256_hex(&shards[shard_index]);
                successful_shards += 1;
                write_ok = true;
            }
            shard_path = path;
        }
        // 写失败的分片不写入 manifest:读/治理路径会按真实放置算法派生该缺失分片(含远程归属)
        // 并触发重建,避免空 checksum 分片造成读路径(判坏)与治理(判健康)判定不一致。
        if write_ok {
            shard_infos.push(EcShardInfo {
                shard_index,
                disk_index,
                path: shard_path,
                checksum,
                node_id: if is_remote { Some(place.node_id) } else { None },
                node_addr: if is_remote {
                    Some(place.node_addr.clone())
                } else {
                    None
                },
            });
        }
    }
    if successful_shards < data_shards {
        let cleanup_failed = cleanup_ec_written_shards(&shard_infos, bucket, &object_hash).await;
        tracing::warn!(
            successful_shards,
            data_shards,
            total_shards,
            cleanup_failed,
            "纠删码写入未达法定票数,已回滚 / ec write quorum not reached, rolled back"
        );
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!(
                "纠删码写入未达到法定票数（{successful_shards}/{data_shards}），已回滚已写分片，清理失败 {cleanup_failed} 个 / erasure write quorum not reached ({successful_shards}/{data_shards}); written shards rolled back, cleanup failed for {cleanup_failed} shard(s)"
            ),
            key,
        ));
    }

    let manifest = EcObjectManifest {
        bucket: bucket.to_string(),
        key: key.to_string(),
        total_size: payload.len() as u64,
        shard_size,
        data_shards,
        parity_shards,
        shards: shard_infos.clone(),
        updated_at: Utc::now(),
    };
    let manifest_path = ec_manifest_path(&bucket_root, key);
    // manifest 多副本 quorum 写(对齐 MinIO 元数据多副本);单机退化本地单写。
    if let Err(message) =
        write_manifest_quorum(state, bucket, &object_hash, &manifest_path, &manifest).await
    {
        let cleanup_failed = cleanup_ec_written_shards(&shard_infos, bucket, &object_hash).await;
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!(
                "写入纠删码清单未达 quorum,已回滚已写分片:{message},清理失败 {cleanup_failed} 个 / erasure manifest quorum write failed: {message}; written shards rolled back; cleanup failed for {cleanup_failed} shard(s)"
            ),
            key,
        ));
    }
    tracing::info!(
        successful_shards,
        total_shards,
        shard_size,
        "纠删码对象写入完成 / ec object written"
    );
    Ok(())
}

/// 流式纠删码编码：从已落盘的源文件按 1 MiB 块逐段编码，内存恒定（不随对象大小增长）。
///
/// 仅用于**非加密**对象（加密对象由调用方走 `write_ec_object` 全内存路径）。
/// 产出的分片布局、`shard_size`、校验和与 `write_ec_object` **逐字节一致**，因此与既有
/// `read_ec_object` 完全向后兼容（Reed-Solomon 编码逐字节独立，整体编码与分块编码结果相同）。
#[tracing::instrument(
    name = "ec_write_streaming",
    skip(state, src_path),
    fields(bucket = %bucket, key = %key, size = total)
)]
pub(crate) async fn write_ec_object_streaming(
    state: &AppState,
    bucket: &str,
    key: &str,
    src_path: &FsPath,
    total: u64,
) -> Result<(), Response> {
    let (data_shards, parity_shards) = ec_layout_for(state).await;
    let total_shards = data_shards + parity_shards;
    // 单机模式分片全部落本地盘,需本地盘数 ≥ total;集群模式由 resolve_shard_placements 校验全局磁盘池。
    if state.local_node_id == 0 && state.data_disks.len() < total_shards {
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "erasure disk count is not enough",
            key,
        ));
    }
    let placement = resolve_shard_placements(state, key, total_shards)
        .await
        .map_err(|message| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &message,
                key,
            )
        })?;
    let bucket_root = bucket_path(state, bucket)?;
    let shard_size = (total as usize).div_ceil(data_shards).max(1);
    let object_hash = sha256_hex(key.as_bytes());
    let reed_solomon = ReedSolomon::new(data_shards, parity_shards).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to create Reed-Solomon encoder: {err}"),
            key,
        )
    })?;

    // 每个分片的输出：文件句柄 + 增量校验和 + 路径 + 盘位 + 成功标志
    let mut shard_files: Vec<Option<tokio::fs::File>> = Vec::with_capacity(total_shards);
    let mut shard_hashers: Vec<Sha256> = Vec::with_capacity(total_shards);
    let mut shard_paths: Vec<PathBuf> = Vec::with_capacity(total_shards);
    let mut shard_ok: Vec<bool> = Vec::with_capacity(total_shards);
    #[allow(clippy::needless_range_loop)]
    for shard_index in 0..total_shards {
        let shard_path = placement[shard_index]
            .local_disk_path
            .join(bucket)
            .join(".rustio_ec")
            .join(&object_hash)
            .join(format!("{shard_index}.bin"));
        let mut ok = true;
        let mut handle = None;
        if let Some(parent) = shard_path.parent() {
            if tokio::fs::create_dir_all(parent).await.is_err() {
                ok = false;
            }
        } else {
            ok = false;
        }
        if ok {
            match tokio::fs::File::create(&shard_path).await {
                Ok(file) => {
                    set_nocache(&file);
                    handle = Some(file);
                }
                Err(_) => ok = false,
            }
        }
        shard_files.push(handle);
        shard_hashers.push(Sha256::new());
        shard_paths.push(shard_path);
        shard_ok.push(ok);
    }

    // data 分片读取器：各自定位到 i*shard_size，并限制读取 shard_size 字节（不越界到下一分片区间）
    let mut readers = Vec::with_capacity(data_shards);
    for i in 0..data_shards {
        let mut file = tokio::fs::File::open(src_path).await.map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to open source for erasure encode: {err}"),
                key,
            )
        })?;
        set_nocache(&file);
        // 源文件短于 i*shard_size 时 seek 失败，该分片全为补零，照常使用受限读取器
        let _ = file
            .seek(std::io::SeekFrom::Start((i * shard_size) as u64))
            .await;
        readers.push(file.take(shard_size as u64));
    }

    const BLOCK: usize = 1024 * 1024;
    let mut produced = 0usize;
    while produced < shard_size {
        let this_block = BLOCK.min(shard_size - produced);
        let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(total_shards);
        for reader in readers.iter_mut().take(data_shards) {
            let mut buf = vec![0u8; this_block];
            let mut filled = 0usize;
            while filled < this_block {
                let read = reader.read(&mut buf[filled..]).await.map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to read source for erasure encode: {err}"),
                        key,
                    )
                })?;
                if read == 0 {
                    break; // 源已读尽，本块剩余保持补零
                }
                filled += read;
            }
            blocks.push(buf);
        }
        for _ in 0..parity_shards {
            blocks.push(vec![0u8; this_block]);
        }
        if let Err(err) = reed_solomon.encode(&mut blocks) {
            cleanup_streaming_shards(&shard_paths).await;
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to encode Reed-Solomon shards: {err}"),
                key,
            ));
        }
        for shard_index in 0..total_shards {
            if !shard_ok[shard_index] {
                continue;
            }
            let write_failed = match shard_files[shard_index].as_mut() {
                Some(file) => file.write_all(&blocks[shard_index]).await.is_err(),
                None => true,
            };
            if write_failed {
                shard_ok[shard_index] = false;
                shard_files[shard_index] = None;
            } else {
                shard_hashers[shard_index].update(&blocks[shard_index]);
            }
        }
        produced += this_block;
    }

    // 收尾：flush + 定稿校验和；失败分片删除文件并置空校验和（read 时检测到后触发重建）
    let mut shard_infos = Vec::with_capacity(total_shards);
    let mut successful = 0usize;
    for (shard_index, ((mut file_opt, hasher), ok_flag)) in shard_files
        .into_iter()
        .zip(shard_hashers)
        .zip(shard_ok.iter().copied())
        .enumerate()
    {
        let place = &placement[shard_index];
        let disk_index = place.local_disk_index;
        let is_remote = place.node_id != 0 && place.node_id != state.local_node_id;
        let path = shard_paths[shard_index].clone();
        let mut checksum = String::new();
        let mut ok = ok_flag;
        if ok {
            let flushed = match file_opt.as_mut() {
                Some(file) => {
                    let ok = file.flush().await.is_ok();
                    if ok {
                        drop_page_cache(file);
                    }
                    ok
                }
                None => false,
            };
            if flushed {
                checksum = hex::encode(hasher.finalize());
                successful += 1;
            } else {
                ok = false;
            }
        }
        // 远程分片:本地临时文件定稿后流式 PUT 到目标节点,成功则删除本地副本(manifest path 留空)。
        let mut manifest_path = path.clone();
        if ok && is_remote {
            match put_remote_shard_file(
                &place.node_addr,
                bucket,
                &object_hash,
                disk_index,
                shard_index,
                &path,
            )
            .await
            {
                Ok(()) => {
                    let _ = tokio::fs::remove_file(&path).await;
                    manifest_path = PathBuf::new();
                }
                Err(message) => {
                    tracing::warn!(
                        shard_index,
                        node = %place.node_addr,
                        error = %message,
                        "远程分片流式写入失败 / remote shard streaming write failed"
                    );
                    ok = false;
                    successful = successful.saturating_sub(1);
                    checksum = String::new();
                }
            }
        }
        if !ok {
            let _ = tokio::fs::remove_file(&path).await;
        }
        // 仅成功写入的分片进入 manifest;失败分片由读/治理按真实放置派生并触发重建,
        // 保持与非流式写路径一致,避免空 checksum 分片造成判定分歧。
        if ok {
            shard_infos.push(EcShardInfo {
                shard_index,
                disk_index,
                path: manifest_path,
                checksum,
                node_id: if is_remote { Some(place.node_id) } else { None },
                node_addr: if is_remote {
                    Some(place.node_addr.clone())
                } else {
                    None
                },
            });
        }
    }

    if successful < data_shards {
        let remote_cleanup_failed =
            cleanup_ec_written_shards(&shard_infos, bucket, &object_hash).await;
        cleanup_streaming_shards(&shard_paths).await;
        tracing::warn!(
            successful_shards = successful,
            data_shards,
            total_shards,
            remote_cleanup_failed,
            "纠删码流式写入未达法定票数,已回滚 / ec streaming write quorum not reached, rolled back"
        );
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!(
                "纠删码写入未达到法定票数（{successful}/{data_shards}），已回滚已写分片 / erasure write quorum not reached ({successful}/{data_shards}); written shards rolled back"
            ),
            key,
        ));
    }

    let manifest = EcObjectManifest {
        bucket: bucket.to_string(),
        key: key.to_string(),
        total_size: total,
        shard_size,
        data_shards,
        parity_shards,
        shards: shard_infos,
        updated_at: Utc::now(),
    };
    let manifest_path = ec_manifest_path(&bucket_root, key);
    // manifest 多副本 quorum 写;单机退化本地单写。
    if let Err(message) =
        write_manifest_quorum(state, bucket, &object_hash, &manifest_path, &manifest).await
    {
        cleanup_streaming_shards(&shard_paths).await;
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!(
                "写入纠删码清单未达 quorum,已回滚已写分片:{message} / erasure manifest quorum write failed: {message}; written shards rolled back"
            ),
            key,
        ));
    }
    tracing::info!(
        successful_shards = successful,
        total_shards,
        shard_size,
        "纠删码流式对象写入完成 / ec object written (streaming)"
    );
    Ok(())
}

async fn cleanup_streaming_shards(paths: &[PathBuf]) {
    for path in paths {
        let _ = tokio::fs::remove_file(path).await;
    }
}

#[tracing::instrument(
    name = "ec_read",
    skip(state, meta, customer_key),
    fields(bucket = %bucket, key = %key)
)]
pub(crate) async fn read_ec_object(
    state: &AppState,
    bucket: &str,
    key: &str,
    meta: Option<&S3ObjectMeta>,
    customer_key: Option<&[u8; 32]>,
) -> Result<Option<Vec<u8>>, Response> {
    let bucket_root = bucket_path(state, bucket)?;
    // manifest 多副本读:本地优先,本地缺失则从集群其他副本取最新并 inline 回写本地。
    let mut manifest = match read_manifest_quorum(state, &bucket_root, bucket, key).await {
        Some(manifest) => manifest,
        None => return Ok(None),
    };
    if manifest.data_shards == 0 {
        return Ok(None);
    }

    let total_shards = manifest.data_shards + manifest.parity_shards;
    if manifest.shards.len() < total_shards {
        let existing = manifest
            .shards
            .iter()
            .map(|shard| shard.shard_index)
            .collect::<HashSet<_>>();
        let object_hash = sha256_hex(key.as_bytes());
        for shard_index in 0..total_shards {
            if existing.contains(&shard_index) {
                continue;
            }
            // 复用真实放置算法推断缺失分片归属(可能是远程节点),避免误判为本地空路径。
            if let Some(info) = derive_shard_info_for_index(
                state,
                key,
                &object_hash,
                bucket,
                shard_index,
                total_shards,
            )
            .await
            {
                manifest.shards.push(info);
            }
        }
    }
    let reed_solomon =
        ReedSolomon::new(manifest.data_shards, manifest.parity_shards).map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create Reed-Solomon decoder: {err}"),
                key,
            )
        })?;
    let mut loaded = vec![None::<Vec<u8>>; total_shards];
    let mut failed = HashSet::new();
    let read_object_hash = sha256_hex(key.as_bytes());
    for shard in &manifest.shards {
        if shard.shard_index >= total_shards {
            continue;
        }
        let bytes = if shard_is_remote(shard, state.local_node_id) {
            // 远程分片:RPC 从目标节点 GET。
            let node_addr = shard.node_addr.as_deref().unwrap_or_default();
            match get_remote_shard(
                node_addr,
                bucket,
                &read_object_hash,
                shard.disk_index,
                shard.shard_index,
            )
            .await
            {
                Ok(bytes) => bytes,
                Err(message) => {
                    tracing::warn!(
                        shard_index = shard.shard_index,
                        node = %node_addr,
                        error = %message,
                        "远程分片读取失败,降级重建 / remote shard read failed, will reconstruct"
                    );
                    failed.insert(shard.shard_index);
                    continue;
                }
            }
        } else {
            match tokio::fs::read(&shard.path).await {
                Ok(bytes) => bytes,
                Err(_) => {
                    failed.insert(shard.shard_index);
                    continue;
                }
            }
        };
        if bytes.len() != manifest.shard_size || sha256_hex(&bytes) != shard.checksum {
            failed.insert(shard.shard_index);
            continue;
        }
        loaded[shard.shard_index] = Some(bytes);
    }
    let existing = manifest
        .shards
        .iter()
        .map(|shard| shard.shard_index)
        .collect::<HashSet<_>>();
    #[allow(clippy::needless_range_loop)]
    for shard_index in 0..total_shards {
        if !existing.contains(&shard_index) || loaded[shard_index].is_none() {
            failed.insert(shard_index);
        }
    }

    let available_shards = loaded.iter().filter(|item| item.is_some()).count();
    if available_shards < manifest.data_shards {
        let affected_disks = failed
            .iter()
            .map(|shard_index| {
                manifest_disk_id_for_shard(&manifest, *shard_index, state.data_disks.len())
            })
            .collect::<Vec<_>>();
        let _ = upsert_storage_job(
            state,
            StorageJobDraft {
                kind: "rebuild".to_string(),
                target: format!("{bucket}/{key}"),
                bucket: Some(bucket.to_string()),
                key: Some(key.to_string()),
                version_id: meta.map(|item| item.version_id.clone()),
                priority: Some(1200),
                affected_disks,
                missing_shards: failed.len(),
                corrupted_shards: 0,
                source: "read_failure".to_string(),
                details: json!({
                    "bucket": bucket,
                    "key": key,
                    "available_shards": available_shards,
                    "required_shards": manifest.data_shards,
                }),
            },
            "pending",
        )
        .await;
        tracing::error!(
            available_shards,
            required_shards = manifest.data_shards,
            total_shards,
            failed_shards = failed.len(),
            "纠删码读取未达法定票数,已排重建任务 / ec read quorum not reached, rebuild job queued"
        );
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!(
                "纠删码读取未达到法定票数：可用分片 {available_shards}/{total_shards}，至少需要 {} / erasure read quorum not reached: {available_shards}/{total_shards} shards available, need at least {}",
                manifest.data_shards,
                manifest.data_shards
            ),
            key,
        ));
    }
    if failed.len() > manifest.parity_shards {
        let affected_disks = failed
            .iter()
            .map(|shard_index| {
                manifest_disk_id_for_shard(&manifest, *shard_index, state.data_disks.len())
            })
            .collect::<Vec<_>>();
        let _ = upsert_storage_job(
            state,
            StorageJobDraft {
                kind: "rebuild".to_string(),
                target: format!("{bucket}/{key}"),
                bucket: Some(bucket.to_string()),
                key: Some(key.to_string()),
                version_id: meta.map(|item| item.version_id.clone()),
                priority: Some(1300),
                affected_disks,
                missing_shards: failed.len(),
                corrupted_shards: failed.len(),
                source: "read_failure".to_string(),
                details: json!({
                    "bucket": bucket,
                    "key": key,
                    "failed_shards": failed.len(),
                    "parity_shards": manifest.parity_shards,
                }),
            },
            "pending",
        )
        .await;
        tracing::error!(
            failed_shards = failed.len(),
            parity_shards = manifest.parity_shards,
            "纠删码分片损坏超出奇偶恢复能力,已排重建任务 / ec shards corrupted beyond parity, rebuild job queued"
        );
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "纠删码分片损坏超出奇偶校验恢复能力 / erasure shards corrupted beyond parity recovery",
            key,
        ));
    }
    if !failed.is_empty() {
        tracing::warn!(
            failed_shards = failed.len(),
            parity_shards = manifest.parity_shards,
            "纠删码降级读取,触发分片重建 / ec degraded read, reconstructing shards"
        );
        reed_solomon.reconstruct(&mut loaded).map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to reconstruct Reed-Solomon shards: {err}"),
                key,
            )
        })?;
        for shard_info in manifest.shards.iter_mut() {
            if !failed.contains(&shard_info.shard_index) {
                continue;
            }
            let Some(recovered) = loaded
                .get(shard_info.shard_index)
                .and_then(|item| item.as_ref())
            else {
                continue;
            };
            if shard_is_remote(shard_info, state.local_node_id) {
                // 远程分片:重建结果 RPC 回写目标节点。失败仅记日志,不阻断本次读取
                // (data 已由 RS 重建出,治理任务会再排重建)。
                let node_addr = shard_info.node_addr.clone().unwrap_or_default();
                match put_remote_shard(
                    &node_addr,
                    bucket,
                    &read_object_hash,
                    shard_info.disk_index,
                    shard_info.shard_index,
                    recovered.clone(),
                )
                .await
                {
                    Ok(remote_checksum) => shard_info.checksum = remote_checksum,
                    Err(message) => tracing::warn!(
                        shard_index = shard_info.shard_index,
                        node = %node_addr,
                        error = %message,
                        "远程分片重建回写失败 / remote shard recovery write-back failed"
                    ),
                }
                continue;
            }
            if let Some(parent) = shard_info.path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to create shard directory during recovery: {err}"),
                        key,
                    )
                })?;
            }
            tokio::fs::write(&shard_info.path, recovered)
                .await
                .map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to persist recovered shard: {err}"),
                        key,
                    )
                })?;
            shard_info.checksum = sha256_hex(recovered);
        }
        // 重建后的 manifest(分片校验和已更新)quorum 回写各副本。
        let manifest_path = ec_manifest_path(&bucket_root, key);
        let recovery_hash = sha256_hex(key.as_bytes());
        if let Err(message) =
            write_manifest_quorum(state, bucket, &recovery_hash, &manifest_path, &manifest).await
        {
            tracing::warn!(error = %message, "重建后 manifest quorum 回写失败");
        }
    }

    let mut payload = Vec::with_capacity(manifest.total_size as usize);
    #[allow(clippy::needless_range_loop)]
    for shard_index in 0..manifest.data_shards {
        let Some(bytes) = loaded[shard_index].as_ref() else {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "缺少纠删码数据分片 / missing erasure data shard",
                key,
            ));
        };
        payload.extend_from_slice(bytes);
    }
    payload.truncate(manifest.total_size as usize);
    touch_object_access_heat(state, bucket, key).await;
    Ok(Some(
        decrypt_payload_from_storage(state, key, payload, meta, customer_key).await?,
    ))
}

/// 流式纠删码读取：按 data 分片顺序逐块产出，内存恒定（不随对象大小增长）。
///
/// 仅在**非加密**且**所有 data 分片完好**（存在且大小匹配）时返回 `Some(Body)`；
/// 否则返回 `None`，由调用方回退到 `read_ec_object` 的全量加载 + 校验 + 重建路径。
/// 这样保证流式过程中途不会因缺数据失败（前置已确认 data 分片齐全）。
#[tracing::instrument(
    name = "ec_read_streaming",
    skip(state, meta, _customer_key),
    fields(bucket = %bucket, key = %key)
)]
pub(crate) async fn read_ec_object_streaming(
    state: &AppState,
    bucket: &str,
    key: &str,
    meta: Option<&S3ObjectMeta>,
    _customer_key: Option<&[u8; 32]>,
) -> Result<Option<axum::body::Body>, Response> {
    // 加密对象为整体 AEAD，无法流式解密，交回退路径处理
    if let Some(meta) = meta {
        if encryption_enabled(meta) {
            return Ok(None);
        }
    }
    let bucket_root = bucket_path(state, bucket)?;
    // manifest 多副本读(本地优先 + 远程回退 inline 回写);无任何副本则交回退路径。
    let manifest = match read_manifest_quorum(state, &bucket_root, bucket, key).await {
        Some(manifest) => manifest,
        None => return Ok(None),
    };
    if manifest.data_shards == 0 {
        return Ok(None);
    }

    // 任一 data 分片落远程节点时,本地无文件可流式读,回退到 read_ec_object 的 RPC 拉取路径。
    if manifest
        .shards
        .iter()
        .any(|shard| shard.shard_index < manifest.data_shards && shard_is_remote(shard, state.local_node_id))
    {
        return Ok(None);
    }

    // 收集 data 分片路径（shard_index 0..data_shards），逐一确认存在且大小等于 shard_size。
    // 仅做元数据检查（不读内容），任一异常即回退，确保后续流式读不会缺数据。
    let mut data_paths: Vec<Option<PathBuf>> = vec![None; manifest.data_shards];
    for shard in &manifest.shards {
        if shard.shard_index < manifest.data_shards {
            data_paths[shard.shard_index] = Some(shard.path.clone());
        }
    }
    let mut ordered_paths = Vec::with_capacity(manifest.data_shards);
    for entry in data_paths {
        let Some(path) = entry else {
            return Ok(None);
        };
        match tokio::fs::metadata(&path).await {
            Ok(metadata) if metadata.len() as usize == manifest.shard_size => {}
            _ => return Ok(None),
        }
        ordered_paths.push(path);
    }

    let total_size = manifest.total_size as usize;
    touch_object_access_heat(state, bucket, key).await;

    let stream = async_stream::stream! {
        let mut remaining = total_size;
        for path in ordered_paths {
            if remaining == 0 {
                break;
            }
            let mut file = match tokio::fs::File::open(&path).await {
                Ok(file) => file,
                Err(err) => {
                    yield Err(err);
                    return;
                }
            };
            set_nocache(&file);
            let mut buf = vec![0u8; 1024 * 1024];
            while remaining > 0 {
                let read = match file.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(read) => read,
                    Err(err) => {
                        yield Err(err);
                        return;
                    }
                };
                let take = read.min(remaining);
                yield Ok(Bytes::copy_from_slice(&buf[..take]));
                remaining -= take;
            }
        }
    };
    Ok(Some(axum::body::Body::from_stream(stream)))
}

/// 流式 EC 对象读取的 Range 变体：仅读取 [start, end] 闭区间内的字节，返回 206 响应对应的 Body。
/// 复用与 `read_ec_object_streaming` 相同的前置检查（manifest quorum、全 data 分片本地、非加密），
/// 不满足时返回 `Ok(None)` 让调用方回退到全量 truncate/drain 路径。
pub(crate) async fn read_ec_object_streaming_range(
    state: &AppState,
    bucket: &str,
    key: &str,
    meta: &S3ObjectMeta,
    start: u64,
    end: u64,
) -> Result<Option<axum::body::Body>, Response> {
    if encryption_enabled(meta) {
        return Ok(None);
    }
    let bucket_root = bucket_path(state, bucket)?;
    let manifest = match read_manifest_quorum(state, &bucket_root, bucket, key).await {
        Some(manifest) => manifest,
        None => return Ok(None),
    };
    if manifest.data_shards == 0 {
        return Ok(None);
    }
    if manifest
        .shards
        .iter()
        .any(|shard| shard.shard_index < manifest.data_shards && shard_is_remote(shard, state.local_node_id))
    {
        return Ok(None);
    }

    let shard_size = manifest.shard_size as u64;
    let total = manifest.total_size as u64;
    let end = end.min(total.saturating_sub(1));
    if start > end {
        return Ok(None);
    }
    let want = end - start + 1;

    let mut data_paths: Vec<Option<PathBuf>> = vec![None; manifest.data_shards];
    for shard in &manifest.shards {
        if shard.shard_index < manifest.data_shards {
            data_paths[shard.shard_index] = Some(shard.path.clone());
        }
    }
    let mut ordered_paths = Vec::with_capacity(manifest.data_shards);
    for entry in data_paths {
        let Some(path) = entry else {
            return Ok(None);
        };
        match tokio::fs::metadata(&path).await {
            Ok(metadata) if metadata.len() as usize == manifest.shard_size => {}
            _ => return Ok(None),
        }
        ordered_paths.push(path);
    }

    touch_object_access_heat(state, bucket, key).await;
    let first_shard = (start / shard_size) as usize;
    let inner = start % shard_size;

    let stream = async_stream::stream! {
        let mut want_remaining = want;
        for (idx, path) in ordered_paths.iter().enumerate().skip(first_shard) {
            if want_remaining == 0 {
                break;
            }
            let mut file = match tokio::fs::File::open(path).await {
                Ok(file) => file,
                Err(err) => { yield Err(err); return; }
            };
            set_nocache(&file);
            if idx == first_shard && inner > 0 {
                use tokio::io::AsyncSeekExt;
                if let Err(err) = file.seek(std::io::SeekFrom::Start(inner)).await {
                    yield Err(err); return;
                }
            }
            // 该分片在对象内的起始偏移
            let shard_obj_start = idx as u64 * shard_size;
            // 该分片在对象内的结束偏移(含)
            let shard_obj_end = ((idx + 1) as u64 * shard_size).min(total).saturating_sub(1);
            // 当前分片的有效读取长度上限
            let max_from_shard = if start > shard_obj_end {
                0
            } else if start >= shard_obj_start {
                (shard_obj_end - start + 1).min(want_remaining)
            } else {
                (shard_obj_end - shard_obj_start + 1).min(want_remaining)
            };
            let mut buf = vec![0u8; 1024 * 1024];
            let mut shard_read = 0u64;
            while shard_read < max_from_shard {
                let to_read = ((max_from_shard - shard_read) as usize).min(buf.len());
                let read = match file.read(&mut buf[..to_read]).await {
                    Ok(0) => break,
                    Ok(read) => read,
                    Err(err) => { yield Err(err); return; }
                };
                if read == 0 { break; }
                yield Ok(Bytes::copy_from_slice(&buf[..read]));
                shard_read += read as u64;
                want_remaining -= read as u64;
            }
        }
    };
    Ok(Some(axum::body::Body::from_stream(stream)))
}

#[tracing::instrument(name = "ec_remove", skip(state), fields(bucket = %bucket, key = %key))]
pub(crate) async fn remove_ec_object(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<(), Response> {
    let bucket_root = bucket_path(state, bucket)?;
    let manifest_path = ec_manifest_path(&bucket_root, key);
    let manifest_bytes = match tokio::fs::read(&manifest_path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to read erasure manifest: {err}"),
                key,
            ));
        }
    };
    if let Ok(manifest) = serde_json::from_slice::<EcObjectManifest>(&manifest_bytes) {
        let object_hash = sha256_hex(key.as_bytes());
        for shard in manifest.shards {
            if shard_is_remote(&shard, state.local_node_id) {
                // 远程分片:RPC 通知目标节点删除。
                let node_addr = shard.node_addr.as_deref().unwrap_or_default();
                if let Err(message) = delete_remote_shard(
                    node_addr,
                    bucket,
                    &object_hash,
                    shard.disk_index,
                    shard.shard_index,
                )
                .await
                {
                    tracing::warn!(
                        shard_index = shard.shard_index,
                        node = %node_addr,
                        error = %message,
                        "远程分片删除失败 / remote shard delete failed"
                    );
                }
            } else {
                let _ = tokio::fs::remove_file(shard.path).await;
            }
        }
    }
    let _ = tokio::fs::remove_file(&manifest_path).await;
    Ok(())
}


//! 对象元数据的嵌入式 KV 存储(redb)+ 内存 LRU 缓存。
//!
//! 真相源为 redb 单文件库,内存只保留有界 LRU 热点缓存,从根本上消除
//! 「海量对象元数据全驻内存」导致的 OOM。
//!
//! 这同时是未来分布式集群的存储地基:对象数据跨节点(EC)后,对象元数据
//! 经 openraft 增量 log 复制到各节点,各节点 apply 到本地 redb。`put`/`remove`
//! 是收敛的写入口,即未来挂载增量复制的位置(本次只留挂点,不实现)。

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use lru::LruCache;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use rustio_core::S3ObjectMeta;

/// redb 表:key = `bucket\0key` 编码字节,value = serde_json 序列化的 `S3ObjectMeta`。
const OBJECT_META_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("object_meta");

/// 默认 LRU 缓存容量(条数),可由环境变量 `RUSTIO_META_CACHE_CAP` 覆盖。
const DEFAULT_CACHE_CAP: usize = 100_000;

/// 对象元数据存储:redb 真相源 + LRU 缓存。
pub(crate) struct MetaStore {
    db: Database,
    cache: Mutex<LruCache<(String, String), S3ObjectMeta>>,
}

impl MetaStore {
    /// 打开(或创建)元数据库,并确保对象表存在。
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let db = Database::create(path).map_err(|err| format!("打开元数据库失败: {err}"))?;
        // 首次创建时初始化表,保证后续只读事务能 open_table。
        let txn = db.begin_write().map_err(|err| err.to_string())?;
        txn.open_table(OBJECT_META_TABLE)
            .map_err(|err| err.to_string())?;
        txn.commit().map_err(|err| err.to_string())?;

        let cap = std::env::var("RUSTIO_META_CACHE_CAP")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_CACHE_CAP);
        let cache = Mutex::new(LruCache::new(
            NonZeroUsize::new(cap).expect("缓存容量已保证非零"),
        ));
        Ok(Self { db, cache })
    }

    /// key 编码:`bucket` + NUL + `key`。NUL 分隔保证 bucket 边界清晰、前缀可排序。
    fn encode_key(bucket: &str, key: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(bucket.len() + 1 + key.len());
        buf.extend_from_slice(bucket.as_bytes());
        buf.push(0);
        buf.extend_from_slice(key.as_bytes());
        buf
    }

    /// bucket 前缀范围 `[bucket\0, bucket\x01)`,覆盖该 bucket 下全部对象。
    fn bucket_prefix_range(bucket: &str) -> (Vec<u8>, Vec<u8>) {
        let mut start = bucket.as_bytes().to_vec();
        start.push(0);
        let mut end = bucket.as_bytes().to_vec();
        end.push(1);
        (start, end)
    }

    /// 点查:先查 LRU,未命中查 redb 并回填缓存。
    /// LRU 锁持有极短(cache hit 仅一次 lookup),不可能在临界区内 panic,
    /// 因此 unwrap 是安全的——Mutex 中毒的唯一路径是持锁线程 panic。
    pub(crate) fn get(&self, bucket: &str, key: &str) -> Result<Option<S3ObjectMeta>, String> {
        let cache_key = (bucket.to_string(), key.to_string());
        if let Some(meta) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(&cache_key) {
            return Ok(Some(meta.clone()));
        }
        let txn = self.db.begin_read().map_err(|err| err.to_string())?;
        let table = txn
            .open_table(OBJECT_META_TABLE)
            .map_err(|err| err.to_string())?;
        let encoded = Self::encode_key(bucket, key);
        let Some(guard) = table
            .get(encoded.as_slice())
            .map_err(|err| err.to_string())?
        else {
            return Ok(None);
        };
        let meta: S3ObjectMeta =
            serde_json::from_slice(guard.value()).map_err(|err| err.to_string())?;
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).put(cache_key, meta.clone());
        Ok(Some(meta))
    }

    /// 不经缓存直接查 redb(后台扫描用,避免冷数据污染 LRU、淘汰前台热点)。
    pub(crate) fn get_uncached(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<S3ObjectMeta>, String> {
        let txn = self.db.begin_read().map_err(|err| err.to_string())?;
        let table = txn
            .open_table(OBJECT_META_TABLE)
            .map_err(|err| err.to_string())?;
        let encoded = Self::encode_key(bucket, key);
        let Some(guard) = table
            .get(encoded.as_slice())
            .map_err(|err| err.to_string())?
        else {
            return Ok(None);
        };
        let meta: S3ObjectMeta =
            serde_json::from_slice(guard.value()).map_err(|err| err.to_string())?;
        Ok(Some(meta))
    }

    /// 写入:redb 写事务落盘(真相源)后更新 LRU。
    pub(crate) fn put(&self, meta: &S3ObjectMeta) -> Result<(), String> {
        let encoded = Self::encode_key(&meta.bucket, &meta.key);
        let bytes = serde_json::to_vec(meta).map_err(|err| err.to_string())?;
        let txn = self.db.begin_write().map_err(|err| err.to_string())?;
        {
            let mut table = txn
                .open_table(OBJECT_META_TABLE)
                .map_err(|err| err.to_string())?;
            table
                .insert(encoded.as_slice(), bytes.as_slice())
                .map_err(|err| err.to_string())?;
        }
        txn.commit().map_err(|err| err.to_string())?;
        // 未来集群:此处提交增量 upsert op 到 openraft,复制到各节点本地 redb。
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put((meta.bucket.clone(), meta.key.clone()), meta.clone());
        Ok(())
    }

    /// 删除:redb 写事务删除后淘汰 LRU 对应项。
    pub(crate) fn remove(&self, bucket: &str, key: &str) -> Result<(), String> {
        let encoded = Self::encode_key(bucket, key);
        let txn = self.db.begin_write().map_err(|err| err.to_string())?;
        {
            let mut table = txn
                .open_table(OBJECT_META_TABLE)
                .map_err(|err| err.to_string())?;
            table
                .remove(encoded.as_slice())
                .map_err(|err| err.to_string())?;
        }
        txn.commit().map_err(|err| err.to_string())?;
        // 未来集群:此处提交增量 delete op 到 openraft。
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop(&(bucket.to_string(), key.to_string()));
        Ok(())
    }

    /// 按 bucket 前缀范围扫描该 bucket 下全部对象元数据(redb range,非全表)。
    pub(crate) fn scan_bucket(&self, bucket: &str) -> Result<Vec<S3ObjectMeta>, String> {
        let (start, end) = Self::bucket_prefix_range(bucket);
        let txn = self.db.begin_read().map_err(|err| err.to_string())?;
        let table = txn
            .open_table(OBJECT_META_TABLE)
            .map_err(|err| err.to_string())?;
        let mut out = Vec::new();
        let range = table
            .range(start.as_slice()..end.as_slice())
            .map_err(|err| err.to_string())?;
        for item in range {
            let (_, value) = item.map_err(|err| err.to_string())?;
            let meta: S3ObjectMeta =
                serde_json::from_slice(value.value()).map_err(|err| err.to_string())?;
            out.push(meta);
        }
        Ok(out)
    }

    /// range 真分页:从 `start_after`(不含)起按 key 有序取最多 `limit` 个对象元数据。
    /// O(log n + page),与 bucket 总对象数解耦——LIST 单页延迟恒定(redb 有序索引核心红利)。
    /// `start_after` 为空表示从 bucket 头部开始。
    pub(crate) fn scan_bucket_page(
        &self,
        bucket: &str,
        start_after: &str,
        limit: usize,
    ) -> Result<Vec<S3ObjectMeta>, String> {
        self.scan_bucket_page_inner(bucket, start_after, limit, false)
    }

    /// 同 `scan_bucket_page`,但起点为 **inclusive**(包含等于 `start` 自身的 key)。
    /// 用于 LIST 的 prefix 下界:prefix 恰等于某对象完整 key 时,该对象必须保留
    /// (exclusive 版本会把它误跳过——LIST(prefix=完整key) 漏对象的根因)。
    pub(crate) fn scan_bucket_page_inclusive(
        &self,
        bucket: &str,
        start: &str,
        limit: usize,
    ) -> Result<Vec<S3ObjectMeta>, String> {
        self.scan_bucket_page_inner(bucket, start, limit, true)
    }

    fn scan_bucket_page_inner(
        &self,
        bucket: &str,
        start_after: &str,
        limit: usize,
        inclusive: bool,
    ) -> Result<Vec<S3ObjectMeta>, String> {
        let (prefix_start, end) = Self::bucket_prefix_range(bucket);
        // 起点:start_after 非空则定位到 bucket\0<start_after>;否则 bucket 头部。
        // exclusive(默认,分页 continuation):追加 0 字节使 range 起点严格大于 start_after 自身。
        // inclusive(prefix 下界):直接用 bucket\0<start> 作起点,保留等于 start 的 key。
        let start = if start_after.is_empty() {
            prefix_start
        } else {
            let mut s = Self::encode_key(bucket, start_after);
            if !inclusive {
                s.push(0);
            }
            s
        };
        let txn = self.db.begin_read().map_err(|err| err.to_string())?;
        let table = txn
            .open_table(OBJECT_META_TABLE)
            .map_err(|err| err.to_string())?;
        let mut out = Vec::with_capacity(limit.min(4096));
        let range = table
            .range(start.as_slice()..end.as_slice())
            .map_err(|err| err.to_string())?;
        for item in range {
            if out.len() >= limit {
                break;
            }
            let (_, value) = item.map_err(|err| err.to_string())?;
            let meta: S3ObjectMeta =
                serde_json::from_slice(value.value()).map_err(|err| err.to_string())?;
            out.push(meta);
        }
        Ok(out)
    }

    /// 全表扫描(仅供低频管理操作使用,如统计、KMS 轮转)。
    pub(crate) fn scan_all(&self) -> Result<Vec<S3ObjectMeta>, String> {
        let txn = self.db.begin_read().map_err(|err| err.to_string())?;
        let table = txn
            .open_table(OBJECT_META_TABLE)
            .map_err(|err| err.to_string())?;
        let mut out = Vec::new();
        let iter = table.iter().map_err(|err| err.to_string())?;
        for item in iter {
            let (_, value) = item.map_err(|err| err.to_string())?;
            let meta: S3ObjectMeta =
                serde_json::from_slice(value.value()).map_err(|err| err.to_string())?;
            out.push(meta);
        }
        Ok(out)
    }

    /// 删除某 bucket 下全部对象元数据(删 bucket 时用),返回删除条数。
    pub(crate) fn delete_bucket_prefix(&self, bucket: &str) -> Result<u64, String> {
        let (start, end) = Self::bucket_prefix_range(bucket);
        let txn = self.db.begin_write().map_err(|err| err.to_string())?;
        let mut count = 0u64;
        {
            let mut table = txn
                .open_table(OBJECT_META_TABLE)
                .map_err(|err| err.to_string())?;
            // 先收集要删的 key(range 借用 &table),再统一 remove(借用 &mut table)。
            let keys: Vec<Vec<u8>> = {
                let range = table
                    .range(start.as_slice()..end.as_slice())
                    .map_err(|err| err.to_string())?;
                let mut keys = Vec::new();
                for item in range {
                    let (key, _) = item.map_err(|err| err.to_string())?;
                    keys.push(key.value().to_vec());
                }
                keys
            };
            for key in keys {
                table
                    .remove(key.as_slice())
                    .map_err(|err| err.to_string())?;
                count += 1;
            }
        }
        txn.commit().map_err(|err| err.to_string())?;
        // 淘汰缓存中属于该 bucket 的条目。
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let evict: Vec<(String, String)> = cache
            .iter()
            .filter(|((cached_bucket, _), _)| cached_bucket == bucket)
            .map(|((cached_bucket, cached_key), _)| (cached_bucket.clone(), cached_key.clone()))
            .collect();
        for key in evict {
            cache.pop(&key);
        }
        Ok(count)
    }

    /// 从旧版「每对象一个 `.rustio_meta/<key>.json`」迁移到 redb。
    ///
    /// 幂等:完成后在 `data_dir` 写标记文件,再次启动直接跳过。遍历 `data_dir` 下各
    /// bucket 目录(非 `.` 开头)的 `.rustio_meta`,凡能反序列化为 `S3ObjectMeta` 者导入;
    /// bucket 级配置(`bucket-*.json`)字段不匹配会反序列化失败而自动跳过。
    /// 用单个写事务批量导入,避免逐条 fsync 拖慢启动。返回迁移条数。
    pub(crate) fn migrate_from_data_dir(&self, data_dir: &Path) -> Result<u64, String> {
        let marker = data_dir.join(".rustio_meta_migrated_v1");
        if marker.exists() {
            return Ok(0);
        }
        let mut migrated = 0u64;
        let txn = self.db.begin_write().map_err(|err| err.to_string())?;
        {
            let mut table = txn
                .open_table(OBJECT_META_TABLE)
                .map_err(|err| err.to_string())?;
            if let Ok(entries) = std::fs::read_dir(data_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_dir() {
                        continue;
                    }
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with('.') {
                        continue; // 跳过 .rustio_meta_raft / .rustio_sites 等内部目录
                    }
                    let meta_dir = path.join(".rustio_meta");
                    if !meta_dir.is_dir() {
                        continue;
                    }
                    let mut json_files = Vec::new();
                    Self::collect_json_files(&meta_dir, &mut json_files);
                    for file in json_files {
                        let Ok(bytes) = std::fs::read(&file) else {
                            continue;
                        };
                        let Ok(meta) = serde_json::from_slice::<S3ObjectMeta>(&bytes) else {
                            continue;
                        };
                        let encoded = Self::encode_key(&meta.bucket, &meta.key);
                        let value = serde_json::to_vec(&meta).map_err(|err| err.to_string())?;
                        table
                            .insert(encoded.as_slice(), value.as_slice())
                            .map_err(|err| err.to_string())?;
                        migrated += 1;
                    }
                }
            }
        }
        txn.commit().map_err(|err| err.to_string())?;
        let _ = std::fs::write(&marker, b"v1");
        Ok(migrated)
    }

    /// 递归收集 `dir` 下所有 `.json` 文件路径(对象 key 可能含 `/`,故需递归)。
    fn collect_json_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::collect_json_files(&path, out);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                out.push(path);
            }
        }
    }

}

